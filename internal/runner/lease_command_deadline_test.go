//go:build linux

package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLeaseDeadlineCommandInitializationAndCleanup(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "live-positive"
		if delayed {
			name = "initialize-crosses-expiry"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, map[string]any{"Spawn": true})
			if delayed {
				f.b.beforeRequest = func() {
					f.b.expiry = time.Now().Add(2 * time.Second).Truncate(time.Second)
					data, err := json.Marshal(map[string]any{"Spawn": true, "DelayAt": "initialize", "DelayUntil": f.b.expiry.Add(100 * time.Millisecond)})
					must(t, err)
					must(t, os.WriteFile(filepath.Join(f.home, "scenario.json"), data, 0600))
				}
			}
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			outcomes := 0
			assertChildrenAbsent := func() {
				for _, file := range []string{"server-pid", "child-pid", "grandchild-pid"} {
					path := filepath.Join(f.home, file)
					if _, err := os.Stat(path); os.IsNotExist(err) && file == "grandchild-pid" {
						continue
					}
					pid := readPID(t, path)
					if syscall.Kill(pid, 0) != syscall.ESRCH {
						t.Fatalf("%s survived command cleanup", file)
					}
				}
			}
			f.d.BeforeRelease = func(ctx context.Context, id string, success bool) error {
				outcomes++
				if ctx.Err() != nil || id != "lease" || success == delayed {
					t.Fatal("outcome lost independent cleanup budget or result")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("cleanup budget changed")
				}
				assertChildrenAbsent()
				return nil
			}
			status := f.run()
			want := 0
			if delayed {
				want = 75
				if !strings.Contains(f.err.String(), "lease_not_active") {
					t.Fatal("lease expiry was not reported")
				}
				if time.Since(f.b.expiry) > 5*time.Second {
					t.Fatal("cleanup exceeded its independent bound")
				}
			}
			requireStatus(t, status, want, f.err.String())
			releases := 0
			for _, call := range f.b.calls {
				if call == "release" {
					releases++
				}
			}
			if releases != 1 || outcomes != 1 {
				t.Fatal("cleanup did not attempt outcome and release exactly once")
			}
			assertChildrenAbsent()
			assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			seen := map[string]bool{}
			for _, event := range f.events() {
				method, _ := event["method"].(string)
				seen[method] = true
			}
			if !seen["initialize"] {
				t.Fatal("control did not reach initialize")
			}
			for _, method := range []string{"account/login/start", "thread/start", "turn/start"} {
				if seen[method] == delayed {
					t.Fatalf("unexpected material action %s: delayed=%t", method, delayed)
				}
			}
			if delayed {
				data, err := os.ReadFile(f.output)
				must(t, err)
				if string(data) != "old" {
					t.Fatal("expired command published output")
				}
			}
			t.Logf("delayed=%t status=%d outcomes=%d releases=%d children_absent=true", delayed, status, outcomes, releases)
		})
	}
}

type deadlineRenewBroker struct {
	BrokerClient
	until time.Time
	seen  bool
	valid bool
}

func (b *deadlineRenewBroker) Renew(ctx context.Context, request RenewRequest) (Lease, error) {
	b.seen = true
	deadline, ok := ctx.Deadline()
	b.valid = ok && !deadline.After(b.until) && ctx.Err() == nil
	return b.BrokerClient.Renew(ctx, request)
}

func TestLeaseDeadlineCoversRefreshAndCleanup(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "live-positive"
		if delayed {
			name = "refresh-crosses-expiry"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, map[string]any{"RefreshCount": 1})
			b := &deadlineRenewBroker{BrokerClient: f.b}
			f.d.Connect = func(context.Context) (BrokerClient, error) { return b, nil }
			f.b.beforeRequest = func() {
				if delayed {
					f.b.expiry = time.Now().Add(2 * time.Second).Truncate(time.Second)
				}
				b.until = f.b.expiry
			}
			f.b.slow = delayed
			f.b.ignoreCancel = delayed
			status := f.run()
			want := 0
			if delayed {
				want = 75
			}
			requireStatus(t, status, want, f.err.String())
			if !b.seen || !b.valid {
				t.Fatal("refresh was not entered live with the original lease deadline")
			}
			pid := readPID(t, filepath.Join(f.home, "server-pid"))
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("refresh cleanup left a child")
			}
			releases := 0
			for _, call := range f.b.calls {
				if call == "release" {
					releases++
				}
			}
			if releases != 1 {
				t.Fatal("refresh did not release exactly once")
			}
			for _, event := range f.events() {
				if reply, _ := event["reply"].(string); delayed && reply == `"refresh-1"` && event["error"] == false {
					t.Fatal("expired refresh delivered material")
				}
			}
			if delayed {
				assertAbsent(t, f.output)
			}
			t.Logf("delayed=%t status=%d refresh_deadline_bound=true releases=%d child_absent=true", delayed, status, releases)
		})
	}
}
