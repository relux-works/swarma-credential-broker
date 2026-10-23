//go:build linux

package authowner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"sync"
	"testing"
	"time"
)

// Claim: canceled queued renewals at N=8/64 do not add vendor writers; reconnect
// reuses the committed generation, and release revokes its publication callback.
func TestProbeCoalescingCancellationPublication(t *testing.T) {
	for _, n := range []int{8, 64} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := newFixture(t, "rotate")
			uid := uint32(os.Geteuid())
			label := f.c.Accounts[0].Label
			p := policy.Policy{Installation: f.c.Installation, Generation: 1, BrokerUID: uid, Executable: f.c.Executable, ExecutableSHA256: f.c.ExecutableSHA256, MaxLeaseSeconds: 3600, Accounts: []policy.Account{{Label: label, VendorID: "fixture-account", AllowedUIDs: []uint32{uid}, Profiles: []string{"example"}, Endpoint: "https://chatgpt.com/backend-api/codex", ReleaseVersion: "0.163.0", QualificationID: f.c.QualificationID, Enabled: true}}}
			m, err := lease.New(p, f.s, f.e, lease.Options{Now: func() time.Time { return f.t.now }}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			rs := make([]wire.LeaseResult, n)
			for i := range rs {
				request := wire.LeaseRequest{Harness: "codex_cli", Profile: "example", Account: label, Channel: "external-token", Binding: p.Binding(uid, p.Accounts[0], "example"), Network: json.RawMessage("null"), LaunchID: fmt.Sprint("probe-", i), Executor: wire.Executor{Capabilities: []string{"credential-injection/1"}, Version: "fixture"}}
				out := m.Call(context.Background(), uid, "lease.request", request, time.Now())
				if out.Err != nil {
					t.Fatal("initial lease", out.Err)
				}
				rs[i] = out.Result.(wire.LeaseResult)
			}
			gate := make(chan struct{})
			f.m.gate = gate
			f.m.started = make(chan struct{}, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(gate) }) }
			defer unblock()
			answers := make([]chan lease.Outcome, n)
			cancels := make([]context.CancelFunc, n)
			for i, r := range rs {
				ctx, cancel := context.WithCancel(context.Background())
				cancels[i] = cancel
				defer cancel()
				answers[i] = make(chan lease.Outcome, 1)
				go func(i int, r wire.LeaseResult) {
					answers[i] <- m.Call(ctx, uid, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now())
				}(i, r)
				if i == 0 {
					select {
					case <-f.m.started:
					case <-time.After(time.Second):
						t.Fatal("writer did not start")
					}
				}
			}
			testutil.Await(t, func() bool { pending, _ := m.Stats(label); return pending == n })
			for i := 1; i < n; i += 2 {
				cancels[i]()
				out := <-answers[i]
				if out.Err == nil || out.Err.Error() != "renew_timeout" {
					t.Fatal("cancellation result", out.Err)
				}
			}
			testutil.Await(t, func() bool { pending, waiters := m.Stats(label); return pending == n/2 && waiters == n/2 })
			unblock()
			for i := 0; i < n; i += 2 {
				out := <-answers[i]
				if out.Err != nil {
					t.Fatal("survivor", out.Err)
				}
				rs[i] = out.Result.(wire.LeaseResult)
				if rs[i].Payload.AccessToken != f.next {
					t.Fatal("wrong generation")
				}
			}
			for i := 1; i < n; i += 2 {
				out := m.Call(context.Background(), uid, "lease.renew", wire.Renew{LeaseID: rs[i].LeaseID, RejectedSHA256: lease.Digest(rs[i].Payload.AccessToken)}, time.Now())
				if out.Err != nil || out.Result.(wire.LeaseResult).Payload.AccessToken != f.next {
					t.Fatal("reconnect refused", out.Err)
				}
			}
			if f.m.count() != 1 {
				t.Fatal("canceled/reconnected work duplicated vendor writer")
			}
			entered := make(chan struct{})
			published := make(chan error, 1)
			go func() {
				published <- m.Publish(context.Background(), uid, p.Generation, rs[0], func(ctx context.Context, _ time.Time) error { close(entered); <-ctx.Done(); return ctx.Err() })
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("publication not entered")
			}
			out := m.Call(context.Background(), uid, "lease.release", wire.Release{LeaseID: rs[0].LeaseID}, time.Now())
			if out.Err != nil {
				t.Fatal("release", out.Err)
			}
			select {
			case err := <-published:
				if err == nil {
					t.Fatal("revoked publication succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("publication not revoked")
			}
			called := false
			err = m.Publish(context.Background(), uid, p.Generation, rs[0], func(context.Context, time.Time) error { called = true; return nil })
			if err == nil || called || f.m.count() != 1 {
				t.Fatal("released result published or started writer")
			}
		})
	}
}
