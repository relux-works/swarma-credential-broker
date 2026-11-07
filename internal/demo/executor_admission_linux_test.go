//go:build linux

package demo

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// These tests use public synthetic records inside a disposable user namespace.
// They do not invoke the privileged P1 helper or contact an account/provider.
func installExecutorRoster(t *testing.T, codex bool) (Roster, LaunchRecord) {
	t.Helper()
	publicRoot(t)
	r := fixtureRoster()
	if codex {
		r.Executor.ID, r.Executor.Path = ExecutorID, ExecutorPath
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	r.BootID = strings.TrimSpace(string(b))
	putRoot(t, RosterPath, r, 0644)
	if err := os.MkdirAll(LaunchDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	os.Chmod("/run/swarma-demo", 0755)
	os.Chmod(LaunchDirectory, 0755)
	l := LaunchRecord{"EX-two-executors", r.Accounts[0].UID, r.Accounts[0].Generation, strings.Repeat("a", 64), r.BootID}
	path, err := LaunchPath(l.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	putRoot(t, path, l, 0444)
	return r, l
}

func TestExecutorRosterManagerLeaseAndPublication(t *testing.T) {
	for _, codex := range []bool{false, true} {
		name := "witness-refuses-codex"
		if codex {
			name = "codex-admits"
		}
		t.Run(name, func(t *testing.T) {
			r, l := installExecutorRoster(t, codex)
			options := BrokerOptions(lease.Options{})
			e := testutil.NewPolicy(t, options, func(p *policy.Policy) {
				p.BrokerUID = 1102
				p.Accounts[0].AllowedUIDs = []uint32{l.UID}
			})
			e.UID = l.UID
			e.Request.LaunchID = l.PlanSHA256
			e.Request.Binding = e.Policy.Binding(l.UID, e.Policy.Accounts[0], e.Request.Profile)
			p := projectionFixture()
			p.Binding = e.Request.Binding
			q := syntheticQualification()
			q.Executable = e.Policy.Executable
			q.ChatGPTAccountID = e.Policy.Accounts[0].VendorID
			putRoot(t, AuthorityPath, p, 0644)
			putRoot(t, QualificationPath, q, 0644)
			if got := e.Manager.Peer(context.Background(), l.UID); got != codex {
				t.Fatalf("peer admission=%t, want %t", got, codex)
			}
			out := e.Manager.Call(context.Background(), l.UID, "lease.request", e.Request, time.Now())
			if !codex {
				if out.Err == nil {
					t.Fatal("witness-only roster issued a Codex lease")
				}
				e.NoLeaseRecords(t)
				return
			}
			if out.Err != nil {
				t.Fatal("Codex lease refused:", lease.ErrorCode(out.Err))
			}
			result := out.Result.(wire.LeaseResult)
			wrote := false
			if err := e.Manager.Publish(context.Background(), l.UID, e.Policy.Generation, result, func(context.Context, time.Time) error { wrote = true; return nil }); err != nil || !wrote {
				t.Fatal("Codex publication refused", err)
			}
			// Runtime holds and stale protected launch generations must still stop
			// both peer admission and the material delivery path.
			r.Runtime.Admitted = false
			putRoot(t, RosterPath, r, 0644)
			if e.Manager.Peer(context.Background(), l.UID) {
				t.Fatal("runtime hold admitted peer")
			}
			wrote = false
			if err := e.Manager.Publish(context.Background(), l.UID, e.Policy.Generation, result, func(context.Context, time.Time) error { wrote = true; return nil }); err == nil || wrote {
				t.Fatal("changed roster published material")
			}
		})
	}
}

func TestExecutorRosterRunnerAuthority(t *testing.T) {
	for _, codex := range []bool{false, true} {
		name := "witness-refuses-codex"
		if codex {
			name = "codex-admits"
		}
		t.Run(name, func(t *testing.T) {
			r, l := installExecutorRoster(t, codex)
			p := projectionFixture()
			q := syntheticQualification()
			o := runner.Options{Account: p.Binding.Account, Profile: p.Binding.Profile, LaunchHome: t.TempDir(), Cwd: r.Accounts[0].Workspace}
			if err := os.MkdirAll(o.Cwd, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll("/srv/swarma-demo") })
			var err error
			q.ConfigSHA256, err = runner.ConfigurationDigest(o, nil)
			if err != nil {
				t.Fatal(err)
			}
			preimage := map[string]any{"uid": l.UID, "profile": p.Binding.Profile, "harness": p.Binding.Harness, "account": p.Binding.Account, "channel": p.Binding.Channel, "endpoint": p.Binding.Endpoint, "executable_sha256": p.Binding.ExecutableSHA256, "policy_generation": p.Binding.PolicyGeneration}
			encoded, err := wire.Encode(preimage)
			if err != nil {
				t.Fatal(err)
			}
			p.Binding.Digest = Hash(encoded)
			q.Evidence.Identity.Executable.SHA256 = p.Binding.ExecutableSHA256
			putRoot(t, AuthorityPath, p, 0644)
			putRoot(t, QualificationPath, q, 0644)
			a := &Authority{Launch: l, UID: l.UID}
			got, err := a.Resolve(context.Background(), o)
			if !codex {
				if err == nil {
					t.Fatal("witness-only roster authorized Codex runner")
				}
				return
			}
			if err != nil || !got.Qualified || got.UID != l.UID || got.BindingDigest != p.Binding.Digest {
				t.Fatal("Codex runner authority refused", err)
			}
			path, _ := LaunchPath(l.ExecutionID)
			l.Generation = strings.Repeat("9", 32)
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			putRoot(t, path, l, 0444)
			if _, err := a.Resolve(context.Background(), o); err == nil {
				t.Fatal("replaced launch authorized runner")
			}
		})
	}
}
