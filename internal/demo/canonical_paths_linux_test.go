//go:build linux

package demo

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func canonicalManager(t *testing.T, l LaunchRecord) *testutil.Env {
	t.Helper()
	e := testutil.NewPolicy(t, BrokerOptions(lease.Options{}), func(p *policy.Policy) {
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
	return e
}

func canonicalAuthority(t *testing.T, r Roster, l LaunchRecord) (*Authority, runner.Options) {
	t.Helper()
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
	return &Authority{Launch: l, UID: l.UID}, o
}

// Every negative changes the actual wire object, beside unchanged P1 output.
// Synthetic owner material only supplies the pre-existing local manager fixture;
// no label matching or admission mock substitutes for the real demo gates.
func TestCanonicalP1CausalAuthorityPairs(t *testing.T) {
	ctx := context.Background()
	for _, bad := range rejectedP1Rosters(t, canonicalP1Roster(t, "codex")) {
		t.Run(bad.name, func(t *testing.T) {
			t.Run("manager", func(t *testing.T) {
				_, l := installExecutorRoster(t, true)
				e := canonicalManager(t, l)
				if !e.Manager.Peer(ctx, l.UID) {
					t.Fatal("canonical positive peer refused")
				}
				result := e.Issue(t)
				wrote := false
				if err := e.Manager.Publish(ctx, l.UID, e.Policy.Generation, result, func(context.Context, time.Time) error { wrote = true; return nil }); err != nil || !wrote {
					t.Fatal("canonical positive publication refused", err)
				}
				putRosterBytes(t, bad.raw)
				wrote = false
				if err := e.Manager.Publish(ctx, l.UID, e.Policy.Generation, result, func(context.Context, time.Time) error { wrote = true; return nil }); err == nil || wrote {
					t.Fatal("invalid wire published material")
				}
				// A fresh manager also refuses, independently of replacement latches.
				cold := canonicalManager(t, l)
				if cold.Manager.Peer(ctx, l.UID) {
					t.Fatal("invalid wire admitted peer")
				}
				coldCall := canonicalManager(t, l)
				if out := coldCall.Manager.Call(ctx, l.UID, "lease.request", coldCall.Request, time.Now()); out.Err == nil {
					t.Fatal("invalid wire issued lease")
				}
				coldCall.NoLeaseRecords(t)
			})
			t.Run("admission", func(t *testing.T) {
				_, l := installExecutorRoster(t, true)
				a := NewAdmission()
				if err := a.Peer(ctx, l.UID); err != nil {
					t.Fatal("positive peer refused", err)
				}
				if err := a.Check(ctx, l.UID, l.PlanSHA256); err != nil {
					t.Fatal("positive admission refused", err)
				}
				wrote := false
				if err := a.Publish(ctx, l.UID, l.PlanSHA256, func(context.Context) error { wrote = true; return nil }); err != nil || !wrote {
					t.Fatal("positive admission publication refused", err)
				}
				putRosterBytes(t, bad.raw)
				cold := NewAdmission()
				if err := cold.Peer(ctx, l.UID); err == nil {
					t.Fatal("invalid wire admitted peer")
				}
				if err := NewAdmission().Check(ctx, l.UID, l.PlanSHA256); err == nil {
					t.Fatal("invalid wire admitted launch")
				}
				wrote = false
				if err := NewAdmission().Publish(ctx, l.UID, l.PlanSHA256, func(context.Context) error { wrote = true; return nil }); err == nil || wrote {
					t.Fatal("invalid wire admission published")
				}
			})
			t.Run("runner-authority", func(t *testing.T) {
				r, l := installExecutorRoster(t, true)
				a, o := canonicalAuthority(t, r, l)
				if got, err := a.Resolve(ctx, o); err != nil || !got.Qualified {
					t.Fatal("canonical positive authority refused", err)
				}
				putRosterBytes(t, bad.raw)
				if _, err := a.Resolve(ctx, o); err == nil {
					t.Fatal("replaced wire authorized runner")
				}
				if _, err := (&Authority{Launch: l, UID: l.UID}).Resolve(ctx, o); err == nil {
					t.Fatal("invalid wire authorized fresh runner")
				}
			})
		})
	}
}
