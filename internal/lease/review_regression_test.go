package lease_test

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Claim: once policy replacement invalidates a lease, restarting with the older generation cannot resurrect it; current-generation restart is accepted.
func TestReviewPolicyRollbackRestart(t *testing.T) {
	for _, rollback := range []bool{true, false} {
		name := "current-generation-control"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			p := e.Policy.Clone()
			p.Generation++
			if e.Manager.Replace(p) != nil {
				t.Fatal("valid replacement refused")
			}
			out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
			if out.Err == nil {
				t.Fatal("old lease not invalidated before restart")
			}
			v := e.Owner.View()
			v.PolicyGeneration = p.Generation
			e.Owner.Set(v)
			req := e.Request
			req.Binding = p.Binding(e.UID, p.Accounts[0], req.Profile)
			out = e.Manager.Call(context.Background(), e.UID, "lease.request", req, time.Now())
			if out.Err != nil {
				t.Fatal("successor generation control failed")
			}
			e.Manager.Close()
			restart := p
			if rollback {
				restart = e.Policy
				v.PolicyGeneration = restart.Generation
				e.Owner.Set(v)
			}
			m, err := lease.New(restart, e.Store, e.Owner, lease.Options{Now: func() time.Time { return e.Now }}, false)
			if err != nil {
				if !rollback {
					t.Fatal("current-generation restart refused")
				}
				return
			}
			defer m.Close()
			if !rollback {
				if m.Call(context.Background(), e.UID, "lease.request", req, time.Now()).Err != nil {
					t.Fatal("current-generation restart cannot issue")
				}
				return
			}
			out = m.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now())
			if out.Err == nil {
				t.Fatal("restart with rolled-back policy resurrected invalidated lease despite retained newer-generation record")
			}
		})
	}
}

// Claim: durable replacement survives a stop before any new lease write; a current-policy restart issues and an older policy cannot reopen.
func TestPolicyWatermarkBeforeLeaseWrite(t *testing.T) {
	for _, rollback := range []bool{true, false} {
		name := "current-control"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			e.Issue(t)
			p := e.Policy.Clone()
			p.Generation++
			if e.Manager.Replace(p) != nil {
				t.Fatal("replacement failed")
			}
			e.Manager.Close() // No generation-two lease exists: the watermark alone must fence restart.
			restart := p
			if rollback {
				restart = e.Policy
			}
			v := e.Owner.View()
			v.PolicyGeneration = restart.Generation
			e.Owner.Set(v)
			m, err := lease.New(restart, e.Store, e.Owner, lease.Options{Now: func() time.Time { return e.Now }}, false)
			if rollback {
				if err == nil {
					m.Close()
					t.Fatal("rollback reopened without a successor lease")
				}
				return
			}
			if err != nil {
				t.Fatal("current restart refused")
			}
			defer m.Close()
			req := e.Request
			req.Binding = p.Binding(e.UID, p.Accounts[0], req.Profile)
			if m.Call(context.Background(), e.UID, "lease.request", req, time.Now()).Err != nil {
				t.Fatal("current restart did not issue")
			}
		})
	}
}

// Claim: release and policy replacement cannot acknowledge through a material publication callback; they progress after its bounded write returns.
func TestPublicationOrdersMutations(t *testing.T) {
	for _, mutation := range []string{"release", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			entered := make(chan struct{})
			resume := make(chan struct{})
			published := make(chan error, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(resume) }) }
			defer unblock()
			go func() {
				published <- e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, r, func(deadline time.Time) error {
					if !time.Now().Before(deadline) {
						return errors.New("expired write deadline")
					}
					close(entered)
					<-resume
					return nil
				})
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("publication not entered")
			}
			mutated := make(chan error, 1)
			started := make(chan struct{})
			go func() {
				close(started)
				if mutation == "release" {
					mutated <- e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now()).Err
				} else {
					p := e.Policy.Clone()
					p.Generation++
					mutated <- e.Manager.Replace(p)
				}
			}()
			<-started
			select {
			case <-mutated:
				t.Fatal("mutation acknowledged during material write")
			case <-time.After(25 * time.Millisecond):
			}
			unblock()
			if <-published != nil {
				t.Fatal("active publication failed")
			}
			if <-mutated != nil {
				t.Fatal("mutation did not progress after write")
			}
			called := false
			err := e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, r, func(time.Time) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("terminal mutation allowed later publication")
			}
		})
	}
}

// Claim: owner-prefixed canonical records coexist with leases across restart; an unknown non-owner namespace still closes admission.
func TestOwnerRecordNamespace(t *testing.T) {
	for _, reserved := range []bool{true, false} {
		name := "owner-intent.json"
		if !reserved {
			name = "unknown-intent.json"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			e.Manager.Close()
			disk, err := e.Store.Account(e.Account, false)
			if err != nil {
				t.Fatal("account fixture failed")
			}
			record := map[string]any{"kind": "attempt-intent/1", "installation_id": e.Policy.Installation, "revision": 1}
			if disk.Put(name, 0, record) != nil {
				t.Fatal("owner record write failed")
			}
			m, err := lease.New(e.Policy, e.Store, e.Owner, lease.Options{Now: func() time.Time { return e.Now }}, false)
			if !reserved {
				if err == nil {
					m.Close()
					t.Fatal("unknown record silently ignored")
				}
				return
			}
			if err != nil {
				t.Fatal("owner namespace misread as lease")
			}
			defer m.Close()
			if m.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now()).Err != nil {
				t.Fatal("lease lost alongside owner record")
			}
		})
	}
}

// Claim: a newer retained lease record is an independent rollback floor even if the installation watermark fixture is older.
func TestPolicyGenerationBelowRecord(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	e.Manager.Close()
	disk, _ := e.Store.Account(e.Account, false)
	records, err := disk.Records()
	if err != nil {
		t.Fatal("record read failed")
	}
	var rec lease.Record
	name := store.LeaseName(r.LeaseID)
	if wire.Decode(records[name], &rec) != nil {
		t.Fatal("record decode failed")
	}
	prior := rec.Revision
	rec.Revision++
	rec.PolicyGeneration++
	if disk.Put(name, prior, rec) != nil {
		t.Fatal("newer record fixture failed")
	}
	m, err := lease.New(e.Policy, e.Store, e.Owner, lease.Options{}, false)
	if err == nil {
		m.Close()
		t.Fatal("newer retained record did not fence rollback")
	}
}

// Claim: uncertain watermark publication poisons current admission, and a renamed successor prevents rollback at restart.
func TestUncertainPolicyWatermark(t *testing.T) {
	var fail atomic.Bool
	e := testutil.NewFault(t, lease.Options{}, nil, func(stage string) error {
		if fail.Load() && stage == "rename" {
			return errors.New("fixture durability failure")
		}
		return nil
	})
	e.Issue(t)
	p := e.Policy.Clone()
	p.Generation++
	fail.Store(true)
	if e.Manager.Replace(p) == nil {
		t.Fatal("uncertain watermark reported committed")
	}
	if out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now()); lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
		t.Fatal("uncertain policy allowed material")
	}
	e.Manager.Close()
	fail.Store(false)
	m, err := lease.New(e.Policy, e.Store, e.Owner, lease.Options{}, false)
	if err == nil {
		m.Close()
		t.Fatal("uncertain successor allowed policy rollback")
	}
	m, err = lease.New(p, e.Store, e.Owner, lease.Options{}, false)
	if err != nil {
		t.Fatal("current durable watermark restart refused")
	}
	m.Close()
}

// Claim: the publication callback receives a monotonic deadline capped by the lease and published whole-second token/account limits, including fractional input times.
func TestPublicationAuthorizationDeadline(t *testing.T) {
	for _, bound := range []string{"lease", "token", "authority"} {
		t.Run(bound, func(t *testing.T) {
			var clock atomic.Int64
			e := testutil.New(t, lease.Options{Now: func() time.Time { return time.Unix(0, clock.Load()) }})
			clock.Store(e.Now.UnixNano())
			r := e.Issue(t)
			expected := 5 * time.Second
			v := e.Owner.View()
			switch bound {
			case "lease":
				until, _ := time.Parse(time.RFC3339, r.AuthorizedUntil)
				clock.Store(until.Add(-expected).UnixNano())
			case "token":
				v.ExpiresAt = e.Now.Add(expected + 500*time.Millisecond)
				e.Owner.Set(v)
			case "authority":
				v.AuthorityUntil = e.Now.Add(expected + 500*time.Millisecond)
				e.Owner.Set(v)
			}
			start := time.Now()
			called := false
			err := e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, r, func(deadline time.Time) error {
				called = true
				if deadline.After(time.Now().Add(expected)) || deadline.Before(start.Add(expected)) {
					return errors.New("write deadline exceeds or shortens authority bound")
				}
				return nil
			})
			if err != nil || !called {
				t.Fatal("publication deadline control failed")
			}
		})
	}
}
