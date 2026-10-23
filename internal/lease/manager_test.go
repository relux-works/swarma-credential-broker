package lease_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Claim: only a lease's delivered digests renew it; superseded delivery returns the owner token without a second refresh, including a lost response retry.
func TestHistoryAndLostResponse(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	bad := lease.Digest(testutil.Token())
	if out := e.Renew(context.Background(), r, bad); lease.ErrorCode(out.Err) != "renew_not_current" {
		t.Fatal("unknown digest accepted")
	}
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if out.Err != nil {
		t.Fatal("valid renewal refused")
	}
	renewed := out.Result.(wire.LeaseResult)
	if renewed.Payload.AccessToken == r.Payload.AccessToken || renewed.AuthorizedUntil != r.AuthorizedUntil {
		t.Fatal("renewal changed wrong authority")
	}
	retry := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if retry.Err != nil || retry.Result.(wire.LeaseResult).Payload.AccessToken != renewed.Payload.AccessToken {
		t.Fatal("lost-response retry failed")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("duplicate refresh")
	}
}

// Claim: 8/64 current-token operations coalesce; a deterministic 65th at 64 held slots is refused and starts no second refresh.
func TestConcurrentBound(t *testing.T) {
	for _, n := range []int{8, 64, 65} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			rs := make([]wire.LeaseResult, n)
			for i := range rs {
				rs[i] = e.Issue(t)
			}
			gate := make(chan struct{})
			e.Owner.Gate(gate)
			answers := make(chan lease.Outcome, n)
			admitted := n
			if admitted > 64 {
				admitted = 64
			}
			for i := 0; i < admitted; i++ {
				go func(r wire.LeaseResult) {
					answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
				}(rs[i])
			}
			testutil.Await(t, func() bool { pending, _ := e.Manager.Stats(e.Account); return pending == admitted })
			if n == 65 {
				out := e.Renew(context.Background(), rs[64], lease.Digest(rs[64].Payload.AccessToken))
				if lease.ErrorCode(out.Err) != "renew_timeout" {
					t.Fatal("overflow admitted")
				}
			}
			close(gate)
			var current string
			for range admitted {
				out := <-answers
				if out.Err != nil {
					t.Fatal("in-bound renewal refused:", lease.ErrorCode(out.Err))
				}
				token := out.Result.(wire.LeaseResult).Payload.AccessToken
				if current == "" {
					current = token
				}
				if current != token {
					t.Fatal("coalesced results differ")
				}
			}
			calls, max := e.Owner.Counts()
			if calls != 1 || max != 1 {
				t.Fatal("writer count exceeded one")
			}
		})
	}
}

// Claim: duplicates use one operation/two response slots; cancel removes only that waiter and capacity recovers.
func TestDuplicateWaiterCancellation(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	answers := make(chan lease.Outcome, 3)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { answers <- e.Renew(ctx, r, lease.Digest(r.Payload.AccessToken)) }()
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 1 && w == 1 })
	go func() { answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 1 && w == 2 })
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); lease.ErrorCode(out.Err) != "renew_timeout" {
		t.Fatal("third waiter accepted")
	}
	cancel()
	<-answers
	testutil.Await(t, func() bool { _, w := e.Manager.Stats(e.Account); return w == 1 })
	go func() { answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	testutil.Await(t, func() bool { _, w := e.Manager.Stats(e.Account); return w == 2 })
	close(gate)
	for range 2 {
		if out := <-answers; out.Err != nil {
			t.Fatal("replacement waiter refused")
		}
	}
}

// Claim: the arrival deadline includes time before admission and late owner completion cannot deliver success; an in-budget control succeeds.
func TestArrivalDeadline(t *testing.T) {
	e := testutil.New(t, lease.Options{RenewTimeout: 300 * time.Millisecond})
	r := e.Issue(t)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	start := time.Now()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if lease.ErrorCode(out.Err) != "renew_timeout" || time.Since(start) > time.Second {
		t.Fatal("deadline not enforced")
	}
	close(gate)
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 0 && w == 0 })
	if out.Result != nil {
		t.Fatal("late material delivered")
	}
	e.Owner.Gate(nil)
	if out = e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err != nil {
		t.Fatal("in-budget control refused")
	}
	out = e.Manager.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now().Add(-time.Second))
	if lease.ErrorCode(out.Err) != "renew_timeout" {
		t.Fatal("arrival time was reset")
	}
}

// Claim: the production default really times out near eight seconds; the controlled completion is under fifteen seconds total.
func TestDefaultRenewDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("bounded default-duration test runs separately")
	}
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	start := time.Now()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	elapsed := time.Since(start)
	close(gate)
	if lease.ErrorCode(out.Err) != "renew_timeout" || elapsed < 7900*time.Millisecond || elapsed > 12*time.Second {
		t.Fatal("default deadline outside bound")
	}
	e.Owner.Gate(nil)
	testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == 0 })
	if e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)).Err != nil {
		t.Fatal("positive completion refused")
	}
}

// Claim: unavailable/reauth/untrusted/stale owners never issue material; safe transient and active snapshots with valid tokens do.
func TestStateAdmission(t *testing.T) {
	for _, state := range []string{owner.Unavailable, owner.Reauth, owner.Transient, owner.Active} {
		t.Run(state, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			v := e.Owner.View()
			v.State = state
			e.Owner.Set(v)
			out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
			if state == owner.Unavailable || state == owner.Reauth {
				code := "lease_owner_unavailable"
				if state == owner.Reauth {
					code = "lease_reauth_required"
				}
				if lease.ErrorCode(out.Err) != code || out.Result != nil {
					t.Fatal("bad state admitted")
				}
			} else if out.Err != nil {
				t.Fatal("valid state refused")
			}
		})
	}
	for _, field := range []string{"trusted", "fresh", "expiry", "qualification"} {
		t.Run(field, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			v := e.Owner.View()
			switch field {
			case "trusted":
				v.Trusted = false
			case "fresh":
				v.Fresh = false
			case "expiry":
				v.ExpiresAt = e.Now
			case "qualification":
				v.Qualified = false
			}
			e.Owner.Set(v)
			out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
			if out.Err == nil || out.Result != nil {
				t.Fatal("incomplete authority admitted")
			}
		})
	}
}

// Claim: release and policy replacement cannot widen or mutate another lease; a current lease remains usable until independently fenced.
func TestLeaseIsolationAndPolicyFence(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	a, b := e.Issue(t), e.Issue(t)
	out := e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: a.LeaseID}, time.Now())
	if out.Err != nil {
		t.Fatal("release failed")
	}
	if out = e.Renew(context.Background(), a, lease.Digest(a.Payload.AccessToken)); lease.ErrorCode(out.Err) != "lease_not_active" {
		t.Fatal("released lease renewed")
	}
	if out = e.Renew(context.Background(), b, lease.Digest(b.Payload.AccessToken)); out.Err != nil {
		t.Fatal("other lease changed")
	}
	p := e.Policy.Clone()
	p.Generation++
	if e.Manager.Replace(p) != nil {
		t.Fatal("replacement failed")
	}
	if out = e.Renew(context.Background(), b, lease.Digest(b.Payload.AccessToken)); lease.ErrorCode(out.Err) != "lease_not_owner" {
		t.Fatal("old generation renewed")
	}
	if e.Manager.WithGeneration(e.Policy.Generation, func() error { return nil }) == nil {
		t.Fatal("old publication admitted")
	}

}

// Claim: deleted/corrupted metadata closes delivery instead of recreating a store or returning cached material.
func TestMissingStore(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	sum := sha256.Sum256([]byte(e.Account))
	identity := filepath.Join(e.Root, "account-"+hex.EncodeToString(sum[:]), "identity.json")
	if os.Remove(identity) != nil {
		t.Fatal("fault injection failed")
	}
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
		t.Fatal("missing store admitted")
	}
}

// Claim: the configurable active bound recovers after release/expiry; expiration of one record leaves a younger record usable (256 is exercised by vectors).
func TestCapacityRecoveryAndExpiryIsolation(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	e := testutil.New(t, lease.Options{MaxActive: 2, Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	a := e.Issue(t)
	mu.Lock()
	now = now.Add(30 * time.Minute)
	mu.Unlock()
	b := e.Issue(t)
	out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
	if lease.ErrorCode(out.Err) != "lease_not_authorised" || out.Result != nil {
		t.Fatal("full capacity admitted")
	}
	mu.Lock()
	now = now.Add(31 * time.Minute)
	mu.Unlock()
	if out = e.Renew(context.Background(), a, lease.Digest(a.Payload.AccessToken)); lease.ErrorCode(out.Err) != "lease_not_active" {
		t.Fatal("expired lease renewed")
	}
	if out = e.Renew(context.Background(), b, lease.Digest(b.Payload.AccessToken)); out.Err != nil || out.Result.(wire.LeaseResult).AuthorizedUntil != b.AuthorizedUntil {
		t.Fatal("expiry changed younger lease")
	}
	c := e.Issue(t)
	if out = e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: c.LeaseID}, time.Now()); out.Err != nil {
		t.Fatal("release failed")
	}
	e.Issue(t)
}

// Claim: an empty-demand proactive attempt uses the owner gate, while admitted demand suppresses proactive rotations (also covered by FIFO vectors).
func TestProactiveGate(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	if err := e.Manager.Proactive(context.Background(), e.Account); err != nil {
		t.Fatal("idle proactive failed")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("idle proactive missing")
	}
	v := e.Owner.View()
	v.State = owner.Unavailable
	e.Owner.Set(v)
	if err := e.Manager.Proactive(context.Background(), e.Account); lease.ErrorCode(err) != "lease_owner_unavailable" {
		t.Fatal("unavailable proactive started")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("refused proactive refreshed")
	}
}

// Claim: owner reauth/unavailability or policy revocation during refresh prevents post-I/O material; a safely resolved refresh succeeds in the history control.
func TestRefreshRechecksAuthority(t *testing.T) {
	for _, change := range []string{"reauth", "unavailable", "policy"} {
		t.Run(change, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			gate := make(chan struct{})
			e.Owner.Gate(gate)
			answer := make(chan lease.Outcome, 1)
			go func() { answer <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
			testutil.Await(t, func() bool { n, _ := e.Owner.Counts(); return n == 1 })
			code := "lease_not_authorised"
			if change == "policy" {
				p := e.Policy.Clone()
				p.Generation++
				if e.Manager.Replace(p) != nil {
					t.Fatal("policy setup failed")
				}
			} else {
				v := e.Owner.View()
				v.State = owner.Unavailable
				code = "lease_owner_unavailable"
				if change == "reauth" {
					v.State = owner.Reauth
					code = "lease_reauth_required"
				}
				e.Owner.Set(v)
			}
			close(gate)
			out := <-answer
			if lease.ErrorCode(out.Err) != code || out.Result != nil {
				t.Fatal("changed authority delivered")
			}
		})
	}
}

// Claim: restart reloads independent records without persisting payload, preserves release tombstones, and expires overdue records before admission.
func TestStartupRecords(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	if e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now()).Err != nil {
		t.Fatal("setup release failed")
	}
	active := e.Issue(t)
	e.Manager.Close()
	m, err := lease.New(e.Policy, e.Store, e.Owner, lease.Options{Now: func() time.Time { return e.Now }}, false)
	if err != nil {
		t.Fatal("restart refused protected records")
	}
	out := m.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now())
	if out.Err != nil {
		t.Fatal("release tombstone lost")
	}
	m.Close()
	m, err = lease.New(e.Policy, e.Store, e.Owner, lease.Options{Now: func() time.Time { return e.Now.Add(61 * time.Minute) }}, false)
	if err != nil {
		t.Fatal("expiry reload failed")
	}
	defer m.Close()
	out = m.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: active.LeaseID, RejectedSHA256: lease.Digest(active.Payload.AccessToken)}, time.Now())
	if lease.ErrorCode(out.Err) != "lease_not_active" || out.Result != nil {
		t.Fatal("restart revived expired authority")
	}
}

// Claim: uncertain publication poisons account admission instead of using cached material or starting another refresh; the initial commit is a positive control.
func TestUncertainLeaseCommit(t *testing.T) {
	var mu sync.Mutex
	fail := false
	e := testutil.NewFault(t, lease.Options{}, nil, func(stage string) error {
		mu.Lock()
		defer mu.Unlock()
		if fail && stage == "rename" {
			return errors.New("fixture durability failure")
		}
		return nil
	})
	r := e.Issue(t)
	mu.Lock()
	fail = true
	mu.Unlock()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
		t.Fatal("uncertain commit delivered")
	}
	before, _ := e.Owner.Counts()
	out = e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
	if lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
		t.Fatal("poisoned store admitted")
	}
	after, _ := e.Owner.Counts()
	if after != before {
		t.Fatal("poisoned store refreshed")
	}
	if e.Manager.Status(context.Background(), e.UID).Accounts[0].State != owner.Unavailable {
		t.Fatal("poisoned status advertised active")
	}
}

// Claim: root marker loss or directory replacement refuses cached material even while old directory descriptors remain open.
func TestRootStoreDisappearance(t *testing.T) {
	for _, fault := range []string{"marker", "rename"} {
		t.Run(fault, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			var err error
			if fault == "marker" {
				err = os.Remove(filepath.Join(e.Root, "identity.json"))
			} else {
				err = os.Rename(e.Root, e.Root+"-moved")
			}
			if err != nil {
				t.Fatal("fixture fault failed")
			}
			out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
			if lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
				t.Fatal("lost root delivered")
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("lost root refreshed")
			}
		})
	}
}

// Claim: qualification is bound to current policy generation, immutable evidence reference and executable digest; a qualified fixture snapshot is the positive control.
func TestQualificationBinding(t *testing.T) {
	for _, field := range []string{"generation", "evidence", "executable"} {
		t.Run(field, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			e.Issue(t)
			v := e.Owner.View()
			switch field {
			case "generation":
				v.PolicyGeneration++
			case "evidence":
				v.QualificationID = "different-evidence"
			case "executable":
				v.ExecutableSHA256 = lease.Digest(testutil.Token())
			}
			e.Owner.Set(v)
			out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
			if lease.ErrorCode(out.Err) != "lease_harness_unqualified" || out.Result != nil {
				t.Fatal("wrong qualification admitted")
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("unqualified request refreshed")
			}
		})
	}
}

// Claim: enforcement expires at the published UTC second, never in an unpublished subsecond tail; a live renewal succeeds and a token with no published lifetime is refused.
func TestAuthorizationSeconds(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2030, 1, 1, 0, 0, 0, 500000000, time.UTC)
	e := testutil.New(t, lease.Options{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	r := e.Issue(t)
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err != nil {
		t.Fatal("live second refused")
	}
	limit, err := time.Parse(time.RFC3339, r.AuthorizedUntil)
	if err != nil {
		t.Fatal("invalid public authorization time")
	}
	mu.Lock()
	now = limit
	mu.Unlock()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if lease.ErrorCode(out.Err) != "lease_not_active" || out.Result != nil {
		t.Fatal("unpublished subsecond authority admitted")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("expired lease refreshed")
	}
	short := testutil.New(t, lease.Options{Now: func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 500000000, time.UTC) }})
	v := short.Owner.View()
	v.ExpiresAt = time.Date(2030, 1, 1, 0, 0, 0, 999999999, time.UTC)
	short.Owner.Set(v)
	out = short.Manager.Call(context.Background(), short.UID, "lease.request", short.Request, time.Now())
	if lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
		t.Fatal("unrepresentable token lifetime admitted")
	}
}

// Claim: a pending renewal and release cannot occupy two operation slots for one lease; after renewal resolves the same owner can durably release it.
func TestSinglePendingLeaseOperation(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	answer := make(chan lease.Outcome, 1)
	go func() { answer <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 1 && w == 1 })
	out := e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now())
	if lease.ErrorCode(out.Err) != "renew_timeout" || out.Result != nil {
		t.Fatal("second operation for lease admitted")
	}
	if p, w := e.Manager.Stats(e.Account); p != 1 || w != 1 {
		t.Fatal("busy refusal changed queue")
	}
	close(gate)
	if (<-answer).Err != nil {
		t.Fatal("pending renewal changed")
	}
	if out = e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now()); out.Err != nil {
		t.Fatal("release slot did not recover")
	}
}

// Claim: active or safely transient owners cannot renew with unchanged rejected material; a subsequent resolved replacement is accepted without widening authority.
func TestUnchangedRenewal(t *testing.T) {
	for _, state := range []string{owner.Active, owner.Transient} {
		t.Run(state, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			r := e.Issue(t)
			view := e.Owner.View()
			view.State = state
			e.Owner.Set(view)
			e.Owner.Next(r.Payload.AccessToken)
			out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
			if lease.ErrorCode(out.Err) != "renew_failed" || out.Result != nil {
				t.Fatal("unchanged rejected material delivered")
			}
			view = e.Owner.View()
			view.State = owner.Active
			e.Owner.Set(view)
			e.Owner.Next(testutil.Token())
			out = e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
			if out.Err != nil || out.Result.(wire.LeaseResult).AuthorizedUntil != r.AuthorizedUntil {
				t.Fatal("resolved replacement refused or widened")
			}
		})
	}
}
