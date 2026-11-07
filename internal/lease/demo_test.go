package lease_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type syntheticAdmission struct {
	mu     sync.Mutex
	closed bool
}

func (a *syntheticAdmission) Peer(ctx context.Context, uid uint32) error {
	return a.Check(ctx, uid, strings.Repeat("a", 64))
}

func (a *syntheticAdmission) Check(ctx context.Context, uid uint32, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil || len(digest) != 64 {
		return errors.New("synthetic admission refused")
	}
	return nil
}
func (a *syntheticAdmission) Publish(ctx context.Context, uid uint32, digest string, fn func(context.Context) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return errors.New("synthetic admission refused")
	}
	return fn(ctx)
}
func (a *syntheticAdmission) retire() { a.mu.Lock(); a.closed = true; a.mu.Unlock() }
func demoFixture(t *testing.T, hook store.Durability) (*testutil.Env, *syntheticAdmission) {
	a := &syntheticAdmission{}
	e := testutil.NewFault(t, lease.Options{DemoAdmission: a}, nil, hook)
	e.Request.LaunchID = strings.Repeat("a", 64)
	return e, a
}
func TestDemoCapsDurableAndNoExtension(t *testing.T) {
	e, _ := demoFixture(t, nil)
	r := e.Issue(t)
	until, err := time.Parse(time.RFC3339, r.AuthorizedUntil)
	if err != nil || until.After(e.Now.Add(300*time.Second)) {
		t.Fatal("five minute cap exceeded")
	}
	for i := 0; i < 2; i++ {
		e.Owner.Next(testutil.Token())
		out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
		if out.Err != nil {
			t.Fatal("in-cap renewal refused", lease.ErrorCode(out.Err))
		}
		next := out.Result.(wire.LeaseResult)
		if next.AuthorizedUntil != r.AuthorizedUntil {
			t.Fatal("renewal extended authority")
		}
		r = next
	}
	before, _ := e.Owner.Counts()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if lease.ErrorCode(out.Err) != "renew_failed" {
		t.Fatal("third renewal admitted")
	}
	after, _ := e.Owner.Counts()
	if before != after {
		t.Fatal("third renewal reached owner")
	}
	disk, err := e.Store.Account(e.Account, false)
	if err != nil {
		t.Fatal(err)
	}
	records, err := disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	var rec lease.Record
	if wire.Decode(records[store.LeaseName(r.LeaseID)], &rec) != nil || rec.RenewalAdmissions != 2 {
		t.Fatal("counter not durable")
	}
	if out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now()); out.Err == nil {
		t.Fatal("physical launch got another lease")
	}
}
func TestDemoFailedAdmissionsCount(t *testing.T) {
	e, _ := demoFixture(t, nil)
	r := e.Issue(t)
	// Returning the same material makes each admitted Refresh fail; it must still
	// consume the allowance durably before the owner executes.
	e.Owner.Next(r.Payload.AccessToken)
	for i := 0; i < 2; i++ {
		if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); lease.ErrorCode(out.Err) != "renew_failed" {
			t.Fatal("failed refresh became success")
		}
	}
	before, _ := e.Owner.Counts()
	if before != 2 {
		t.Fatal("expected two logical admissions")
	}
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err == nil {
		t.Fatal("failed attempts restored cap")
	}
	after, _ := e.Owner.Counts()
	if after != before {
		t.Fatal("cap bypass after failed attempts")
	}
}
func TestDemoDeduplicatedWaitersConsumeOne(t *testing.T) {
	e, _ := demoFixture(t, nil)
	r := e.Issue(t)
	gate := make(chan struct{})
	entered := e.Owner.Gate(gate)
	answers := make(chan lease.Outcome, 2)
	go func() { answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	<-entered
	go func() { answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	testutil.Await(t, func() bool { _, w := e.Manager.Stats(e.Account); return w == 2 })
	close(gate)
	for i := 0; i < 2; i++ {
		if out := <-answers; out.Err != nil {
			t.Fatal(lease.ErrorCode(out.Err))
		}
	}
	disk, _ := e.Store.Account(e.Account, false)
	records, _ := disk.Records()
	var rec lease.Record
	if wire.Decode(records[store.LeaseName(r.LeaseID)], &rec) != nil || rec.RenewalAdmissions != 1 {
		t.Fatal("duplicate waiters consumed two")
	}
}
func TestDemoRestartAndLostReplyNeverReset(t *testing.T) {
	e, a := demoFixture(t, nil)
	r := e.Issue(t)
	e.Owner.Next(testutil.Token())
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	// Discard the reply, close the broker, and recover from its existing records.
	e.Manager.Close()
	m, err := lease.New(e.Policy, e.Store, e.Owner, lease.Options{DemoAdmission: a, Now: func() time.Time { return e.Now }}, false)
	if err != nil {
		t.Fatal("restart failed closed at store rather than record", err)
	}
	defer m.Close()
	before, _ := e.Owner.Counts()
	if out := m.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now()); out.Err == nil {
		t.Fatal("restart renewed ambiguous lease")
	}
	if out := m.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now()); out.Err == nil {
		t.Fatal("restart reissued physical launch")
	}
	after, _ := e.Owner.Counts()
	if after != before {
		t.Fatal("restart touched owner")
	}
}
func TestDemoUnknownCounterWriteClosesAccount(t *testing.T) {
	fail := false
	hook := func(stage string) error {
		if fail && stage == "rename" {
			return errors.New("synthetic uncertain write")
		}
		return nil
	}
	e, _ := demoFixture(t, hook)
	r := e.Issue(t)
	fail = true
	before, _ := e.Owner.Counts()
	out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
	if out.Err == nil {
		t.Fatal("unknown durable write admitted")
	}
	after, _ := e.Owner.Counts()
	if after != before {
		t.Fatal("owner called before durable count")
	}
	fail = false
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err == nil {
		t.Fatal("account reopened after uncertain write")
	}
}
func TestDemoRetirementBlocksAfterOwnerAndAtPublication(t *testing.T) {
	e, a := demoFixture(t, nil)
	r := e.Issue(t)
	gate := make(chan struct{})
	entered := e.Owner.Gate(gate)
	answer := make(chan lease.Outcome, 1)
	go func() { answer <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
	<-entered
	a.retire()
	close(gate)
	if out := <-answer; out.Err == nil {
		t.Fatal("retirement during owner work delivered material")
	}
	wrote := false
	if err := e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, r, func(context.Context, time.Time) error { wrote = true; return nil }); err == nil || wrote {
		t.Fatal("retired roster published material")
	}
}
func TestDemoAuthorityExpiryClampsInitialLease(t *testing.T) {
	e, _ := demoFixture(t, nil)
	view := e.Owner.View()
	view.AuthorityUntil = e.Now.Add(17 * time.Second)
	e.Owner.Set(view)
	r := e.Issue(t)
	until, _ := time.Parse(time.RFC3339, r.AuthorizedUntil)
	if !until.Equal(view.AuthorityUntil) {
		t.Fatal("operator authority bound ignored")
	}
	view.State = owner.Unavailable
	e.Owner.Set(view)
	if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err == nil {
		t.Fatal("unavailable owner renewed")
	}
}

func TestDemoEarlierCurrentBoundsRefuseInsteadOfExtending(t *testing.T) {
	for _, provider := range []bool{false, true} {
		e, _ := demoFixture(t, nil)
		r := e.Issue(t)
		s := e.Owner.View()
		if provider {
			s.ExpiresAt = e.Now.Add(20 * time.Second)
		} else {
			s.AuthorityUntil = e.Now.Add(20 * time.Second)
		}
		e.Owner.Set(s)
		if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err == nil {
			t.Fatal("renewal exceeded earlier current bound")
		}
		wrote := false
		if err := e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, r, func(context.Context, time.Time) error { wrote = true; return nil }); err == nil || wrote {
			t.Fatal("publication exceeded current authority")
		}
	}
}
