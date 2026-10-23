package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: null primitive array elements are malformed and close without a response or lease side effects; typed arrays are valid controls.
func TestReviewMalformedArrayMember(t *testing.T) {
	for _, tc := range []string{"hello-null-version", "request-null-capability", "valid-control"} {
		t.Run(tc, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			c := dial(t, start(t, e, nil))
			if tc == "hello-null-version" {
				if err := wire.Write(c, wire.Request{Method: "hello", ID: "bad", Params: json.RawMessage(`{"profile":"codex-refresher-v0","versions":[null]}`)}); err != nil {
					t.Fatal("fixture write")
				}
			} else {
				hello(t, c)
				raw, _ := json.Marshal(e.Request)
				var params map[string]any
				json.Unmarshal(raw, &params)
				if tc == "request-null-capability" {
					params["executor"].(map[string]any)["capabilities"] = []any{"credential-injection/1", nil}
				}
				body, _ := wire.Encode(params)
				if err := wire.Write(c, wire.Request{Method: "lease.request", ID: "probe", Params: body}); err != nil {
					t.Fatal("fixture write")
				}
			}
			b, err := wire.Read(c)
			if tc == "valid-control" {
				var r response
				if err != nil || wire.Decode(b, &r) != nil || r.Error != nil {
					t.Fatal("valid positive control refused")
				}
				return
			}
			if err == nil {
				t.Error("malformed null array member received a response; required close without response")
			}
			disk, _ := e.Store.Account(e.Account, false)
			records, err := disk.Records()
			if err != nil {
				t.Fatal("fixture metadata unavailable")
			}
			if len(records) != 0 {
				t.Errorf("malformed request created %d lease records", len(records))
			}
		})
	}
}

// reviewOwner can pause one Snapshot while preserving the production owner's context contract.
type reviewOwner struct {
	owner.Owner
	n       atomic.Int64
	pauseAt int64
	entered chan struct{}
	resume  chan struct{}
}

func (o *reviewOwner) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	n := o.n.Add(1)
	if n == o.pauseAt {
		close(o.entered)
		select {
		case <-o.resume:
		case <-ctx.Done():
			return owner.Snapshot{}, ctx.Err()
		}
	}
	return o.Owner.Snapshot(ctx, label)
}
func reviewAdapter(t *testing.T, e *testutil.Env, pauseAt int64, options lease.Options) *reviewOwner {
	t.Helper()
	e.Manager.Close()
	o := &reviewOwner{Owner: e.Owner, pauseAt: pauseAt, entered: make(chan struct{}), resume: make(chan struct{})}
	if options.Now == nil {
		options.Now = func() time.Time { return e.Now }
	}
	m, err := lease.New(e.Policy, e.Store, o, options, false)
	if err != nil {
		t.Fatal("replacement fixture setup")
	}
	e.Manager = m
	t.Cleanup(m.Close)
	return o
}
func awaitReview(t *testing.T, c <-chan struct{}) {
	t.Helper()
	// This is fixture ordering, not a latency contract. The package timeout
	// still detects a missing event; scheduling delay cannot fake a refusal.
	<-c
}

// Claim: an acknowledged release or authorization expiry during final owner I/O, changed policy or unavailable owner forbids later material; unchanged active state is a positive control.
func TestReviewFinalAuthorizationFence(t *testing.T) {
	for _, tc := range []string{"released", "expired", "policy-changed", "owner-unavailable", "valid-control"} {
		t.Run(tc, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			var now atomic.Int64
			now.Store(e.Now.Unix())
			o := reviewAdapter(t, e, 3, lease.Options{Now: func() time.Time { return time.Unix(now.Load(), 0) }})
			var once sync.Once
			resume := func() { once.Do(func() { close(o.resume) }) }
			defer resume()
			r := e.Issue(t) // snapshot 1; renew execution 2; final delivery 3.
			c := dial(t, start(t, e, nil))
			hello(t, c)
			body, _ := wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
			if wire.Write(c, wire.Request{Method: "lease.renew", ID: "renew", Params: body}) != nil {
				t.Fatal("fixture write")
			}
			awaitReview(t, o.entered)
			if tc == "released" {
				other := dial(t, c.RemoteAddr().String())
				hello(t, other)
				out := request(t, other, "lease.release", "release", wire.Release{LeaseID: r.LeaseID})
				if out.Error != nil {
					t.Fatal("release positive control failed")
				}
			}
			if tc == "expired" {
				until, _ := time.Parse(time.RFC3339, r.AuthorizedUntil)
				now.Store(until.Unix())
			}
			if tc == "policy-changed" {
				p := e.Policy.Clone()
				p.Generation++
				if e.Manager.Replace(p) != nil {
					t.Fatal("policy replacement refused")
				}
			}
			if tc == "owner-unavailable" {
				v := e.Owner.View()
				v.State = owner.Unavailable
				e.Owner.Set(v)
			}
			resume()
			if tc == "policy-changed" {
				closed(t, c)
				return
			}
			out := reply(t, c)
			if tc == "valid-control" {
				if out.Error != nil {
					t.Fatal("active control refused")
				}
				return
			}
			code := "lease_not_active"
			if tc == "owner-unavailable" {
				code = "lease_owner_unavailable"
			}
			if out.Error == nil || out.Error.Code != code || out.Result != nil {
				t.Fatal("material delivered after terminal authorization change during final owner I/O")
			}
		})
	}
}

// Claim: cancellation before a refresh attempt is admitted must not start that attempt later; an in-budget snapshot is the positive control.
func TestReviewExpiredBeforeRefresh(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		name := "valid-control"
		if cancelled {
			name = "expired-before-refresh"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			o := reviewAdapter(t, e, 2, lease.Options{RenewTimeout: 100 * time.Millisecond})
			var once sync.Once
			resume := func() { once.Do(func() { close(o.resume) }) }
			defer resume()
			r := e.Issue(t)
			c := dial(t, start(t, e, nil))
			hello(t, c)
			body, _ := wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
			wire.Write(c, wire.Request{Method: "lease.renew", ID: "renew", Params: body})
			awaitReview(t, o.entered)
			if cancelled {
				out := reply(t, c)
				if out.Error == nil || out.Error.Code != "renew_timeout" {
					t.Fatal("timeout control failed")
				}
			}
			resume()
			if !cancelled {
				if reply(t, c).Error != nil {
					t.Fatal("in-budget control failed")
				}
			}
			testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 0 && w == 0 })
			n, _ := e.Owner.Counts()
			if cancelled && n != 0 {
				t.Errorf("started %d refresh attempts after the only waiter had already timed out", n)
			}
			if !cancelled && n != 1 {
				t.Fatal("in-budget refresh did not execute")
			}
		})
	}
}

// Claim: denied peers cannot convert request-body UID fields into authority.
func TestReviewDeniedUIDSmuggling(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	c := dial(t, start(t, e, func(s *Server) { s.peer = func(*net.UnixConn) (uint32, error) { return e.UID + 1, nil } }))
	_ = wire.Write(c, map[string]any{"method": "hello", "request_id": "probe", "params": map[string]any{"uid": e.UID, "profile": wire.Profile, "versions": []int{1}}})
	r := reply(t, c)
	if r.ID != nil || r.Error == nil || r.Error.Code != "role_not_permitted" {
		t.Fatal("UID smuggling changed accept verdict")
	}
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatal("denied peer remains open")
	}
	e.NoLeaseRecords(t)
}

type reviewErrorOwner struct {
	owner.Owner
	fail     atomic.Bool
	material string
}

func (o *reviewErrorOwner) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	if o.fail.Load() {
		return owner.Snapshot{State: o.material}, errors.New(o.material)
	}
	return o.Owner.Snapshot(ctx, label)
}

// Claim: raw owner errors/states containing a synthetic canary never escape through status or lease replies; removing the injected error restores issuance.
func TestReviewOwnerErrorRedaction(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	e.Manager.Close()
	o := &reviewErrorOwner{Owner: e.Owner, material: testutil.Token()}
	o.fail.Store(true)
	m, err := lease.New(e.Policy, e.Store, o, lease.Options{Now: func() time.Time { return e.Now }}, false)
	if err != nil {
		t.Fatal("replacement setup failed")
	}
	e.Manager = m
	t.Cleanup(m.Close)
	c := dial(t, start(t, e, nil))
	hello(t, c)
	status := request(t, c, "status", "status", struct{}{})
	b, _ := wire.Encode(status)
	if materialLeak(b, []string{o.material}, false) {
		t.Fatal("owner status reflected canary")
	}
	refused := request(t, c, "lease.request", "refused", e.Request)
	b, _ = wire.Encode(refused)
	if materialLeak(b, []string{o.material}, false) {
		t.Fatal("owner error reflected canary")
	}
	if refused.Error == nil || refused.Error.Code != "lease_owner_unavailable" {
		t.Fatal("owner error not sanitized to fixed refusal")
	}
	e.NoLeaseRecords(t)
	o.fail.Store(false)
	if request(t, c, "lease.request", "control", e.Request).Error != nil {
		t.Fatal("valid owner control refused")
	}
}
