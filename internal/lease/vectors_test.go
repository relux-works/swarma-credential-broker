package lease_test

import (
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func instantiate(t *testing.T, c testutil.Vector, e *testutil.Env, id, token string) any {
	t.Helper()
	b, _ := json.Marshal(c.Request)
	var r wire.Request
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("invalid vector request")
	}
	switch r.Method {
	case "lease.request":
		var p wire.LeaseRequest
		var m map[string]any
		json.Unmarshal(r.Params, &m)
		binding := m["credential_binding"].(map[string]any)
		binding["digest"] = ""
		raw, _ := json.Marshal(m)
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("invalid lease template")
		}
		a := e.Policy.Accounts[0]
		a.Label = p.Account
		p.Binding = e.Policy.Binding(e.UID, a, p.Profile)
		return p
	case "lease.renew":
		var p wire.Renew
		json.Unmarshal(r.Params, &p)
		p.LeaseID = id
		if p.RejectedSHA256 == lease.Digest("fixture-access-a") {
			p.RejectedSHA256 = lease.Digest(token)
		}
		return p
	case "lease.release":
		return wire.Release{LeaseID: id}
	}
	t.Fatal("unknown vector method")
	return nil
}

// Claim: vector admission verdicts are reached through the real policy/lease path; runner and kernel-connection cases are tested in their owning slice/package.
func TestAdmissionVectors(t *testing.T) {
	for _, c := range testutil.Vectors(t, "admission") {
		if c.Request == nil || c.ID == "peer-allowed" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) {
				if q, ok := c.Setup["tuple_qualified"].(bool); ok && !q {
					p.Accounts[0].QualificationID = ""
				}
			})
			r := instantiate(t, c, e, "", "").(wire.LeaseRequest)
			out := e.Manager.Call(context.Background(), e.UID, "lease.request", r, time.Now())
			if code, ok := c.Expect["error_code"].(string); ok {
				if out.Result != nil || lease.ErrorCode(out.Err) != code {
					t.Fatal("wrong admission refusal")
				}
				if n, _ := e.Owner.Counts(); n != 0 {
					t.Fatal("refusal started refresh")
				}
				e.NoLeaseRecords(t)
			} else if out.Err != nil {
				t.Fatal("valid admission refused")
			}
		})
	}
}

// Claim: every non-runner renewal vector drives the core using private random-token/UID instantiation; no future lifecycle or runner assertion is counted here.
// Virtual time isolates arrival budgets from fixture I/O and scheduling. Held
// owners and quiescence barriers establish admission before overflow or expiry;
// real-clock deadline enforcement remains covered by the deadline regressions.
func TestRenewalVectors(t *testing.T) {
	for _, c := range testutil.Vectors(t, "renewal") {
		t.Run(c.ID, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if c.ID == "fifo-progress" || c.ID == "fifo-starvation" {
					testFIFO(t, c)
					return
				}
				timeout := 3 * time.Second
				if c.ID == "renew-late" {
					timeout = 25 * time.Millisecond
				}
				e := testutil.NewPolicy(t, lease.Options{RenewTimeout: timeout}, func(p *policy.Policy) {
					if c.ID == "owner-mismatch" {
						p.Accounts[1].AllowedUIDs = []uint32{p.BrokerUID + 1}
					}
				})
				r := e.Issue(t)
				initial := r.Payload.AccessToken
				if trusted, ok := c.Setup["trusted_time"].(bool); ok && !trusted {
					v := e.Owner.View()
					v.Trusted = false
					e.Owner.Set(v)
				}
				if c.ID == "renew-superseded" {
					v := e.Owner.View()
					v.AccessToken = testutil.Token()
					v.Generation++
					e.Owner.Set(v)
				}
				if c.Setup["lease_state"] == "released" {
					out := e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now())
					if out.Err != nil {
						t.Fatal("release setup failed")
					}
				}
				if c.ID == "lease-capacity" || c.ID == "lease-capacity-available" {
					target := int(c.Setup["active_lease_count"].(float64))
					for i := 1; i < target; i++ {
						e.Issue(t)
					}
				}
				if c.ID == "many-lease-independent" {
					other := e.Issue(t)
					if other.LeaseID == r.LeaseID || other.Account != r.Account {
						t.Fatal("records not independent")
					}
					disk, err := e.Store.Account(e.Account, false)
					if err != nil {
						t.Fatal("metadata unavailable")
					}
					records, err := disk.Records()
					if err != nil || len(records) != 2 {
						t.Fatal("independent records missing")
					}
					return
				}
				if c.ID == "many-lease-release" {
					other := e.Issue(t)
					out := e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now())
					if out.Err != nil {
						t.Fatal("release refused")
					}
					renew := e.Renew(context.Background(), other, lease.Digest(other.Payload.AccessToken))
					if renew.Err != nil || renew.Result.(wire.LeaseResult).AuthorizedUntil != other.AuthorizedUntil {
						t.Fatal("other record changed")
					}
					return
				}
				if n, ok := c.Setup["concurrent_requests"].(float64); ok {
					testVectorContention(t, e, r, int(n), c)
					return
				}
				if c.ID == "queue-full" || c.ID == "queue-slot" {
					testVectorQueue(t, e, r, c)
					return
				}
				var out lease.Outcome
				if c.ID == "owner-mismatch" {

					out = e.Manager.Call(context.Background(), e.UID+1, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(initial)}, time.Now())
				} else {
					params := instantiate(t, c, e, r.LeaseID, initial)
					method := c.Request["method"].(string)
					if c.ID == "renew-late" {
						gate := make(chan struct{})
						e.Owner.Gate(gate)
						out = e.Manager.Call(context.Background(), e.UID, method, params, time.Now())
						close(gate)
						testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == 0 })
					} else {
						if c.ID == "renew-in-budget" {
							gate := make(chan struct{})
							e.Owner.Gate(gate)
							time.AfterFunc(100*time.Millisecond, func() { close(gate) })
						}
						out = e.Manager.Call(context.Background(), e.UID, method, params, time.Now())
					}
				}
				if code, ok := c.Expect["error_code"].(string); ok {
					if out.Result != nil || lease.ErrorCode(out.Err) != code {
						t.Fatal("wrong renewal refusal")
					}
				} else {
					if out.Err != nil {
						t.Fatal("positive vector refused:", lease.ErrorCode(out.Err))
					}
					if result, ok := out.Result.(wire.LeaseResult); ok {
						if result.Account != e.Account || result.AuthorizedUntil != r.AuthorizedUntil {
							t.Fatal("renewal widened authority")
						}
						if c.ID == "renew-superseded" && result.Payload.AccessToken != e.Owner.View().AccessToken {
							t.Fatal("superseded result stale")
						}
					}
				}
				if c.ID == "lease-capacity" {
					if e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: r.LeaseID}, time.Now()).Err != nil {
						t.Fatal("capacity release failed")
					}
					e.Issue(t)
				}
				if expected, ok := c.Expect["vendor_writers_started"].(float64); ok {
					calls, _ := e.Owner.Counts()
					if calls != int(expected) {
						t.Fatal("wrong refresh count")
					}
				}
			})
		})
	}
}
func testVectorContention(t *testing.T, e *testutil.Env, first wire.LeaseResult, n int, c testutil.Vector) {
	t.Helper()
	records := []wire.LeaseResult{first}
	for len(records) < n {
		records = append(records, e.Issue(t))
	}
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	answers := make(chan lease.Outcome, n)
	admit := n
	if n > 64 {
		admit = 64
	}
	for i := 0; i < admit; i++ {
		go func(r wire.LeaseResult) {
			answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
		}(records[i])
	}
	synctest.Wait()
	testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == admit })
	if n > 64 {
		out := e.Renew(context.Background(), records[64], lease.Digest(records[64].Payload.AccessToken))
		if lease.ErrorCode(out.Err) != c.Expect["overflow_error_code"] {
			t.Fatal("missing deterministic overflow")
		}
	}
	close(gate)
	var token string
	for range admit {
		out := <-answers
		if out.Err != nil {
			t.Fatal("admitted vector waiter failed")
		}
		current := out.Result.(wire.LeaseResult).Payload.AccessToken
		if token != "" && current != token {
			t.Fatal("unequal contention result")
		}
		token = current
	}
	calls, max := e.Owner.Counts()
	if calls != 1 || max != 1 {
		t.Fatal("multiple refresh writers")
	}
}
func testVectorQueue(t *testing.T, e *testutil.Env, r wire.LeaseResult, c testutil.Vector) {
	t.Helper()
	n := int(c.Setup["queued_waiters"].(float64))
	records := make([]wire.LeaseResult, n)
	for i := range records {
		records[i] = e.Issue(t)
	}
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	answers := make(chan lease.Outcome, n+1)
	for _, record := range records {
		go func(v wire.LeaseResult) {
			answers <- e.Renew(context.Background(), v, lease.Digest(v.Payload.AccessToken))
		}(record)
	}
	synctest.Wait()
	testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == n })
	if c.ID == "queue-full" {
		out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken))
		if lease.ErrorCode(out.Err) != "renew_timeout" {
			t.Fatal("full queue admitted")
		}
	} else {
		go func() { answers <- e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)) }()
		synctest.Wait()
		testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == 64 })
		n++
	}
	close(gate)
	for range n {
		if (<-answers).Err != nil {
			t.Fatal("queued control failed")
		}
	}
}
func testFIFO(t *testing.T, c testutil.Vector) {
	t.Helper()
	var mu sync.Mutex
	var order []string
	e := testutil.New(t, lease.Options{Observe: func(event lease.Event) {
		if event.Kind == "dequeue" {
			mu.Lock()
			order = append(order, event.LeaseID)
			mu.Unlock()
		}
	}})
	n := len(c.Setup["arrivals"].([]any))
	rs := make([]wire.LeaseResult, n)
	for i := range rs {
		rs[i] = e.Issue(t)
	}
	mu.Lock()
	order = nil
	mu.Unlock()
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	answers := make(chan lease.Outcome, n)
	for i, r := range rs {
		go func(v wire.LeaseResult) {
			answers <- e.Renew(context.Background(), v, lease.Digest(v.Payload.AccessToken))
		}(r)
		target := i + 1
		synctest.Wait()
		testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == target })
	}
	if due, _ := c.Setup["proactive_refresh_due"].(bool); due {
		if e.Manager.Proactive(context.Background(), e.Account) != nil {
			t.Fatal("proactive coalescence failed")
		}
		if calls, _ := e.Owner.Counts(); calls != 1 {
			t.Fatal("proactive jumped ahead")
		}
	}
	close(gate)
	for range n {
		if (<-answers).Err != nil {
			t.Fatal("FIFO waiter did not terminate")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != n {
		t.Fatal("lost FIFO operation")
	}
	for i, r := range rs {
		if order[i] != r.LeaseID {
			t.Fatal("FIFO order changed")
		}
	}
}

// Claim: selected lifecycle vectors exercise only the core's refusal/admission at the owner boundary; actual writer recovery remains outside this test.
func TestLifecycleBoundaryVectors(t *testing.T) {
	for _, c := range testutil.Vectors(t, "lifecycle") {
		switch c.ID {
		case "store-missing", "store-current", "store-rollback", "store-reconciled", "transient-ambiguous", "transient-safe":
		default:
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			v := e.Owner.View()
			switch c.ID {
			case "store-missing", "store-rollback", "transient-ambiguous":
				v.State = owner.Unavailable
				v.Fresh = false
			case "transient-safe":
				v.State = owner.Transient
			}
			e.Owner.Set(v)
			out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
			if c.Expect["state"] == owner.Unavailable {
				if lease.ErrorCode(out.Err) != "lease_owner_unavailable" || out.Result != nil {
					t.Fatal("unavailable owner admitted")
				}
			} else if out.Err != nil {
				t.Fatal("resolved boundary control refused")
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("admission retried owner")
			}
		})
	}
}

// Claim: enrolment mapping vectors exercise the static unique-vendor invariant only; their administrative enrolment codes and owner activation remain outside this boundary test.
func TestLifecycleMappingBoundaryVectors(t *testing.T) {
	for _, v := range testutil.Vectors(t, "lifecycle") {
		if v.ID != "duplicate-account" && v.ID != "distinct-account" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			p := e.Policy.Clone()
			p.Generation++
			candidate := p.Accounts[0]
			candidate.Label = "example/codex/candidate"
			candidate.VendorID = v.Setup["candidate_vendor_account_id"].(string)
			p.Accounts = append(p.Accounts, candidate)
			err := e.Manager.Replace(p)
			if v.ID == "duplicate-account" {
				if err == nil || !reflect.DeepEqual(e.Manager.Policy(), e.Policy) {
					t.Fatal("duplicate mapping admitted or changed state")
				}
			} else {
				if err != nil {
					t.Fatal("distinct mapping refused")
				}
				current := e.Manager.Policy()
				if !reflect.DeepEqual(current.Accounts[:len(e.Policy.Accounts)], e.Policy.Accounts) {
					t.Fatal("existing mapping changed")
				}
				count := 0
				for _, a := range current.Accounts {
					if a.VendorID == candidate.VendorID {
						count++
					}
				}
				if count != 1 {
					t.Fatal("distinct mapping count wrong")
				}
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("mapping validation started owner")
			}
		})
	}
}
