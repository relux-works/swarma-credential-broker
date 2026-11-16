//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/claude"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const fixtureToken = "FAKE_CLAUDE_TOKEN_NOT_A_CREDENTIAL_a1"
const fixtureAccount = "owner/claude/service-test"

type authorityFixture struct {
	mu                                    sync.RWMutex
	principals                            map[uint32]Principal
	binding                               wire.ServiceBinding
	caller                                wire.ServiceCaller
	serviceOK, callerOK, local, available bool
	mode                                  string
	serviceUntil, callerUntil             time.Time
	owner                                 uint32
	bindingID                             string
	confirmed                             bool
	counter                               int
	extra                                 map[wire.ServiceBinding]bool
}

func (a *authorityFixture) WithIdentity(ctx context.Context, fn func(View) error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fn(a)
}
func (a *authorityFixture) OperatorAct(_ Principal, _ string, _ json.RawMessage) bool {
	return a.confirmed
}

// This is a fixture codec; production must reuse its baseline event codec.
func (a *authorityFixture) Event(raw json.RawMessage) bool {
	var event struct {
		Kind  string `json:"kind"`
		Class string `json:"class"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || len(members) != 2 || event.Kind != "credential_error" {
		return false
	}
	return event.Class == "auth" || event.Class == "permission" || event.Class == "quota" || event.Class == "unknown"
}
func (a *authorityFixture) Sequence() json.RawMessage { return json.RawMessage(`1`) }
func (a *authorityFixture) WithCurrent(ctx context.Context, fn func(View) error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.available || ctx.Err() != nil {
		return errors.New("fixture evidence unavailable")
	}
	return fn(a)
}
func (a *authorityFixture) Principal(uid uint32) (Principal, error) {
	p, ok := a.principals[uid]
	if !ok {
		return Principal{}, errors.New("fixture principal absent")
	}
	return p, nil
}
func (a *authorityFixture) Service(b wire.ServiceBinding) error {
	p := a.principals[b.UID]
	if !a.serviceOK || !a.local || a.mode != "secret-free" || (b != a.binding && !a.extra[b]) || p.Generation != b.Generation || p.Role != "service" {
		return wire.Refuse("service_binding_mismatch")
	}
	return nil
}
func (a *authorityFixture) Caller(b wire.ServiceBinding, c wire.ServiceCaller) (time.Time, string, error) {
	p := a.principals[c.UID]
	if !a.callerOK || !a.local || a.mode != "secret-free" || (b != a.binding && !a.extra[b]) || c != a.caller || p.Generation != c.Generation || p.Role != "worker" {
		return time.Time{}, "", wire.Refuse("lease_caller_revoked")
	}
	return a.callerUntil, a.bindingID, nil
}
func (a *authorityFixture) Owner(uid uint32, account string) bool {
	return uid == a.owner && account == fixtureAccount
}

type countedAccount struct {
	*claude.Account
	entries int
	before  func()
	info    *wire.ServiceAccount
}

func (a *countedAccount) ServiceAccount() (wire.ServiceAccount, error) {
	if a.info != nil {
		return *a.info, nil
	}
	return a.Account.ServiceAccount()
}
func (a *countedAccount) Publish(ctx context.Context, until time.Time, now func() time.Time, fn func([]byte) error) error {
	a.entries++
	if a.before != nil {
		a.before()
	}
	return a.Account.Publish(ctx, until, now, fn)
}

type brokerFixture struct {
	b                    *Broker
	a                    *authorityFixture
	custody              *countedAccount
	records              *store.Account
	disk                 *store.Store
	root                 string
	now                  time.Time
	uid, operator, owner uint32
}

func newBrokerFixture(t *testing.T, hook store.Durability) *brokerFixture {
	t.Helper()
	f := &brokerFixture{now: time.Now().UTC(), uid: uint32(os.Geteuid())}
	f.operator, f.owner = f.uid+1, f.uid+2
	f.root = filepath.Join(t.TempDir(), "store")
	s, err := store.Open(f.root, "fixture-service", f.uid, true, hook)
	if err != nil {
		t.Fatal("fixture store setup failed")
	}
	f.disk = s
	t.Cleanup(func() { s.Close() })
	f.records, err = s.Account(fixtureAccount, true)
	if err != nil {
		t.Fatal("fixture account setup failed")
	}
	a, err := claude.NewAccount(f.records, "fixture-service", fixtureAccount)
	if err != nil || a.Enroll([]byte(fixtureToken), nil) != nil {
		t.Fatal("fixture enrollment failed")
	}
	f.custody = &countedAccount{Account: a}
	binding := wire.ServiceBinding{Service: Gateway, UID: f.uid, Generation: "service-generation-1", Account: fixtureAccount, Kind: Kind, PolicyDigest: strings.Repeat("a", 64)}
	caller := wire.ServiceCaller{Account: fixtureAccount, UID: f.uid + 3, Generation: "agent-generation-1", LaunchID: "fixture-launch"}
	f.a = &authorityFixture{principals: map[uint32]Principal{
		f.uid:      {UID: f.uid, Role: "service", Generation: binding.Generation, Service: Gateway},
		f.operator: {UID: f.operator, Role: "operator", Generation: "operator-generation"},
		f.owner:    {UID: f.owner, Role: "owner", Generation: "owner-generation"},
		caller.UID: {UID: caller.UID, Role: "worker", Generation: caller.Generation},
	}, binding: binding, caller: caller, serviceOK: true, callerOK: true, local: true, available: true, mode: "secret-free", serviceUntil: f.now.Add(time.Hour), callerUntil: f.now.Add(time.Hour), owner: f.owner, bindingID: "binding-1", confirmed: true}
	f.b, err = New(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now })
	if err != nil {
		t.Fatal("fixture broker setup failed")
	}
	return f
}
func encode(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := wire.Encode(v)
	if err != nil {
		t.Fatal("fixture request encoding failed")
	}
	return b
}
func noMaterial(t *testing.T, raw []byte) {
	t.Helper()
	digest := sha256.Sum256([]byte(fixtureToken))
	for _, v := range []string{fixtureToken, base64.StdEncoding.EncodeToString([]byte(fixtureToken)), hex.EncodeToString([]byte(fixtureToken)), hex.EncodeToString(digest[:])} {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("fixture material escaped permitted gateway result")
		}
	}
}
func (f *brokerFixture) call(t *testing.T, uid uint32, method string, params any, publish func(any) error) error {
	t.Helper()
	f.a.counter++
	op := fmt.Sprint(f.a.counter)
	switch r := params.(type) {
	case wire.ServiceBinding:
		if method == "service.bind" {
			params = wire.ServiceBind{OperationID: op, ServiceBinding: r}
		} else {
			id := "unknown"
			for _, b := range f.b.bindings {
				if b.State == "active" && b.Binding() == r {
					id = b.ID
				}
			}
			params = wire.ServiceUnbind{OperationID: op, BindingID: id}
		}
	case wire.ServiceLeaseID:
		if method == "service.lease.renew" {
			params = wire.ServiceRenew{OperationID: op, ServiceLeaseID: r}
		}
	case wire.ServiceHold:
		if r.OperationID == "" {
			r.OperationID = op
		}
		if r.Account == "" {
			r.Account = fixtureAccount
		}
		params = r
	case wire.ServiceLift:
		if r.OperationID == "" {
			r.OperationID = op
		}
		if r.HoldID == "" {
			if h := f.b.held(r.Account); h != nil {
				r.HoldID = h.ID
			} else {
				r.HoldID = "unknown"
			}
		}
		params = r
	}
	p, err := f.b.Open(context.Background(), uid)
	if err != nil {
		return err
	}
	return f.b.Call(context.Background(), p, method, encode(t, params), publish)
}
func (f *brokerFixture) metadata(t *testing.T, uid uint32, method string, params any) (any, error) {
	t.Helper()
	var result any
	err := f.call(t, uid, method, params, func(v any) error { noMaterial(t, encode(t, v)); result = v; return nil })
	if err != nil {
		noMaterial(t, []byte(err.Error()))
		noMaterial(t, encode(t, err))
	}
	return result, err
}
func (f *brokerFixture) bind(t *testing.T) {
	t.Helper()
	if _, err := f.metadata(t, f.operator, "service.bind", f.a.binding); err != nil {
		t.Fatal("valid service bind refused")
	}
}
func (f *brokerFixture) request() wire.ServiceRequest {
	f.a.counter++
	return wire.ServiceRequest{OperationID: fmt.Sprint(f.a.counter), ServiceCaller: f.a.caller}
}
func (f *brokerFixture) issue(t *testing.T) wire.ServiceLease {
	t.Helper()
	var out wire.ServiceLease
	err := f.call(t, f.uid, "service.lease.request", f.request(), func(v any) error {
		var ok bool
		out, ok = v.(wire.ServiceLease)
		if !ok || out.Payload.Value != fixtureToken || out.Account != fixtureAccount || out.Kind != Kind {
			t.Fatal("gateway control material mismatch")
		}
		return nil
	})
	if err != nil || out.LeaseID == "" {
		t.Fatalf("valid gateway lease refused: %v", err)
	}
	return out
}
func refused(t *testing.T, err error, code string) {
	t.Helper()
	var r *wire.Error
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("wrong fixed refusal: got %v, want %s", err, code)
	}
	noMaterial(t, encode(t, err))
}

// Every named refusal is adjacent to a gateway-positive control. Rejected
// requests never enter custody publication or emit any material-bearing result.
func TestServiceRefusalsBeforeMaterial(t *testing.T) {
	for _, name := range []string{"worker", "orchestrator", "operator", "owner", "unbound", "stale-service-generation", "inactive-agent", "wrong-agent-generation", "wrong-launch", "wrong-account", "wrong-kind", "wrong-policy", "expired-service-authority", "expired-caller-authority", "exposed-lane", "remote-placement", "unavailable-authority"} {
		t.Run(name, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			f.issue(t)
			uid, req, code := f.uid, f.request(), "service_binding_mismatch"
			switch name {
			case "worker", "orchestrator", "operator", "owner":
				p := f.a.principals[f.uid]
				p.Role, p.Service = name, ""
				f.a.principals[f.uid] = p
				code = "role_not_permitted"
			case "unbound":
				code = "role_not_permitted"
				if _, err := f.metadata(t, f.operator, "service.unbind", f.a.binding); err != nil {
					t.Fatal("unbind control failed")
				}
			case "stale-service-generation":
				code = "role_not_permitted"
				p := f.a.principals[f.uid]
				p.Generation = "service-generation-2"
				f.a.principals[f.uid] = p
			case "inactive-agent":
				code = "lease_caller_revoked"
				f.a.callerOK = false
			case "wrong-agent-generation":
				code = "lease_caller_revoked"
				req.ServiceCaller.Generation = "agent-generation-2"
			case "wrong-launch":
				code = "lease_caller_revoked"
				req.ServiceCaller.LaunchID = "another-launch"
			case "wrong-account":
				code = "service_binding_unknown"
				req.ServiceCaller.Account = "another-account"
			case "wrong-kind":
				f.a.binding.Kind = "api-key"
			case "wrong-policy":
				f.a.binding.PolicyDigest = strings.Repeat("b", 64)
			case "expired-service-authority":
				f.a.serviceOK = false
				code = "service_binding_mismatch"
			case "expired-caller-authority":
				f.a.callerUntil = f.now
				code = "lease_not_active"
			case "exposed-lane":
				f.a.mode = "exposed"
			case "remote-placement":
				f.a.local = false
			case "unavailable-authority":
				f.a.available = false
				code = "revocation_state_unavailable"
			}
			before, replies, leasesBefore := f.custody.entries, 0, len(f.b.leases)
			err := f.call(t, uid, "service.lease.request", req, func(any) error { replies++; return nil })
			refused(t, err, code)
			if replies != 0 || f.custody.entries != before || len(f.b.leases) != leasesBefore {
				t.Fatal("refusal entered material publication or allocated a lease")
			}
		})
	}
}

// Each authority is necessary at both issue and renewal, independently of the
// other. This test kills omission of either check, rather than agreement alone.
func TestServiceTwoAuthorities(t *testing.T) {
	for _, method := range []string{"issue", "renew"} {
		for _, missing := range []string{"service", "caller"} {
			t.Run(method+"/"+missing, func(t *testing.T) {
				f := newBrokerFixture(t, nil)
				f.bind(t)
				l := f.issue(t)
				if missing == "service" {
					f.a.serviceOK = false
				} else {
					f.a.callerOK = false
				}
				before, replies := f.custody.entries, 0
				name, params := "service.lease.request", any(f.request())
				if method == "renew" {
					name, params = "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID}
				}
				err := f.call(t, f.uid, name, params, func(any) error { replies++; return nil })
				code := "lease_caller_revoked"
				if missing == "service" {
					code = "service_binding_mismatch"
				}
				refused(t, err, code)
				if replies != 0 || f.custody.entries != before {
					t.Fatal("single-authority lease escaped")
				}
			})
		}
	}
}

// The deadline is min(now+900s, caller authority deadline, vendor expiry), with
// equality expired. Renewal cannot revive an expired lease or ignore a ceiling.
func TestServiceCeilingAndDeadline(t *testing.T) {
	for _, bound := range []string{"ceiling", "caller", "vendor"} {
		t.Run(bound, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			want := f.now.Add(V0LeaseCeiling)
			switch bound {
			case "caller":
				want = f.now.Add(45 * time.Second)
				f.a.callerUntil = want
			case "vendor":
				want = f.now.Add(60 * time.Second).Truncate(time.Second)
				// A fresh fixture enrollment carries optional, exact vendor evidence.
				other := filepath.Join(t.TempDir(), "vendor-store")
				s, err := store.Open(other, "fixture-service", f.uid, true, nil)
				if err != nil {
					t.Fatal("vendor fixture store failed")
				}
				defer s.Close()
				r, err := s.Account(fixtureAccount, true)
				if err != nil {
					t.Fatal("vendor fixture account failed")
				}
				a, err := claude.NewAccount(r, "fixture-service", fixtureAccount)
				if err != nil || a.Enroll([]byte(fixtureToken), &want) != nil {
					t.Fatal("vendor evidence enrollment failed")
				}
				f.custody = &countedAccount{Account: a}
				f.b, err = New(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now })
				if err != nil {
					t.Fatal("vendor fixture broker failed")
				}
				f.bind(t)
			}
			l := f.issue(t)
			until, err := time.Parse(time.RFC3339Nano, l.AuthorizedUntil)
			if err != nil || !until.Equal(want) {
				t.Fatal("lease did not respect exclusive deadline minimum")
			}
			// A current lease can renew with the same checked authority.
			if err := f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID}, func(v any) error {
				x, ok := v.(wire.ServiceLease)
				if !ok || x.AuthorizedUntil != l.AuthorizedUntil || x.Payload.Value != fixtureToken {
					t.Fatal("renewal control mismatch")
				}
				return nil
			}); err != nil {
				t.Fatal("valid renewal failed")
			}
			f.now = until
			before := f.custody.entries
			_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID})
			refused(t, err, "lease_not_active")
			if f.custody.entries != before {
				t.Fatal("expired lease entered custody")
			}
		})
	}
}

// Hold is lessee-only with the exact reason, persists before acknowledgment,
// fences every lease without rewriting it, and survives restart. Only the account owner
// can lift; a removed binding never inherits its old leases. No vendor stop is claimed.
func TestServiceHoldOrderingAndOwnerLift(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	other := f.issue(t)
	for _, tc := range []struct {
		uid    uint32
		params wire.ServiceHold
		code   string
	}{
		{f.operator, wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"}, "role_not_permitted"},
		{f.uid, wire.ServiceHold{LeaseID: "not-a-lease", Reason: "leak_match"}, "lease_not_owner"},
		{f.uid, wire.ServiceHold{LeaseID: l.LeaseID, Reason: "unproven-reason"}, "hold_reason_unknown"},
	} {
		_, err := f.metadata(t, tc.uid, "account.hold", tc.params)
		refused(t, err, tc.code)
		if _, err := f.custody.ExpiresAt(); err != nil {
			t.Fatal("invalid hold changed account")
		}
	}
	replies := 0
	err := f.call(t, f.uid, "account.hold", wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"}, func(v any) error {
		replies++
		noMaterial(t, encode(t, v))
		fresh, err := claude.NewAccount(f.records, "fixture-service", fixtureAccount)
		if err != nil {
			t.Fatal("fresh hold witness failed")
		}
		s, err := fresh.Status()
		if err != nil || s.State != "enrolled" || freshHoldCount(f) != 1 {
			t.Fatal("hold reply preceded durable state")
		}
		return nil
	})
	if err != nil || replies != 1 {
		t.Fatal("valid hold acknowledgment failed")
	}
	for _, id := range []string{l.LeaseID, other.LeaseID} {
		out, err := f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: id})
		if err != nil || out.(map[string]any)["verdict"] != "revoked" {
			t.Fatal("held lease poll remained open")
		}
		_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: id})
		refused(t, err, "account_hold_active")
	}
	for _, uid := range []uint32{f.uid, f.operator, f.a.caller.UID} {
		_, err := f.metadata(t, uid, "account.hold.lift", wire.ServiceLift{Account: fixtureAccount})
		refused(t, err, "role_not_permitted")
		s, err := f.custody.Status()
		if err != nil || s.State != "enrolled" || freshHoldCount(f) != 1 {
			t.Fatal("non-owner lift altered the hold")
		}
	}
	f.a.owner = f.owner + 10
	_, err = f.metadata(t, f.owner, "account.hold.lift", wire.ServiceLift{Account: fixtureAccount})
	refused(t, err, "role_not_permitted")
	s, err := f.custody.Status()
	if err != nil || s.State != "enrolled" || freshHoldCount(f) != 1 {
		t.Fatal("unrelated owner altered the hold")
	}
	f.a.owner = f.owner
	if _, err = f.metadata(t, f.owner, "account.hold.lift", wire.ServiceLift{Account: fixtureAccount}); err != nil {
		t.Fatal("account owner could not lift hold")
	}
	if err = f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID}, func(any) error { return nil }); err != nil {
		t.Fatal("lift failed to admit current unchanged lease")
	}
	f.issue(t)
}

// Every durability-stage failure refuses without acknowledgment and leaves
// leases closed, beside the successful durable hold in the preceding test.
func TestServiceHoldDurabilityFailure(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			armed := false
			f := newBrokerFixture(t, func(s string) error {
				if armed && s == stage {
					return errors.New("fixture durability fault")
				}
				return nil
			})
			f.bind(t)
			l := f.issue(t)
			armed = true
			replies := 0
			err := f.call(t, f.uid, "account.hold", wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"}, func(any) error { replies++; return nil })
			refused(t, err, "account_hold_unknown")
			if replies != 0 {
				t.Fatal("uncertain hold acknowledged")
			}
			_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID})
			refused(t, err, "lease_owner_unavailable")
		})
	}
}

// Unbind/rebind tombstones and lease identities persist through restart, and wrong
// role/generation cannot create or remove a binding. Metadata contains no token.
func TestServiceBindingAndRevocation(t *testing.T) {
	f := newBrokerFixture(t, nil)
	for _, uid := range []uint32{f.uid, f.owner, f.a.caller.UID} {
		_, err := f.metadata(t, uid, "service.bind", f.a.binding)
		refused(t, err, "role_not_permitted")
		s, err := f.custody.LoadServiceState()
		if err != nil || s.Revision != 0 || len(s.Bindings) != 0 {
			t.Fatal("unauthorized bind changed protected state")
		}
	}
	wrong := f.a.binding
	wrong.Generation = "stale-generation"
	_, err := f.metadata(t, f.operator, "service.bind", wrong)
	refused(t, err, "principal_ledger_mismatch")
	f.bind(t)
	l := f.issue(t)
	out, err := f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if err != nil || out.(map[string]any)["verdict"] != "not_revoked" {
		t.Fatal("live lease poll control failed")
	}
	wrong.PolicyDigest = strings.Repeat("b", 64)
	_, err = f.metadata(t, f.operator, "service.unbind", wrong)
	refused(t, err, "service_binding_unknown")
	if _, err = f.metadata(t, f.operator, "service.unbind", f.a.binding); err != nil {
		t.Fatal("operator unbind failed")
	}
	f.bind(t)
	_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	refused(t, err, "service_binding_unknown")
	f.issue(t)
	restarted, err := New(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now })
	if err != nil {
		t.Fatal("binding restart failed")
	}
	f.b = restarted
	_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	refused(t, err, "service_binding_unknown")
	f.issue(t)
}

// Missing/extra fields, roles and placeholders cannot widen broker input. The
// broker has no placeholder field or mapping; every invalid shape refuses.
func TestServiceClosedInputAndZeroValues(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	f.issue(t)
	p, _ := f.b.Open(context.Background(), f.uid)
	for _, raw := range []string{`{}`, `{"caller":null,"kind":"claude-oauth-token","policy_digest":"x"}`, `{"role":"service"}`, `{"placeholder":"nonsecret"}`} {
		before := f.custody.entries
		err := f.b.Call(context.Background(), p, "service.lease.request", json.RawMessage(raw), func(any) error { t.Fatal("invalid shape published"); return nil })
		refused(t, err, "request_malformed")
		if before != f.custody.entries {
			t.Fatal("invalid shape entered custody")
		}
	}
	var absent *Broker
	if _, err := absent.Open(context.Background(), f.uid); err == nil {
		t.Fatal("nil broker opened")
	}
	if _, err := New(nil, map[string]Account{fixtureAccount: f.custody}, nil); err == nil {
		t.Fatal("missing authority accepted")
	}
	if _, err := New(f.a, nil, nil); err == nil {
		t.Fatal("missing custody accepted")
	}
	for _, raw := range []string{strings.Join(os.Environ(), "\n"), strings.Join(os.Args, "\n")} {
		noMaterial(t, []byte(raw))
	}
}

// Cancellation, expiry between admission and custody, and uncertain write all
// close before any further material release; a fresh lease is the valid control.
func TestServicePublicationBoundaries(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	f.custody.before = func() { f.now = f.now.Add(V0LeaseCeiling) }
	replies := 0
	err := f.call(t, f.uid, "service.lease.request", f.request(), func(any) error { replies++; return nil })
	refused(t, err, "lease_owner_unavailable")
	if replies != 0 {
		t.Fatal("late publication released material")
	}
	f.custody.before = nil
	f.now = f.now.Add(-V0LeaseCeiling)
	_, err = f.metadata(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	refused(t, err, "lease_not_active") // A backward clock never revives elapsed authority.
	f.now = f.now.Add(V0LeaseCeiling + time.Second)
	current := f.issue(t)
	err = f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: current.LeaseID}, func(any) error { return errors.New(fixtureToken) })
	refused(t, err, "lease_owner_unavailable")
	if err = f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: current.LeaseID}, func(any) error { return nil }); err != nil {
		t.Fatal("lost reply prevented a current renewal")
	}
	p, _ := f.b.Open(context.Background(), f.uid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := f.custody.entries
	err = f.b.Call(ctx, p, "service.lease.request", encode(t, f.request()), func(any) error { t.Fatal("cancelled publish"); return nil })
	if err == nil || f.custody.entries != before {
		t.Fatal("cancelled request reached custody")
	}
}

// A second current service is not the lessee; knowing an ID gives it neither
// renewal nor hold authority. The actual lessee remains usable after rejection.
func TestServiceNonLessee(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	uid := f.uid + 20
	f.a.principals[uid] = Principal{UID: uid, Role: "service", Generation: "other-service-generation", Service: Gateway}
	other := f.a.binding
	other.UID = uid
	other.Generation = "other-service-generation"
	f.a.extra = map[wire.ServiceBinding]bool{other: true}
	if _, err := f.metadata(t, f.operator, "service.bind", other); err != nil {
		t.Fatal("second principal bind", err)
	}
	for _, tc := range []struct {
		method string
		params any
	}{
		{"account.hold", wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"}},
		{"service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID}},
		{"service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID}},
	} {
		before := f.custody.entries
		_, err := f.metadata(t, uid, tc.method, tc.params)
		refused(t, err, "lease_not_owner")
		if f.custody.entries != before {
			t.Fatal("non-lessee entered custody")
		}
	}
	if err := f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: l.LeaseID}, func(any) error { return nil }); err != nil {
		t.Fatal("lessee control failed")
	}
}

// Authority settlement excludes a concurrent revocation through the actual
// publish callback. Once the revocation settles, renewal cannot release bytes.
// This is the provider interface contract, not native user-manager qualification.
func TestServiceAuthorityPublicationFence(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	p, err := f.b.Open(context.Background(), f.uid)
	if err != nil {
		t.Fatal("principal control failed")
	}
	entered, release, callDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		callDone <- f.b.Call(context.Background(), p, "service.lease.request", encode(t, f.request()), func(any) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication not entered")
	}
	if f.a.mu.TryLock() {
		f.a.mu.Unlock()
		t.Fatal("authority gate released before material write")
	}
	unblock()
	if err := <-callDone; err != nil {
		t.Fatal("publication control failed")
	}
	f.a.mu.Lock()
	f.a.callerOK = false
	f.a.mu.Unlock()
	before := f.custody.entries
	_, err = f.metadata(t, f.uid, "service.lease.request", f.request())
	refused(t, err, "lease_caller_revoked")
	if f.custody.entries != before {
		t.Fatal("settled revocation released late material")
	}
}

// Polls consume no material, and unavailable/currentness/expiry changes cannot
// be mistaken for permission. Unknown IDs are not a transferable observation.
func TestServiceRevocationPollNeighbors(t *testing.T) {
	for _, change := range []string{"caller-revoked", "service-revoked", "expired", "held", "released"} {
		t.Run(change, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			l := f.issue(t)
			out, err := f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID})
			if err != nil || out.(map[string]any)["verdict"] != "not_revoked" {
				t.Fatal("poll control failed")
			}
			switch change {
			case "caller-revoked":
				f.a.callerOK = false
			case "service-revoked":
				f.a.serviceOK = false
			case "expired":
				f.now = f.now.Add(V0LeaseCeiling)
			case "held":
				if _, e := f.metadata(t, f.uid, "account.hold", wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"}); e != nil {
					t.Fatal("hold fixture failed")
				}
			case "released":
				if _, err := f.metadata(t, f.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: l.LeaseID}); err != nil {
					t.Fatal("release control failed")
				}
			}
			before := f.custody.entries
			out, err = f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID})
			want := "revoked"
			if change == "caller-revoked" || change == "service-revoked" || change == "held" {
				want = "revoked"
				if change == "service-revoked" {
					want = "unavailable"
				}
			}
			if err != nil || out.(map[string]any)["verdict"] != want || before != f.custody.entries {
				t.Fatal("revocation poll widened or opened material")
			}
		})
	}
}

func freshHoldCount(f *brokerFixture) int {
	s, e := f.custody.LoadServiceState()
	if e != nil {
		return -1
	}
	n := 0
	for _, h := range s.Holds {
		if h.State == "active" {
			n++
		}
	}
	return n
}
