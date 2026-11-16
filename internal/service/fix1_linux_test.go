//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/claude"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func restart(t *testing.T, f *brokerFixture) {
	t.Helper()
	a, err := claude.NewAccount(f.records, "fixture-service", fixtureAccount)
	if err != nil {
		t.Fatal(err)
	}
	f.custody = &countedAccount{Account: a}
	f.b, err = New(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now })
	if err != nil {
		t.Fatal("restart failed", err)
	}
}
func renew(t *testing.T, f *brokerFixture, id string) error {
	t.Helper()
	return f.call(t, f.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: id}, func(any) error { return nil })
}
func hold(t *testing.T, f *brokerFixture, id string) error {
	t.Helper()
	_, err := f.metadata(t, f.uid, "account.hold", wire.ServiceHold{LeaseID: id, Reason: "leak_match"})
	return err
}

// B1: unchanged originating identity renews; replacement for the same uid and
// generation refuses without mutation/material, including after broker restart.
// Containment remains available: section 5.8 does not repeat use authority.
func TestOriginatingBindingReplacement(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-process", true: "restart"}[reopen], func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			l := f.issue(t)
			if err := renew(t, f, l.LeaseID); err != nil {
				t.Fatal("unchanged binding control", err)
			}
			before := *f.b.leases[l.LeaseID]
			f.a.bindingID = "binding-replacement"
			if reopen {
				restart(t, f)
			}
			entries := f.custody.entries
			refused(t, renew(t, f, l.LeaseID), "lease_unbound")
			if !reflect.DeepEqual(before, *f.b.leases[l.LeaseID]) || entries != f.custody.entries {
				t.Fatal("replacement changed old lease or published")
			}
			out, err := f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID})
			if err != nil || out.(map[string]any)["verdict"] != "revoked" {
				t.Fatal("replaced binding poll did not revoke")
			}
			fresh := f.issue(t)
			if f.b.leases[fresh.LeaseID].AgentBindingID != "binding-replacement" {
				t.Fatal("fresh issue failed to resolve binding")
			}
			if err = hold(t, f, l.LeaseID); err != nil {
				t.Fatal("replacement prevented containment", err)
			}
		})
	}
}

// B2: an already qualified lessee can contain a leak after either authority
// ends or its reader goes down. In each case renewal refuses before material,
// but hold succeeds durably without changing account or lease states.
func TestHoldAfterAuthorityEnds(t *testing.T) {
	for _, change := range []string{"caller-revoked", "service-authority-ended", "binding-removed", "reader-down", "vendor-expired"} {
		t.Run(change, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			l := f.issue(t)
			if err := renew(t, f, l.LeaseID); err != nil {
				t.Fatal("valid authority control", err)
			}
			before := *f.b.leases[l.LeaseID]
			switch change {
			case "caller-revoked":
				f.a.callerOK = false
			case "service-authority-ended":
				f.a.serviceOK = false
			case "binding-removed":
				f.a.bindingID = ""
			case "reader-down":
				f.a.available = false
			case "vendor-expired":
				info, err := f.custody.ServiceAccount()
				if err != nil {
					t.Fatal(err)
				}
				info.ExpiresAt = &f.now
				f.custody.info = &info
			}
			entries := f.custody.entries
			if err := renew(t, f, l.LeaseID); err == nil {
				t.Fatal("ended authority still renewed")
			}
			if err := hold(t, f, l.LeaseID); err != nil {
				t.Fatal("containment depends on ended use authority", err)
			}
			if !reflect.DeepEqual(before, *f.b.leases[l.LeaseID]) || entries != f.custody.entries {
				t.Fatal("containment rewrote lease or released material")
			}
			state, err := f.custody.LoadServiceState()
			if err != nil || len(state.Holds) != 1 || state.Holds[0].State != "active" {
				t.Fatal("hold missing from durable state")
			}
			metadata, err := f.custody.Status()
			if err != nil || metadata.State != "enrolled" {
				t.Fatal("hold rewrote account state")
			}
		})
	}
}

// The ended-lease containment window is inclusive, survives restart, and ends
// one nanosecond past the configured lifetime. Wrong account/reason/owner have
// no state effect, even when multiple checks could fail simultaneously.
func TestHoldWindowAndOrderedRefusals(t *testing.T) {
	for _, kind := range []string{"released", "expired"} {
		for _, late := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/boundary", true: "/late"}[late], func(t *testing.T) {
				f := newBrokerFixture(t, nil)
				f.bind(t)
				l := f.issue(t)
				end := f.now
				if kind == "released" {
					if _, err := f.metadata(t, f.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: l.LeaseID}); err != nil {
						t.Fatal(err)
					}
				} else {
					end = f.b.leases[l.LeaseID].Until
				}
				f.now = end.Add(V0LeaseCeiling)
				if late {
					f.now = f.now.Add(time.Nanosecond)
				}
				restart(t, f)
				before, _ := f.custody.LoadServiceState()
				err := hold(t, f, l.LeaseID)
				if late {
					refused(t, err, "lease_not_active")
					after, _ := f.custody.LoadServiceState()
					if !reflect.DeepEqual(before, after) {
						t.Fatal("stale hold mutated state")
					}
				} else if err != nil {
					t.Fatal("boundary control refused", err)
				}
			})
		}
	}
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	for _, tc := range []struct{ lease, account, reason, code string }{
		{"unknown", fixtureAccount, "wrong", "lease_not_owner"},
		{l.LeaseID, "other-account", "wrong", "service_binding_mismatch"},
		{l.LeaseID, fixtureAccount, "wrong", "hold_reason_unknown"},
	} {
		before, _ := f.custody.LoadServiceState()
		_, err := f.metadata(t, f.uid, "account.hold", wire.ServiceHold{LeaseID: tc.lease, Account: tc.account, Reason: tc.reason})
		refused(t, err, tc.code)
		after, _ := f.custody.LoadServiceState()
		if !reflect.DeepEqual(before, after) {
			t.Fatal("refusal changed protected state")
		}
	}
	if err := hold(t, f, l.LeaseID); err != nil {
		t.Fatal("valid hold after refusals", err)
	}
}

// Same-operation retries retain identities and the single recorded extension
// across restart. Changed arguments conflict. Replaying expired/released leases
// refuses rather than returning material or creating a second effect.
func TestDurableServiceReplay(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	req := f.request()
	var first wire.ServiceLease
	err := f.call(t, f.uid, "service.lease.request", req, func(v any) error { first = v.(wire.ServiceLease); return errors.New("lost reply") })
	refused(t, err, "lease_owner_unavailable")
	restart(t, f)
	if err = f.call(t, f.uid, "service.lease.request", req, func(v any) error {
		if !reflect.DeepEqual(v, first) {
			t.Fatal("replay changed issue outcome")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.b.leases) != 1 {
		t.Fatal("issue retry duplicated lease")
	}
	bad := req
	bad.LaunchID = "different-launch"
	_, err = f.metadata(t, f.uid, "service.lease.request", bad)
	refused(t, err, "service_operation_conflict")
	f.now = f.now.Add(time.Second)
	renewal := wire.ServiceRenew{OperationID: "one-renewal", ServiceLeaseID: wire.ServiceLeaseID{LeaseID: first.LeaseID}}
	var until string
	if err = f.call(t, f.uid, "service.lease.renew", renewal, func(v any) error { until = v.(wire.ServiceLease).AuthorizedUntil; return nil }); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	restart(t, f)
	if err = f.call(t, f.uid, "service.lease.renew", renewal, func(v any) error {
		if v.(wire.ServiceLease).AuthorizedUntil != until {
			t.Fatal("retry extended twice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.metadata(t, f.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: first.LeaseID}); err != nil {
		t.Fatal(err)
	}
	before, _ := f.custody.LoadServiceState()
	_, err = f.metadata(t, f.uid, "service.lease.renew", renewal)
	refused(t, err, "lease_not_active")
	after, _ := f.custody.LoadServiceState()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("replay revived released lease")
	}
	// An independently issued lease exercises the exclusive deadline replay.
	req = f.request()
	var id string
	if err = f.call(t, f.uid, "service.lease.request", req, func(v any) error { id = v.(wire.ServiceLease).LeaseID; return nil }); err != nil {
		t.Fatal(err)
	}
	f.now = f.b.leases[id].Until
	_, err = f.metadata(t, f.uid, "service.lease.request", req)
	refused(t, err, "lease_not_active")
}

// Lost hold replies reconcile without a second hold, even after authority loss
// and restart. The exact account owner must name the active hold and confirm the
// widening act. Duplicate binds refuse; the same operator may bind and lift.
func TestHoldReplayAndConfirmedOwner(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.a.owner = f.operator
	f.bind(t)
	l := f.issue(t)
	_, err := f.metadata(t, f.operator, "service.bind", f.a.binding)
	refused(t, err, "service_binding_mismatch")
	r := wire.ServiceHold{OperationID: "hold-once", LeaseID: l.LeaseID, Account: fixtureAccount, Reason: "leak_match"}
	err = f.call(t, f.uid, "account.hold", r, func(any) error { return errors.New("lost reply") })
	refused(t, err, "lease_owner_unavailable")
	h := *f.b.held(fixtureAccount)
	restart(t, f)
	f.a.available = false
	if _, err = f.metadata(t, f.uid, "account.hold", r); err != nil {
		t.Fatal("hold replay depended on current reader", err)
	}
	if len(f.b.holds) != 1 || f.b.held(fixtureAccount).ID != h.ID {
		t.Fatal("retry wrote second hold")
	}
	r.Reason = "wrong"
	_, err = f.metadata(t, f.uid, "account.hold", r)
	refused(t, err, "service_operation_conflict")
	f.a.available = true
	lift := wire.ServiceLift{OperationID: "lift-once", HoldID: h.ID, Account: fixtureAccount}
	f.a.confirmed = false
	_, err = f.metadata(t, f.operator, "account.hold.lift", lift)
	refused(t, err, "role_not_permitted")
	f.a.confirmed = true
	bad := lift
	bad.HoldID = "unknown"
	_, err = f.metadata(t, f.operator, "account.hold.lift", bad)
	refused(t, err, "account_hold_not_found")
	if _, err = f.metadata(t, f.operator, "account.hold.lift", lift); err != nil {
		t.Fatal("same operator/owner could not lift", err)
	}
	if _, err = f.metadata(t, f.operator, "account.hold.lift", lift); err != nil {
		t.Fatal("lift replay failed", err)
	}
	lift.OperationID = "no-active-hold"
	_, err = f.metadata(t, f.operator, "account.hold.lift", lift)
	refused(t, err, "account_hold_not_found")
}

// Source and closed-field validation is exact, preserves zero-valued uid, and
// maps the accepted codes without dropping them into owner-unavailable.
func TestAcceptedServiceFieldsAndCodes(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	for _, field := range []string{"body", "placeholder", "value"} {
		raw := map[string]any{"operation_id": "bad-hold", "service_lease_id": l.LeaseID, "account": fixtureAccount, "reason_code": "leak_match", field: "inert"}
		_, err := f.metadata(t, f.uid, "account.hold", raw)
		refused(t, err, "request_malformed")
	}
	for _, code := range []string{"secret_free_lease_required", "request_malformed", "service_operation_conflict", "service_binding_unknown", "service_binding_mismatch", "account_hold_active", "hold_reason_unknown", "account_hold_unknown", "account_hold_not_found"} {
		if wire.Refuse(code).Code != code {
			t.Fatal("assigned code lost", code)
		}
	}
	if err := hold(t, f, l.LeaseID); err != nil {
		t.Fatal(err)
	}
	out, err := f.metadata(t, f.owner, "status", struct{}{})
	if err != nil || len(out.(map[string]any)["holds"].([]any)) != 1 {
		t.Fatal("owner cannot discover hold identity")
	}
}

// Startup rejects ceilings above 900 instead of clamping; an admitted smaller
// ceiling bounds issue and the recently-ended hold window independently.
func TestConfiguredServiceLifetime(t *testing.T) {
	f := newBrokerFixture(t, nil)
	if _, err := NewWithLifetime(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now }, V0LeaseCeiling+time.Second); err == nil {
		t.Fatal("oversized ceiling clamped")
	}
	var err error
	f.b, err = NewWithLifetime(f.a, map[string]Account{fixtureAccount: f.custody}, func() time.Time { return f.now }, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.bind(t)
	l := f.issue(t)
	if !f.b.leases[l.LeaseID].Until.Equal(f.now.Add(10 * time.Second)) {
		t.Fatal("smaller ceiling ignored")
	}
	f.now = f.now.Add(20*time.Second + time.Nanosecond)
	refused(t, hold(t, f, l.LeaseID), "lease_not_active")
}

// Unavailable current evidence publishes unavailable using the provider's own
// sequence encoding; a positive read and an explicit revocation are distinct.
func TestPollUnavailableSequence(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	f.a.available = false
	out, err := f.metadata(t, f.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if err != nil || out.(map[string]any)["verdict"] != "unavailable" || !json.Valid(out.(map[string]any)["revocation_sequence"].(json.RawMessage)) {
		t.Fatal("unknown evidence became current")
	}
	f.a.available = true
	if err = renew(t, f, l.LeaseID); err != nil {
		t.Fatal("complete read control", err)
	}
	// Use the public call boundary, including identity acquired independently.
	p, err := f.b.Open(context.Background(), f.uid)
	if err != nil || p.Role != "service" {
		t.Fatal("identity control")
	}
}

// Current source transactions are durable before payload publication; reopening
// from the callback sees the exact originating and service binding identities.
func TestServiceLeaseDurableBeforeReply(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	err := f.call(t, f.uid, "service.lease.request", f.request(), func(v any) error {
		l := v.(wire.ServiceLease)
		fresh, e := claude.NewAccount(f.records, "fixture-service", fixtureAccount)
		if e != nil {
			t.Fatal(e)
		}
		s, e := fresh.LoadServiceState()
		if e != nil || len(s.Leases) != 1 || s.Leases[0].ID != l.LeaseID || s.Leases[0].AgentBindingID != f.a.bindingID || s.Leases[0].BindingID != s.Bindings[0].ID {
			t.Fatal("material preceded durable lease identity")
		}
		noMaterial(t, encode(t, s))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The persisted consumed-time watermark prevents a backward wall-clock step
// across restart from making a now-expired caller authority current again.
func TestServiceWatermarkAcrossRestart(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	f.now = f.now.Add(time.Minute)
	if err := renew(t, f, l.LeaseID); err != nil {
		t.Fatal("current-time control", err)
	}
	consumed := f.now
	f.now = f.now.Add(-2 * time.Minute)
	f.a.callerUntil = consumed.Add(-time.Second)
	restart(t, f)
	entries := f.custody.entries
	refused(t, renew(t, f, l.LeaseID), "lease_not_active")
	if f.custody.entries != entries {
		t.Fatal("clock rollback released material")
	}
}

// Non-active account states refuse by their assigned code, without a lease
// mutation or material callback; the active account is the adjacent control.
func TestServiceInactiveAccount(t *testing.T) {
	for _, tc := range []struct{ state, code string }{{"revoked", "lease_account_revoked"}, {"reauth_required", "lease_reauth_required"}, {"owner_unavailable", "lease_owner_unavailable"}, {"refresh_failed_transient", "lease_owner_unavailable"}} {
		t.Run(tc.state, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			l := f.issue(t)
			info, err := f.custody.ServiceAccount()
			if err != nil {
				t.Fatal(err)
			}
			info.State = tc.state
			f.custody.info = &info
			before := *f.b.leases[l.LeaseID]
			entries := f.custody.entries
			refused(t, renew(t, f, l.LeaseID), tc.code)
			if !reflect.DeepEqual(before, *f.b.leases[l.LeaseID]) || entries != f.custody.entries {
				t.Fatal("inactive account changed lease or published")
			}
		})
	}
}

// Several gateway triples can bind one account. A lease gives no hold authority
// to its neighbor, while a qualified lessee's hold closes both principals and
// preserves both lease records byte for byte through hold and owner lift.
func TestMultipleGatewayAccountHold(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	other := f.a.binding
	other.UID += 20
	other.Generation = "other-generation"
	f.a.principals[other.UID] = Principal{UID: other.UID, Role: "service", Generation: other.Generation, Service: Gateway}
	f.a.extra = map[wire.ServiceBinding]bool{other: true}
	if _, err := f.metadata(t, f.operator, "service.bind", other); err != nil {
		t.Fatal("separate triple refused", err)
	}
	var id string
	if err := f.call(t, other.UID, "service.lease.request", f.request(), func(v any) error { id = v.(wire.ServiceLease).LeaseID; return nil }); err != nil {
		t.Fatal("second principal control", err)
	}
	beforeA, beforeB := *f.b.leases[l.LeaseID], *f.b.leases[id]
	_, err := f.metadata(t, other.UID, "account.hold", wire.ServiceHold{LeaseID: l.LeaseID, Reason: "leak_match"})
	refused(t, err, "lease_not_owner")
	if err = hold(t, f, l.LeaseID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		uid uint32
		id  string
	}{{f.uid, l.LeaseID}, {other.UID, id}} {
		out, e := f.metadata(t, tc.uid, "service.revocation.check", wire.ServiceLeaseID{LeaseID: tc.id})
		if e != nil || out.(map[string]any)["verdict"] != "revoked" {
			t.Fatal("account hold left another gateway open")
		}
		_, e = f.metadata(t, tc.uid, "service.lease.renew", wire.ServiceLeaseID{LeaseID: tc.id})
		refused(t, e, "account_hold_active")
	}
	if !reflect.DeepEqual(beforeA, *f.b.leases[l.LeaseID]) || !reflect.DeepEqual(beforeB, *f.b.leases[id]) {
		t.Fatal("hold rewrote lease records")
	}
}

// A revoked record with no durable transition-time evidence cannot acquire the
// ended-lease window; the same lessee's active lease remains a valid trigger.
func TestHoldMissingEndEvidence(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	valid := f.issue(t)
	f.b.leases[l.LeaseID].State = "revoked"
	refused(t, hold(t, f, l.LeaseID), "lease_not_active")
	if err := hold(t, f, valid.LeaseID); err != nil {
		t.Fatal("active trigger control", err)
	}
}

// A failure after rename but before directory sync is UNKNOWN. A fresh custody
// wrapper re-confirms the recovered journal before its same-operation retry
// acknowledges the one existing hold; no replacement lease is needed.
func TestHoldUnknownRecovery(t *testing.T) {
	armed := false
	f := newBrokerFixture(t, func(stage string) error {
		if armed && stage == "directory-sync" {
			return errors.New("fixture directory sync failure")
		}
		return nil
	})
	f.bind(t)
	l := f.issue(t)
	r := wire.ServiceHold{OperationID: "unknown-recovery", LeaseID: l.LeaseID, Account: fixtureAccount, Reason: "leak_match"}
	armed = true
	_, err := f.metadata(t, f.uid, "account.hold", r)
	refused(t, err, "account_hold_unknown")
	armed = false
	restart(t, f)
	f.a.available = false
	if _, err = f.metadata(t, f.uid, "account.hold", r); err != nil {
		t.Fatal("unknown hold could not reconcile", err)
	}
	if len(f.b.holds) != 1 || freshHoldCount(f) != 1 {
		t.Fatal("unknown retry duplicated hold")
	}
}

// Removed service bindings close their registered connections. Registration
// itself admits no unbound service.
func TestServiceUnbindClosesConnections(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	p, err := f.b.Open(context.Background(), f.uid)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	cleanup, err := f.b.RegisterConnection(context.Background(), p, func() { closed = true })
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if closed {
		t.Fatal("current connection closed before unbind")
	}
	if _, err = f.metadata(t, f.operator, "service.unbind", f.a.binding); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("unbind retained old generation connection")
	}
	if _, err = f.b.Open(context.Background(), f.uid); err == nil {
		t.Fatal("removed binding retained service role")
	}
	f.bind(t)
	if _, err = f.b.Open(context.Background(), f.uid); err != nil {
		t.Fatal("fresh bind control", err)
	}
}

// Returning an already active hold still binds the new operation's canonical
// arguments; replay after lift reports current lifted state and creates no hold.
func TestExistingHoldOperationCorrelation(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	if err := hold(t, f, l.LeaseID); err != nil {
		t.Fatal(err)
	}
	r := wire.ServiceHold{OperationID: "existing-hold", LeaseID: l.LeaseID, Account: fixtureAccount, Reason: "leak_match"}
	if _, err := f.metadata(t, f.uid, "account.hold", r); err != nil {
		t.Fatal(err)
	}
	bad := r
	bad.Reason = "wrong"
	_, err := f.metadata(t, f.uid, "account.hold", bad)
	refused(t, err, "service_operation_conflict")
	if _, err = f.metadata(t, f.owner, "account.hold.lift", wire.ServiceLift{Account: fixtureAccount}); err != nil {
		t.Fatal(err)
	}
	out, err := f.metadata(t, f.uid, "account.hold", r)
	if err != nil || out.(map[string]any)["state"] != "lifted" || len(f.b.holds) != 1 {
		t.Fatal("replay misreported current hold state")
	}
}

// Operator bind replay uses only its recorded outcome and authenticated act;
// a use-authority outage cannot make a successful recorded bind indeterminate.
func TestServiceBindReplayWithoutAuthority(t *testing.T) {
	f := newBrokerFixture(t, nil)
	r := wire.ServiceBind{OperationID: "bind-once", ServiceBinding: f.a.binding}
	if _, err := f.metadata(t, f.operator, "service.bind", r); err != nil {
		t.Fatal(err)
	}
	f.a.available = false
	if _, err := f.metadata(t, f.operator, "service.bind", r); err != nil {
		t.Fatal("bind replay required live use authority", err)
	}
	r.OperationID = "different-bind"
	_, err := f.metadata(t, f.operator, "service.bind", r)
	refused(t, err, "revocation_state_unavailable")
}

// Reporting typed metadata cannot hold, release or renew a lease; a malformed
// event changes nothing. Release succeeds under ended caller authority and is
// idempotent without a second durable transition.
func TestServiceReportAndRelease(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	before := *f.b.leases[l.LeaseID]
	_, err := f.metadata(t, f.uid, "event.report", map[string]any{"service_lease_id": l.LeaseID, "event": map[string]any{"kind": "credential_error", "class": "auth"}})
	if err != nil || !reflect.DeepEqual(before, *f.b.leases[l.LeaseID]) || len(f.b.holds) != 0 {
		t.Fatal("typed report changed authority", err)
	}
	_, err = f.metadata(t, f.uid, "event.report", map[string]any{"service_lease_id": l.LeaseID, "event": map[string]any{"kind": "credential_error", "class": "auth", "body": "inert"}})
	refused(t, err, "request_malformed")
	f.a.callerOK = false
	f.a.available = false
	if _, err = f.metadata(t, f.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: l.LeaseID}); err != nil {
		t.Fatal("release required caller authority", err)
	}
	state, _ := f.custody.LoadServiceState()
	if _, err = f.metadata(t, f.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: l.LeaseID}); err != nil {
		t.Fatal("release retry failed", err)
	}
	after, _ := f.custody.LoadServiceState()
	if !reflect.DeepEqual(state, after) {
		t.Fatal("release retry rewrote transition")
	}
}

// Every uncertain durability stage can reconcile on a fresh connection with
// the same operation, without restarting or delivering another credential.
func TestHoldUnknownSameOperationRetry(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			armed := false
			f := newBrokerFixture(t, func(point string) error {
				if armed && point == stage {
					return errors.New("fixture hold write failure")
				}
				return nil
			})
			f.bind(t)
			l := f.issue(t)
			r := wire.ServiceHold{OperationID: "same-operation-retry", LeaseID: l.LeaseID, Account: fixtureAccount, Reason: "leak_match"}
			armed = true
			_, err := f.metadata(t, f.uid, "account.hold", r)
			refused(t, err, "account_hold_unknown")
			armed = false
			f.a.available = false
			before := f.custody.entries
			if _, err = f.metadata(t, f.uid, "account.hold", r); err != nil {
				t.Fatal("same-operation retry did not reconcile unknown hold", err)
			}
			if freshHoldCount(f) != 1 || len(f.b.holds) != 1 || f.custody.entries != before {
				t.Fatal("hold reconciliation duplicated effect or material")
			}
		})
	}
}

// The default clock's monotonic projection consumes elapsed time even if its
// wall reading moves back; the injected floor is a bounded clock witness, not
// native reboot or qualified-time evidence.
func TestServiceMonotonicProjection(t *testing.T) {
	f := newBrokerFixture(t, nil)
	f.bind(t)
	l := f.issue(t)
	if err := renew(t, f, l.LeaseID); err != nil {
		t.Fatal("clock control", err)
	}
	f.a.callerUntil = f.now.Add(time.Minute)
	f.b.realClock = true
	f.b.anchorWall = f.now.Add(time.Minute)
	f.b.anchorMono = time.Now().Add(-time.Second)
	refused(t, renew(t, f, l.LeaseID), "lease_not_active")
}
