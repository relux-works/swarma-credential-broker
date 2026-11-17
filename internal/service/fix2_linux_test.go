//go:build linux

package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Section 5.1 step 2 retains the baseline bind_target_invalid spelling and
// leaves the journal untouched; the adjacent conforming bind still succeeds.
func TestServiceBindTargetInvalid(t *testing.T) {
	for _, field := range []string{"service_name", "kind"} {
		t.Run(field, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			r := wire.ServiceBind{OperationID: "invalid-target", ServiceBinding: f.a.binding}
			if field == "service_name" {
				r.Service = "other-service"
			} else {
				r.Kind = "other-kind"
			}
			before, err := f.custody.LoadServiceState()
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.metadata(t, f.operator, "service.bind", r)
			refused(t, err, "bind_target_invalid")
			after, err := f.custody.LoadServiceState()
			if err != nil || !reflect.DeepEqual(before, after) || len(f.b.bindings) != 0 || f.custody.entries != 0 {
				t.Fatal("invalid bind changed state or entered custody")
			}
			f.bind(t)
			f.issue(t)
		})
	}
}

// Untyped identity-reader failure is section 2.2 principal_ledger_mismatch,
// including the bind replay preflight. No callback, journal write or custody
// entry occurs; restoring only that reader admits the identical valid call.
func TestServiceIdentityReaderRefusals(t *testing.T) {
	for _, method := range []string{"service.bind", "service.unbind", "account.hold", "account.hold.lift", "service.lease.release", "event.report"} {
		t.Run(method, func(t *testing.T) {
			f := newBrokerFixture(t, nil)
			f.bind(t)
			l := f.issue(t)
			uid := f.uid
			var params any
			switch method {
			case "service.bind":
				uid = f.operator
				// Replaying the original successful bind remains identity-gated.
				s := f.b.bindings[f.b.leases[l.LeaseID].BindingID]
				params = wire.ServiceBind{OperationID: s.OperationID, ServiceBinding: s.Binding()}
			case "service.unbind":
				uid = f.operator
				params = wire.ServiceUnbind{OperationID: "unbind-reader", BindingID: f.b.leases[l.LeaseID].BindingID}
			case "account.hold":
				params = wire.ServiceHold{OperationID: "hold-reader", LeaseID: l.LeaseID, Account: fixtureAccount, Reason: "leak_match"}
			case "account.hold.lift":
				if err := hold(t, f, l.LeaseID); err != nil {
					t.Fatal(err)
				}
				uid = f.owner
				params = wire.ServiceLift{OperationID: "lift-reader", HoldID: f.b.held(fixtureAccount).ID, Account: fixtureAccount}
			case "service.lease.release":
				params = wire.ServiceLeaseID{LeaseID: l.LeaseID}
			case "event.report":
				params = map[string]any{"service_lease_id": l.LeaseID, "event": map[string]any{"kind": "credential_error", "class": "auth"}}
			}
			p, err := f.b.Open(context.Background(), uid)
			if err != nil {
				t.Fatal(err)
			}
			before, err := f.custody.LoadServiceState()
			if err != nil {
				t.Fatal(err)
			}
			entries, callbacks := f.custody.entries, 0
			publish := func(v any) error {
				callbacks++
				noMaterial(t, encode(t, v))
				return nil
			}
			f.b.authority = pollIdentityFailure{f.a}
			err = f.b.Call(context.Background(), p, method, encode(t, params), publish)
			refused(t, err, "principal_ledger_mismatch")
			after, err := f.custody.LoadServiceState()
			if err != nil || !reflect.DeepEqual(before, after) || f.custody.entries != entries || callbacks != 0 {
				t.Fatal("unreadable identity changed state or published")
			}
			f.b.authority = f.a
			if err = f.b.Call(context.Background(), p, method, encode(t, params), publish); err != nil || callbacks != 1 {
				t.Fatal("restored identity control failed", err)
			}
		})
	}
}
