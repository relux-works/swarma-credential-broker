package statev0

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the serialized reserve bounds a valid retained removal, terminal lease and hold with maximal escaped strings, numeric fields, timestamps and the largest configured receipt pin. This is a bounded closed-format witness, not runtime authorization.
func TestServiceNarrowingReserveMaximality(test *testing.T) {
	state := recordControl(test)
	state.Bindings, state.Leases, state.Operations = state.Bindings[:1], state.Leases[:1], state.Operations[:2]
	text := strings.Repeat("\x01", 128)
	identifier := strings.Repeat("f", 32)
	at := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	operator := "4294967295:" + text + ":operator:"
	service := "4294967295:" + text + ":service:credential-gateway"
	binding, lease := &state.Bindings[0], &state.Leases[0]
	binding.ID, binding.Generation, binding.UID = text, text, ^uint32(0)
	binding.CreatedBy = operator
	lease.ID, lease.BindingID, lease.Generation, lease.UID = text, text, text, ^uint32(0)
	bind := &state.Operations[0]
	bind.Principal = operator
	bind.Arguments, _ = wire.Encode(wire.ServiceBind{OperationID: binding.OperationID, ServiceBinding: binding.Binding()})
	bind.Result, _ = wire.Encode(map[string]any{"service_binding_id": binding.ID, "service_name": binding.Service, "uid": binding.UID, "service_generation": binding.Generation, "account": binding.Account, "kind": binding.Kind, "installation_policy_digest": binding.PolicyDigest, "state": "active"})
	request := &state.Operations[1]
	request.Principal = service
	request.Arguments, _ = wire.Encode(wire.ServiceRequest{OperationID: lease.OperationID, ServiceCaller: lease.Caller()})
	request.Result, _ = wire.Encode(map[string]any{"service_lease_id": lease.ID, "authorized_until": lease.Until})
	_, journal, _ := serviceTestJournal(test, ServiceStateV2{})
	pin := assemblyv0.PrincipalPin{UID: ^uint32(0), Name: text, Home: "/" + text}
	journal.callers = append(journal.callers, pin)
	if err := journal.valid(journalAccount, state); err != nil {
		test.Fatal("maximal active positive control is invalid", err)
	}
	reserved, err := journal.reservedState(state)
	if err != nil {
		test.Fatal(err)
	}
	next := cloneService(test, state)
	next.Revision, next.Watermark = assemblyv0.MaxSafeInteger, at
	next.Bindings[0].State, next.Bindings[0].RemovedOperationID, next.Bindings[0].RemovedAt = "removed", &identifier, &at
	next.Leases[0].State = "released"
	receipt := &OperationReceipt{
		Nonce: assemblyv0.Nonce(identifier), TerminalCaller: pin,
		BootID: "ffffffff-ffff-ffff-ffff-ffffffffffff", PeerPID: assemblyv0.MaxSafeInteger, PeerStartTicks: assemblyv0.MaxSafeInteger,
		Freshness: assemblyv0.BoottimeFreshness{Kind: "boottime", BootID: "ffffffff-ffff-ffff-ffff-ffffffffffff", NotBeforeMS: assemblyv0.MaxSafeInteger - 300000, ExpiresAtMS: assemblyv0.MaxSafeInteger},
	}
	arguments, _ := wire.Encode(wire.ServiceUnbind{OperationID: identifier, BindingID: text})
	result, _ := wire.Encode(map[string]any{"service_binding_id": text, "state": "removed"})
	next.Operations = append(next.Operations, ServiceOperationV2{Principal: operator, Method: "service.unbind", OperationID: assemblyv0.OperationID(identifier), Arguments: arguments, Result: result, At: &at, Receipt: receipt})
	hold := wire.AccountHoldRecord{ID: text, Account: journalAccount, Reason: "leak_match", Service: "credential-gateway", UID: ^uint32(0), Generation: text, BindingID: text, LeaseID: text, OperationID: identifier, PlacedAt: at, State: "active"}
	next.Holds = append(next.Holds, hold)
	arguments, _ = wire.Encode(wire.ServiceHold{OperationID: identifier, LeaseID: text, Account: journalAccount, Reason: "leak_match"})
	result, _ = wire.Encode(hold.Metadata())
	next.Operations = append(next.Operations, ServiceOperationV2{Principal: service, Method: "account.hold", OperationID: assemblyv0.OperationID(identifier), Arguments: arguments, Result: result, At: &at})
	if err := journal.valid(journalAccount, next); err != nil {
		test.Fatal("maximal narrowing positive control is invalid", err)
	}
	if _, err := retained(state, next); err != nil {
		test.Fatal("maximal narrowing lost retained evidence", err)
	}
	actual, err := wire.Encode(next)
	if err != nil || len(actual) > len(reserved) {
		test.Fatal("reserve underestimates maximal valid narrowing", len(actual), len(reserved), err)
	}
	test.Logf("maximal valid narrowing=%d reserved=%d", len(actual), len(reserved))
}

// Claim: at the widening ceiling an eligible hold commits before any unbind can free slack, preserving all bindings, leases and retained outcomes. Omitting hold headroom must fail this witness.
func TestServiceNarrowingHoldFirstAtCeiling(test *testing.T) {
	control := fullRecordControl(test)
	gate, journal, records := serviceTestJournal(test, control)
	if err := gate.With(context.Background(), func(tx *Tx) error {
		prior := loadService(test, journal, tx)
		next := cloneService(test, prior)
		next.Revision++
		placeHold(test, &next)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); err != nil {
			test.Fatal("eligible hold at widening ceiling refused before any unbind", err)
		}
		loaded := loadService(test, journal, tx)
		if !same(prior.Bindings, loaded.Bindings) || !same(prior.Leases, loaded.Leases) || !same(prior.Operations, loaded.Operations[:len(prior.Operations)]) || len(loaded.Holds) != 1 || loaded.Holds[0].State != "active" || records.writes != 1 {
			test.Fatal("hold-first commit evicted evidence or changed bindings/leases")
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
}
