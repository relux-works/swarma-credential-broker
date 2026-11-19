package statev0

import (
	"bytes"
	"context"
	"errors"
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

// Claim: after a durable hold and lift, the reserve ceiling still admits a new hold with a maximal escaped ID and timestamp without eviction; one extra history outcome refuses without a write. The same transitions below the ceiling are the valid control.
func TestServiceNarrowingHoldAfterLiftAtCeiling(test *testing.T) {
	for _, name := range []string{"below-ceiling", "reserve-ceiling"} {
		test.Run(name, func(test *testing.T) {
			gate, journal, records := serviceTestJournal(test, recordControl(test))
			if err := gate.With(context.Background(), func(tx *Tx) error {
				prior := loadService(test, journal, tx)
				held := cloneService(test, prior)
				held.Revision++
				placeHold(test, &held)
				if err := journal.CommitLocked(tx, journalAccount, prior.Revision, held); err != nil {
					test.Fatal("valid first hold did not commit", err)
				}
				prior = loadService(test, journal, tx)
				lifted := cloneService(test, prior)
				lifted.Revision++
				operation := serviceFixture(test, "utc").Operations[0]
				identifier := strings.Repeat("d", 32)
				at := lifted.Watermark
				hold := &lifted.Holds[0]
				hold.State, hold.LiftedBy, hold.LiftOperationID, hold.LiftedAt = "lifted", &operation.Principal, &identifier, &at
				operation.Method, operation.OperationID, operation.At = "account.hold.lift", assemblyv0.OperationID(identifier), &at
				operation.Receipt.Nonce = assemblyv0.Nonce(strings.Repeat("c", 32))
				operation.Arguments, _ = wire.Encode(wire.ServiceLift{OperationID: identifier, HoldID: hold.ID, Account: journalAccount})
				operation.Result, _ = wire.Encode(map[string]any{"hold_id": hold.ID, "account": journalAccount, "state": "lifted"})
				lifted.Operations = append(lifted.Operations, operation)
				if err := journal.CommitLocked(tx, journalAccount, prior.Revision, lifted); err != nil {
					test.Fatal("valid hold lift did not commit", err)
				}
				prior = loadService(test, journal, tx)
				if len(prior.Holds) != 1 || prior.Holds[0].State != "lifted" {
					test.Fatal("lifted hold was not durable")
				}
				if name == "reserve-ceiling" {
					full := cloneService(test, prior)
					full.Revision++
					baseCount := len(full.Operations)
					sample, err := wire.Encode(historyOperation(test, 0))
					if err != nil {
						test.Fatal(err)
					}
					for index := range MaxServiceJournalBytes/len(sample) + 1 {
						full.Operations = append(full.Operations, historyOperation(test, index))
					}
					operations := full.Operations
					lower, upper := baseCount, len(operations)
					for lower < upper {
						middle := (lower + upper + 1) / 2
						full.Operations = operations[:middle]
						if journal.reserve(full) == nil {
							lower = middle
						} else {
							upper = middle - 1
						}
					}
					full.Operations = operations[:lower]
					if err := journal.CommitLocked(tx, journalAccount, prior.Revision, full); err != nil {
						test.Fatal("valid full-record lifted hold did not commit", err)
					}
					prior = loadService(test, journal, tx)
					reserved, err := journal.reservedState(prior)
					if err != nil || len(records.data) < 1000000 || len(reserved) > MaxServiceJournalBytes {
						test.Fatal("lifted-hold control did not reach the reserve edge", len(records.data), len(reserved), err)
					}
					test.Logf("lifted hold at ceiling: stored=%d reserved=%d limit=%d", len(records.data), len(reserved), MaxServiceJournalBytes)
					overflow := cloneService(test, prior)
					overflow.Revision++
					overflow.Operations = append(overflow.Operations, historyOperation(test, len(prior.Operations)-baseCount))
					if err := journal.valid(journalAccount, overflow); err != nil {
						test.Fatal("overflow neighbor was not structurally valid", err)
					}
					before, writes := append([]byte(nil), records.data...), records.writes
					if err := journal.ReserveLocked(tx, journalAccount, overflow); !errors.Is(err, ErrCapacity) {
						test.Fatal("extra history outcome did not refuse at reserve preflight", err)
					}
					if err := journal.CommitLocked(tx, journalAccount, prior.Revision, overflow); !errors.Is(err, ErrCapacity) {
						test.Fatal("extra history outcome did not refuse at commit", err)
					}
					if records.writes != writes || !bytes.Equal(before, records.data) {
						test.Fatal("capacity refusal changed durable state")
					}
				}
				next := cloneService(test, prior)
				next.Revision++
				lease := next.Leases[1]
				identifier = strings.Repeat("b", 32)
				at = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
				next.Watermark = at
				nextHold := wire.AccountHoldRecord{ID: strings.Repeat("\x01", 128), Account: journalAccount, Reason: "leak_match", Service: lease.Service, UID: lease.UID, Generation: lease.Generation, BindingID: lease.BindingID, LeaseID: lease.ID, OperationID: identifier, PlacedAt: at, State: "active"}
				arguments, _ := wire.Encode(wire.ServiceHold{OperationID: identifier, LeaseID: lease.ID, Account: journalAccount, Reason: "leak_match"})
				result, _ := wire.Encode(nextHold.Metadata())
				next.Holds = append(next.Holds, nextHold)
				next.Operations = append(next.Operations, ServiceOperationV2{Principal: servicePrincipal(lease.UID, lease.Generation), Method: "account.hold", OperationID: assemblyv0.OperationID(identifier), Arguments: arguments, Result: result, At: &at})
				if err := journal.valid(journalAccount, next); err != nil {
					test.Fatal("hold after lift positive control is invalid", err)
				}
				writes := records.writes
				if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); err != nil {
					test.Fatal("hold after lift exceeded the reserve", err)
				}
				loaded := loadService(test, journal, tx)
				if records.writes != writes+1 || !same(next, loaded) || !same(prior.Bindings, loaded.Bindings) || !same(prior.Leases, loaded.Leases) || !same(prior.Holds, loaded.Holds[:len(prior.Holds)]) || !same(prior.Operations, loaded.Operations[:len(prior.Operations)]) {
					test.Fatal("hold after lift lost retained evidence or changed unrelated state")
				}
				return nil
			}); err != nil {
				test.Fatal(err)
			}
		})
	}
}
