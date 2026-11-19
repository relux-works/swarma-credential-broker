package statev0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const journalAccount = "fixture/claude/subscription"

type memoryServiceRecords struct {
	data       []byte
	writes     int
	fault      bool
	writeFault bool
}

func (records *memoryServiceRecords) ReadService() ([]byte, error) {
	if len(records.data) == 0 || records.fault {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), records.data...), nil
}

func (records *memoryServiceRecords) CreateService(state ServiceStateV2) error {
	if len(records.data) != 0 {
		return ErrConflict
	}
	if records.fault || records.writeFault {
		return ErrUnavailable
	}
	records.data, _ = wire.Encode(state)
	records.writes++
	return nil
}

func (records *memoryServiceRecords) CommitService(prior uint64, state ServiceStateV2) error {
	var previous ServiceStateV2
	if records.fault || records.writeFault {
		return ErrUnavailable
	}
	if wire.Decode(records.data, &previous) != nil || previous.Revision != prior {
		return ErrConflict
	}
	records.data, _ = wire.Encode(state)
	records.writes++
	return nil
}

func serviceFixture(test *testing.T, name string) ServiceStateV2 {
	test.Helper()
	data, err := os.ReadFile("testdata/construction-v0/service-" + name + ".json")
	var state ServiceStateV2
	if err != nil || wire.Decode(data, &state) != nil {
		test.Fatal("cannot load landed service vector", err)
	}
	return state
}

func completeServiceVector(test *testing.T, name string) ServiceStateV2 {
	test.Helper()
	state := serviceFixture(test, "utc")
	operation := state.Operations[0]
	var arguments wire.ServiceBind
	var result struct {
		ID string `json:"service_binding_id"`
	}
	if json.Unmarshal(operation.Arguments, &arguments) != nil || json.Unmarshal(operation.Result, &result) != nil {
		test.Fatal("cannot construct records for exact operation vector")
	}
	binding := wire.ServiceBindingRecord{ID: result.ID, Service: arguments.Service, UID: arguments.UID, Generation: arguments.Generation, Account: arguments.Account, Kind: arguments.Kind, PolicyDigest: arguments.PolicyDigest, CreatedBy: operation.Principal, OperationID: arguments.OperationID, CreatedAt: state.Watermark, State: "active"}
	if name == "boottime" {
		removal := serviceFixture(test, "boottime").Operations[0]
		id := string(removal.OperationID)
		binding.State, binding.RemovedOperationID, binding.RemovedAt = "removed", &id, &state.Watermark
		state.Operations = append(state.Operations, removal)
	}
	state.Bindings = append(state.Bindings, binding)
	return state
}

func serviceTestJournal(test *testing.T, state ServiceStateV2) (*SerialGate, *Journal, *memoryServiceRecords) {
	test.Helper()
	gate := NewGate()
	records := &memoryServiceRecords{}
	pin := serviceFixture(test, "utc").Operations[0].Receipt.TerminalCaller
	journal, err := NewServiceJournal(gate, "fixture-installation-v0", map[string]ServiceRecords{journalAccount: records}, []assemblyv0.PrincipalPin{pin})
	if err != nil {
		test.Fatal(err)
	}
	if state.Kind != "" {
		records.data, err = wire.Encode(state)
		if err != nil {
			test.Fatal(err)
		}
		if err := gate.With(context.Background(), func(tx *Tx) error { return journal.ReconcileLocked(tx, journalAccount) }); err != nil {
			test.Fatal("valid existing service journal did not reconcile", err)
		}
		records.writes = 0
	}
	return gate, journal, records
}

func loadService(test *testing.T, journal *Journal, tx *Tx) ServiceStateV2 {
	test.Helper()
	state, err := journal.LoadLocked(tx, journalAccount)
	if err != nil {
		test.Fatal(err)
	}
	return state
}

func cloneService(test *testing.T, state ServiceStateV2) ServiceStateV2 {
	test.Helper()
	data, err := wire.Encode(state)
	var copied ServiceStateV2
	if err != nil || wire.Decode(data, &copied) != nil {
		test.Fatal("cannot clone control", err)
	}
	return copied
}

// Claim: both exact landed operation/receipt vectors survive in coherent record histories after durable reconciliation; /1, extra/missing members, malformed receipts, unknown intents and noncanonical bytes never become empty or successful state.
func TestServiceJournalVersion(test *testing.T) {
	for _, name := range []string{"utc", "boottime"} {
		test.Run(name, func(test *testing.T) {
			control := completeServiceVector(test, name)
			gate, journal, records := serviceTestJournal(test, control)
			if err := gate.With(context.Background(), func(tx *Tx) error {
				loaded := loadService(test, journal, tx)
				if !same(loaded.Operations, control.Operations) {
					test.Fatal("version-aware load changed receipt or nullable time")
				}
				return nil
			}); err != nil {
				test.Fatal(err)
			}
			valid := append([]byte(nil), records.data...)
			for _, entry := range []struct{ name, old, new string }{
				{"legacy", ServiceJournalKind, "claude-service-journal/1"},
				{"future", ServiceJournalKind, "claude-service-journal/3"},
				{"unknown-member", `"bindings":`, `"unknown":true,"bindings":`},
				{"missing-receipt", `,"receipt":{`, `,"omitted_receipt":{`},
				{"null-receipt", `"receipt":{`, `"receipt":null,"extra":{`},
				{"unknown-intent", `"method":"service.`, `"method":"intent.service.`},
				{"wrong-installation", `fixture-installation-v0`, `other-installation`},
				{"invalid-pin", `/var/empty/fixture-person`, `relative/fixture-person`},
				{"duplicate-member", `"revision":2`, `"revision":2,"revision":2`},
				{"noncanonical", `"bindings":`, `"bindings" :`},
			} {
				test.Run(entry.name, func(test *testing.T) {
					records.data = bytes.Replace(valid, []byte(entry.old), []byte(entry.new), 1)
					if bytes.Equal(records.data, valid) {
						test.Fatal("negative fixture did not apply")
					}
					before := append([]byte(nil), records.data...)
					err := gate.With(context.Background(), func(tx *Tx) error {
						_, err := journal.LoadLocked(tx, journalAccount)
						return err
					})
					if !errors.Is(err, ErrUnavailable) || records.writes != 0 || !bytes.Equal(before, records.data) {
						test.Fatal("invalid journal was adopted or mutated", err)
					}
					err = gate.With(context.Background(), func(tx *Tx) error { return journal.ReconcileLocked(tx, journalAccount) })
					if !errors.Is(err, ErrUnavailable) || records.writes != 0 || !bytes.Equal(before, records.data) {
						test.Fatal("invalid journal reconciled or mutated", err)
					}
				})
			}
		})
	}
}

// Claim: reads/commits do not initialize missing state; explicit empty fresh initialization succeeds once, and an existing /1 or /2 cannot be overwritten by initialization. Enrollment-intent authority remains U19.
func TestEnrollmentServiceJournalInitialization(test *testing.T) {
	gate, journal, records := serviceTestJournal(test, ServiceStateV2{})
	empty := journalControls(test)["service-empty"].(ServiceStateV2)
	if err := gate.With(context.Background(), func(tx *Tx) error {
		if _, err := journal.LoadLocked(tx, journalAccount); !errors.Is(err, ErrUnavailable) {
			test.Fatal("missing state became empty", err)
		}
		if err := journal.CommitLocked(tx, journalAccount, 0, empty); !errors.Is(err, ErrUnavailable) {
			test.Fatal("ordinary commit initialized missing state", err)
		}
		if records.writes != 0 {
			test.Fatal("missing state had a write")
		}
		if err := journal.InitializeLocked(tx, journalAccount, empty); err != nil {
			return err
		}
		before := append([]byte(nil), records.data...)
		if err := journal.InitializeLocked(tx, journalAccount, empty); !errors.Is(err, ErrConflict) || !bytes.Equal(before, records.data) {
			test.Fatal("repeat initialization overwrote history", err)
		}
		loadService(test, journal, tx)
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	for _, kind := range []string{"claude-service-journal/1", ServiceJournalKind} {
		gate, journal, records := serviceTestJournal(test, ServiceStateV2{})
		state := empty
		state.Kind = kind
		records.data, _ = wire.Encode(state)
		before := append([]byte(nil), records.data...)
		err := gate.With(context.Background(), func(tx *Tx) error { return journal.InitializeLocked(tx, journalAccount, empty) })
		if !errors.Is(err, ErrConflict) || records.writes != 0 || !bytes.Equal(before, records.data) {
			test.Fatal("existing journal was adopted", kind, err)
		}
	}
}

// Claim: equal committed retries return the original complete result without writes; unequal arguments, duplicate outcomes, result extension/rewrite and unknown outcomes refuse without changing retained evidence.
func TestCommittedServiceRetry(test *testing.T) {
	control := completeServiceVector(test, "utc")
	gate, journal, records := serviceTestJournal(test, control)
	if err := gate.With(context.Background(), func(tx *Tx) error {
		operation := control.Operations[0]
		replayed, err := journal.ReplayLocked(tx, journalAccount, operation.Principal, operation.Method, operation.OperationID, operation.Arguments)
		if err != nil || replayed == nil || !same(*replayed, operation) || records.writes != 0 {
			test.Fatal("equal retry did not return original durable outcome", err)
		}
		unequal := bytes.Replace(operation.Arguments, []byte(`"uid":4005`), []byte(`"uid":4006`), 1)
		if _, err := journal.ReplayLocked(tx, journalAccount, operation.Principal, operation.Method, operation.OperationID, unequal); !errors.Is(err, ErrConflict) {
			test.Fatal("unequal committed retry did not conflict", err)
		}
		prior := loadService(test, journal, tx)
		before := append([]byte(nil), records.data...)
		for _, change := range []func(*ServiceStateV2){
			func(state *ServiceStateV2) { state.Operations = append(state.Operations, state.Operations[0]) },
			func(state *ServiceStateV2) { state.Operations = []ServiceOperationV2{} },
			func(state *ServiceStateV2) { state.Operations[0].Result = []byte(`{"state":"active"}`) },
			func(state *ServiceStateV2) {
				state.Operations[0].Result = bytes.Replace(state.Operations[0].Result, []byte(`11223344556677889900aabbccddeeff`), []byte(`ffeeddccbbaa00998877665544332211`), 1)
			},
			func(state *ServiceStateV2) { state.Operations[0].Receipt.Nonce = "ffeeddccbbaa00998877665544332211" },
			func(state *ServiceStateV2) { state.Operations[0].Method = "service.unknown.intent" },
		} {
			next := cloneService(test, prior)
			next.Revision++
			change(&next)
			if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); !errors.Is(err, ErrConflict) || !bytes.Equal(before, records.data) || records.writes != 0 {
				test.Fatal("retry evidence changed on refusal", err)
			}
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
}

func recordControl(test *testing.T) ServiceStateV2 {
	test.Helper()
	state := serviceFixture(test, "utc")
	operation := state.Operations[0]
	at := *operation.At
	state.Operations = []ServiceOperationV2{}
	for index := range 2 {
		binding := wire.ServiceBindingRecord{ID: fmt.Sprintf("%032x", index+10), Service: "credential-gateway", UID: uint32(index + 4005), Generation: fmt.Sprintf("%032x", index+20), Account: journalAccount, Kind: "claude-oauth-token", PolicyDigest: "sha256:" + strings.Repeat("a", 64), CreatedBy: operation.Principal, OperationID: fmt.Sprintf("%032x", index+30), CreatedAt: at, State: "active"}
		state.Bindings = append(state.Bindings, binding)
		lease := wire.ServiceLeaseRecord{ID: fmt.Sprintf("%032x", index+40), BindingID: binding.ID, Service: binding.Service, UID: binding.UID, Generation: binding.Generation, Account: journalAccount, Harness: "claude_code", Kind: binding.Kind, AgentUID: 4010, AgentGeneration: strings.Repeat("b", 32), AgentBindingID: strings.Repeat("c", 32), LaunchID: strings.Repeat("d", 32), OperationID: fmt.Sprintf("%032x", index+50), Until: at.Add(300 * time.Second), State: "active"}
		state.Leases = append(state.Leases, lease)
		bind := serviceFixture(test, "utc").Operations[0]
		bind.OperationID = assemblyv0.OperationID(binding.OperationID)
		bind.Receipt.Nonce = assemblyv0.Nonce(fmt.Sprintf("%032x", index+70))
		bind.Arguments, _ = wire.Encode(wire.ServiceBind{OperationID: binding.OperationID, ServiceBinding: binding.Binding()})
		bind.Result, _ = wire.Encode(map[string]any{"service_binding_id": binding.ID, "service_name": binding.Service, "uid": binding.UID, "service_generation": binding.Generation, "account": binding.Account, "kind": binding.Kind, "installation_policy_digest": binding.PolicyDigest, "state": "active"})
		request, _ := wire.Encode(wire.ServiceRequest{OperationID: lease.OperationID, ServiceCaller: lease.Caller()})
		result, _ := wire.Encode(map[string]any{"service_lease_id": lease.ID, "authorized_until": lease.Until})
		state.Operations = append(state.Operations, bind, ServiceOperationV2{Principal: servicePrincipal(lease.UID, lease.Generation), Method: "service.lease.request", OperationID: assemblyv0.OperationID(lease.OperationID), Arguments: request, Result: result, At: &at})
	}
	return state
}

func historyOperation(test *testing.T, index int) ServiceOperationV2 {
	test.Helper()
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	leaseID := fmt.Sprintf("%032x", 40)
	arguments, err := wire.Encode(map[string]any{"service_lease_id": leaseID, "event": map[string]any{"kind": "error", "class": "unknown"}})
	result, resultErr := wire.Encode(map[string]any{"service_lease_id": leaseID, "state": "active"})
	if err != nil || resultErr != nil {
		test.Fatal(err, resultErr)
	}
	return ServiceOperationV2{Principal: fmt.Sprintf("4005:%032x:service:credential-gateway", 20), Method: "event.report", OperationID: assemblyv0.OperationID(fmt.Sprintf("%032x", index+1000)), Arguments: arguments, Result: result, At: &at}
}

func fullRecordControl(test *testing.T) ServiceStateV2 {
	test.Helper()
	state := recordControl(test)
	_, journal, _ := serviceTestJournal(test, state)
	sample, _ := wire.Encode(historyOperation(test, 0))
	upper := MaxServiceJournalBytes/len(sample) + 1
	for index := range upper {
		state.Operations = append(state.Operations, historyOperation(test, index))
	}
	operations := state.Operations
	lower := 1
	upper = len(operations)
	for lower < upper {
		middle := (lower + upper + 1) / 2
		state.Operations = operations[:middle]
		reserved, err := journal.reservedState(state)
		if err == nil && len(reserved) <= MaxServiceJournalBytes {
			lower = middle
		} else {
			upper = middle - 1
		}
	}
	state.Operations = operations[:lower]
	data, _ := wire.Encode(state)
	reserved, _ := journal.reservedState(state)
	if len(data) < 1000000 || len(reserved) > MaxServiceJournalBytes || journal.reserve(state) != nil {
		test.Fatal("full-record positive control did not exercise real bounded history", len(data), len(reserved))
	}
	test.Logf("full record: stored=%d reserved=%d limit=%d operations=%d bindings=%d leases=%d", len(data), len(reserved), MaxServiceJournalBytes, len(state.Operations), len(state.Bindings), len(state.Leases))
	return state
}

func removeBinding(test *testing.T, state *ServiceStateV2, index int) {
	test.Helper()
	operation := serviceFixture(test, "boottime").Operations[0]
	operation.OperationID = assemblyv0.OperationID(fmt.Sprintf("%032x", index+50000))
	operation.Receipt.Nonce = assemblyv0.Nonce(fmt.Sprintf("%032x", index+60000))
	binding := &state.Bindings[index]
	id := string(operation.OperationID)
	binding.State, binding.RemovedOperationID, binding.RemovedAt = "removed", &id, &state.Watermark
	operation.Arguments, _ = wire.Encode(wire.ServiceUnbind{OperationID: id, BindingID: binding.ID})
	operation.Result, _ = wire.Encode(map[string]any{"service_binding_id": binding.ID, "state": "removed"})
	state.Operations = append(state.Operations, operation)
}

func placeHold(test *testing.T, state *ServiceStateV2) {
	test.Helper()
	lease := state.Leases[0]
	id := strings.Repeat("e", 32)
	hold := wire.AccountHoldRecord{ID: strings.Repeat("f", 32), Account: journalAccount, Reason: "leak_match", Service: lease.Service, UID: lease.UID, Generation: lease.Generation, BindingID: lease.BindingID, LeaseID: lease.ID, OperationID: id, PlacedAt: state.Watermark, State: "active"}
	arguments, _ := wire.Encode(wire.ServiceHold{OperationID: id, LeaseID: lease.ID, Account: journalAccount, Reason: "leak_match"})
	result, _ := wire.Encode(hold.Metadata())
	state.Holds = append(state.Holds, hold)
	state.Operations = append(state.Operations, ServiceOperationV2{Principal: "4005:" + lease.Generation + ":service:credential-gateway", Method: "account.hold", OperationID: assemblyv0.OperationID(id), Arguments: arguments, Result: result, At: &state.Watermark})
}

// Claim: a near-1-MiB journal with bindings, leases and retained outcomes refuses widening before a write, while every reserved BOOTTIME removal and a full eligible hold commit without eviction. PL-SERVICE-RESERVE must fail this full-record control.
func TestServiceNarrowingReserveFullRecord(test *testing.T) {
	control := fullRecordControl(test)
	gate, journal, records := serviceTestJournal(test, control)
	if err := gate.With(context.Background(), func(tx *Tx) error {
		prior := loadService(test, journal, tx)
		wider := cloneService(test, prior)
		wider.Revision++
		binding := wider.Bindings[0]
		binding.ID, binding.Generation, binding.OperationID = strings.Repeat("9", 32), strings.Repeat("8", 32), strings.Repeat("7", 32)
		wider.Bindings = append(wider.Bindings, binding)
		bind := serviceFixture(test, "utc").Operations[0]
		bind.OperationID = assemblyv0.OperationID(binding.OperationID)
		bind.Arguments, _ = wire.Encode(wire.ServiceBind{OperationID: binding.OperationID, ServiceBinding: binding.Binding()})
		bind.Result, _ = wire.Encode(map[string]any{"service_binding_id": binding.ID, "service_name": binding.Service, "uid": binding.UID, "service_generation": binding.Generation, "account": binding.Account, "kind": binding.Kind, "installation_policy_digest": binding.PolicyDigest, "state": "active"})
		wider.Operations = append(wider.Operations, bind)
		before := append([]byte(nil), records.data...)
		data, _ := wire.Encode(wider)
		if len(data) > MaxServiceJournalBytes {
			test.Fatal("negative control only tests plain size, not the reservation", len(data))
		}
		if err := journal.ReserveLocked(tx, journalAccount, wider); !errors.Is(err, ErrCapacity) {
			test.Fatal("widening consumed reserved removal/hold bytes", err)
		}
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, wider); !errors.Is(err, ErrCapacity) || records.writes != 0 || !bytes.Equal(before, records.data) {
			test.Fatal("widening mutated before reserve admission", err)
		}
		for index := range prior.Bindings {
			next := cloneService(test, prior)
			next.Revision++
			removeBinding(test, &next, index)
			if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); err != nil {
				test.Fatal("pre-reserved full-record unbind failed", index, err)
			}
			prior = loadService(test, journal, tx)
		}
		next := cloneService(test, prior)
		next.Revision++
		placeHold(test, &next)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); err != nil {
			test.Fatal("pre-reserved full-record hold failed", err)
		}
		loaded := loadService(test, journal, tx)
		if !same(control.Operations, loaded.Operations[:len(control.Operations)]) || len(loaded.Holds) != 1 || loaded.Holds[0].State != "active" || !loaded.Watermark.Equal(control.Watermark) {
			test.Fatal("narrowing evicted evidence, cleared hold, or advanced an untrusted watermark")
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
}

// Claim: missing/unreadable own state, stale CAS, failed publication, evidence eviction and watermark changes on at:null never acknowledge narrowing; the same removal succeeds with healthy own state.
func TestServiceNarrowingOwnState(test *testing.T) {
	gate, journal, records := serviceTestJournal(test, recordControl(test))
	if err := gate.With(context.Background(), func(tx *Tx) error {
		prior := loadService(test, journal, tx)
		next := cloneService(test, prior)
		next.Revision++
		removeBinding(test, &next, 0)
		before := append([]byte(nil), records.data...)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision-1, next); !errors.Is(err, ErrConflict) {
			test.Fatal("stale revision succeeded", err)
		}
		for _, missing := range []bool{false, true} {
			if missing {
				records.data = nil
			} else {
				records.fault = true
			}
			if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); !errors.Is(err, ErrUnavailable) || records.writes != 0 {
				test.Fatal("own-state loss acknowledged narrowing", err)
			}
			records.data, records.fault = append([]byte(nil), before...), false
		}
		bad := cloneService(test, next)
		bad.Watermark = bad.Watermark.Add(time.Second)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, bad); !errors.Is(err, ErrConflict) {
			test.Fatal("at:null advanced wall-time watermark", err)
		}
		bad = cloneService(test, next)
		bad.Operations = bad.Operations[:len(bad.Operations)-1]
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, bad); !errors.Is(err, ErrConflict) {
			test.Fatal("removal without retained outcome was acknowledged", err)
		}
		if !bytes.Equal(before, records.data) || records.writes != 0 {
			test.Fatal("negative controls changed state")
		}
		return journal.CommitLocked(tx, journalAccount, prior.Revision, next)
	}); err != nil {
		test.Fatal("healthy same narrowing refused", err)
	}
}

// Claim: closed historical method/receipt/record neighbors refuse without writes beside a healthy protected journal; these checks validate stored shapes, not current principal or time authority.
func TestServiceJournalSemanticRefusals(test *testing.T) {
	for _, entry := range []struct {
		name   string
		change func(*ServiceStateV2)
	}{
		{"widening-null-time", func(state *ServiceStateV2) { state.Operations[0].At = nil }},
		{"operator-null-receipt", func(state *ServiceStateV2) { state.Operations[0].Receipt = nil }},
		{"duplicate-outcome", func(state *ServiceStateV2) { state.Operations = append(state.Operations, state.Operations[0]) }},
		{"wrong-result-state", func(state *ServiceStateV2) {
			state.Operations[0].Result = bytes.Replace(state.Operations[0].Result, []byte(`"state":"active"`), []byte(`"state":"removed"`), 1)
		}},
		{"result-token-extension", func(state *ServiceStateV2) {
			state.Operations[0].Result = bytes.Replace(state.Operations[0].Result, []byte(`{`), []byte(`{"token":"inert-forbidden",`), 1)
		}},
		{"wrong-inner-id", func(state *ServiceStateV2) {
			state.Operations[0].Arguments = bytes.Replace(state.Operations[0].Arguments, []byte(state.Operations[0].OperationID), []byte(`ffeeddccbbaa99887766554433221100`), 1)
		}},
		{"wide-boottime", func(state *ServiceStateV2) {
			state.Operations[0].Receipt.Freshness = assemblyv0.BoottimeFreshness{Kind: "boottime", BootID: state.Operations[0].Receipt.BootID, NotBeforeMS: 1000, ExpiresAtMS: 301000}
		}},
		{"overlong-utc", func(state *ServiceStateV2) {
			state.Operations[0].Receipt.Freshness = assemblyv0.UTCFreshness{Kind: "utc", NotBefore: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T00:05:01Z"}
		}},
		{"zero-peer", func(state *ServiceStateV2) { state.Operations[0].Receipt.PeerPID = 0 }},
		{"wrong-boot-shape", func(state *ServiceStateV2) { state.Operations[0].Receipt.BootID = strings.Repeat("z", 36) }},
		{"revision-zero", func(state *ServiceStateV2) { state.Revision = 0 }},
		{"binding-duplicate", func(state *ServiceStateV2) { state.Bindings = append(state.Bindings, state.Bindings[0]) }},
		{"binding-missing-outcome", func(state *ServiceStateV2) { state.Operations = state.Operations[1:] }},
		{"invalid-policy-digest", func(state *ServiceStateV2) { state.Bindings[0].PolicyDigest = "not-a-digest" }},
		{"lease-other-binding", func(state *ServiceStateV2) { state.Leases[0].BindingID = state.Bindings[1].ID }},
		{"lease-other-account", func(state *ServiceStateV2) { state.Leases[0].Account = "fixture/other" }},
		{"lease-revived-state", func(state *ServiceStateV2) { state.Leases[0].State = "pending" }},
	} {
		test.Run(entry.name, func(test *testing.T) {
			control := recordControl(test)
			gate, journal, records := serviceTestJournal(test, control)
			entry.change(&control)
			data, err := wire.Encode(control)
			if err != nil {
				test.Fatal("negative setup did not reach storage", err)
			}
			records.data = data
			err = gate.With(context.Background(), func(tx *Tx) error { _, err := journal.LoadLocked(tx, journalAccount); return err })
			if !errors.Is(err, ErrUnavailable) || records.writes != 0 || !bytes.Equal(data, records.data) {
				test.Fatal("invalid stored neighbor admitted or mutated", err)
			}
		})
	}
}

// Claim: narrowing cannot erase or clear retained holds, leases, receipts or revision/time evidence; the same healthy removal retains the active hold and its original outcome.
func TestServiceNarrowingPreservesHold(test *testing.T) {
	control := recordControl(test)
	placeHold(test, &control)
	gate, journal, records := serviceTestJournal(test, control)
	if err := gate.With(context.Background(), func(tx *Tx) error {
		prior := loadService(test, journal, tx)
		for _, change := range []func(*ServiceStateV2){
			func(state *ServiceStateV2) { state.Holds = []wire.AccountHoldRecord{} },
			func(state *ServiceStateV2) { state.Leases = []wire.ServiceLeaseRecord{} },
			func(state *ServiceStateV2) { state.Operations = []ServiceOperationV2{} },
			func(state *ServiceStateV2) { state.Revision = 1 },
			func(state *ServiceStateV2) { state.Watermark = state.Watermark.Add(-time.Second) },
		} {
			next := cloneService(test, prior)
			narrowingRevision := prior.Revision + 1
			next.Revision = narrowingRevision
			removeBinding(test, &next, 0)
			change(&next)
			if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); !errors.Is(err, ErrConflict) || records.writes != 0 {
				test.Fatal("narrowing lost retained hold/history or reset evidence", err)
			}
		}
		next := cloneService(test, prior)
		next.Revision++
		removeBinding(test, &next, 0)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); err != nil {
			return err
		}
		loaded := loadService(test, journal, tx)
		if !same(prior.Holds, loaded.Holds) || !same(prior.Operations, loaded.Operations[:len(prior.Operations)]) {
			test.Fatal("healthy narrowing did not preserve hold and replay evidence")
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
}

// Claim: a current terminal pin change does not invalidate a retained historical receipt or make own-state narrowing depend on authority history; only a newly supplied receipt must fit the configured construction pins.
func TestServiceHistoricalReceiptPin(test *testing.T) {
	state := recordControl(test)
	gate, _, records := serviceTestJournal(test, state)
	current := state.Operations[0].Receipt.TerminalCaller
	current.Name, current.Home = "fixture-successor", "/var/empty/fixture-successor"
	journal, err := NewServiceJournal(gate, state.InstallationID, map[string]ServiceRecords{journalAccount: records}, []assemblyv0.PrincipalPin{current})
	if err != nil {
		test.Fatal(err)
	}
	if err := gate.With(context.Background(), func(tx *Tx) error {
		if err := journal.ReconcileLocked(tx, journalAccount); err != nil {
			return err
		}
		prior := loadService(test, journal, tx)
		next := cloneService(test, prior)
		next.Revision++
		removeBinding(test, &next, 0)
		if err := journal.CommitLocked(tx, journalAccount, prior.Revision, next); !errors.Is(err, ErrConflict) {
			test.Fatal("new receipt escaped configured reservation pins", err)
		}
		next.Operations[len(next.Operations)-1].Receipt.TerminalCaller = current
		return journal.CommitLocked(tx, journalAccount, prior.Revision, next)
	}); err != nil {
		test.Fatal("historical receipt blocked healthy current narrowing", err)
	}
}

// Claim: uncertainty fences only the affected account, preserves its exact bytes, and requires explicit reconciliation; an independent healthy account still commits through the same shared gate.
func TestServiceJournalAccountIsolation(test *testing.T) {
	gate, firstJournal, bad := serviceTestJournal(test, recordControl(test))
	good := &memoryServiceRecords{}
	other := "fixture/claude/other"
	journal, err := NewServiceJournal(gate, firstJournal.installation, map[string]ServiceRecords{journalAccount: bad, other: good}, firstJournal.callers)
	if err != nil {
		test.Fatal(err)
	}
	if err := gate.With(context.Background(), func(tx *Tx) error {
		if err := journal.ReconcileLocked(tx, journalAccount); err != nil {
			return err
		}
		empty := journalControls(test)["service-empty"].(ServiceStateV2)
		if err := journal.InitializeLocked(tx, other, empty); err != nil {
			return err
		}
		state := loadService(test, journal, tx)
		prior := state.Revision
		state.Revision++
		removeBinding(test, &state, 0)
		before := append([]byte(nil), bad.data...)
		bad.writeFault = true
		if err := journal.CommitLocked(tx, journalAccount, prior, state); !errors.Is(err, ErrUnavailable) || !bytes.Equal(before, bad.data) {
			test.Fatal("uncertain publication acknowledged or changed bytes", err)
		}
		bad.writeFault = false
		if _, err := journal.LoadLocked(tx, journalAccount); !errors.Is(err, ErrUnavailable) {
			test.Fatal("uncertain account reopened without reconciliation", err)
		}
		goodState, err := journal.LoadLocked(tx, other)
		if err != nil {
			return err
		}
		goodState.Revision++
		if err := journal.CommitLocked(tx, other, goodState.Revision-1, goodState); err != nil {
			return err
		}
		return journal.ReconcileLocked(tx, journalAccount)
	}); err != nil {
		test.Fatal("independent account or healthy reconciliation refused", err)
	}
}

// Claim: the complete reserve includes the longest unchanged terminal lease-state encoding, not the shorter revoked/expired encodings; this is a byte bound, not a new lease-release operation reserve.
func TestServiceReserveTerminalWidth(test *testing.T) {
	control := recordControl(test)
	_, journal, _ := serviceTestJournal(test, control)
	data, err := journal.reservedState(control)
	var reserved ServiceStateV2
	if err != nil || wire.Decode(data, &reserved) != nil {
		test.Fatal("complete reserve control could not decode", err)
	}
	for index, lease := range control.Leases {
		bound, err := wire.Encode(reserved.Leases[index])
		if err != nil {
			test.Fatal(err)
		}
		for _, terminal := range []string{"released", "expired", "revoked"} {
			lease.State = terminal
			encoded, err := wire.Encode(lease)
			if err != nil || len(bound) < len(encoded) {
				test.Fatal("reserve undercounts a closed terminal lease state", terminal, len(bound), len(encoded), err)
			}
		}
	}
}
