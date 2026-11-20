//go:build linux && broker_lab

package labv0

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: a fresh terminal stop or invalidation pair publishes only its exact native narrowing result and stays fenced; wrong, missing, pending or moved evidence publishes nothing beside valid controls.
func TestLabObservationNarrowingPublicationPairs(test *testing.T) {
	for _, mode := range []string{"terminal-stop", "terminal-wrong-stop", "terminal-pending-stop", "terminal-missing", "terminal-final-mismatch", "terminal-invalidation", "terminal-wrong-invalidation"} {
		test.Run(mode, func(test *testing.T) {
			use, _, server, _ := continuedFixture(test, "terminal-stop")
			purpose := observationPurpose{kind: "stop", effectID: "fixture-stop-operation"}
			published := 0
			if use.publicationFor(context.Background(), purpose, func() error { published++; return nil }) != nil || published != 1 || use.current() == nil {
				test.Fatal("terminal stop control")
			}
			before, _ := object(use.record)
			server.setMode(mode, true)
			if strings.Contains(mode, "invalidation") {
				purpose = observationPurpose{kind: "invalidation", effectID: use.client.pins.start["operation_id"].(string)}
			}
			err := use.publicationFor(context.Background(), purpose, func() error { published++; return nil })
			valid := mode == "terminal-stop" || mode == "terminal-invalidation"
			if valid && (err != nil || published != 2 || use.record["floor"].(int64) <= before["floor"].(int64)) {
				test.Fatal("terminal valid control", err)
			}
			if !valid && (!errors.Is(err, ErrUnknown) || published != 1 || !labcontract.Equal(use.record, before)) {
				test.Fatal("invalid narrowing published", err)
			}
			if use.current() == nil {
				test.Fatal("narrowing resurrected use")
			}
		})
	}
}

// Claim: a pair in its mandatory cooldown holds no account lock; an actual existing-engine hold commits before that cooldown ends, fences immediately, and prevents the in-flight pair from publishing or losing the hold.
func TestLabObservationContainmentDoesNotQueue(test *testing.T) {
	use, fixture, server, _ := continuedFixture(test, "valid")
	fixture.start(test)
	fixture.bind(test)
	issued, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32)))
	if err != nil {
		test.Fatal(err)
	}
	lease := issued.(wire.ServiceLease)
	admitContinued(test, use)
	published := atomic.Int64{}
	result := make(chan error, 1)
	go func() {
		result <- use.publication(context.Background(), "start", func() error { published.Add(1); return nil })
	}()
	deadline := time.Now().Add(500 * time.Millisecond)
	for server.requests.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.requests.Load() != 3 {
		test.Fatal("pair did not enter its second cooldown")
	}
	started := time.Now()
	use.fence()
	_, err = fixture.call(test, 4101, "account.hold", wire.ServiceHold{OperationID: strings.Repeat("c", 32), LeaseID: lease.LeaseID, Account: accountLabel, Reason: "leak_match"})
	if err != nil || time.Since(started) >= 200*time.Millisecond {
		test.Fatal("hold queued behind native pair", err)
	}
	if err := <-result; !errors.Is(err, ErrUnknown) || published.Load() != 0 || use.current() == nil {
		test.Fatal("pair survived containment", err)
	}
	state, err := fixture.a.LoadServiceState()
	if err != nil || len(state.Holds) != 1 {
		test.Fatal("hold lost", err)
	}
}

func continuedFixture(test *testing.T, mode string) (*continuedUse, *labFixture, *observationFixtureServer, *atomic.Int64) {
	test.Helper()
	fixture := newLabFixture(test, true)
	server := newObservationFixtureServer(test, mode)
	closed := new(atomic.Int64)
	use, err := newContinuedUse(fixture.a, server.client, func() { closed.Add(1) })
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(use.fence)
	return use, fixture, server, closed
}

func admitContinued(test *testing.T, use *continuedUse) {
	test.Helper()
	if err := use.publication(context.Background(), "start", func() error { return nil }); err != nil {
		test.Fatal("admitted pair", err)
	}
	if use.current() != nil {
		test.Fatal("pair did not open bounded use")
	}
}

// Claim: the real joined recovery reader accepts a committed observation but refuses counter, baseline, time, generation, cardinality and nested-response size corruption without reconstructing authority.
func TestLabObservationRecoveryCounterPairs(test *testing.T) {
	use, fixture, server, _ := continuedFixture(test, "valid")
	admitContinued(test, use)
	raw, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	for _, mode := range []string{"seen", "floor", "generation", "receipt", "observed", "cardinality", "baseline-size"} {
		test.Run(mode, func(test *testing.T) {
			if _, _, err := readRecovery(raw, fixture.a.installation); err != nil {
				test.Fatal("recovery control", err)
			}
			envelope, _ := labcontract.ReadRecovery(raw)
			record := envelope["observation"].([]any)[0].(map[string]any)
			switch mode {
			case "seen":
				record["seen"] = record["floor"].(int64) - 1
			case "floor":
				record["floor"] = record["floor"].(int64) + 1
				record["seen"] = record["floor"]
			case "generation":
				record["store_generation"] = strings.Repeat("d", 32)
			case "receipt":
				record["receipt_monotonic_ms"] = int64(0)
			case "observed":
				record["observed_monotonic_ms"] = int64(0)
			case "cardinality":
				envelope["observation"] = []any{record, record}
			case "baseline-size":
				baseline := record["baseline"].(map[string]any)
				invalidations, receipts := make([]any, 256), make([]any, 256)
				for position := range receipts {
					invalidations[position] = server.invalidation
					receipts[position] = baseline["receipts"].([]any)[0]
				}
				baseline["invalidations"], baseline["receipts"] = invalidations, receipts
				encoded, _ := wire.Encode(baseline)
				if len(encoded) <= 65536 {
					test.Fatal("oversize plant not applied")
				}
			}
			bad, _ := wire.Encode(envelope)
			if _, err := labcontract.ReadRecovery(bad); err != nil {
				test.Fatal("semantic plant violated shape", err)
			}
			if _, _, err := readRecovery(bad, fixture.a.installation); err == nil || err.Error() != "recovery_observation" {
				test.Fatal("corrupt recovery admitted", err)
			}
		})
	}
}

// Claim: one fresh pair durably publishes F=S; periodic fresh singles preserve the exact floor/baseline/result, advance only S, and cannot admit a fresh or restarted use.
func TestLabObservationConsumptionDurablePairs(test *testing.T) {
	use, fixture, server, _ := continuedFixture(test, "valid")
	if use.current() == nil || use.periodic(context.Background()) == nil || server.requests.Load() != 0 {
		test.Fatal("fresh single enabled use")
	}
	admitContinued(test, use)
	before, _ := object(use.record)
	if use.periodic(context.Background()) != nil || server.requests.Load() != 3 {
		test.Fatal("single valid control")
	}
	after, _ := object(use.record)
	for _, name := range []string{"floor", "baseline", "publication", "result_sha256"} {
		if !labcontract.Equal(before[name], after[name]) {
			test.Fatal("single published", name)
		}
	}
	if before["floor"] != int64(9) || after["seen"] != int64(10) {
		test.Fatal("separate counters")
	}
	raw, err := fixture.records.Read(stateName)
	envelope, decodeErr := labcontract.ReadRecovery(raw)
	if err != nil || decodeErr != nil || !labcontract.Equal(envelope["observation"], []any{after}) || envelope["state"].(map[string]any)["revision"] != int64(1) || envelope["revision"] != int64(3) {
		test.Fatal("atomic recovery lost engine or observation state", err, decodeErr)
	}
	use.fence()
	restarted, err := newContinuedUse(fixture.a, server.client, func() {})
	if err != nil || restarted.current() == nil || restarted.periodic(context.Background()) == nil {
		test.Fatal("restart adopted cached admission", err)
	}
	admitContinued(test, restarted)
	defer restarted.fence()
	if restarted.record["floor"] != int64(12) || server.requests.Load() != 5 {
		test.Fatal("reused single or earlier final as pair candidate")
	}
}

// Claim: every periodic transport, completeness, binding, replay and native-proof failure closes admitted use with no F/S update or publication; every mode is beside a fresh valid single.
func TestLabObservationPeriodicAdversarialPairs(test *testing.T) {
	for _, mode := range []string{"wrong-start-uid", "stale-generation", "partial", "timeout", "pending-stop", "not-current", "incomplete", "wrong-manager", "store-generation", "counter-generation", "debit-mismatch", "invalidation", "duplicate-receipt", "replayed-sequence", "moved-proof"} {
		test.Run(mode, func(test *testing.T) {
			for _, fault := range []bool{false, true} {
				use, fixture, server, closed := continuedFixture(test, "valid")
				admitContinued(test, use)
				before, _ := fixture.records.Read(stateName)
				server.setMode(mode, fault)
				err := use.periodic(context.Background())
				if !fault {
					if err != nil || use.current() != nil || closed.Load() != 0 {
						test.Fatal("valid single", err)
					}
					use.fence()
					continue
				}
				after, _ := fixture.records.Read(stateName)
				if !errors.Is(err, ErrUnknown) || use.current() == nil || closed.Load() != 1 || string(before) != string(after) {
					test.Fatal("periodic failure did not close without publication", err)
				}
				server.setMode("valid", true)
				if use.periodic(context.Background()) == nil || use.current() == nil {
					test.Fatal("single reopened sticky fence")
				}
			}
		})
	}
}

// Claim: pair entry immediately fences prior use; final mismatch or uncertain joined CAS publishes no result and never advances an acknowledged floor, beside a valid second publication.
func TestLabObservationPublicationAtomicPairs(test *testing.T) {
	for _, mode := range []string{"valid", "revalidation-mismatch", "cas-uncertain", "wrong-kind", "single-is-not-publication"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, server, closed := continuedFixture(test, "valid")
			admitContinued(test, use)
			before, _ := object(use.record)
			if mode == "revalidation-mismatch" {
				server.setMode(mode, true)
			}
			if mode == "cas-uncertain" {
				*fixture.fault = "rename"
			}
			kind := "commit"
			if mode == "wrong-kind" {
				kind = "current"
			}
			published := 0
			var err error
			if mode == "single-is-not-publication" {
				err = use.periodic(context.Background())
			} else {
				err = use.publication(context.Background(), kind, func() error { published++; return nil })
			}
			if mode == "valid" {
				if err != nil || published != 1 || closed.Load() != 1 || use.current() != nil || use.record["floor"].(int64) <= before["seen"].(int64) {
					test.Fatal("valid publication", err)
				}
			} else if mode == "single-is-not-publication" {
				if err != nil || published != 0 || use.record["floor"] != before["floor"] {
					test.Fatal("single enabled publication", err)
				}
			} else if err == nil || published != 0 || use.current() == nil || !labcontract.Equal(use.record, before) {
				test.Fatal("failed publication exposed result/floor", err)
			}
		})
	}
}

// Claim: slow in-time singles stay usable, but delayed scheduling or absent periodic work independently closes use before the native-age ceiling without a current request.
func TestLabObservationIndependentAgeFence(test *testing.T) {
	for _, mode := range []string{"slow-valid", "late-scheduler", "absent-single"} {
		test.Run(mode, func(test *testing.T) {
			use, _, server, closed := continuedFixture(test, "valid")
			admitContinued(test, use)
			if mode == "slow-valid" {
				server.setMode(mode, true)
				if use.periodic(context.Background()) != nil || use.current() != nil || closed.Load() != 0 {
					test.Fatal("slow single valid control")
				}
				return
			}
			if mode == "late-scheduler" {
				waitObservationCooldown(context.Background(), use.record["receipt_monotonic_ms"].(int64)*int64(time.Millisecond)+int64(560*time.Millisecond))
				if use.periodic(context.Background()) == nil || closed.Load() != 1 {
					test.Fatal("late single admitted")
				}
				return
			}
			deadline := use.record["observed_monotonic_ms"].(int64)*int64(time.Millisecond) + int64(nativeAge)
			for closed.Load() == 0 {
				now, _ := bootNanos()
				if now >= deadline {
					test.Fatal("independent fence missed ceiling")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if use.current() == nil {
				test.Fatal("age fence left use open")
			}
		})
	}
}

// Claim: composed existing-engine current checks return inside 300 ms without an observation/pair or floor advance, and a fenced native proof can return only unavailable metadata, never a usable verdict or a journal effect.
func TestLabObservationComposedPeriodicCurrent(test *testing.T) {
	use, fixture, server, _ := continuedFixture(test, "valid")
	fixture.start(test)
	fixture.bind(test)
	issued, err := fixture.call(test, 4101, "service.lease.request", fixture.request("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	if err != nil {
		test.Fatal(err)
	}
	admitContinued(test, use)
	broker, err := service.NewLabWithLifetime(continuedAuthority{fixture.authority, use}, map[string]service.Account{accountLabel: fixture.a}, func() time.Time { return fixture.now }, fixture.facts.lifetime)
	if err != nil {
		test.Fatal(err)
	}
	principal, err := broker.Open(context.Background(), 4101)
	if err != nil {
		test.Fatal(err)
	}
	raw, _ := wire.Encode(wire.ServiceLeaseID{LeaseID: issued.(wire.ServiceLease).LeaseID})
	before, _ := fixture.records.Read(stateName)
	for _, fenced := range []bool{false, true} {
		if fenced {
			use.fence()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		var result any
		err = broker.Call(ctx, principal, "service.revocation.check", json.RawMessage(raw), func(value any) error { result = value; return nil })
		cancel()
		if !fenced && (err != nil || result == nil || result.(map[string]any)["verdict"] != "not_revoked") {
			test.Fatal("composed current control", err)
		}
		if fenced && (err == nil && (result == nil || result.(map[string]any)["verdict"] != "unavailable")) {
			test.Fatal("fenced current published", err)
		}
	}
	after, _ := fixture.records.Read(stateName)
	if string(before) != string(after) || server.requests.Load() != 2 {
		test.Fatal("current consumed pair or changed durable floor")
	}
}
