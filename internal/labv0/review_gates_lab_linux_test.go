//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the actual initial-observation reader enforces both cooldown and <50 ms lateness, beside an in-window Unix response; this isolates the first-read gate rather than scheduler qualification.
func TestLabReviewInitialObservationWindow(test *testing.T) {
	for _, mode := range []string{"valid", "early", "late"} {
		test.Run(mode, func(test *testing.T) {
			use, _, _, _ := continuedFixture(test, "valid")
			now, err := bootNanos()
			if err != nil {
				test.Fatal(err)
			}
			receipt := now - int64(observationWindow)
			if mode == "early" {
				receipt += int64(100 * time.Millisecond)
			}
			if mode == "late" {
				receipt -= int64(100 * time.Millisecond)
			}
			_, err = use.initialObservation(context.Background(), 7, observationPurpose{kind: "start"}, receipt)
			if mode == "valid" {
				if err != nil {
					test.Fatal("initial read control", err)
				}
			} else if !errors.Is(err, ErrUnknown) {
				test.Fatal("initial read outside scheduling window admitted", err)
			}
		})
	}
}

// Claim: current() independently refuses age >=1200 ms and future timestamps without relying on a running guard; a fresh local proof remains usable and each refusal closes once.
func TestLabReviewCurrentAgePredicate(test *testing.T) {
	for _, mode := range []string{"valid", "expired", "future"} {
		test.Run(mode, func(test *testing.T) {
			now, err := bootNanos()
			if err != nil {
				test.Fatal(err)
			}
			observed := now / int64(time.Millisecond)
			if mode == "expired" {
				observed -= int64(nativeAge / time.Millisecond)
			}
			if mode == "future" {
				observed += 1000
			}
			closed := new(atomic.Int64)
			use := &continuedUse{open: true, record: map[string]any{"observed_monotonic_ms": observed}, closeUse: func() { closed.Add(1) }}
			err = use.current()
			if mode == "valid" {
				if err != nil || closed.Load() != 0 {
					test.Fatal("fresh local proof control", err)
				}
			} else if !errors.Is(err, ErrUnknown) || use.open || closed.Load() != 1 || use.current() == nil || closed.Load() != 1 {
				test.Fatal("invalid native age admitted or closure repeated", err)
			}
		})
	}
}

// Claim: both passed CAS deadline slots are checked before and after durability; pair-budget/native-age labels share slot 1 and do not isolate caller wiring. Late writes stay UNKNOWN and early refusals preserve the join, beside timely commits.
func TestLabReviewObservationCommitDeadlines(test *testing.T) {
	for _, boundary := range []string{"connection", "pair-budget", "native-age"} {
		for _, phase := range []string{"valid", "before-cas", "after-cas"} {
			test.Run(boundary+"/"+phase, func(test *testing.T) {
				use, fixture, server, _ := continuedFixture(test, "valid")
				admitContinued(test, use)
				previous, _ := object(use.record)
				receipt := previous["receipt_monotonic_ms"].(int64) * int64(time.Millisecond)
				if err := waitObservationCooldown(context.Background(), receipt+int64(observationWindow+5*time.Millisecond)); err != nil {
					test.Fatal(err)
				}
				sample, err := server.client.collect(context.Background(), previous["seen"].(int64))
				if err != nil {
					test.Fatal("fresh sample control", err)
				}
				updated, _ := object(previous)
				updated["seen"] = sample.record["sequence"]
				updated["observed_monotonic_ms"] = sample.record["observed_monotonic_ms"]
				updated["receipt_monotonic_ms"] = sample.after / int64(time.Millisecond)
				before, _ := fixture.records.Read(stateName)
				envelope, err := labcontract.ReadRecovery(before)
				if err != nil {
					test.Fatal(err)
				}
				now, _ := bootNanos()
				deadlines := []int64{now + int64(time.Second), now + int64(time.Second)}
				position := 0
				if boundary != "connection" {
					position = 1
				}
				if phase == "before-cas" {
					deadlines[position] = now - 1
				}
				if phase == "after-cas" {
					deadlines[position] = now + int64(60*time.Millisecond)
					fixture.durability = func(stage string) {
						if stage == "directory-sync" {
							waitObservationCooldown(context.Background(), deadlines[position]+int64(20*time.Millisecond))
						}
					}
				}
				fixture.a.mu.Lock()
				err = use.commit(context.Background(), envelope, updated, deadlines...)
				fixture.a.mu.Unlock()
				after, _ := fixture.records.Read(stateName)
				if phase == "valid" {
					joined, decodeErr := labcontract.ReadRecovery(after)
					if err != nil || decodeErr != nil || !labcontract.Equal(joined["state"], envelope["state"]) || !labcontract.Equal(joined["external"], envelope["external"]) || !labcontract.Equal(joined["observation"], []any{updated}) {
						test.Fatal("timely joined CAS control", err, decodeErr)
					}
					return
				}
				if !errors.Is(err, ErrUnknown) {
					test.Fatal("late CAS acknowledged", err)
				}
				if phase == "before-cas" && !bytes.Equal(before, after) {
					test.Fatal("expired pre-CAS deadline changed durable join")
				}
				if phase == "after-cas" {
					if bytes.Equal(before, after) {
						test.Fatal("late successful durability plant did not land")
					}
					assertUnknownAccount(test, fixture)
				}
			})
		}
	}
}

// Claim: successful but late directory-sync publishes nothing and leaves UNKNOWN; a late publication callback cannot reopen use, beside an identical timely full-pair control.
func TestLabReviewPublicationDeadlines(test *testing.T) {
	for _, mode := range []string{"valid", "late-cas", "late-publish"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, _, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			before, _ := object(use.record)
			if mode == "late-cas" {
				fixture.durability = func(stage string) {
					if stage == "directory-sync" {
						time.Sleep(300 * time.Millisecond)
					}
				}
			}
			published := 0
			err := use.publication(context.Background(), "commit", func() error {
				published++
				if mode == "late-publish" {
					time.Sleep(300 * time.Millisecond)
				}
				return nil
			})
			if mode == "valid" {
				if err != nil || published != 1 || use.current() != nil {
					test.Fatal("timely publication control", err)
				}
				return
			}
			if !errors.Is(err, ErrUnknown) || use.current() == nil || !labcontract.Equal(use.record, before) {
				test.Fatal("late publication reopened use or floor", err)
			}
			if mode == "late-cas" {
				if published != 0 {
					test.Fatal("late CAS exposed publication")
				}
				assertUnknownAccount(test, fixture)
			} else if published != 1 {
				test.Fatal("late callback plant did not execute")
			}
		})
	}
}

// Claim: a periodic single whose successful CAS finishes after its original observation deadline closes use and leaves UNKNOWN without installing S/F, beside a timely single control.
func TestLabReviewPeriodicLateCAS(test *testing.T) {
	for _, fault := range []bool{false, true} {
		use, fixture, _, closed := continuedFixture(test, "valid")
		admitContinued(test, use)
		before, _ := object(use.record)
		if fault {
			fixture.durability = func(stage string) {
				if stage == "directory-sync" {
					time.Sleep(300 * time.Millisecond)
				}
			}
		}
		err := use.periodic(context.Background())
		if !fault {
			if err != nil || use.current() != nil || closed.Load() != 0 || use.record["floor"] != before["floor"] || use.record["seen"].(int64) <= before["seen"].(int64) {
				test.Fatal("timely single control", err)
			}
		} else if !errors.Is(err, ErrUnknown) || use.current() == nil || closed.Load() != 1 || !labcontract.Equal(use.record, before) {
			test.Fatal("late single CAS acknowledged or reopened use", err)
		} else {
			assertUnknownAccount(test, fixture)
		}
		use.fence()
	}
}

// Claim: a fence during the final Unix response prevents the pre-CAS write, while an identical unfenced final response commits and publishes.
func TestLabReviewFenceBeforeObservationCAS(test *testing.T) {
	for _, fault := range []bool{false, true} {
		use, fixture, server, _ := continuedFixture(test, "valid")
		admitContinued(test, use)
		before, _ := fixture.records.Read(stateName)
		server.modeMu.Lock()
		server.beforeWrite = func(ordinal int64) {
			if fault && ordinal == 4 {
				use.fence()
			}
		}
		server.modeMu.Unlock()
		published := 0
		err := use.publication(context.Background(), "commit", func() error { published++; return nil })
		after, _ := fixture.records.Read(stateName)
		if !fault {
			if err != nil || published != 1 || bytes.Equal(before, after) {
				test.Fatal("unfenced final response control", err)
			}
		} else if !errors.Is(err, ErrUnknown) || published != 0 || !bytes.Equal(before, after) || use.current() == nil {
			test.Fatal("fenced final response committed or published", err)
		}
		use.fence()
	}
}

// Claim: a post-response currentness fence invokes containment outside the account mutex, so a closer can acquire it; the same single without the age change remains usable.
func TestLabReviewContainmentCallbackLockOrder(test *testing.T) {
	for _, fault := range []bool{false, true} {
		use, fixture, server, _ := continuedFixture(test, "valid")
		admitContinued(test, use)
		closerLocked := new(atomic.Bool)
		use.mu.Lock()
		use.epoch++
		use.closeUse = func() {
			if fixture.a.mu.TryLock() {
				closerLocked.Store(true)
				fixture.a.mu.Unlock()
			}
		}
		use.mu.Unlock()
		server.modeMu.Lock()
		server.beforeWrite = func(ordinal int64) {
			if fault && ordinal == 3 {
				use.mu.Lock()
				use.record["observed_monotonic_ms"] = int64(0)
				use.mu.Unlock()
			}
		}
		server.modeMu.Unlock()
		err := use.periodic(context.Background())
		if !fault {
			if err != nil || use.current() != nil || closerLocked.Load() {
				test.Fatal("unchanged single control", err)
			}
		} else if !errors.Is(err, ErrUnknown) || use.current() == nil || !closerLocked.Load() {
			test.Fatal("containment callback ran under account lock", err)
		}
		use.fence()
	}
}

// Claim: contract-shaped response ID and future-time mismatches are refused by the real pair client despite an unchanged nested start, beside a valid pair for each fault.
func TestLabReviewObservationResponseJoins(test *testing.T) {
	for _, mode := range []string{"response-operation-id", "response-start-id", "future-observation"} {
		test.Run(mode, func(test *testing.T) {
			observationPairControl(test)
			server := newObservationFixtureServer(test, mode)
			shape, _ := object(server.response)
			switch mode {
			case "response-operation-id":
				shape["operation_id"] = "dddddddddddddddddddddddddddddddd"
			case "response-start-id":
				shape["start_id"] = "dddddddddddddddddddddddddddddddd"
			case "future-observation":
				now, _ := bootNanos()
				shape["observed_monotonic_ms"] = now/int64(time.Millisecond) + 500
			}
			encoded, _ := wire.Encode(shape)
			if _, err := labcontract.Read(observationResponseFormat, encoded); err != nil {
				test.Fatal("semantic response plant violated grammar", err)
			}
			if _, err := server.client.pair(context.Background(), 7); !errors.Is(err, ErrUnknown) {
				test.Fatal("invalid response join admitted", err)
			}
		})
	}
}

// Claim: re-sealed, CAS-written held/tombstone/gateway/revision mismatches remain UNKNOWN through the account projection and material boundary beside a valid joined lease state.
func TestLabReviewRecoveryJoinPredicates(test *testing.T) {
	for _, mode := range []string{"held", "revoked", "gateway-uid", "gateway-generation", "state-revision"} {
		test.Run(mode, func(test *testing.T) {
			fixture := newLabFixture(test, true)
			fixture.start(test)
			fixture.bind(test)
			if _, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32))); err != nil {
				test.Fatal(err)
			}
			if _, err := fixture.a.Snapshot(); err != nil {
				test.Fatal("valid join control", err)
			}
			raw, _ := fixture.records.Read(stateName)
			envelope, err := labcontract.ReadRecovery(raw)
			if err != nil {
				test.Fatal(err)
			}
			prior := envelope["revision"].(int64)
			envelope["previous_revision"], envelope["revision"] = prior, prior+1
			external := envelope["external"].(map[string]any)
			binding := external["bindings"].([]any)[0].(map[string]any)
			gateway := binding["gateway"].(map[string]any)
			expected := "recovery_binding_join"
			switch mode {
			case "held":
				external["held"] = true
				expected = "recovery_hold_join"
			case "revoked":
				binding["revoked"] = true
			case "gateway-uid":
				gateway["uid"] = gateway["uid"].(int64) + 1
			case "gateway-generation":
				gateway["generation"] = "dddddddddddddddddddddddddddddddd"
			case "state-revision":
				envelope["state"].(map[string]any)["revision"] = prior + 2
				expected = "recovery_join"
			}
			sealJournal(external)
			envelope["external_sha256"] = digest(external)
			encoded, _ := wire.Encode(envelope)
			if _, err := labcontract.ReadRecovery(encoded); err != nil {
				test.Fatal("plant violated frozen grammar", err)
			}
			if _, _, err := readRecovery(encoded, fixture.a.installation); err == nil || err.Error() != expected {
				test.Fatal("semantic join mismatch admitted or wrong refusal", err)
			}
			if err := fixture.records.Put(stateName, uint64(prior), envelope); err != nil {
				test.Fatal("re-sealed mismatch plant did not reach disk", err)
			}
			assertUnknownAccount(test, fixture)
			after, _ := fixture.records.Read(stateName)
			if !bytes.Equal(encoded, after) {
				test.Fatal("UNKNOWN read repaired or rewrote mismatched join")
			}
		})
	}
}
