//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
)

func observationUncertainty(test *testing.T, use *continuedUse, fixture *labFixture, mode string) {
	test.Helper()
	if mode == "rename-uncertain" {
		*fixture.fault = "rename"
	} else if mode == "late-cas" {
		fixture.durability = func(stage string) {
			if stage == "directory-sync" {
				time.Sleep(300 * time.Millisecond)
			}
		}
	}
	published := 0
	err := use.publication(context.Background(), "commit", func() error { published++; return nil })
	fixture.durability = nil
	if mode == "control" {
		if err != nil || published != 1 || use.current() != nil {
			test.Fatal("valid publication control", err)
		}
		return
	}
	if !errors.Is(err, ErrUnknown) || published != 0 || use.current() == nil {
		test.Fatal("uncertain observation CAS acknowledged", err)
	}
	assertUnknownAccount(test, fixture)
}

// Claim: after its own rename-uncertain or late CAS, a new non-reused admitted pair reconciles the complete durable join and reopens projection/use, beside an unfaulted publication control.
func TestReviewD1NewPairReconcilesObservationUncertainty(test *testing.T) {
	for _, mode := range []string{"control", "rename-uncertain", "late-cas"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, server, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			observationUncertainty(test, use, fixture, mode)
			before, err := fixture.records.Read(stateName)
			if err != nil {
				test.Fatal(err)
			}
			envelope, err := labcontract.ReadRecovery(before)
			if err != nil {
				test.Fatal(err)
			}
			seen := envelope["observation"].([]any)[0].(map[string]any)["seen"].(int64)
			requests := server.requests.Load()
			published := 0
			err = use.publication(context.Background(), "start", func() error { published++; return nil })
			if err != nil || published != 1 || use.current() != nil {
				test.Fatal("new admitted pair could not reconcile observation uncertainty", err)
			}
			if server.requests.Load() != requests+2 || use.record["floor"].(int64) <= seen || use.record["seen"] != use.record["floor"] {
				test.Fatal("reconciliation reused an observation or failed to advance the floor")
			}
			after, err := fixture.records.Read(stateName)
			joined, joinErr := labcontract.ReadRecovery(after)
			if err != nil || joinErr != nil || joined["revision"].(int64) != envelope["revision"].(int64)+1 || !labcontract.Equal(joined["observation"], []any{use.record}) || !labcontract.Equal(joined["external"], envelope["external"]) || !labcontract.Equal(joined["state"], envelope["state"]) {
				test.Fatal("reconciliation did not commit exactly one unchanged engine/external join", err, joinErr)
			}
			if _, err := fixture.a.Snapshot(); err != nil {
				test.Fatal("reconciled projection stayed UNKNOWN", err)
			}
			if _, err := fixture.a.ServiceAccount(); err != nil {
				test.Fatal("reconciled account stayed UNKNOWN", err)
			}
			delivered := 0
			err = fixture.a.Publish(context.Background(), fixture.now.Add(fixture.facts.lifetime), func() time.Time { return fixture.now }, func(material []byte) error {
				delivered++
				if string(material) != "ssh-placeholder" {
					test.Fatal("unexpected fixture material")
				}
				return nil
			})
			if err != nil || delivered != 1 {
				test.Fatal("reconciled material stayed UNKNOWN", err)
			}
			if err := use.periodic(context.Background()); err != nil {
				test.Fatal("reconciled periodic control", err)
			}
		})
	}
}

func observationCASWithoutPair(test *testing.T, use *continuedUse, fixture *labFixture, server *observationFixtureServer, cached bool) error {
	test.Helper()
	raw, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	envelope, err := labcontract.ReadRecovery(raw)
	if err != nil {
		test.Fatal(err)
	}
	updated, err := object(envelope["observation"].([]any)[0].(map[string]any))
	if err != nil {
		test.Fatal(err)
	}
	if !cached {
		receipt := updated["receipt_monotonic_ms"].(int64) * int64(time.Millisecond)
		if err := waitObservationCooldown(context.Background(), receipt+int64(periodicDelay)); err != nil {
			test.Fatal(err)
		}
		sample, err := server.client.collect(context.Background(), updated["seen"].(int64))
		if err != nil {
			test.Fatal("fresh single control", err)
		}
		updated["seen"] = sample.record["sequence"]
		updated["observed_monotonic_ms"] = sample.record["observed_monotonic_ms"]
		updated["receipt_monotonic_ms"] = sample.after / int64(time.Millisecond)
	}
	fixture.a.mu.Lock()
	defer fixture.a.mu.Unlock()
	return use.commit(context.Background(), envelope, updated)
}

// Claim: a single, cached CAS, periodic call, replayed/partial publication or restarted reader cannot reconcile observation uncertainty or change its durable join; each negative has a valid single and later fresh-pair control.
func TestReviewD1NonPairCannotReconcile(test *testing.T) {
	for _, mode := range []string{"single-cas", "cached-cas", "periodic", "replayed-pair", "partial-pair", "restart"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, server, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			if err := use.periodic(context.Background()); err != nil {
				test.Fatal("valid periodic control", err)
			}
			if err := observationCASWithoutPair(test, use, fixture, server, false); err != nil {
				test.Fatal("valid single CAS control", err)
			}
			observationUncertainty(test, use, fixture, "rename-uncertain")
			before, err := fixture.records.Read(stateName)
			if err != nil {
				test.Fatal(err)
			}
			published := 0
			switch mode {
			case "single-cas", "cached-cas":
				err = observationCASWithoutPair(test, use, fixture, server, mode == "cached-cas")
			case "periodic":
				err = use.periodic(context.Background())
			case "replayed-pair", "partial-pair":
				serverMode := "replayed-sequence"
				if mode == "partial-pair" {
					serverMode = "partial"
				}
				server.setMode(serverMode, true)
				err = use.publication(context.Background(), "start", func() error { published++; return nil })
				server.setMode("valid", true)
			case "restart":
				restarted, restartErr := newAccount(fixture.records, fixture.a.context, fixture.a.project)
				if restartErr != nil {
					test.Fatal(restartErr)
				}
				recovered, restartErr := newContinuedUse(restarted, server.client, func() {})
				if restartErr != nil || recovered.current() == nil {
					test.Fatal("restart reopened cached use", restartErr)
				}
				if _, err := restarted.Snapshot(); !errors.Is(err, ErrUnknown) {
					test.Fatal("restart reopened projection", err)
				}
				err = recovered.publication(context.Background(), "start", func() error { published++; return nil })
			}
			if !errors.Is(err, ErrUnknown) || published != 0 || use.current() == nil {
				test.Fatal("non-pair reconciled observation uncertainty", err)
			}
			assertUnknownAccount(test, fixture)
			after, readErr := fixture.records.Read(stateName)
			if readErr != nil || !bytes.Equal(before, after) {
				test.Fatal("non-pair changed the uncertain durable join", readErr)
			}
			admitContinued(test, use)
			if _, err := fixture.a.Snapshot(); err != nil {
				test.Fatal("later pair control", err)
			}
		})
	}
}

// Claim: engine confirmation cannot clear observation uncertainty, and an uncertain/rejected engine write additionally blocks pair reconciliation until engine confirmation; only the subsequent fresh pair restores projection/use.
func TestReviewD1EngineUncertaintyAfterObservation(test *testing.T) {
	for _, mode := range []string{"engine-confirmation", "engine-rename", "engine-rejected"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, _, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			observationUncertainty(test, use, fixture, "rename-uncertain")
			state, err := fixture.a.LoadServiceState()
			if err != nil {
				test.Fatal(err)
			}
			state.Revision++
			if mode == "engine-rename" {
				*fixture.fault = "rename"
			} else if mode == "engine-rejected" {
				state.Revision++
			}
			err = fixture.a.StoreServiceState(state)
			if mode == "engine-confirmation" && err != nil || mode != "engine-confirmation" && !errors.Is(err, ErrUnknown) {
				test.Fatal("engine uncertainty plant/control", err)
			}
			assertUnknownAccount(test, fixture)
			if mode != "engine-confirmation" {
				before, _ := fixture.records.Read(stateName)
				published := 0
				err = use.publication(context.Background(), "start", func() error { published++; return nil })
				if !errors.Is(err, ErrUnknown) || published != 0 || use.current() == nil {
					test.Fatal("pair cleared subsequent engine uncertainty", err)
				}
				assertUnknownAccount(test, fixture)
				after, readErr := fixture.records.Read(stateName)
				if readErr != nil || !bytes.Equal(before, after) {
					test.Fatal("pair overwrote engine uncertainty", readErr)
				}
				state, err = fixture.a.LoadServiceState()
				if err != nil {
					test.Fatal(err)
				}
				state.Revision++
				if err := fixture.a.StoreServiceState(state); err != nil {
					test.Fatal("engine confirmation control", err)
				}
				assertUnknownAccount(test, fixture)
			}
			admitContinued(test, use)
			if _, err := fixture.a.Snapshot(); err != nil {
				test.Fatal("reconciled engine/observation control", err)
			}
		})
	}
}

// Claim: recovering an observation record fences projection/material even after engine confirmation, whether or not its last CAS was uncertain; only a new non-reused pair restores the recovered use.
func TestReviewD1RestartRequiresPair(test *testing.T) {
	for _, mode := range []string{"control", "rename-uncertain", "late-cas"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, server, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			observationUncertainty(test, use, fixture, mode)
			use.fence()
			restarted, err := newAccount(fixture.records, fixture.a.context, fixture.a.project)
			if err != nil {
				test.Fatal(err)
			}
			recovered, err := newContinuedUse(restarted, server.client, func() {})
			if err != nil {
				test.Fatal(err)
			}
			test.Cleanup(recovered.fence)
			state, err := restarted.LoadServiceState()
			if err != nil {
				test.Fatal(err)
			}
			state.Revision++
			if err := restarted.StoreServiceState(state); err != nil {
				test.Fatal("restart engine confirmation control", err)
			}
			if _, err := restarted.Snapshot(); !errors.Is(err, ErrUnknown) {
				test.Fatal("restart confirmation cleared observation reconciliation fence", err)
			}
			if _, err := restarted.ServiceAccount(); !errors.Is(err, ErrUnknown) {
				test.Fatal("restart confirmation reopened account", err)
			}
			delivered := false
			err = restarted.Publish(context.Background(), fixture.now.Add(fixture.facts.lifetime), func() time.Time { return fixture.now }, func([]byte) error { delivered = true; return nil })
			if !errors.Is(err, ErrUnknown) || delivered || recovered.current() == nil || recovered.periodic(context.Background()) == nil {
				test.Fatal("restart confirmation reopened cached material/use", err)
			}
			seen := recovered.record["seen"].(int64)
			admitContinued(test, recovered)
			if recovered.record["floor"].(int64) <= seen {
				test.Fatal("restart pair reused an observation")
			}
			if _, err := restarted.Snapshot(); err != nil {
				test.Fatal("restart fresh pair control", err)
			}
		})
	}
}
