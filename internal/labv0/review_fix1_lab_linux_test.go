//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Claim: an independent fence during publication cannot be overwritten by that pair; the identical unfenced publication opens bounded use.
func TestReviewFenceDuringPublishIsSticky(test *testing.T) {
	for _, mode := range []string{"valid", "during-publish", "during-cas"} {
		test.Run(mode, func(test *testing.T) {
			use, fixture, _, _ := continuedFixture(test, "valid")
			admitContinued(test, use)
			before, _ := object(use.record)
			if mode == "during-cas" {
				fixture.durability = func(stage string) {
					if stage == "directory-sync" {
						use.fence()
					}
				}
			}
			published := 0
			err := use.publication(context.Background(), "commit", func() error {
				published++
				if mode == "during-publish" {
					use.fence()
				}
				return nil
			})
			if mode == "valid" {
				if err != nil || published != 1 || use.current() != nil {
					test.Fatal("valid publication refused", err)
				}
				return
			}
			if !errors.Is(err, ErrUnknown) || use.current() == nil || digest(use.record) != digest(before) {
				test.Fatal("publication overwrote sticky fence", err)
			}
			if mode == "during-cas" && published != 0 {
				test.Fatal("fenced CAS enabled publication")
			}
			if use.periodic(context.Background()) == nil || use.current() == nil {
				test.Fatal("later single reopened sticky fence")
			}
		})
	}
}

func assertUnknownAccount(test *testing.T, fixture *labFixture) {
	test.Helper()
	if _, err := fixture.a.Snapshot(); !errors.Is(err, ErrUnknown) {
		test.Fatal("UNKNOWN projection reopened", err)
	}
	if _, err := fixture.a.ServiceAccount(); !errors.Is(err, ErrUnknown) {
		test.Fatal("UNKNOWN account reopened", err)
	}
	delivered := false
	err := fixture.a.Publish(context.Background(), fixture.now.Add(fixture.facts.lifetime), func() time.Time { return fixture.now }, func([]byte) error { delivered = true; return nil })
	if !errors.Is(err, ErrUnknown) || delivered {
		test.Fatal("UNKNOWN material reopened", err)
	}
}

func observationDoesNotResolveEngineUnknown(test *testing.T, publication bool) {
	test.Helper()
	use, fixture, _, _ := continuedFixture(test, "valid")
	fixture.start(test)
	fixture.bind(test)
	admitContinued(test, use)
	if err := use.periodic(context.Background()); err != nil {
		test.Fatal("valid periodic control", err)
	}
	if _, err := fixture.a.Snapshot(); err != nil {
		test.Fatal("valid projection control", err)
	}
	*fixture.fault = "rename"
	if _, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("b", 32))); err == nil {
		test.Fatal("uncertain engine write acknowledged")
	}
	assertUnknownAccount(test, fixture)
	before, err := fixture.records.Read(stateName)
	if err != nil {
		test.Fatal(err)
	}
	state, _, err := readRecovery(before, fixture.a.installation)
	if err != nil || len(state.Leases) != 1 {
		test.Fatal("uncertainty plant did not land", err)
	}
	published := 0
	if publication {
		err = use.publication(context.Background(), "commit", func() error { published++; return nil })
	} else {
		err = use.periodic(context.Background())
	}
	if !errors.Is(err, ErrUnknown) || published != 0 || use.current() == nil {
		test.Fatal("observation acknowledged engine uncertainty", err)
	}
	assertUnknownAccount(test, fixture)
	after, err := fixture.records.Read(stateName)
	if err != nil || !bytes.Equal(before, after) {
		test.Fatal("observation CAS changed an UNKNOWN account", err)
	}
	if _, err := fixture.call(test, 4101, "service.lease.request", fixture.request(strings.Repeat("e", 32))); err == nil {
		test.Fatal("later widening bypassed UNKNOWN")
	}
	assertUnknownAccount(test, fixture)
}

// Claim: after an actual rename-uncertain lease write, a periodic single cannot clear engine UNKNOWN, write S/F or expose projection/material, beside its valid single control.
func TestReviewProbeObservationCommitClearsEngineUnknown(test *testing.T) {
	observationDoesNotResolveEngineUnknown(test, false)
}

// Claim: a fresh publication pair cannot reconcile an unrelated uncertain engine write or expose its lease; a valid single/projection precedes the uncertainty plant.
func TestReviewProbePublicationCommitClearsEngineUnknown(test *testing.T) {
	observationDoesNotResolveEngineUnknown(test, true)
}
