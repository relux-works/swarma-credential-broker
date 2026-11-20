//go:build linux

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the existing engine replays the original issue deadline after two later renewals and restart, rather than its latest lease deadline.
func TestLabB1HistoricalReplayAfterRenewals(test *testing.T) {
	fixture := newBrokerFixture(test, nil)
	fixture.bind(test)
	request := fixture.request()
	var original wire.ServiceLease
	if err := fixture.call(test, fixture.uid, "service.lease.request", request, func(value any) error {
		original = value.(wire.ServiceLease)
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	for _, digit := range []string{"1", "2"} {
		fixture.now = fixture.now.Add(time.Second)
		renewal := wire.ServiceRenew{OperationID: strings.Repeat(digit, 32), ServiceLeaseID: wire.ServiceLeaseID{LeaseID: original.LeaseID}}
		if err := fixture.call(test, fixture.uid, "service.lease.renew", renewal, func(value any) error {
			if value.(wire.ServiceLease).AuthorizedUntil == original.AuthorizedUntil {
				test.Fatal("renewal did not create the distinct-deadline control")
			}
			return nil
		}); err != nil {
			test.Fatal(err)
		}
	}
	restart(test, fixture)
	entries := len(fixture.b.states[fixtureAccount].Operations)
	if err := fixture.call(test, fixture.uid, "service.lease.request", request, func(value any) error {
		if value.(wire.ServiceLease).AuthorizedUntil != original.AuthorizedUntil {
			test.Fatal("historical replay substituted the latest lease deadline")
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	if len(fixture.b.states[fixtureAccount].Operations) != entries || len(fixture.b.leases) != 1 {
		test.Fatal("historical replay added a durable effect")
	}
	contradictory := request
	contradictory.LaunchID = "synthetic-other-launch"
	_, err := fixture.metadata(test, fixture.uid, "service.lease.request", contradictory)
	refused(test, err, "service_operation_conflict")
	if len(fixture.b.states[fixtureAccount].Operations) != entries || len(fixture.b.leases) != 1 {
		test.Fatal("contradictory retry added a durable effect")
	}
}

// Claim: released-lease hold eligibility distinguishes the exact release time, including its inclusive ceiling and one-nanosecond negative.
func TestLabB1ReleaseTimeRequiredForHoldBoundary(test *testing.T) {
	fixture := newBrokerFixture(test, nil)
	fixture.bind(test)
	lease := fixture.issue(test)
	fixture.now = fixture.now.Add(time.Second)
	releasedAt := fixture.now
	if _, err := fixture.metadata(test, fixture.uid, "service.lease.release", wire.ServiceLeaseID{LeaseID: lease.LeaseID}); err != nil {
		test.Fatal(err)
	}
	record := fixture.b.leases[lease.LeaseID]
	fixture.now = releasedAt.Add(V0LeaseCeiling)
	if !fixture.b.holdEligible(record) {
		test.Fatal("valid inclusive release-time boundary refused")
	}
	fixture.now = fixture.now.Add(time.Nanosecond)
	if fixture.b.holdEligible(record) {
		test.Fatal("one-nanosecond-late hold admitted")
	}
	fixture.now = releasedAt.Add(V0LeaseCeiling)
	state := fixture.b.states[fixtureAccount]
	for index := range state.Operations {
		operation := &state.Operations[index]
		if operation.Method == "service.lease.release" {
			operation.At = operation.At.Add(-time.Nanosecond)
		}
	}
	if fixture.b.holdEligible(record) {
		test.Fatal("changing only the missing journal timestamp failed to change hold eligibility")
	}
}
