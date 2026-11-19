//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func managedBroker(t *testing.T) (*managedFixture, *brokerFixture, Principal) {
	t.Helper()
	fixture := newManagedFixture(t)
	broker := newBrokerFixture(t, nil)
	delete(broker.a.principals, broker.uid)
	broker.uid = managedFixtureUID
	principal := Principal{UID: managedFixtureUID, Generation: managedFixtureGeneration, Service: Gateway, Role: "service"}
	broker.a.principals[broker.uid] = principal
	broker.a.binding.UID = broker.uid
	broker.a.binding.Generation = principal.Generation
	broker.bind(t)
	fixture.authority.facts = broker.a
	broker.b.authority = fixture.authority
	return fixture, broker, principal
}

// Claim: issuance and replay refuse expired identity evidence before publication;
// a saved outcome remains replayable without creating a duplicate lease.
func TestManagedMaterialWindow(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name := "issue"
		if replay {
			name = "replay"
		}
		t.Run(name, func(t *testing.T) {
			_, broker, principal := managedBroker(t)
			broker.issue(t)
			request := encode(t, broker.request())
			var result wire.ServiceLease
			published := 0
			publish := func(value any) error {
				published++
				result = value.(wire.ServiceLease)
				return nil
			}
			if replay {
				if err := broker.b.Call(context.Background(), principal, "service.lease.request", request, publish); err != nil {
					t.Fatal(err)
				}
			}
			published = 0
			broker.custody.before = func() { time.Sleep(genjournal.ReaderHold + 50*time.Millisecond) }
			err := broker.b.Call(context.Background(), principal, "service.lease.request", request, publish)
			refused(t, err, "principal_ledger_mismatch")
			if published != 0 {
				t.Fatal("expired identity evidence released material")
			}
			leases := len(broker.b.leases)
			if leases != 2 {
				t.Fatalf("saved outcome lost or duplicated: leases=%d", leases)
			}
			broker.custody.before = nil
			if err := broker.b.Call(context.Background(), principal, "service.lease.request", request, publish); err != nil {
				t.Fatal(err)
			}
			if published != 1 || result.LeaseID == "" || len(broker.b.leases) != leases {
				t.Fatal("fresh evidence did not replay the saved outcome exactly once")
			}
		})
	}
}

// Claim: waiting for broker state cannot extend the identity window or publish;
// an uncontended request on the same provider is the valid control.
func TestManagedGateWaitWindow(t *testing.T) {
	_, broker, principal := managedBroker(t)
	broker.issue(t)
	<-broker.b.gate
	timer := time.AfterFunc(4*genjournal.ReaderHold, func() { broker.b.gate <- struct{}{} })
	defer func() {
		if timer.Stop() {
			broker.b.gate <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*genjournal.ReaderHold)
	defer cancel()
	started := time.Now()
	published, leases := 0, len(broker.b.leases)
	err := broker.b.Call(ctx, principal, "service.lease.request", encode(t, broker.request()), func(any) error { published++; return nil })
	refused(t, err, "principal_ledger_mismatch")
	if elapsed := time.Since(started); elapsed >= 2*genjournal.ReaderHold {
		t.Fatalf("broker state wait outlived the identity window: %v", elapsed)
	}
	if published != 0 || len(broker.b.leases) != leases {
		t.Fatal("expired broker state wait changed material or lease state")
	}
}

// Claim: a successful handoff is not retrospectively reported as effect-none
// refusal; transport completion within the window remains a qualification gate.
func TestManagedPublishedResponseNotRelabelled(t *testing.T) {
	_, broker, principal := managedBroker(t)
	broker.issue(t)
	published := 0
	err := broker.b.Call(context.Background(), principal, "service.lease.request", encode(t, broker.request()), func(any) error {
		published++
		time.Sleep(genjournal.ReaderHold + 50*time.Millisecond)
		return nil
	})
	if err != nil || published != 1 {
		t.Fatalf("completed material handoff relabelled: published=%d err=%v", published, err)
	}
}
