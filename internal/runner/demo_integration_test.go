//go:build linux

package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type demoLaunchBroker struct {
	BrokerClient
	expected string
	observed bool
}

func (b *demoLaunchBroker) Request(ctx context.Context, r LeaseRequest) (Lease, error) {
	if r.LaunchID != b.expected {
		return Lease{}, errors.New("protected launch digest changed")
	}
	b.observed = true
	return b.BrokerClient.Request(ctx, r)
}

func TestDemoProtectedLaunchAndOutcomeBeforeRelease(t *testing.T) {
	f := newFixture(t, nil)
	f.d.LaunchID = strings.Repeat("a", 64)
	inspected := &demoLaunchBroker{BrokerClient: f.b, expected: f.d.LaunchID}
	f.d.Connect = func(context.Context) (BrokerClient, error) { return inspected, nil }
	called := false
	f.d.BeforeRelease = func(ctx context.Context, leaseID string, success bool) error {
		if leaseID != "lease" {
			t.Fatal("outcome did not bind acquired lease")
		}
		if ctx.Err() != nil || !success {
			t.Fatal("completed synthetic turn not observed")
		}
		f.b.mu.Lock()
		defer f.b.mu.Unlock()
		for _, event := range f.b.calls {
			if event == "release" {
				t.Fatal("outcome followed lease release")
			}
		}
		called = true
		return nil
	}
	requireStatus(t, f.run(), 0, f.err.String())
	if !called || !inspected.observed {
		t.Fatal("missing pre-release outcome")
	}
}
func TestDemoOutcomeWriteFailureStillReleases(t *testing.T) {
	f := newFixture(t, nil)
	f.d.BeforeRelease = func(context.Context, string, bool) error { return errors.New("synthetic outcome storage failure") }
	requireStatus(t, f.run(), 75, f.err.String())
	found := false
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	for _, event := range f.b.calls {
		if event == "release" {
			found = true
		}
	}
	if !found {
		t.Fatal("failed outcome write bypassed lease release")
	}
}
