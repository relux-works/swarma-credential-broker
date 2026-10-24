package testutil

import (
	"context"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// Claim: gate entry is published only after the refresh count becomes visible;
// cancellation while held returns its intended error without rotating material.
func TestGateEntryNotification(t *testing.T) {
	f := &Fake{view: owner.Snapshot{Generation: 1, AccessToken: "fixture-material"}}
	gate := make(chan struct{})
	entered := f.Gate(gate)
	select {
	case <-entered:
		t.Fatal("entry before refresh")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	exited := make(chan struct{})
	defer func() { cancel(); <-exited }()
	go func() { defer close(exited); _, err := f.Refresh(ctx, "fixture", 1); done <- err }()
	<-entered
	if n, _ := f.Counts(); n != 1 {
		t.Fatal("entry before call count")
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatal("wrong held cancellation", err)
	}
	if f.View().AccessToken != "fixture-material" {
		t.Fatal("cancelled gate rotated material")
	}
	close(gate)
	f.Next("fixture-next")
	if _, err := f.Refresh(context.Background(), "fixture", 1); err != nil || f.View().AccessToken != "fixture-next" {
		t.Fatal("open gate control", err)
	}
}
