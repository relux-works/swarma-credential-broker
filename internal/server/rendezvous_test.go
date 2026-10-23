package server

import (
	"testing"
	"testing/synctest"
	"time"
)

// Claim: fixture rendezvous waits for its event even after arbitrary scheduling
// delay; elapsed fixture time is not a production latency refusal.
func TestReviewRendezvousScheduling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		go func() { time.Sleep(time.Hour); close(entered) }()
		defer func() { <-entered }() // Reap the delayed fixture even on a failed guard.
		awaitReview(t, entered)
		select {
		case <-entered:
		default:
			t.Fatal("rendezvous returned before entry")
		}
	})
}
