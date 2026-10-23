package lease

import (
	"context"
	"testing"
	"time"
)

// Claim: state admission returns the original deadline/cancellation error without acquiring a held gate; a subsequent uncancelled caller acquires it after release.
func TestStateMutexCancellation(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name := "cancel"
		if timeout {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			var mu stateMutex
			mu.Lock()
			released := false
			defer func() {
				if !released {
					mu.Unlock()
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			if timeout {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- mu.LockContext(ctx) }()
			if !timeout {
				cancel()
			}
			select {
			case err := <-result:
				if err != ctx.Err() {
					t.Fatal("wrong admission rejection")
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("admission ignored cancellation while state gate held")
			}
			mu.Unlock()
			released = true
			control, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if mu.LockContext(control) != nil {
				t.Fatal("uncancelled control refused")
			}
			mu.Unlock()
		})
	}
}
