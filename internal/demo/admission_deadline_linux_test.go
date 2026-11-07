//go:build linux

package demo

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAdmissionContentionHonorsCallerDeadline(t *testing.T) {
	for _, operation := range []string{"peer", "check", "publish"} {
		t.Run(operation, func(t *testing.T) {
			a := NewAdmission()
			if err := a.mu.lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer a.mu.unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			wrote := false
			go func() {
				switch operation {
				case "peer":
					done <- a.Peer(ctx, 30000)
				case "check":
					done <- a.Check(ctx, 30000, strings.Repeat("a", 64))
				case "publish":
					done <- a.Publish(ctx, 30000, strings.Repeat("a", 64), func(context.Context) error { wrote = true; return nil })
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) || wrote {
					t.Fatal("expired gate wait did not refuse without a write")
				}
			case <-time.After(time.Second):
				t.Fatal("caller remained blocked behind the held admission gate")
			}
		})
	}
	// The zero-value gate permits live callers, and canceled contenders cannot
	// consume its token after returning.
	var mu admissionMutex
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if mu.lock(ctx) == nil {
			t.Fatal("canceled gate caller admitted")
		}
		if err := mu.lock(context.Background()); err != nil {
			t.Fatal(err)
		}
		mu.unlock()
	}
}
