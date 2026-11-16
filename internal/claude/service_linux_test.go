//go:build linux

package claude

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Expired, held, cancelled and invalid publication requests never invoke their
// material consumer. Each case starts with a real protected-store valid control.
func TestGatewayCustodyRefusalNeighbors(t *testing.T) {
	for _, name := range []string{"held", "expired", "cancelled", "nil-clock", "nil-consumer", "corrupt-material"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			enroll(t, f.a)
			now := time.Now().UTC()
			clock := func() time.Time { return now }
			expires := now.Add(time.Minute)
			calls := 0
			consumer := func(token []byte) error {
				calls++
				if string(token) != fakeToken {
					t.Fatal("gateway material control mismatch")
				}
				return nil
			}
			if f.a.Publish(context.Background(), expires, clock, consumer) != nil || calls != 1 {
				t.Fatal("custody publication control failed")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "held":
				if f.a.Hold() != nil {
					t.Fatal("hold failed")
				}
			case "expired":
				expires = now
			case "cancelled":
				cancel()
			case "nil-clock":
				clock = nil
			case "nil-consumer":
				consumer = nil
			case "corrupt-material":
				if os.WriteFile(filepath.Join(f.dir, materialName), []byte("{}"), 0600) != nil {
					t.Fatal("fixture corruption failed")
				}
			}
			before := calls
			err := f.a.Publish(ctx, expires, clock, consumer)
			if !errors.Is(err, ErrUnavailable) || calls != before {
				t.Fatal("invalid custody request delivered material")
			}
			safeOutput(t, []byte(err.Error()))
		})
	}
}

// Hold cannot acknowledge or update state while a material callback still owns
// the account gate; after it returns, held state prevents every later callback.
func TestGatewayCustodyHoldFence(t *testing.T) {
	f := newFixture(t, nil)
	enroll(t, f.a)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		done <- f.a.Publish(context.Background(), time.Now().Add(time.Minute), time.Now, func([]byte) error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("custody callback not entered")
	}
	if f.a.mu.TryLock() {
		f.a.mu.Unlock()
		t.Fatal("account gate released before publication")
	}
	unblock()
	if <-done != nil {
		t.Fatal("publication control failed")
	}
	if f.a.Hold() != nil {
		t.Fatal("hold after publication failed")
	}
	called := false
	if f.a.Publish(context.Background(), time.Now().Add(time.Minute), time.Now, func([]byte) error { called = true; return nil }) == nil || called {
		t.Fatal("held account released material")
	}
}
