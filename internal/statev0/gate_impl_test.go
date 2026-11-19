package statev0

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Claim: only the exact live callback token authorizes its own shared gate; copied, zero, foreign, cancelled and escaped tokens cannot run an effect.
func TestSharedGateTokenLifetime(test *testing.T) {
	gate, foreign := NewGate(), NewGate()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var escaped *Tx
	effects := 0
	if err := gate.With(ctx, func(tx *Tx) error {
		escaped = tx
		if err := Use(tx, gate, func() error { effects++; return nil }); err != nil {
			return err
		}
		copied := *tx
		for _, entry := range []struct {
			tx   *Tx
			gate Gate
		}{{nil, gate}, {&Tx{}, gate}, {&copied, gate}, {tx, foreign}} {
			if err := Use(entry.tx, entry.gate, func() error { effects++; return nil }); !errors.Is(err, ErrTransaction) {
				test.Fatal("invalid token authorized effect", err)
			}
		}
		cancel()
		if err := Use(tx, gate, func() error { effects++; return nil }); !errors.Is(err, context.Canceled) {
			test.Fatal("cancelled transaction authorized effect", err)
		}
		return nil
	}); !errors.Is(err, context.Canceled) {
		test.Fatal("callback cancellation lost", err)
	}
	if err := Check(escaped, gate); !errors.Is(err, ErrTransaction) || effects != 1 {
		test.Fatal("escaped transaction remained live", err, effects)
	}
	if err := gate.With(context.Background(), func(tx *Tx) error {
		if err := Check(escaped, gate); !errors.Is(err, ErrTransaction) {
			test.Fatal("old token revived in successor callback", err)
		}
		return Check(tx, gate)
	}); err != nil {
		test.Fatal("valid successor refused", err)
	}
}

// Claim: concurrent publishers share one serialization boundary; cancelled waiters and forbidden recursive acquisition never enter it, and panic releases the gate.
func TestSharedGateSerialization(test *testing.T) {
	gate := NewGate()
	var workers sync.WaitGroup
	count := 0
	for range 32 {
		workers.Go(func() {
			if err := gate.With(context.Background(), func(tx *Tx) error {
				return Use(tx, gate, func() error { count++; return nil })
			}); err != nil {
				test.Error(err)
			}
		})
	}
	workers.Wait()
	if count != 32 {
		test.Fatal("shared state lost a publication", count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.With(ctx, func(*Tx) error { test.Fatal("cancelled waiter entered"); return nil }); !errors.Is(err, context.Canceled) {
		test.Fatal("cancelled waiter did not refuse", err)
	}
	if err := gate.With(context.Background(), func(*Tx) error {
		deadline, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := gate.With(deadline, func(*Tx) error { test.Fatal("recursive gate entered"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
			test.Fatal("recursive acquisition did not stay closed", err)
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				test.Error("panic control did not execute")
			}
		}()
		_ = gate.With(context.Background(), func(*Tx) error { panic("synthetic callback panic") })
	}()
	if err := gate.With(context.Background(), func(tx *Tx) error { return Check(tx, gate) }); err != nil {
		test.Fatal("panic stranded the gate", err)
	}
}
