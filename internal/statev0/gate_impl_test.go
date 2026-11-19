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

// Claim: concurrent publishers share one serialization boundary; cancelled waiters and recursive With acquisition never enter it, and panic releases the gate.
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

// Claim: sequential token uses succeed; nested Use/Check refuse without an effect or deadlock, and cancellation leaves the gate available to a successor. Arbitrary blocking caller work is outside this synchronous contract.
func TestSharedGateNestedUseRefuses(test *testing.T) {
	for _, name := range []string{"sequential", "nested-use", "nested-check", "cancelled-nested-check"} {
		test.Run(name, func(test *testing.T) {
			gate := NewGate()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			type result struct {
				err     error
				nested  error
				effects int
			}
			done := make(chan result, 1)
			go func() {
				observed := result{}
				observed.err = gate.With(ctx, func(tx *Tx) error {
					if err := Check(tx, gate); err != nil {
						return err
					}
					return Use(tx, gate, func() error {
						observed.effects++
						switch name {
						case "nested-use":
							observed.nested = Use(tx, gate, func() error { observed.effects++; return nil })
						case "nested-check", "cancelled-nested-check":
							if name == "cancelled-nested-check" {
								cancel()
							}
							observed.nested = Check(tx, gate)
						}
						return nil
					})
				})
				done <- observed
			}()
			select {
			case observed := <-done:
				if observed.effects != 1 || name != "sequential" && !errors.Is(observed.nested, ErrTransaction) {
					test.Fatal("nested token use did not refuse without effects", observed)
				}
				if name == "cancelled-nested-check" {
					if !errors.Is(observed.err, context.Canceled) {
						test.Fatal("nested cancellation did not fail closed", observed.err)
					}
				} else if observed.err != nil {
					test.Fatal("valid outer use failed", observed.err)
				}
			case <-time.After(2 * time.Second):
				test.Fatal("nested token use deadlocked past its transaction deadline")
			}
			successor, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := gate.With(successor, func(tx *Tx) error { return Check(tx, gate) }); err != nil {
				test.Fatal("nested use or cancellation stranded the shared gate", err)
			}
		})
	}
}
