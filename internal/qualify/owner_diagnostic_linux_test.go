//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Installation is intentionally absent from the compiled production graph.
func withOwnerDiagnostics(ctx context.Context, emit func(string)) context.Context {
	return context.WithValue(ctx, ownerDiagnosticSinkKey{}, &ownerDiagnosticSink{emit: emit})
}

// Claim: one expired synthetic mux wait retains the scenario, schedule, last
// phase, deadline budget and underlying cause; a ready frame is silent. No
// process, real account, timer race, or production timeout injection is involved.
func TestOwnerDiagnosticSingleWaitTimeout(t *testing.T) {
	for _, scenario := range []string{"contention-unresolved-a", "contention-unresolved-b"} {
		for _, timeout := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/timeout=%t", scenario, timeout), func(t *testing.T) {
				var logs []string
				parent := withOwnerDiagnostics(context.Background(), func(s string) { logs = append(logs, s) })
				deadline := time.Now().Add(time.Second)
				if timeout {
					deadline = time.Now().Add(-time.Second)
				}
				ctx, cancel := context.WithDeadline(parent, deadline)
				defer cancel()
				ownerDiagnosticScenario(ctx, scenario)
				ownerDiagnosticPhase(ctx, "both constructors held")
				mux := &parallelMux{ctx: ctx, events: make(chan parallelFrame, 1), done: make(chan struct{})}
				if !timeout {
					mux.events <- parallelFrame{Kind: "notice", Op: "startup"}
				}
				h := &parallelHarness{ctx: ctx}
				_, err := h.take(&parallelSession{mux: mux, member: "A"}, func(f parallelFrame) bool { return f.Kind == "notice" })
				ownerDiagnosticFailure(ctx, fmtDiagnosticError(err))
				if !timeout {
					if err != nil || len(logs) != 0 {
						t.Fatalf("ready control: %v %v", err, logs)
					}
					return
				}
				if !errors.Is(err, context.DeadlineExceeded) || len(logs) != 1 {
					t.Fatalf("single-wait failure missing: %v %v", err, logs)
				}
				wantSchedule := "A-first"
				if strings.HasSuffix(scenario, "-b") {
					wantSchedule = "B-first"
				}
				for _, want := range []string{"row=replacement-contention", "side=negative", "scenario=" + scenario, "schedule=" + wantSchedule, "last=\"both constructors held\"", "pending=\"mux.nextFrame/A\"", "wait_elapsed=", "work_elapsed=", "work_budget=", "*fmt.wrapError", "deadline exceeded"} {
					if !strings.Contains(logs[0], want) {
						t.Errorf("missing %q: %s", want, logs[0])
					}
				}
				// Cleanup and repeated reports cannot replace the original failed wait.
				ownerDiagnosticWait(ctx, "cleanup join")(errors.New("later error"))
				ownerDiagnosticFailure(ctx, err)
				if len(logs) != 1 {
					t.Fatal("unbounded repeated diagnostic", logs)
				}
			})
		}
	}
}

func fmtDiagnosticError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("synthetic wait: %w", err)
}

// Claim: diagnostics cannot expose arbitrary wrapper/PathError text, and chain
// fanout and cycles remain bounded. A known deadline remains identifiable.
func TestOwnerDiagnosticBounds(t *testing.T) {
	material := strings.Repeat("synthetic-private-marker", 200)
	err := errors.Join(&os.PathError{Op: material, Path: material, Err: context.DeadlineExceeded}, fmt.Errorf("%s: %w", material, context.Canceled))
	text := ownerDiagnosticError(err)
	if strings.Contains(text, "synthetic-private-marker") || !strings.Contains(text, "*fs.PathError") || !strings.Contains(text, "deadline exceeded") || !strings.Contains(text, "canceled") || len(text) > 1024 {
		t.Fatal("unsafe error chain", text)
	}
	if text := ownerDiagnosticError(&ownerDiagnosticCycle{}); len(text) > 1024 || strings.Count(text, "text-redacted") != 8 {
		t.Fatal("unbounded cycle", text)
	}
}

type ownerDiagnosticCycle struct{}

func (*ownerDiagnosticCycle) Error() string   { return "synthetic-private-marker" }
func (e *ownerDiagnosticCycle) Unwrap() error { return e }

type ownerDiagnosticCounted struct {
	next  error
	steps *atomic.Int32
	cycle bool
}

func (*ownerDiagnosticCounted) Error() string { return "generated counted error" }
func (e *ownerDiagnosticCounted) Unwrap() error {
	// The fixture terminates even under an unbounded-classification mutant.
	if e.steps.Add(1) >= 64 {
		return context.Canceled
	}
	if e.cycle {
		return e
	}
	return e.next
}

type ownerDiagnosticJoined struct {
	children []error
	steps    *atomic.Int32
}

func (*ownerDiagnosticJoined) Error() string { return "generated joined error" }
func (e *ownerDiagnosticJoined) Unwrap() []error {
	e.steps.Add(1)
	return e.children
}

// Claim: the real instrumented mux wait shares one eight-step walk between
// held classification and formatting. Oversized/cyclic chains and wide nil
// fanout become truncated/unknown; in-budget Held remains expected. The cycle
// has a separate fixture step cap and timeout guard. Without a sink the wait
// returns the identical error without any walk. Unwrap method internals are
// outside the traversal-call bound.
func TestOwnerDiagnosticWaitTraversalBudget(t *testing.T) {
	for _, test := range []struct {
		name                 string
		enabled, held, cycle bool
		wrappers             int
		joined               bool
		wantHeld, truncated  bool
	}{
		{name: "no-sink", wrappers: 32},
		{name: "over-budget", enabled: true, wrappers: 32, truncated: true},
		{name: "held-within-budget", enabled: true, held: true, wrappers: 7, wantHeld: true},
		{name: "held-beyond-budget", enabled: true, held: true, wrappers: 8, truncated: true},
		{name: "cycle", enabled: true, cycle: true, truncated: true},
		{name: "nil-fanout", enabled: true, joined: true, truncated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var steps atomic.Int32
			var failure error = context.DeadlineExceeded
			if test.held {
				failure = errOwnerHeld
			}
			for i := 0; i < test.wrappers; i++ {
				failure = &ownerDiagnosticCounted{next: failure, steps: &steps}
			}
			if test.cycle {
				failure = &ownerDiagnosticCounted{steps: &steps, cycle: true}
			}
			if test.joined {
				children := make([]error, 32)
				children[len(children)-1] = errOwnerHeld
				failure = &ownerDiagnosticJoined{children: children, steps: &steps}
			}
			ctx := context.Background()
			if test.enabled {
				ctx = withOwnerDiagnostics(ctx, func(string) { t.Error("wait emitted a report") })
				ownerDiagnosticScenario(ctx, "contention-unresolved-a")
				ownerDiagnosticPhase(ctx, "before wait")
			}
			done := make(chan struct{})
			close(done)
			mux := &parallelMux{ctx: ctx, events: make(chan parallelFrame), done: done, err: failure}
			h := &parallelHarness{ctx: ctx}
			result := make(chan error, 1)
			go func() {
				_, err := h.take(&parallelSession{mux: mux, member: "A"}, func(parallelFrame) bool { return false })
				result <- err
			}()
			select {
			case err := <-result:
				if err != failure {
					t.Fatal("wait changed returned error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("bounded fixture wait did not terminate")
			}
			if !test.enabled {
				if steps.Load() != 0 {
					t.Fatal("nil sink walked error", steps.Load())
				}
				return
			}
			if steps.Load() > 8 {
				t.Fatal("diagnostic wait exceeded traversal budget", steps.Load())
			}
			s := ownerDiagnostics(ctx)
			if test.wantHeld {
				if s.failed != "" || s.phase != "before wait" {
					t.Fatal("in-budget held error recorded as failed", s.failed, s.phase)
				}
			} else if !strings.Contains(s.failed, "pending=\"mux.nextFrame/A\"") || strings.Contains(s.failed, "truncated") != test.truncated {
				t.Fatal("unknown error lost wait/truncation", s.failed)
			}
		})
	}
}

// Claim: the changed existing row collector retains the original pending
// Control bytes and no artifact after an expired work context, with or without
// the test-only sink. The installed sink retains the formerly discarded error.
func TestOwnerDiagnosticRowOutputParity(t *testing.T) {
	broker, _, _ := ownerTools(t)
	_, c, root := setup(t)
	d := newFixtureDriver("", "0.163.0")
	d.rowExecutable = broker.Name()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var logs []string
	baseline, err := wire.Encode(pendingRowControl())
	if err != nil {
		t.Fatal(err)
	}
	for _, withSink := range []bool{false, true} {
		parent := ctx
		if withSink {
			parent = withOwnerDiagnostics(ctx, func(s string) { logs = append(logs, s) })
		}
		got := d.runRow(parent, c.Policy, root, "replacement-contention", "negative")
		raw, err := wire.Encode(got)
		if err != nil || !bytes.Equal(raw, baseline) {
			t.Fatalf("pending output changed: %s %v", raw, err)
		}
		if _, err := os.Stat(rowFile(root, "replacement-contention", "negative")); !os.IsNotExist(err) {
			t.Fatal("failed row gained artifact", err)
		}
		if !withSink && len(logs) != 0 {
			t.Fatal("nil sink emitted")
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "scenario=contention-unresolved-a") || !strings.Contains(logs[0], "error_chain=") {
		t.Fatal("collector discarded failure", logs)
	}
}
