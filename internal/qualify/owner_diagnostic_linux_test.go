//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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
