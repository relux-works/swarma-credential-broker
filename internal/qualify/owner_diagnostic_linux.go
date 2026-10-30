//go:build linux

package qualify

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Only tests install this sink. The parent collector owns its state; child
// supervisors never write it. No diagnostic becomes qualification evidence.
type ownerDiagnosticSinkKey struct{}
type ownerDiagnosticSink struct {
	emit                       func(string)
	row, side, scenario, phase string
	start, deadline            time.Time
	failed                     string
	emitted                    bool
}

func ownerDiagnostics(ctx context.Context) *ownerDiagnosticSink {
	if ctx == nil {
		return nil
	}
	sink, _ := ctx.Value(ownerDiagnosticSinkKey{}).(*ownerDiagnosticSink)
	return sink
}

func (s *ownerDiagnosticSink) begin(row, side string) {
	if s == nil {
		return
	}
	s.row, s.side, s.emitted = row, side, false
}

func ownerDiagnosticScenario(ctx context.Context, scenario string) {
	s := ownerDiagnostics(ctx)
	if s == nil {
		return
	}
	// Derive labels from the closed script table, never from frame contents.
	if s.row == "" {
		s.row, s.side = "unknown", "unknown"
		for _, row := range []string{"daemon-death", "replacement-contention", "transient-ambiguous", "rotation-crash", "cleanup-interrupted"} {
			for _, side := range []string{"positive", "negative"} {
				for _, script := range lifecycleScripts(row, side) {
					if script == scenario {
						s.row, s.side = row, side
					}
				}
			}
		}
	}
	if !lifecycleScenario(scenario) {
		scenario = "unknown"
	}
	s.scenario, s.phase, s.failed = scenario, "scenario-start", ""
	s.start = time.Now()
	s.deadline, _ = ctx.Deadline()
}

// Labels are deliberately closed: frame data, paths, identities, and payloads
// must never reach the diagnostic, even when a synthetic peer misbehaves.
func ownerDiagnosticOp(op string) string {
	switch op {
	case "startup", "challenge", "persist", "close", "lease.request", "lease.renew", "lease.release", "prerequisite", "constructor", "ready", "call-event", "account", "read", "start", "observe", "stop", "confidence":
		return op
	}
	return "other"
}

func ownerDiagnosticWait(ctx context.Context, wait string) func(error) {
	s := ownerDiagnostics(ctx)
	if s == nil {
		return func(error) {}
	}
	start := time.Now()
	return func(err error) {
		if err == nil {
			s.phase = wait + " completed"
			return
		}
		chain, held := ownerDiagnosticInspect(err)
		if held {
			return
		}
		if s.failed == "" {
			s.failed = fmt.Sprintf("last=%q pending=%q wait_elapsed=%s work_elapsed=%s work_budget=%s cause=%s", s.phase, wait, time.Since(start), time.Since(s.start), s.deadline.Sub(s.start), chain)
		}
	}
}

// Preserve the chain structure and standard causes without formatting arbitrary
// errors (PathError, peer errors, and wrapper text can carry paths or material).
func ownerDiagnosticError(err error) string {
	chain, _ := ownerDiagnosticInspect(err)
	return chain
}

const ownerDiagnosticBudget = 8

// Classification shares the formatter's walk: no custom Is/As/Error methods
// run. Nil joined children also consume steps, so wide fanout cannot evade the
// bound. An exhausted walk is unknown, even if another branch contained Held.
// The bound limits traversal calls, not arbitrary work inside an Unwrap method.
func ownerDiagnosticInspect(err error) (chain string, held bool) {
	var b strings.Builder
	var visit func(error)
	steps, nodes := 0, 0
	truncated := false
	visit = func(e error) {
		if steps >= ownerDiagnosticBudget {
			truncated = true
			return
		}
		steps++
		if e == nil {
			return
		}
		if nodes > 0 {
			b.WriteString(" -> ")
		}
		nodes++
		held = held || e == errOwnerHeld
		label := "text-redacted"
		switch e {
		case context.DeadlineExceeded:
			label = "deadline exceeded"
		case context.Canceled:
			label = "canceled"
		case io.EOF:
			label = "EOF"
		case io.ErrUnexpectedEOF:
			label = "unexpected EOF"
		case io.ErrClosedPipe:
			label = "closed pipe"
		case os.ErrDeadlineExceeded:
			label = "I/O timeout"
		default:
			label = ownerDiagnosticLiteralLabel(e)
		}
		fmt.Fprintf(&b, "%T(%s)", e, label)
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			if steps == ownerDiagnosticBudget {
				truncated = true
				return
			}
			for _, child := range joined.Unwrap() {
				if steps == ownerDiagnosticBudget {
					truncated = true
					break
				}
				visit(child)
			}
		} else if single, ok := e.(interface{ Unwrap() error }); ok {
			if steps == ownerDiagnosticBudget {
				truncated = true
				return
			}
			visit(single.Unwrap())
		}
	}
	visit(err)
	if truncated {
		b.WriteString(" -> truncated")
		held = false
	}
	return b.String(), held
}

func ownerDiagnosticFailure(ctx context.Context, err error) {
	s := ownerDiagnostics(ctx)
	if s == nil || err == nil || s.emitted {
		return
	}
	s.emitted = true
	state := s.failed
	if state == "" {
		state = fmt.Sprintf("last=%q pending=none work_elapsed=%s work_budget=%s", s.phase, time.Since(s.start), s.deadline.Sub(s.start))
	}
	schedule := "sequential"
	if strings.HasSuffix(s.scenario, "-a") {
		schedule = "A-first"
	}
	if strings.HasSuffix(s.scenario, "-b") {
		schedule = "B-first"
	}
	record := fmt.Sprintf("owner failure row=%s side=%s scenario=%s schedule=%s %s error_chain=%s", s.row, s.side, s.scenario, schedule, state, ownerDiagnosticError(err))
	if len(record) > 2048 {
		record = record[:2048]
	}
	s.emit(record)
}

func ownerDiagnosticPhase(ctx context.Context, phase string) {
	if s := ownerDiagnostics(ctx); s != nil {
		s.phase = phase
	}
}
func ownerDiagnosticMember(member string) string {
	switch member {
	case "A", "B", "O1":
		return member
	}
	return "owner"
}
