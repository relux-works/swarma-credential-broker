//go:build linux

package qualify

import (
	"context"
	"fmt"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
)

type ownerCompletion uint8

const (
	ownerCompletionUnavailable ownerCompletion = iota
	ownerPending
	ownerReturned
)

type ownerCloseSnapshot struct {
	cancelIssued bool // Only this close method's cancellation, not its parent.
	completion   ownerCompletion
	origin       egress.OriginDiagnostic
	operation    egress.OriginOperation
	child        egress.OriginChildProgress
}

// This is the entire pre-cancel observation: two atomic loads and a nonblocking
// channel sample, with no callback, lock, I/O, wait or retry loop.
func (s *ownerSession) closeSnapshot(cancelIssued bool) ownerCloseSnapshot {
	v := ownerCloseSnapshot{cancelIssued: cancelIssued}
	first := s.origin.Observation()
	if s.done != nil {
		select {
		case <-s.done:
			v.completion = ownerReturned
		default:
			v.completion = ownerPending
		}
	}
	last := s.origin.Observation()
	v.origin, v.operation, v.child = last.OriginDiagnostic, last.Operation, last.Child
	return stableCloseSnapshot(first, v)
}

func stableCloseSnapshot(first egress.OriginObservation, v ownerCloseSnapshot) ownerCloseSnapshot {
	last := egress.OriginObservation{OriginDiagnostic: v.origin, Operation: v.operation, Child: v.child}
	if !first.Valid() || !last.Valid() || first == (egress.OriginObservation{}) || first != last {
		v = ownerCloseSnapshot{cancelIssued: v.cancelIssued}
	}
	return v
}

func ownerDiagnosticClose(ctx context.Context, v *ownerCloseSnapshot) {
	sink := ownerDiagnostics(ctx)
	if sink == nil || v == nil {
		return
	}
	observed := egress.OriginObservation{OriginDiagnostic: v.origin, Operation: v.operation, Child: v.child}
	if !observed.Valid() || observed == (egress.OriginObservation{}) {
		v = &ownerCloseSnapshot{cancelIssued: v.cancelIssued}
	}
	cancel := "not_issued"
	if v.cancelIssued {
		cancel = "issued"
	}
	completion := "unavailable"
	switch v.completion {
	case ownerPending:
		completion = "pending"
	case ownerReturned:
		completion = "returned"
	}
	phase := "unavailable"
	if v.origin.Phase == egress.OriginJoined && (v.origin.Exit == egress.ExitUnavailable || v.origin.Exit > egress.ExitSignaled) {
		// A malformed diagnostic is never an observation of a completed wait.
		v = &ownerCloseSnapshot{cancelIssued: v.cancelIssued, completion: v.completion}
	}
	switch v.origin.Phase {
	case egress.OriginStarting:
		phase = "starting"
	case egress.OriginSupervising:
		phase = "supervising"
	case egress.OriginEntered:
		phase = "entered"
	case egress.OriginTerminal:
		phase = "terminal"
	case egress.OriginJoining:
		phase = "joining"
	case egress.OriginJoined:
		phase = "joined"
	}
	exit := "unavailable"
	if v.origin.Phase == egress.OriginJoined {
		switch v.origin.Exit {
		case egress.ExitZero:
			exit = "zero"
		case egress.ExitNonzero:
			exit = "nonzero"
		case egress.ExitSignaled:
			exit = "signaled"
		}
	}
	// Index only after closed validation. No numeric, caller-provided or OS text
	// reaches the sink; these labels describe observations, never execution credit.
	operations := [...]string{"unavailable", "start", "started_callback", "bootstrap_receive", "bootstrap_ack", "notification", "entry_receive", "entry_ack", "task_inventory", "wait_peek", "terminal_peek", "birth_read", "stop_consume", "resume", "trace_options", "exec_read", "identity", "ready_callback", "challenge", "membership", "terminate", "final_wait", "refusal_cleanup", "waited_callback", "pause"}
	children := [...]string{"unavailable", "started", "stop_observed", "terminal_observed", "wait_returned"}
	sink.emit(fmt.Sprintf("owner close timeout close_cancel=%s supervisor=%s phase=%s exit=%s operation=%s child=%s", cancel, completion, phase, exit, operations[v.operation], children[v.child]))
}
