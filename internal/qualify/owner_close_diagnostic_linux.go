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
}

// This is the entire pre-cancel observation: two atomic loads and a nonblocking
// channel sample, with no callback, lock, I/O, wait or retry loop.
func (s *ownerSession) closeSnapshot(cancelIssued bool) ownerCloseSnapshot {
	v := ownerCloseSnapshot{cancelIssued: cancelIssued}
	first := s.origin.Diagnostic()
	if s.done != nil {
		select {
		case <-s.done:
			v.completion = ownerReturned
		default:
			v.completion = ownerPending
		}
	}
	v.origin = s.origin.Diagnostic()
	return stableCloseSnapshot(first, v)
}

func stableCloseSnapshot(first egress.OriginDiagnostic, v ownerCloseSnapshot) ownerCloseSnapshot {
	if first != v.origin {
		v.completion = ownerCompletionUnavailable
		v.origin = egress.OriginDiagnostic{}
	}
	return v
}

func ownerDiagnosticClose(ctx context.Context, v *ownerCloseSnapshot) {
	sink := ownerDiagnostics(ctx)
	if sink == nil || v == nil {
		return
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
	sink.emit(fmt.Sprintf("owner close timeout close_cancel=%s supervisor=%s phase=%s exit=%s", cancel, completion, phase, exit))
}
