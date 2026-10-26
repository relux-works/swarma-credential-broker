package runner

import "context"

// Outcome is the completed Command status and a bounded local classification.
// It is code testimony, not independent proof of invocation or observed effects.
type Outcome struct {
	Status int
	Kind   OutcomeKind
}
type OutcomeKind uint8

const (
	OutcomeSuccess OutcomeKind = iota + 1
	OutcomeSourceConflict
	OutcomeFailure
)

type outcomeContext struct {
	context.Context
	out *Outcome
}

// CommandWithOutcome shares Command's execution and final deferred classifier.
// No result is observable until Command's cleanup and panic handling return.
func CommandWithOutcome(ctx context.Context, args []string, streams IO, d Dependencies) (out Outcome) {
	out.Status = Command(&outcomeContext{ctx, &out}, args, streams, d)
	return
}
