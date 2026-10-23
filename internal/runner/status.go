package runner

import (
	"context"
	"io"
)

// Phases match the normative table in docs/runner.md. They describe the active
// operation, rather than guessing provenance from an arbitrary error chain.
type phase string

const (
	phasePreflight  phase = "preflight"
	phaseAuthority  phase = "authority"
	phaseConnect    phase = "connect/verify"
	phaseHello      phase = "hello"
	phaseRequest    phase = "request"
	phaseRecheck    phase = "recheck"
	phaseInitialize phase = "start/initialize"
	phaseLogin      phase = "login"
	phaseTurn       phase = "turn"
	phaseRefresh    phase = "refresh"
	phaseStreaming  phase = "streaming"
	phaseFinal      phase = "final"
	phaseTeardown   phase = "teardown"
	phaseRelease    phase = "release"
)

type origin uint8

const (
	originSuccess origin = iota
	originInput
	originAdmission
	originTransport
	originOwnStop
	originOutput
	originRenewal
	originCleanup
	originRelease
	originVendor
	originUnexpected
)

type stopCause uint8

const (
	stopNone stopCause = iota
	stopDeadline
	stopInterrupt
)

type exitFailure struct {
	phase  phase
	origin origin
	code   string
}

func (f *exitFailure) Error() string { return f.code }

type statusRecord struct {
	phase      phase
	failure    *exitFailure
	ownStop    stopCause
	outputStop stopCause
	execution  context.Context
}
type observationKey struct{}

// Only direct, runner-created failures are consumed here. No Error, Unwrap,
// Is or As method on a foreign error is called, including typed-nil errors.
func (r *statusRecord) capture(err error) {
	if err == nil {
		return
	}
	if f, ok := err.(*exitFailure); ok && f != nil {
		r.failure = f
		return
	}
	f := &exitFailure{r.phase, originTransport, "credential_injection_unavailable"}
	if e, ok := err.(*Refusal); ok && e != nil {
		f.code = e.Code
		switch e.Status {
		case 64:
			f.origin = originInput
		case 69:
			f.origin = originAdmission
		case 75:
			switch {
			case e.Code == "output_unavailable":
				f.origin = originOutput
			case e.Code == "lease_not_active":
				f.origin = originRenewal
			case r.phase == phaseStreaming || r.phase == phaseFinal:
				f.origin = originOutput
			case r.phase == phaseRefresh:
				f.origin = originRenewal
			case r.phase == phaseRelease:
				f.origin = originRelease
			default:
				f.origin = originCleanup
			}
		case 1:
			f.origin = originVendor
		}
	}
	r.failure = f
}
func (r *statusRecord) observe(ctx context.Context) {
	if r.ownStop != stopNone || ctx == nil {
		return
	}
	// Context errors are observed directly; adapter errors cannot set this field.
	switch ctx.Err() {
	case context.DeadlineExceeded:
		r.ownStop = stopDeadline
	case context.Canceled:
		r.ownStop = stopInterrupt
	}
}
func (r *statusRecord) unexpected() {
	code := "credential_injection_unavailable"
	if r.phase == phaseStreaming || r.phase == phaseFinal {
		code = "output_unavailable"
	}
	r.capture(&exitFailure{r.phase, originUnexpected, code})
}
func (r *statusRecord) outputFailure() error {
	if r.outputStop != stopNone {
		r.ownStop = r.outputStop
		return &exitFailure{r.phase, originOwnStop, "execution_stopped"}
	}
	return &exitFailure{r.phase, originOutput, "output_unavailable"}
}
func unavailable(p phase) bool {
	return p == phaseRefresh || p == phaseStreaming || p == phaseFinal || p == phaseTeardown || p == phaseRelease
}

// classify is the only exit-status mapping. Cleanup has already run. Its guard
// also protects the diagnostic embedding seam; no foreign error is formatted.
func classify(r *statusRecord, w io.Writer) (status int) {
	status = 75
	defer func() {
		if recover() != nil {
			status = 75
		}
	}()
	r.observe(r.execution)
	code := ""
	f := r.failure
	switch {
	case f != nil && (f.origin == originOutput || f.origin == originRenewal || f.origin == originCleanup || f.origin == originRelease || f.origin == originUnexpected && unavailable(f.phase)):
		status, code = 75, f.code
	case r.ownStop == stopDeadline:
		status, code = 124, "execution_deadline"
	case r.ownStop == stopInterrupt:
		status, code = 130, "interrupted"
	case f == nil:
		status = 0
	case f.origin == originInput:
		status, code = 64, f.code
	case f.origin == originVendor:
		status, code = 1, f.code
	default:
		status, code = 69, f.code
	}
	if code != "" {
		report(w, code)
	}
	return
}

// Each cleanup operation is isolated so a panicking adapter cannot skip stop,
// release, erasure or the remaining independent cleanup operations.
func cleanupAttempt(fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = refuse("teardown_unconfirmed", 75)
		}
	}()
	return fn()
}
