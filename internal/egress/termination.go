package egress

import (
	"context"
	"encoding/hex"
	"os"
	"sync"
)

// TerminationController is a parent-only, single-use qualification authority.
// It is never inherited by the supervised image. Run still returns its actual
// nonzero wait error and invalidates ordinary origin facts after SIGKILL.
type TerminationController struct {
	mu      sync.Mutex
	origin  *CaseOrigin
	request chan string
	used    bool
	fact    TerminationFacts
}

// TerminationFacts describe a planned terminal event, not ordinary run credit.
// Gate is the parent's sealed semantic-prefix digest, not a child phase claim.
type TerminationFacts struct {
	Context, Gate, WaitError                             string
	PID, Signal, Exit, Waits                             int
	Verified, Entered, SignalSent, TraceComplete, Joined bool
	valid                                                bool `json:"-"`
}

func (f TerminationFacts) Valid() bool {
	return f.valid && f.Context != "" && digest32(f.Gate) && f.PID > 0 && f.Verified && f.Entered && f.SignalSent && f.Signal == 9 && f.Exit == -1 && f.Waits == 1 && f.WaitError != "" && f.TraceComplete && f.Joined
}

func digest32(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// Kill consumes one authorization only while the measured role is live. The
// supervisor, which owns the pidfd and sole wait, performs the actual signal.
// A gate digest must be made only after checking a held synchronous call.
func (c *TerminationController) Kill(ctx context.Context, gate string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used || !digest32(gate) || !c.origin.Live(int(c.origin.pid.Load())) || ctx.Err() != nil {
		return ErrUnavailable
	}
	c.used = true
	select {
	case c.request <- gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *TerminationController) Facts() TerminationFacts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fact
}

func plannedOrigin(o *CaseOrigin) (*CaseOrigin, *TerminationController, error) {
	c := &TerminationController{origin: o, request: make(chan string, 1)}
	o.termination = c
	return o, c, nil
}

// Record only a supervisor-issued signal, never teardown's forced cleanup.
func (c *TerminationController) sent(gate string, sent bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fact = TerminationFacts{Context: c.origin.ownerContext, Gate: gate, PID: int(c.origin.pid.Load()), Verified: c.origin.verified.Load(), Entered: c.origin.entered.Load(), SignalSent: sent}
}

func (c *TerminationController) joined(state *os.ProcessState, waitErr, supervisionErr error, traceComplete bool, signal int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := &c.fact
	f.TraceComplete = traceComplete
	f.Waits++
	if state != nil {
		f.Joined = true
		f.Exit = state.ExitCode()
	}
	f.Signal = signal
	if waitErr != nil {
		f.WaitError = waitErr.Error()
	}
	f.valid = supervisionErr == nil && !c.origin.invalid.Load() && f.SignalSent
}
