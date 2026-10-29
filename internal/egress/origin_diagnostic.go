package egress

import "os"

// OriginPhase describes the supervisor's last published observation, not the
// child's current OS state or an origin/qualification certificate.
type OriginPhase uint8

const (
	OriginUnavailable OriginPhase = iota
	OriginStarting
	OriginSupervising
	OriginEntered
	OriginTerminal
	OriginJoining
	OriginJoined
)

type OriginExit uint8

const (
	ExitUnavailable OriginExit = iota
	ExitZero
	ExitNonzero
	ExitSignaled
)

// OriginDiagnostic contains no identity or caller-supplied text. Phase and Exit
// come from one atomic load; none of the authority/credit paths read this word.
type OriginDiagnostic struct {
	Phase OriginPhase
	Exit  OriginExit
}

func (o *CaseOrigin) Diagnostic() OriginDiagnostic {
	if o == nil {
		return OriginDiagnostic{}
	}
	v := o.diagnostic.Load()
	p, e := OriginPhase(v&255), OriginExit(v>>8)
	if v>>16 != 0 || p > OriginJoined || e > ExitSignaled || p != OriginJoined && e != ExitUnavailable || p == OriginJoined && e == ExitUnavailable {
		return OriginDiagnostic{}
	}
	return OriginDiagnostic{p, e}
}

func (o *CaseOrigin) observePhase(p OriginPhase) {
	o.diagnostic.Store(uint32(p))
}

func (o *CaseOrigin) observeWait(state *os.ProcessState) {
	if state == nil {
		return
	}
	e := ExitNonzero
	if state.ExitCode() == 0 {
		e = ExitZero
	} else if state.ExitCode() < 0 {
		e = ExitSignaled
	}
	o.diagnostic.Store(uint32(OriginJoined) | uint32(e)<<8)
}
