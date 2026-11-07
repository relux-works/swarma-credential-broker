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

// OriginOperation names an entered supervisor operation, never its arguments.
// It is an observation of control flow, not proof that a syscall is blocked.
type OriginOperation uint8

const (
	OperationUnavailable OriginOperation = iota
	OperationStart
	OperationStartedCallback
	OperationBootstrapReceive
	OperationBootstrapAck
	OperationNotification
	OperationEntryReceive
	OperationEntryAck
	OperationTaskInventory
	OperationWaitPeek
	OperationTerminalPeek
	OperationBirthRead
	OperationStopConsume
	OperationResume
	OperationTraceOptions
	OperationExecRead
	OperationIdentity
	OperationReadyCallback
	OperationChallenge
	OperationMembership
	OperationTerminate
	OperationFinalWait
	OperationRefusalCleanup
	OperationWaitedCallback
	OperationPause
)

// OriginChildProgress is the last separately observed owned-child event. A stop
// or non-consuming terminal peek is not a completed child wait.
type OriginChildProgress uint8

const (
	ChildUnavailable OriginChildProgress = iota
	ChildStarted
	ChildStopObserved
	ChildTerminalObserved
	ChildWaitReturned
)

// OriginObservation is one atomic, payload-free publication. Its fields never
// supply authority or execution credit. Unavailable does not imply inactivity.
type OriginObservation struct {
	OriginDiagnostic
	Operation OriginOperation
	Child     OriginChildProgress
}

// Valid also checks synthetic formatter inputs; enum neighbours cannot turn a
// malformed observation into a completed wait.
func (v OriginObservation) Valid() bool {
	if v.Phase == OriginUnavailable {
		// A refused final wait clears phase, exit and child evidence. Its
		// entered Waited(nil) callback is still known until that call returns.
		return v.Exit == ExitUnavailable && v.Child == ChildUnavailable &&
			(v.Operation == OperationUnavailable || v.Operation == OperationWaitedCallback)
	}
	return v.Phase <= OriginJoined && v.Exit <= ExitSignaled &&
		v.Operation <= OperationPause && v.Child <= ChildWaitReturned &&
		(v.Phase == OriginJoined) == (v.Exit != ExitUnavailable) &&
		(v.Child != ChildWaitReturned || v.Phase == OriginJoined) &&
		(v.Phase != OriginJoined || (v.Operation == OperationUnavailable || v.Operation == OperationWaitedCallback) && (v.Child == ChildUnavailable || v.Child == ChildWaitReturned))
}

func (o *CaseOrigin) Diagnostic() OriginDiagnostic {
	return o.Observation().OriginDiagnostic
}

func (o *CaseOrigin) Observation() OriginObservation {
	if o == nil {
		return OriginObservation{}
	}
	v := o.diagnostic.Load()
	s := OriginObservation{OriginDiagnostic{OriginPhase(v & 255), OriginExit(v >> 8 & 255)}, OriginOperation(v >> 16 & 255), OriginChildProgress(v >> 24)}
	if !s.Valid() {
		return OriginObservation{}
	}
	return s
}

func (o *CaseOrigin) observePhase(p OriginPhase) {
	if p == OriginUnavailable {
		o.diagnostic.Store(0)
		return
	}
	o.diagnostic.Store(o.diagnostic.Load()&0xffff0000 | uint32(p))
}

// Only the owning supervisor writes these observations. Readers only load;
// publication adds no CAS retry, wait event, lock, callback or OS query.
func (o *CaseOrigin) observeOperation(op OriginOperation) {
	if o != nil {
		o.diagnostic.Store(o.diagnostic.Load()&0xff00ffff | uint32(op)<<16)
	}
}

func (o *CaseOrigin) observeChild(p OriginChildProgress) {
	if o != nil {
		o.diagnostic.Store(o.diagnostic.Load()&0x00ffffff | uint32(p)<<24)
	}
}

func (o *CaseOrigin) observeWait(state *os.ProcessState) {
	e := ExitUnavailable
	if state != nil {
		if state.Exited() {
			if code := state.ExitCode(); code == 0 {
				e = ExitZero
			} else if code > 0 {
				e = ExitNonzero
			}
		} else if status, ok := state.Sys().(interface{ Signaled() bool }); ok && status.Signaled() {
			// Unix WaitStatus distinguishes actual signal death from a ptrace
			// stop. Both can have ExitCode -1; that value alone proves neither.
			e = ExitSignaled
		}
	}
	if e == ExitUnavailable {
		// Do not retain a previous terminal observation for nil/non-exit input.
		o.observePhase(OriginUnavailable)
		return
	}
	o.diagnostic.Store(uint32(OriginJoined) | uint32(e)<<8 | uint32(ChildWaitReturned)<<24)
}
