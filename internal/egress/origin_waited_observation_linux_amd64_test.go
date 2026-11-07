//go:build linux && amd64

package egress

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// An empty unstarted Cmd takes the real refusal defer without a child, PID,
// signal, wait syscall or procfs read. The callback observes its own entry.
func TestWaitedRefusalObservation(t *testing.T) {
	o := &CaseOrigin{}
	// Stale synthetic diagnostics must be cleared by the failed wait.
	o.diagnostic.Store(observationWord(OriginObservation{OriginDiagnostic{OriginJoined, ExitZero}, OperationUnavailable, ChildWaitReturned}))
	cmd := &exec.Cmd{}
	calls := 0
	err := o.finishWait(cmd, Config{Waited: func(state *os.ProcessState) {
		calls++
		if state != nil {
			t.Error("refusal supplied terminal state")
		}
		want := OriginObservation{Operation: OperationWaitedCallback}
		got := o.Observation()
		t.Logf("callback raw=%08x decoded=%+v", o.diagnostic.Load(), got)
		if got != want || !got.Valid() || o.Diagnostic() != (OriginDiagnostic{}) {
			t.Errorf("entered callback lost or acquired wait evidence: got %+v want %+v", got, want)
		}
		if o.Facts() != (OriginFacts{}) || o.Live(0) {
			t.Error("refused wait acquired authority")
		}
	}}, &originOwner{})
	if !errors.Is(err, ErrUnavailable) || calls != 1 || cmd.Process != nil || cmd.ProcessState != nil {
		t.Fatalf("refusal changed: err=%v calls=%d cmd=%+v", err, calls, cmd)
	}
	if o.Observation() != (OriginObservation{}) || o.Facts() != (OriginFacts{}) || o.Live(0) {
		t.Fatal("callback return retained operation or granted authority")
	}
	if err = o.finishWait(cmd, Config{Waited: func(*os.ProcessState) { calls++ }}, &originOwner{}); !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatal("refusal callback repeated", err, calls)
	}
}

func TestWaitedObservationValidNeighbours(t *testing.T) {
	for _, phase := range []OriginPhase{OriginJoining, OriginJoined} {
		o := &CaseOrigin{}
		want := OriginObservation{OriginDiagnostic{phase, ExitUnavailable}, OperationWaitedCallback, ChildStopObserved}
		if phase == OriginJoined {
			want.Exit, want.Child = ExitZero, ChildWaitReturned
		}
		o.diagnostic.Store(observationWord(want))
		if got := o.Observation(); got != want || !got.Valid() {
			t.Fatalf("valid neighbour discarded: %+v want %+v", got, want)
		}
		if o.Facts() != (OriginFacts{}) || o.Live(0) {
			t.Fatal("synthetic diagnostic granted authority")
		}
	}
}

func TestWaitedUnknownObservationClosedState(t *testing.T) {
	o := &CaseOrigin{}
	check := func(v OriginObservation, valid bool) {
		t.Helper()
		o.diagnostic.Store(observationWord(v))
		if v.Valid() != valid || valid && o.Observation() != v || !valid && o.Observation() != (OriginObservation{}) {
			t.Fatalf("unknown phase contract: %+v valid=%v decoded=%+v", v, valid, o.Observation())
		}
	}
	for b := 0; b <= 255; b++ {
		op := OriginOperation(b)
		check(OriginObservation{Operation: op}, op == OperationUnavailable || op == OperationWaitedCallback)
		check(OriginObservation{Operation: OperationWaitedCallback, Child: OriginChildProgress(b)}, b == 0)
		check(OriginObservation{OriginDiagnostic: OriginDiagnostic{Exit: OriginExit(b)}, Operation: OperationWaitedCallback}, b == 0)
	}
}
