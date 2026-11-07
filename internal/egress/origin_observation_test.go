package egress

import (
	"sync"
	"testing"
)

func observationWord(v OriginObservation) uint32 {
	return uint32(v.Phase) | uint32(v.Exit)<<8 | uint32(v.Operation)<<16 | uint32(v.Child)<<24
}

// These are inert publications, not simulated child waits or execution proof.
func TestOriginObservationTransitions(t *testing.T) {
	o := &CaseOrigin{}
	steps := []OriginObservation{
		{},
		{OriginDiagnostic{OriginStarting, ExitUnavailable}, OperationStart, ChildUnavailable},
		{OriginDiagnostic{OriginSupervising, ExitUnavailable}, OperationTaskInventory, ChildStarted},
		{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationWaitPeek, ChildStopObserved},
		{OriginDiagnostic{OriginTerminal, ExitUnavailable}, OperationEntryReceive, ChildTerminalObserved},
		{OriginDiagnostic{OriginJoining, ExitUnavailable}, OperationFinalWait, ChildTerminalObserved},
		{OriginDiagnostic{OriginJoined, ExitZero}, OperationUnavailable, ChildWaitReturned},
	}
	for _, want := range steps {
		o.diagnostic.Store(observationWord(want))
		if got := o.Observation(); got != want || o.Diagnostic() != want.OriginDiagnostic {
			t.Fatalf("transition: got %+v want %+v", got, want)
		}
		if o.Facts() != (OriginFacts{}) || o.Live(0) {
			t.Fatal("observation granted authority")
		}
	}
	for _, bad := range []OriginObservation{
		{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationPause + 1, ChildStopObserved},
		{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationWaitPeek, ChildWaitReturned + 1},
		{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationWaitPeek, ChildWaitReturned},
		{OriginDiagnostic{OriginJoined, ExitZero}, OperationFinalWait, ChildWaitReturned},
		{OriginDiagnostic{OriginJoined, ExitZero}, OperationUnavailable, ChildStarted},
		{OriginDiagnostic{OriginUnavailable, ExitUnavailable}, OperationWaitPeek, ChildUnavailable},
	} {
		o.diagnostic.Store(observationWord(bad))
		if o.Observation() != (OriginObservation{}) {
			t.Fatalf("invalid neighbour accepted: %+v", bad)
		}
	}
	// Each operation has a valid neighbour; unknown byte values fail closed.
	for op := 0; op <= 255; op++ {
		v := OriginObservation{OriginDiagnostic{OriginEntered, ExitUnavailable}, OriginOperation(op), ChildStopObserved}
		o.diagnostic.Store(observationWord(v))
		got := o.Observation()
		if op <= int(OperationPause) && got != v || op > int(OperationPause) && got != (OriginObservation{}) {
			t.Fatalf("operation boundary %d: %+v", op, got)
		}
	}
	for child := 0; child <= 255; child++ {
		v := OriginObservation{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationWaitPeek, OriginChildProgress(child)}
		o.diagnostic.Store(observationWord(v))
		got := o.Observation()
		if child < int(ChildWaitReturned) && got != v || child >= int(ChildWaitReturned) && got != (OriginObservation{}) {
			t.Fatalf("child boundary %d: %+v", child, got)
		}
	}
}

func TestOriginObservationPublication(t *testing.T) {
	o := &CaseOrigin{}
	a := OriginObservation{OriginDiagnostic{OriginEntered, ExitUnavailable}, OperationNotification, ChildStopObserved}
	b := OriginObservation{OriginDiagnostic{OriginJoining, ExitUnavailable}, OperationFinalWait, ChildTerminalObserved}
	o.diagnostic.Store(observationWord(a))
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for i := 0; i < 10000; i++ {
			o.diagnostic.Store(observationWord(b))
			o.diagnostic.Store(observationWord(a))
		}
	}()
	for i := 0; i < 10000; i++ {
		if v := o.Observation(); v != a && v != b {
			t.Errorf("torn publication: %+v", v)
			break
		}
	}
	group.Wait()
	// The production publication helpers preserve the independently observed
	// child event through phase/operation changes and clear it on unavailable.
	o.observeOperation(OperationPause)
	o.observePhase(OriginJoining)
	if v := o.Observation(); v.Operation != OperationPause || v.Child != ChildStopObserved || v.Phase != OriginJoining {
		t.Fatal("publication lost separate event", v)
	}
	o.observeChild(ChildTerminalObserved)
	if v := o.Observation(); v.Child != ChildTerminalObserved {
		t.Fatal("child publication lost", v)
	}
	o.observePhase(OriginUnavailable)
	if o.Observation() != (OriginObservation{}) || o.Facts() != (OriginFacts{}) || o.Live(0) {
		t.Fatal("unavailable acquired evidence")
	}
}
