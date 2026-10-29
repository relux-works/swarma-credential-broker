package egress

import (
	"sync"
	"testing"
)

// Claim: the zero/nil/invalid word is unavailable, and concurrent publication
// never tears the phase/exit pair. Diagnostic writes do not grant origin credit.
func TestOriginDiagnosticSnapshot(t *testing.T) {
	var absent *CaseOrigin
	if absent.Diagnostic() != (OriginDiagnostic{}) {
		t.Fatal("nil origin became known")
	}
	o := &CaseOrigin{}
	for _, raw := range []uint32{0, 255, 1 << 24, uint32(OriginJoined), uint32(OriginEntered) | uint32(ExitZero)<<8} {
		o.diagnostic.Store(raw)
		if o.Diagnostic() != (OriginDiagnostic{}) {
			t.Fatal("malformed state gained evidence", raw)
		}
	}
	o.observePhase(OriginSupervising)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for i := 0; i < 10000; i++ {
			o.diagnostic.Store(uint32(OriginJoined) | uint32(ExitZero)<<8)
			o.observePhase(OriginSupervising)
		}
	}()
	for i := 0; i < 10000; i++ {
		v := o.Diagnostic()
		if v != (OriginDiagnostic{OriginJoined, ExitZero}) && v != (OriginDiagnostic{OriginSupervising, ExitUnavailable}) {
			t.Errorf("torn observation: %+v", v)
			break
		}
	}
	group.Wait()
	if o.Facts() != (OriginFacts{}) || o.Live(0) {
		t.Fatal("diagnostic acquired authority")
	}
}
