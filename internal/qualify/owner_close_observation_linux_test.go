//go:build linux

package qualify

import (
	"context"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
)

func TestOwnerCloseObservationCoherence(t *testing.T) {
	first := egress.OriginObservation{OriginDiagnostic: egress.OriginDiagnostic{Phase: egress.OriginEntered}, Operation: egress.OperationWaitPeek, Child: egress.ChildStopObserved}
	v := ownerCloseSnapshot{cancelIssued: true, completion: ownerPending, origin: first.OriginDiagnostic, operation: first.Operation, child: first.Child}
	if got := stableCloseSnapshot(first, v); got != v {
		t.Fatal("stable operation discarded", got)
	}
	for _, changed := range []ownerCloseSnapshot{
		{cancelIssued: true, completion: ownerReturned, origin: first.OriginDiagnostic, operation: egress.OperationResume, child: first.Child},
		{cancelIssued: true, completion: ownerReturned, origin: first.OriginDiagnostic, operation: first.Operation, child: egress.ChildTerminalObserved},
	} {
		if got := stableCloseSnapshot(first, changed); got != (ownerCloseSnapshot{cancelIssued: true}) {
			t.Fatal("mixed operation/child retained completion", got)
		}
	}
	if got := stableCloseSnapshot(egress.OriginObservation{}, ownerCloseSnapshot{completion: ownerReturned}); got != (ownerCloseSnapshot{}) {
		t.Fatal("unavailable origin retained completion", got)
	}
	bad := first
	bad.Operation = 255
	if got := stableCloseSnapshot(bad, ownerCloseSnapshot{completion: ownerReturned, origin: bad.OriginDiagnostic, operation: bad.Operation, child: bad.Child}); got != (ownerCloseSnapshot{}) {
		t.Fatal("equal malformed samples retained completion", got)
	}
}

func TestOwnerCloseObservationClosedOutput(t *testing.T) {
	var got string
	ctx := withOwnerDiagnostics(context.Background(), func(s string) { got = s })
	v := ownerCloseSnapshot{completion: ownerPending, origin: egress.OriginDiagnostic{Phase: egress.OriginEntered}, operation: egress.OperationWaitPeek, child: egress.ChildStopObserved}
	ownerDiagnosticClose(ctx, &v)
	if got != "owner close timeout close_cancel=not_issued supervisor=pending phase=entered exit=unavailable operation=wait_peek child=stop_observed" {
		t.Fatal("separate observation missing", got)
	}
	for op := 0; op <= 255; op++ {
		v.operation = egress.OriginOperation(op)
		ownerDiagnosticClose(ctx, &v)
		if len(got) > 200 || !strings.Contains(got, "operation=") || !strings.Contains(got, "child=") {
			t.Fatal("unbounded formatter", got)
		}
		if op > int(egress.OperationPause) && !strings.Contains(got, "supervisor=unavailable phase=unavailable exit=unavailable operation=unavailable child=unavailable") {
			t.Fatal("unknown operation retained completion", got)
		}
	}
	v.operation = egress.OperationWaitPeek
	for child := 0; child <= 255; child++ {
		v.child = egress.OriginChildProgress(child)
		ownerDiagnosticClose(ctx, &v)
		if child >= int(egress.ChildWaitReturned) && !strings.Contains(got, "supervisor=unavailable phase=unavailable exit=unavailable operation=unavailable child=unavailable") {
			t.Fatal("invalid child retained completion", got)
		}
	}
	// A joined observation remains distinct from a pending final wait.
	v = ownerCloseSnapshot{completion: ownerReturned, origin: egress.OriginDiagnostic{Phase: egress.OriginJoined, Exit: egress.ExitZero}, child: egress.ChildWaitReturned}
	ownerDiagnosticClose(ctx, &v)
	if !strings.HasSuffix(got, "phase=joined exit=zero operation=unavailable child=wait_returned") {
		t.Fatal("joined positive lost", got)
	}
	v.operation = egress.OperationFinalWait
	ownerDiagnosticClose(ctx, &v)
	if !strings.Contains(got, "supervisor=unavailable phase=unavailable exit=unavailable") {
		t.Fatal("pending operation invented completed wait", got)
	}
}
