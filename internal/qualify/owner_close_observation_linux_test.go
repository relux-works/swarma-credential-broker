//go:build linux

package qualify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
)

// TestOwnerCloseObservationCoherence proves stable actual values survive while
// changed or malformed samples lose completion and lifecycle evidence.
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

// TestOwnerCloseObservationClosedOutput proves only closed enum labels reach
// diagnostics and malformed values cannot retain completion evidence.
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

// TestOwnerCloseWaitedUnknownObservation proves a waited callback with unknown
// lifecycle remains UNKNOWN, including when completion is sampled as returned.
func TestOwnerCloseWaitedUnknownObservation(t *testing.T) {
	first := egress.OriginObservation{Operation: egress.OperationWaitedCallback}
	v := ownerCloseSnapshot{cancelIssued: true, completion: ownerPending, operation: first.Operation}
	want := v
	want.completion = ownerCompletionUnavailable
	if got := stableCloseSnapshot(first, v); got != want {
		t.Fatal("entered callback discarded with unknown wait phase", got)
	}
	var got string
	ctx := withOwnerDiagnostics(context.Background(), func(s string) { got = s })
	ownerDiagnosticClose(ctx, &v)
	if got != "owner close timeout close_cancel=issued supervisor=unavailable phase=unavailable exit=unavailable operation=waited_callback child=unavailable" {
		t.Fatal("known callback or unknown wait evidence lost", got)
	}
	v.completion = ownerReturned
	if got := stableCloseSnapshot(first, v); got != want {
		t.Fatal("unknown wait phase retained returned completion", got)
	}
	ownerDiagnosticClose(ctx, &v)
	if got != "owner close timeout close_cancel=issued supervisor=unavailable phase=unavailable exit=unavailable operation=waited_callback child=unavailable" {
		t.Fatal("formatter retained unknown completion", got)
	}
	// A different endpoint or stale terminal/child evidence still clears the
	// whole observation and the separately sampled completion value.
	for _, last := range []ownerCloseSnapshot{
		{cancelIssued: true, completion: ownerReturned},
		{cancelIssued: true, completion: ownerReturned, operation: first.Operation, origin: egress.OriginDiagnostic{Exit: egress.ExitZero}},
		{cancelIssued: true, completion: ownerReturned, operation: first.Operation, child: egress.ChildWaitReturned},
	} {
		if got := stableCloseSnapshot(first, last); got != (ownerCloseSnapshot{cancelIssued: true}) {
			t.Fatal("mixed or invalid callback sample retained completion", got)
		}
		ownerDiagnosticClose(ctx, &last)
		if got != "owner close timeout close_cancel=issued supervisor=unavailable phase=unavailable exit=unavailable operation=unavailable child=unavailable" {
			t.Fatal("malformed callback sample retained output", got)
		}
	}
}

// TestOwnerCloseObservationInterleaving proves the real closeSnapshot reads can
// be separated deterministically by a test-only overlay and that a known-bad
// coherence check fails while its stable positive and record checks still run.
func TestOwnerCloseObservationInterleaving(t *testing.T) {
	race := ownerCloseRaceEnabled
	t.Logf("nested overlay race instrumentation=%t", race)

	validOutput, validErr := runOwnerCloseOverlay(t, "valid", false, race)
	if validErr != nil ||
		!strings.Contains(validOutput, "--- PASS: TestOwnerCloseInterleaveOverlay") ||
		!strings.Contains(validOutput, "--- PASS: TestOwnerCloseOperationInterleaveOverlay") ||
		!strings.Contains(validOutput, "--- PASS: TestOwnerCloseUnknownCallbackOverlay") ||
		!strings.Contains(validOutput, "--- PASS: TestOwnerCloseStableOverlay") {
		t.Fatalf("valid overlay controls did not pass: %v\n%s", validErr, boundedOverlayOutput(validOutput))
	}

	badOutput, badErr := runOwnerCloseOverlay(t, "known-bad", true, race)
	if badErr == nil ||
		!strings.Contains(badOutput, "--- FAIL: TestOwnerCloseInterleaveOverlay") ||
		!strings.Contains(badOutput, "interleaving diagnostic not UNKNOWN") ||
		!strings.Contains(badOutput, "--- PASS: TestOwnerCloseStableOverlay") ||
		strings.Contains(badOutput, "underlying ownerSession record changed") ||
		strings.Contains(badOutput, "underlying report changed") ||
		strings.Contains(badOutput, "diagnostic granted execution credit") {
		t.Fatalf("known-bad overlay missed its intended diagnostic failure or invalidated controls: %v\n%s", badErr, boundedOverlayOutput(badOutput))
	}
}

func runOwnerCloseOverlay(t *testing.T, variant string, knownBad, race bool) (string, error) {
	t.Helper()
	dir := ownerCloseOverlayDir(t, variant)
	overlayPath := writeOwnerCloseOverlay(t, dir, knownBad)

	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	args := []string{"test"}
	if race {
		args = append(args, "-race")
	}
	args = append(args,
		"-mod=readonly",
		"-overlay="+overlayPath,
		"-p=1",
		"-count=1",
		"-timeout=45s",
		"-run=^TestOwnerClose(Interleave|OperationInterleave|UnknownCallback|Stable)Overlay$",
		"-v",
		".",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	packageDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve qualify package directory: %w", err)
	}
	cmd := exec.CommandContext(ctx, goTool, args...)
	cmd.Dir = packageDir
	cmd.Env = ownerCloseOfflineEnv()
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		err = fmt.Errorf("overlay command timed out: %w", ctx.Err())
	}
	return string(output), err
}

func ownerCloseOverlayDir(t *testing.T, variant string) string {
	t.Helper()
	if base := os.Getenv("OWNER_CLOSE_OVERLAY_DIR"); base != "" {
		if !filepath.IsAbs(base) {
			t.Fatalf("OWNER_CLOSE_OVERLAY_DIR must be absolute")
		}
		dir := filepath.Join(base, variant)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create isolated overlay directory: %v", err)
		}
		return dir
	}
	return t.TempDir()
}

func writeOwnerCloseOverlay(t *testing.T, dir string, knownBad bool) string {
	t.Helper()
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ownerPath := filepath.Join(packageDir, "owner_close_diagnostic_linux.go")
	originPath := filepath.Clean(filepath.Join(packageDir, "../egress/origin_diagnostic.go"))
	overlayTestPath := filepath.Join(packageDir, "owner_close_interleaving_overlay_test.go")
	if _, err := os.Stat(overlayTestPath); err == nil {
		t.Fatalf("overlay test path already exists: %s", filepath.Base(overlayTestPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect overlay test path: %v", err)
	}

	ownerOriginal, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatalf("read closeSnapshot source: %v", err)
	}
	originOriginal, err := os.ReadFile(originPath)
	if err != nil {
		t.Fatalf("read origin observation source: %v", err)
	}

	ownerInstrumented := string(ownerOriginal)
	closeMethod := "func (s *ownerSession) closeSnapshot(cancelIssued bool) ownerCloseSnapshot {"
	if strings.Count(ownerInstrumented, closeMethod) != 1 {
		t.Fatal("closeSnapshot instrumentation anchor changed")
	}
	ownerInstrumented = strings.Replace(ownerInstrumented, closeMethod,
		"var ownerCloseAfterFirstObservation func(egress.OriginObservation)\nvar ownerCloseAfterSecondObservation func(egress.OriginObservation)\n\n"+closeMethod, 1)
	firstRead := "\tfirst := s.origin.Observation()\n"
	hook := "\tif ownerCloseAfterFirstObservation != nil {\n\t\townerCloseAfterFirstObservation(first)\n\t}\n"
	if strings.Count(ownerInstrumented, firstRead) != 1 {
		t.Fatal("first Observation instrumentation anchor changed")
	}
	ownerInstrumented = strings.Replace(ownerInstrumented, firstRead, firstRead+hook, 1)
	lastRead := "\tlast := s.origin.Observation()\n"
	secondHook := "\tif ownerCloseAfterSecondObservation != nil {\n\t\townerCloseAfterSecondObservation(last)\n\t}\n"
	if strings.Count(ownerInstrumented, lastRead) != 1 {
		t.Fatal("second Observation instrumentation anchor changed")
	}
	ownerInstrumented = strings.Replace(ownerInstrumented, lastRead, lastRead+secondHook, 1)
	if knownBad {
		start := strings.Index(ownerInstrumented, "func stableCloseSnapshot(")
		if start < 0 {
			t.Fatal("stableCloseSnapshot instrumentation anchor missing")
		}
		endRelative := strings.Index(ownerInstrumented[start:], "\n}\n")
		if endRelative < 0 {
			t.Fatal("stableCloseSnapshot function boundary missing")
		}
		end := start + endRelative + len("\n}\n")
		badFunction := "func stableCloseSnapshot(first egress.OriginObservation, v ownerCloseSnapshot) ownerCloseSnapshot {\n\t_ = first\n\treturn v\n}\n"
		ownerInstrumented = ownerInstrumented[:start] + badFunction + ownerInstrumented[end:]
	}

	originInstrumented := string(originOriginal)
	setterAnchor := "func (o *CaseOrigin) observePhase(p OriginPhase) {\n"
	setter := "func SetObservationForOverlay(o *CaseOrigin, v OriginObservation) {\n" +
		"\tif o != nil {\n" +
		"\t\to.diagnostic.Store(uint32(v.Phase) | uint32(v.Exit)<<8 | uint32(v.Operation)<<16 | uint32(v.Child)<<24)\n" +
		"\t}\n" +
		"}\n\n"
	if strings.Count(originInstrumented, setterAnchor) != 1 {
		t.Fatal("origin observation instrumentation anchor changed")
	}
	originInstrumented = strings.Replace(originInstrumented, setterAnchor, setter+setterAnchor, 1)

	probe := "package qualify\n" +
		"import (\n" +
		"\t\"context\"\n" +
		"\t\"errors\"\n" +
		"\t\"reflect\"\n" +
		"\t\"testing\"\n" +
		"\t\"github.com/relux-works/swarma-credential-broker/internal/egress\"\n" +
		")\n\n" +
		"// TestOwnerCloseInterleaveOverlay proves a changed real Observation between closeSnapshot reads becomes UNKNOWN without changing the ownerSession record.\n" +
		"func TestOwnerCloseInterleaveOverlay(t *testing.T) {\n" +
		"\tfirst := egress.OriginObservation{OriginDiagnostic: egress.OriginDiagnostic{Phase: egress.OriginEntered}, Operation: egress.OperationWaitPeek, Child: egress.ChildStopObserved}\n" +
		"\tjoining := egress.OriginObservation{OriginDiagnostic: egress.OriginDiagnostic{Phase: egress.OriginJoining}, Operation: egress.OperationWaitedCallback, Child: egress.ChildStopObserved}\n" +
		"\torigin := &egress.CaseOrigin{}\n" +
		"\tegress.SetObservationForOverlay(origin, first)\n" +
		"\tdone := make(chan struct{})\n" +
		"\tclose(done)\n" +
		"\trecord := rowExecution{Launched: true, Handshake: true, Started: true, HelperExit: -1, WorkerExit: -1, CaseExit: -1, Diagnostic: \"case_status_unavailable\"}\n" +
		"\ts := &ownerSession{origin: origin, done: done, execution: record, report: egress.Report{Incomplete: true}, err: errors.New(\"synthetic incomplete owner\")}\n" +
		"\tbeforeExecution, beforeReport, beforeErr := s.execution, s.report, s.err\n" +
		"\tfirstCalls, secondCalls := 0, 0\n" +
		"\townerCloseAfterFirstObservation = func(got egress.OriginObservation) {\n" +
		"\t\tfirstCalls++\n" +
		"\t\tif got != first { t.Errorf(\"hook did not follow first real Observation read: got %+v want %+v\", got, first) }\n" +
		"\t\tegress.SetObservationForOverlay(origin, joining)\n" +
		"\t}\n" +
		"\townerCloseAfterSecondObservation = func(got egress.OriginObservation) {\n" +
		"\t\tsecondCalls++\n" +
		"\t\tif got != joining { t.Errorf(\"second hook did not capture joining/WaitedCallback: got %+v want %+v\", got, joining) }\n" +
		"\t}\n" +
		"\tdefer func() { ownerCloseAfterFirstObservation, ownerCloseAfterSecondObservation = nil, nil }()\n" +
		"\tgot := s.closeSnapshot(true)\n" +
		"\tif firstCalls != 1 || secondCalls != 1 { t.Errorf(\"real Observation reads recorded first=%d second=%d, want one each\", firstCalls, secondCalls) }\n" +
		"\tif got.completion != ownerCompletionUnavailable || got.origin != (egress.OriginDiagnostic{}) || got.operation != egress.OperationUnavailable || got.child != egress.ChildUnavailable {\n" +
		"\t\tt.Errorf(\"interleaving retained completion or lifecycle: %+v\", got)\n" +
		"\t}\n" +
		"\tvar diagnostic string\n" +
		"\tctx := withOwnerDiagnostics(context.Background(), func(value string) { diagnostic = value })\n" +
		"\townerDiagnosticClose(ctx, &got)\n" +
		"\twant := \"owner close timeout close_cancel=issued supervisor=unavailable phase=unavailable exit=unavailable operation=unavailable child=unavailable\"\n" +
		"\tif diagnostic != want { t.Errorf(\"interleaving diagnostic not UNKNOWN: got %q want %q\", diagnostic, want) }\n" +
		"\tif !reflect.DeepEqual(beforeExecution, s.execution) { t.Errorf(\"underlying ownerSession record changed: before=%+v after=%+v\", beforeExecution, s.execution) }\n" +
		"\tif !reflect.DeepEqual(beforeReport, s.report) { t.Errorf(\"underlying report changed: before=%+v after=%+v\", beforeReport, s.report) }\n" +
		"\tif s.err != beforeErr { t.Errorf(\"underlying owner error changed\") }\n" +
		"\tif s.execution.credit(false) { t.Errorf(\"diagnostic granted execution credit\") }\n" +
		"\tif observed := origin.Observation(); observed != joining { t.Errorf(\"real origin state was cleared: got %+v want %+v\", observed, joining) }\n" +
		"\tif origin.Facts() != (egress.OriginFacts{}) || origin.Live(0) { t.Errorf(\"diagnostic altered authority facts: %+v\", origin.Facts()) }\n" +
		"}\n\n" +
		"// TestOwnerCloseStableOverlay proves two stable real Observation reads retain a joined positive snapshot without granting credit.\n" +
		"func TestOwnerCloseStableOverlay(t *testing.T) {\n" +
		"\townerCloseAfterFirstObservation, ownerCloseAfterSecondObservation = nil, nil\n" +
		"\tstable := egress.OriginObservation{OriginDiagnostic: egress.OriginDiagnostic{Phase: egress.OriginJoined, Exit: egress.ExitZero}, Operation: egress.OperationWaitedCallback, Child: egress.ChildWaitReturned}\n" +
		"\torigin := &egress.CaseOrigin{}\n" +
		"\tegress.SetObservationForOverlay(origin, stable)\n" +
		"\tdone := make(chan struct{})\n" +
		"\tclose(done)\n" +
		"\ts := &ownerSession{origin: origin, done: done, execution: newRowExecution()}\n" +
		"\tgot := s.closeSnapshot(false)\n" +
		"\twant := ownerCloseSnapshot{completion: ownerReturned, origin: stable.OriginDiagnostic, operation: stable.Operation, child: stable.Child}\n" +
		"\tif got != want { t.Fatalf(\"stable actual snapshot changed: got %+v want %+v\", got, want) }\n" +
		"\tvar diagnostic string\n" +
		"\tctx := withOwnerDiagnostics(context.Background(), func(value string) { diagnostic = value })\n" +
		"\townerDiagnosticClose(ctx, &got)\n" +
		"\twantDiagnostic := \"owner close timeout close_cancel=not_issued supervisor=returned phase=joined exit=zero operation=waited_callback child=wait_returned\"\n" +
		"\tif diagnostic != wantDiagnostic { t.Fatalf(\"stable positive diagnostic changed: got %q want %q\", diagnostic, wantDiagnostic) }\n" +
		"\tif s.execution.credit(false) || origin.Facts() != (egress.OriginFacts{}) || origin.Live(0) { t.Fatal(\"stable diagnostic granted execution credit or authority\") }\n" +
		"}\n"
	probe += `
// Claim: changing only operation between the real reads still discards completion.
// The stable joined observation in TestOwnerCloseStableOverlay is the positive.
func TestOwnerCloseOperationInterleaveOverlay(t *testing.T) {
	first := egress.OriginObservation{OriginDiagnostic: egress.OriginDiagnostic{Phase: egress.OriginEntered}, Operation: egress.OperationWaitPeek, Child: egress.ChildStopObserved}
	last := first
	last.Operation = egress.OperationWaitedCallback
	origin := &egress.CaseOrigin{}
	egress.SetObservationForOverlay(origin, first)
	done := make(chan struct{})
	close(done)
	s := &ownerSession{origin: origin, done: done, execution: newRowExecution(), report: egress.Report{Incomplete: true}, err: errors.New("synthetic incomplete owner")}
	beforeExecution, beforeReport, beforeErr := s.execution, s.report, s.err
	firstCalls, secondCalls := 0, 0
	ownerCloseAfterFirstObservation = func(got egress.OriginObservation) {
		firstCalls++
		if got != first { t.Fatal("first operation-only read changed", got) }
		egress.SetObservationForOverlay(origin, last)
	}
	ownerCloseAfterSecondObservation = func(got egress.OriginObservation) {
		secondCalls++
		if got != last { t.Fatal("last operation-only read changed", got) }
	}
	defer func() { ownerCloseAfterFirstObservation, ownerCloseAfterSecondObservation = nil, nil }()
	got := s.closeSnapshot(true)
	if got != (ownerCloseSnapshot{cancelIssued: true}) { t.Error("operation-only interleaving retained completion", got) }
	var diagnostic string
	ownerDiagnosticClose(withOwnerDiagnostics(context.Background(), func(value string) { diagnostic = value }), &got)
	if diagnostic != "owner close timeout close_cancel=issued supervisor=unavailable phase=unavailable exit=unavailable operation=unavailable child=unavailable" { t.Error("operation-only diagnostic not UNKNOWN", diagnostic) }
	if firstCalls != 1 || secondCalls != 1 { t.Error("operation-only reads not exercised exactly once", firstCalls, secondCalls) }
	if !reflect.DeepEqual(beforeExecution, s.execution) || !reflect.DeepEqual(beforeReport, s.report) || beforeErr != s.err || s.execution.credit(false) || origin.Facts() != (egress.OriginFacts{}) || origin.Live(0) { t.Error("operation-only diagnostic changed record, credit or authority") }
}

// Claim: a stable unavailable-phase callback survives both real reads without
// completion evidence, for either pending or returned completion channels.
func TestOwnerCloseUnknownCallbackOverlay(t *testing.T) {
	ownerCloseAfterFirstObservation, ownerCloseAfterSecondObservation = nil, nil
	for _, returned := range []bool{false, true} {
		origin := &egress.CaseOrigin{}
		egress.SetObservationForOverlay(origin, egress.OriginObservation{Operation: egress.OperationWaitedCallback})
		done := make(chan struct{})
		if returned { close(done) }
		s := &ownerSession{origin: origin, done: done, execution: newRowExecution()}
		got := s.closeSnapshot(false)
		if got != (ownerCloseSnapshot{operation: egress.OperationWaitedCallback}) { t.Error("stable unknown callback lost or gained evidence", got) }
		var diagnostic string
		ownerDiagnosticClose(withOwnerDiagnostics(context.Background(), func(value string) { diagnostic = value }), &got)
		if diagnostic != "owner close timeout close_cancel=not_issued supervisor=unavailable phase=unavailable exit=unavailable operation=waited_callback child=unavailable" { t.Error("stable unknown callback diagnostic changed", diagnostic) }
		if s.execution.credit(false) || origin.Facts() != (egress.OriginFacts{}) || origin.Live(0) { t.Error("unknown callback granted credit or authority") }
	}
}
`
	formattedProbe, err := format.Source([]byte(probe))
	if err != nil {
		t.Fatalf("format interleaving overlay test: %v", err)
	}
	probe = string(formattedProbe)

	ownerOverlayPath := filepath.Join(dir, "owner_close_diagnostic_linux.go")
	originOverlayPath := filepath.Join(dir, "origin_diagnostic.go")
	probePath := filepath.Join(dir, "owner_close_interleaving_overlay_test.go")
	if err := os.WriteFile(ownerOverlayPath, []byte(ownerInstrumented), 0o600); err != nil {
		t.Fatalf("write instrumented closeSnapshot overlay: %v", err)
	}
	if err := os.WriteFile(originOverlayPath, []byte(originInstrumented), 0o600); err != nil {
		t.Fatalf("write origin setter overlay: %v", err)
	}
	if err := os.WriteFile(probePath, []byte(probe), 0o600); err != nil {
		t.Fatalf("write interleaving overlay test: %v", err)
	}
	overlay := map[string]map[string]string{"Replace": {
		ownerPath:       ownerOverlayPath,
		originPath:      originOverlayPath,
		overlayTestPath: probePath,
	}}
	overlayBytes, err := json.Marshal(overlay)
	if err != nil {
		t.Fatalf("encode overlay manifest: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlayBytes, 0o600); err != nil {
		t.Fatalf("write overlay manifest: %v", err)
	}
	t.Logf("overlay owner_original_sha256=%s owner_instrumented_sha256=%s origin_original_sha256=%s origin_instrumented_sha256=%s probe_sha256=%s manifest_sha256=%s",
		sha256Hex(ownerOriginal), sha256Hex([]byte(ownerInstrumented)),
		sha256Hex(originOriginal), sha256Hex([]byte(originInstrumented)),
		sha256Hex([]byte(probe)), sha256Hex(overlayBytes))
	return overlayPath
}

func ownerCloseOfflineEnv() []string {
	env := make([]string, 0, 24)
	for _, key := range []string{
		"PATH", "HOME", "TMPDIR", "GOTMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT",
		"GO", "GOOS", "GOARCH", "CGO_ENABLED", "CC", "CXX", "GOMAXPROCS",
		"LANG", "LC_ALL", "TZ",
	} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	env = append(env, "GOPROXY=off", "GOAUTH=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off")
	return env
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func boundedOverlayOutput(output string) string {
	const limit = 6000
	if len(output) <= limit {
		return output
	}
	return output[:limit] + "\n[overlay output truncated]"
}
