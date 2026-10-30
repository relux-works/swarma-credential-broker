//go:build linux && amd64

package qualify

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const rowFailureRecordsPerSide = 2

// rowsFailureDiagnostics reads completed report records only. Private credit
// evidence and live context are absent after report decoding; neither is inferred.
func rowsFailureDiagnostics(id string, records []rowExecutionRecord) []string {
	if !rowImplemented(id) {
		return []string{"row=unavailable side=positive execution=unavailable", "row=unavailable side=negative execution=unavailable"}
	}
	var lines []string
	for _, side := range []string{"positive", "negative"} {
		count := 0
		for _, record := range records {
			if record.ID != id || record.Side != side {
				continue
			}
			count++
			if count > rowFailureRecordsPerSide {
				continue
			}
			e := record.Execution
			lines = append(lines, fmt.Sprintf("row=%s side=%s record=%d launched=%t handshake=%t started=%t completed=%t joined=%t helper_exit=%d worker_exit=%d case_exit=%d diagnostic=%s runner_evidence=%t context=unavailable credit=unavailable", id, side, count, e.Launched, e.Handshake, e.Started, e.Completed, e.Joined, e.HelperExit, e.WorkerExit, e.CaseExit, rowFailureDiagnosticCode(e.Diagnostic), e.Runner != nil))
		}
		if count == 0 {
			lines = append(lines, fmt.Sprintf("row=%s side=%s execution=unavailable context=unavailable credit=unavailable", id, side))
		}
		if count > rowFailureRecordsPerSide {
			lines = append(lines, fmt.Sprintf("row=%s side=%s records_truncated=true limit=%d", id, side, rowFailureRecordsPerSide))
		}
	}
	return lines
}

func rowFailureDiagnosticCode(d rowDiagnostic) string {
	switch d {
	case "":
		return "none"
	case "case_not_started", "case_status_unavailable", "observation_invalid", "case_origin_unavailable", "case_pair_unavailable", "observation_unavailable", "fixture_unavailable", "launcher_lookup_failed", "launcher_not_found", "launcher_not_executable", "launcher_unavailable", "helper_pipe_unavailable", "peer_handshake_unavailable", "peer_identity_mismatch", "case_evidence_invalid", "case_evidence_unavailable", "peer_fixture_unavailable", "peer_pair_unavailable":
		return string(d)
	default:
		return "unrecognized"
	}
}

// Claim: both matching sides retain the recorded incomplete/invalid-credit
// predicates and diagnostic codes; unrelated rows, artifact bytes and pointers
// contribute no output. No private credit or live context is reconstructed.
func TestRowsFailureDiagnosticsMatching(t *testing.T) {
	const id = "transient-ambiguous"
	positive := rowExecution{Launched: true, Handshake: true, Started: true, Completed: false, Joined: true, HelperExit: 0, WorkerExit: -1, CaseExit: -1, Diagnostic: "observation_invalid", artifact: "private-proof-canary"}
	negative := newRowExecution()
	negative.Diagnostic = "case_pair_unavailable"
	records := []rowExecutionRecord{{"frame-oversized", "positive", rowExecution{Diagnostic: "unrelated-private-canary"}}, {id, "negative", negative}, {id, "positive", positive}, {id, "other-private-side", positive}}
	want := []string{
		"row=transient-ambiguous side=positive record=1 launched=true handshake=true started=true completed=false joined=true helper_exit=0 worker_exit=-1 case_exit=-1 diagnostic=observation_invalid runner_evidence=false context=unavailable credit=unavailable",
		"row=transient-ambiguous side=negative record=1 launched=false handshake=false started=false completed=false joined=false helper_exit=-1 worker_exit=-1 case_exit=-1 diagnostic=case_pair_unavailable runner_evidence=false context=unavailable credit=unavailable",
	}
	if got := rowsFailureDiagnostics(id, records); !reflect.DeepEqual(got, want) {
		t.Fatalf("matching diagnostic facts differ:\ngot %q\nwant %q", got, want)
	}
	if !reflect.DeepEqual(records[2].Execution, positive) {
		t.Fatal("formatter mutated recorded execution")
	}
}

// Claim: missing records are explicitly unavailable, while a present record
// with an empty diagnostic preserves its actual fields without claiming credit.
func TestRowsFailureDiagnosticsMissing(t *testing.T) {
	const id = "transient-ambiguous"
	got := rowsFailureDiagnostics(id, nil)
	for i, side := range []string{"positive", "negative"} {
		want := "row=" + id + " side=" + side + " execution=unavailable context=unavailable credit=unavailable"
		if got[i] != want {
			t.Fatalf("missing %s fabricated: %q", side, got)
		}
	}
	got = rowsFailureDiagnostics(id, []rowExecutionRecord{{id, "positive", newRowExecution()}})
	if len(got) != 2 || !strings.Contains(got[0], "diagnostic=none") || !strings.Contains(got[0], "case_exit=-1") || !strings.Contains(got[1], "side=negative execution=unavailable") {
		t.Fatal("present/missing distinction lost", got)
	}
}

// Claim: output is capped per side, overflow is disclosed, and an available
// negative side remains visible even after positive-side truncation.
func TestRowsFailureDiagnosticsBound(t *testing.T) {
	const id = "transient-ambiguous"
	var records []rowExecutionRecord
	for i := 0; i < rowFailureRecordsPerSide+1; i++ {
		records = append(records, rowExecutionRecord{id, "positive", newRowExecution()})
	}
	records = append(records, rowExecutionRecord{id, "negative", newRowExecution()})
	got := rowsFailureDiagnostics(id, records)
	if len(got) != rowFailureRecordsPerSide+2 || got[2] != "row=transient-ambiguous side=positive records_truncated=true limit=2" || !strings.Contains(got[3], "side=negative record=1") {
		t.Fatal("bound hides overflow/side", got)
	}
	exact := rowsFailureDiagnostics(id, records[:rowFailureRecordsPerSide])
	if strings.Contains(strings.Join(exact, "\n"), "truncated") {
		t.Fatal("exact bound falsely truncated", exact)
	}
}

// Claim: unknown diagnostic strings, identifiers and nested pointer content
// cannot disclose raw paths/proofs or add log lines; known codes remain exact.
func TestRowsFailureDiagnosticsRedaction(t *testing.T) {
	const id = "transient-ambiguous"
	e := newRowExecution()
	e.Diagnostic = "/private-canary\nextra-line"
	e.Runner = &runnerEvidence{}
	got := strings.Join(rowsFailureDiagnostics(id, []rowExecutionRecord{{id, "positive", e}}), "\n")
	if strings.Contains(got, "private-canary") || strings.Contains(got, "extra-line") || !strings.Contains(got, "diagnostic=unrecognized runner_evidence=true") {
		t.Fatal("unsafe diagnostic disclosed", got)
	}
	got = strings.Join(rowsFailureDiagnostics("/private-canary", nil), "\n")
	if strings.Contains(got, "private-canary") || !strings.Contains(got, "row=unavailable") {
		t.Fatal("unsafe row label", got)
	}
}
