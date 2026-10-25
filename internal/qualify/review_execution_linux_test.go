//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: helper-only completion metadata cannot establish canonical case entry.
// The fault helper has no case, child, socket operation or passing observation.
// TestPeerRowFixture is the adjacent real-case positive control.
func TestReviewPeerHelperOnlyCompletion(t *testing.T) {
	f := configuredPeerRow(t)
	f.PeerHelper = rowTool(t, "./testdata/metadataonly")
	_, c, root := setup(t)
	var records []rowExecutionRecord
	d := driver{executions: &records}
	var row qualification.Case
	for _, v := range qualification.Pending(qualification.Identity{}).Cases {
		if v.ID == "peer-denied" {
			row = v
		}
	}
	d.runPeerRows(context.Background(), f, c.Policy, root, &row)
	for _, control := range []qualification.Control{row.Negative, row.Positive} {
		if control.Executed || control.ExitCode != -1 || control.Verdict != "pending" || len(control.Artifacts) != 0 {
			t.Errorf("helper-only report gained case execution: executed=%v status=%d verdict=%s artifacts=%d", control.Executed, control.ExitCode, control.Verdict, len(control.Artifacts))
		}
	}
	for _, record := range records {
		if record.Execution.Started || record.Execution.Completed {
			t.Errorf("unobserved case entry credited: side=%s execution=%+v", record.Side, record.Execution)
		}
	}
}

// Claim: helper-only lifecycle metadata also stays unrun in the driver report.
// Unrelated worker rows are unavailable; the measured candidate is never run.
func TestReviewPeerHelperOnlyReport(t *testing.T) {
	f := configuredPeerRow(t)
	f.PeerHelper = rowTool(t, "./testdata/metadataonly")
	path, c, root := setup(t)
	configuration := filepath.Join(filepath.Dir(path), "roles.json")
	b, e := wire.Encode(f)
	if e != nil || os.WriteFile(configuration, b, 0600) != nil {
		t.Fatal("fixture configuration")
	}
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = filepath.Join(root, "unavailable-worker")
	var out bytes.Buffer
	if code := d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--fixtures", "--fixture-config", configuration, "--evidence-dir", root}, &out); code != 69 {
		t.Fatal("driver status", code)
	}
	var result report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &result) != nil {
		t.Fatal("driver report")
	}
	for _, row := range result.Cases {
		if row.ID == "peer-denied" {
			for _, control := range []qualification.Control{row.Negative, row.Positive} {
				if control.Executed || control.ExitCode != -1 || control.Verdict != "pending" || len(control.Artifacts) != 0 {
					t.Errorf("helper-only report gained emitted execution: executed=%v status=%d verdict=%s artifacts=%d", control.Executed, control.ExitCode, control.Verdict, len(control.Artifacts))
				}
			}
			return
		}
	}
	t.Fatal("missing peer row")
}

// Claim: a pre-case worker receipt alone cannot establish canonical entry in
// transport, admission or runner. The fixture never calls a case or uses I/O
// except the receipt. Existing real cases supply the positive controls.
func TestReviewPreCaseReceipt(t *testing.T) {
	worker := rowTool(t, "./testdata/receiptonly")
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"frame-oversized", "account-unknown", "home-auth-present"} {
		t.Run(id, func(t *testing.T) {
			_, c, root := setup(t)
			var records []rowExecutionRecord
			d := driver{rowExecutable: worker, runnerExecutable: fake, executions: &records}
			control := d.runRow(context.Background(), c.Policy, root, id, "positive")
			if control.Executed || control.ExitCode != -1 || control.Verdict != "pending" || len(control.Artifacts) != 0 {
				t.Errorf("pre-case receipt gained execution: executed=%v status=%d verdict=%s artifacts=%d", control.Executed, control.ExitCode, control.Verdict, len(control.Artifacts))
			}
		})
	}
}

// Claim: unknown helper diagnostic text is replaced by a fixed parent code in
// the emitted report; no case execution or second helper launch is credited.
func TestReviewDiagnosticBoundary(t *testing.T) {
	f := configuredPeerRow(t)
	f.PeerHelper = rowTool(t, "./testdata/unknowndiagnostic")
	path, c, root := setup(t)
	configuration := filepath.Join(filepath.Dir(path), "roles.json")
	b, e := wire.Encode(f)
	if e != nil || os.WriteFile(configuration, b, 0600) != nil {
		t.Fatal("fixture configuration")
	}
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = filepath.Join(root, "unavailable-worker")
	var out bytes.Buffer
	if code := d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--fixtures", "--fixture-config", configuration, "--evidence-dir", root}, &out); code != 69 {
		t.Fatal("driver status", code)
	}
	if strings.Contains(out.String(), "fixture-diagnostic-canary") {
		t.Fatal("raw helper diagnostic emitted")
	}
	var result report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &result) != nil {
		t.Fatal("driver report")
	}
	seen := map[string]rowExecution{}
	for _, record := range result.Executions {
		if record.ID == "peer-denied" {
			seen[record.Side] = record.Execution
		}
	}
	if len(seen) != 2 || seen["negative"].Diagnostic != "case_evidence_invalid" || seen["negative"].Started || seen["positive"].Launched {
		t.Fatal("diagnostic boundary state", seen)
	}
}
