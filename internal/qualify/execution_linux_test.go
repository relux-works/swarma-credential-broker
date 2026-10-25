//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: only the worker's four fixed phase codes can cross its reply boundary;
// arbitrary helper diagnostic text cannot become report content.
func TestWorkerDiagnosticCodes(t *testing.T) {
	for _, code := range []rowDiagnostic{"", "case_not_started", "case_status_unavailable", "observation_invalid"} {
		if !workerDiagnostic(code) {
			t.Fatal("fixed worker code rejected")
		}
	}
	if workerDiagnostic("untrusted diagnostic") {
		t.Fatal("helper diagnostic text accepted")
	}
}

// Claim: the externally emitted report preserves typed startup diagnostics
// while both peer controls remain pending, without recording helper output.
func TestPeerStartupReportDiagnostics(t *testing.T) {
	f := configuredPeerRow(t)
	path, c, root := setup(t)
	configuration := filepath.Join(filepath.Dir(path), "roles.json")
	b, _ := wire.Encode(f)
	if os.WriteFile(configuration, b, 0600) != nil {
		t.Fatal("fixture configuration")
	}
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = filepath.Join(root, "missing-worker")
	t.Setenv("PATH", t.TempDir())
	var out bytes.Buffer
	if d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--fixtures", "--fixture-config", configuration, "--evidence-dir", root}, &out) != 69 {
		t.Fatal("unavailable run status")
	}
	var report report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &report) != nil {
		t.Fatal("report")
	}
	seen := map[string]rowDiagnostic{}
	for _, record := range report.Executions {
		if record.ID == "peer-denied" {
			seen[record.Side] = record.Execution.Diagnostic
			if record.Execution.Launched || record.Execution.Started || record.Execution.CaseExit != -1 {
				t.Fatal("unrun report gained execution", record)
			}
		}
	}
	if len(seen) != 2 || seen["negative"] != "launcher_lookup_failed" || seen["positive"] != "peer_pair_unavailable" {
		t.Fatal("typed startup diagnostics lost", seen)
	}
}

// Claim: actual canonical exchanges ending with status 17 retain that status
// for peer, transport, admission and runner, despite invalid observation bytes.
// The normal real pair and TestRowsHarness supply the adjacent zero-status control.
func TestCaseCompletionStatus(t *testing.T) {
	worker := rowTool(t, "./testdata/caseexit")
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"peer-denied", "frame-oversized", "account-unknown", "home-auth-present"} {
		t.Run(id, func(t *testing.T) {
			_, c, root := setup(t)
			var records []rowExecutionRecord
			d := driver{rowExecutable: worker, runnerExecutable: fake, executions: &records}
			var row qualification.Case
			if id == "peer-denied" {
				f := configuredPeerRow(t)
				f.PeerHelper = worker
				row.ID = id
				d.runPeerRows(context.Background(), f, c.Policy, root, &row)
			} else {
				row = qualification.Case{ID: id, Positive: d.runRow(context.Background(), c.Policy, root, id, "positive"), Negative: d.runRow(context.Background(), c.Policy, root, id, "negative")}
			}
			if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, row) != nil {
				t.Fatal("completed failure evidence rejected", row)
			}
			for _, control := range []qualification.Control{row.Positive, row.Negative} {
				if !control.Executed || control.ExitCode != 17 || control.Verdict != "failed" {
					t.Fatal("completed case status replaced", control)
				}
			}
			if len(records) != 2 {
				t.Fatal("completion records missing")
			}
			for _, record := range records {
				e := record.Execution
				wantHelper := 17
				if id == "peer-denied" {
					wantHelper = 0 // outer helper completed; bounded case exited 17
				}
				if !e.credit(id == "peer-denied") || e.WorkerExit != 17 || e.HelperExit != wantHelper || e.CaseExit != 17 || e.Diagnostic != "observation_invalid" {
					t.Fatal("completion status lost", e)
				}
			}
		})
	}
}

// Claim: missing/non-executable launchers, early helper exits and invalid
// handshakes stay unrun, with joined actual helper status and typed diagnostics.
func TestPeerStartupDiagnostics(t *testing.T) {
	configured := configuredPeerRow(t)
	for _, kind := range []string{"missing", "non-executable", "early", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			f := configured
			_, c, root := setup(t)
			wantCode := rowDiagnostic("peer_handshake_unavailable")
			wantExit := 17
			switch kind {
			case "missing", "non-executable":
				dir := t.TempDir()
				t.Setenv("PATH", dir)
				// Go's PATH lookup uses ErrNotFound for both absent and
				// non-executable entries; do not invent a more specific cause.
				wantCode, wantExit = "launcher_lookup_failed", -1
				if kind == "non-executable" {
					if os.WriteFile(filepath.Join(dir, "sudo"), []byte("fixture"), 0600) != nil {
						t.Fatal("launcher fixture")
					}
				}
			default:
				helper := filepath.Join(t.TempDir(), "helper")
				text := "#!/bin/sh\nexit 17\n"
				if kind == "mismatch" {
					// Real UID/GID, deliberately invalid PID; never an invented peer.
					text = "#!/bin/sh\nprintf '{\"UID\":%s,\"GID\":%s,\"PID\":0}\\n' \"$(id -u)\" \"$(id -g)\"\nexit 23\n"
					wantCode, wantExit = "peer_identity_mismatch", 23
				}
				if os.WriteFile(helper, []byte(text), 0700) != nil {
					t.Fatal("helper fixture")
				}
				f.PeerHelper = helper
			}
			var records []rowExecutionRecord
			row := qualification.Case{ID: "peer-denied"}
			(driver{executions: &records}).runPeerRows(context.Background(), f, c.Policy, root, &row)
			for _, control := range []qualification.Control{row.Positive, row.Negative} {
				if control.Executed || control.ExitCode != -1 || control.Verdict != "pending" || len(control.Artifacts) != 0 {
					t.Fatal("startup failure gained execution", control)
				}
			}
			if len(records) != 2 {
				t.Fatal("startup diagnostics missing")
			}
			e := records[0].Execution
			if e.Diagnostic != wantCode || e.HelperExit != wantExit || e.Started || e.Completed || e.CaseExit != -1 || e.Handshake || e.Joined != (wantExit >= 0) {
				t.Fatal("startup phase/status conflated", e)
			}
			if records[1].Execution.Launched || records[1].Execution.Diagnostic != "peer_pair_unavailable" {
				t.Fatal("unavailable pair launched its neighbor", records[1])
			}
		})
	}
}

// Claim: starting a worker/launcher that exits before canonical entry cannot
// acquire execution credit in any of the shared transport/admission/runner paths.
func TestRowStartupEvidence(t *testing.T) {
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"frame-oversized", "account-unknown", "home-auth-present"} {
		for _, kind := range []string{"missing", "early"} {
			t.Run(id+"/"+kind, func(t *testing.T) {
				_, c, root := setup(t)
				worker := filepath.Join(t.TempDir(), "worker")
				if kind == "early" && os.WriteFile(worker, []byte("#!/bin/sh\nexit 17\n"), 0700) != nil {
					t.Fatal("worker fixture")
				}
				var records []rowExecutionRecord
				d := driver{rowExecutable: worker, runnerExecutable: fake, executions: &records}
				control := d.runRow(context.Background(), c.Policy, root, id, "positive")
				if control.Executed || control.Verdict != "pending" || control.ExitCode != -1 || len(control.Artifacts) != 0 {
					t.Fatal("worker startup gained execution", control)
				}
				if len(records) != 1 || records[0].Execution.Started || records[0].Execution.CaseExit != -1 {
					t.Fatal("worker phase evidence", records)
				}
				e := records[0].Execution
				if kind == "early" && (!e.Launched || !e.Joined || e.HelperExit != 17 || e.Diagnostic != "case_not_started") {
					t.Fatal("worker actual wait status lost", e)
				}
			})
		}
	}
}

// Claim: execution proof and recorded exit are mandatory even for failed rows;
// a self-consistent artifact hash cannot replace missing start/completion proof.
func TestExecutionArtifactIntegrity(t *testing.T) {
	_, c, root := setup(t)
	d := driver{rowExecutable: rowTool(t, "../../cmd/swarma-credential-broker")}
	id := "frame-oversized"
	row := qualification.Case{ID: id, Positive: d.runRow(context.Background(), c.Policy, root, id, "positive"), Negative: d.runRow(context.Background(), c.Policy, root, id, "negative")}
	b, _ := os.ReadFile(rowFile(root, id, "negative"))
	for _, defect := range []string{"missing", "start", "completion", "status"} {
		t.Run(defect, func(t *testing.T) {
			var a rowArtifact
			if wire.Decode(b, &a) != nil {
				t.Fatal("original artifact")
			}
			a.Control.Verdict = "failed"
			switch defect {
			case "missing":
				a.Execution = nil
			case "start":
				a.Execution.Started = false
			case "completion":
				a.Execution.Completed = false
			case "status":
				a.Execution.CaseExit++
			}
			tampered, _ := wire.Encode(a)
			if os.WriteFile(rowFile(root, id, "negative"), tampered, 0600) != nil {
				t.Fatal("artifact plant")
			}
			copy := row
			copy.Negative.Verdict = "failed"
			copy.Negative.Artifacts = []string{qualification.Hash(tampered)}
			if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, copy) == nil {
				t.Fatal("unproved execution credited", defect)
			}
		})
	}
}
