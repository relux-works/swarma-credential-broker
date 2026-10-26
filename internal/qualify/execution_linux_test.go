//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// Claim: attested transport/admission retain genuine canonical 0/17 statuses;
// peer and unaccepted runner images retain only launcher diagnostics.
func TestCaseCompletionStatus(t *testing.T) {
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, status := range []int{0, 17} {
		worker := rowTool(t, "../../cmd/swarma-credential-broker")
		if status != 0 {
			worker = rowTool(t, "./testdata/caseexit")
		}
		for _, id := range []string{"peer-denied", "frame-oversized", "account-unknown", "home-auth-present"} {
			t.Run(fmt.Sprintf("%s/%d", id, status), func(t *testing.T) {
				_, c, root := setup(t)
				var records []rowExecutionRecord
				d := driver{rowExecutable: worker, runnerExecutable: fake, executions: &records}
				if runnerRow(id) && status == 0 {
					d.runnerAcceptedImage = acceptedRunnerDriver(t, worker, fake).runnerAcceptedImage
				}
				if id == "peer-denied" {
					f := configuredPeerRow(t)
					if status != 0 {
						f.PeerHelper = worker
					}
					row := qualification.Case{ID: id}
					d.runPeerRows(context.Background(), f, c.Policy, root, &row)
					assertOriginPending(t, root, id, row.Negative)
					assertOriginPending(t, root, id, row.Positive)
				} else {
					control := d.runRow(context.Background(), c.Policy, root, id, "positive")
					if runnerRow(id) && status != 0 {
						assertOriginPending(t, root, id, control)
					} else if !control.Executed || control.ExitCode != status || control.Verdict != map[int]string{0: "passed", 17: "failed"}[status] {
						t.Fatal("canonical status lost", control)
					}
				}
				if len(records) == 0 {
					t.Fatal("missing launcher diagnostics")
				}
				e := records[0].Execution
				want := status
				if id == "peer-denied" {
					want = 0
				}
				if id != "peer-denied" && (!runnerRow(id) || status == 0) {
					if !e.credit(false) || e.CaseExit != status {
						t.Fatal("canonical wait/status missing", e)
					}
					return
				}
				if !e.Joined || e.HelperExit != want || e.Started || e.Completed || e.WorkerExit != -1 || e.CaseExit != -1 {
					t.Fatal("launcher status promoted to case", e)
				}
			})
		}
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
// Runner early exit uses a measured native image without testimony; a script is
// separately refused at its interpreter image, before its claimed exit 17.
func TestRowStartupEvidence(t *testing.T) {
	fake := rowTool(t, "../runner/testdata/appserver")
	early := rowTool(t, "./testdata/earlyexit")
	for _, id := range []string{"frame-oversized", "account-unknown", "home-auth-present"} {
		for _, kind := range []string{"missing", "early", "interpreter"} {
			if kind == "interpreter" && !runnerRow(id) {
				continue
			}
			t.Run(id+"/"+kind, func(t *testing.T) {
				_, c, root := setup(t)
				worker := filepath.Join(t.TempDir(), "worker")
				if (kind == "early" || kind == "interpreter") && os.WriteFile(worker, []byte("#!/bin/sh\nexit 17\n"), 0700) != nil {
					t.Fatal("worker fixture")
				}
				if kind == "early" && runnerRow(id) {
					worker = early
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
				if runnerRow(id) && kind != "missing" {
					wantExit := 17
					if kind == "interpreter" {
						wantExit = -1 // killed at the refused exec stop, never script exit 17
					}
					if !e.Launched || !e.Joined || e.HelperExit != wantExit || e.Diagnostic != "observation_invalid" || e.Handshake || e.Completed || e.WorkerExit != -1 {
						t.Fatal("runner measured startup wait/refusal lost", e)
					}
				} else if kind == "early" && (!e.Launched || !e.Joined || e.HelperExit != 17 || e.Diagnostic != "case_not_started" && e.Diagnostic != "case_origin_unavailable") {
					t.Fatal("worker actual wait status lost", e)
				}
			})
		}
	}
}

// Claim: even self-consistent claimed lifecycle metadata cannot establish
// execution or authorize artifacts without a supported origin witness.
func TestExecutionArtifactIntegrity(t *testing.T) {
	// Even internally consistent claimed lifecycle fields have no origin witness.
	for _, status := range []int{0, 17} {
		e := rowExecution{Launched: true, Handshake: true, Started: true, Completed: true, Joined: true, HelperExit: status, WorkerExit: status, CaseExit: status}
		if e.credit(false) || e.credit(true) {
			t.Fatal("unproved execution credited", e)
		}
		c := executionControl("frame-oversized", "positive", e, time.Second)
		if c.Executed || c.ExitCode != -1 || len(c.Artifacts) != 0 {
			t.Fatal("claimed status gained credit", c)
		}
	}
}
