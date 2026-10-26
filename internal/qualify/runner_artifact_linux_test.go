//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Acceptance is a private test decision about this compiled audited fixture,
// independent of the image subsequently selected for a particular invocation.
func acceptedRunnerDriver(t *testing.T, worker, fake string) driver {
	t.Helper()
	f, err := qualification.OpenExecutable(worker)
	mustTestimony(t, err)
	defer f.Close()
	digest, err := descriptorDigest(f)
	mustTestimony(t, err)
	return driver{rowExecutable: worker, runnerExecutable: fake, runnerAcceptedImage: digest}
}

// Claim: both actual pairs carry the closed testimony schema and protected
// artifacts privately bound to their own accepted image, observations and wait.
// Serialized fields, refreshed hashes, another invocation, absent artifacts and
// absent joins cannot replace that proof. These remain synthetic-code evidence.
func TestRunnerArtifactBinding(t *testing.T) {
	worker, fake := rowTool(t, "../../cmd/swarma-credential-broker"), rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"home-auth-present", "source-conflict"} {
		t.Run(id, func(t *testing.T) {
			_, c, root := setup(t)
			d := acceptedRunnerDriver(t, worker, fake)
			var records []rowExecutionRecord
			d.executions = &records
			pair := qualification.Case{ID: id}
			d.runRunnerPair(context.Background(), c.Policy, root, &pair)
			check := func(pair qualification.Case, records []rowExecutionRecord) error {
				return validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, pair, records)
			}
			if check(pair, records) != nil || len(records) != 2 {
				t.Fatal("actual runner pair not bound", pair, records)
			}
			for _, r := range records {
				e := r.Execution
				control := map[string]qualification.Control{"positive": pair.Positive, "negative": pair.Negative}[r.Side]
				wantStatus, wantOutcome := 0, "success"
				if r.Side == "negative" {
					wantStatus, wantOutcome = 69, "credential_source_conflict"
				}
				if !e.credit(false) || e.Runner.Class != "measured-code-testimony" || e.Runner.CaseImage != d.runnerAcceptedImage || e.Runner.CommandStatus != wantStatus || e.Runner.CommandOutcome != wantOutcome || e.CaseExit != 0 || control.Command[0] != "/proc/self/fd/3" {
					t.Fatal("runner evidence schema/outcomes", e)
				}
			}
			path := rowFile(root, id, "negative")
			original, err := os.ReadFile(path)
			mustTestimony(t, err)
			for _, defect := range []string{"artifact", "private-proof", "class", "missing-class", "image", "outcome", "join", "preparatory", "bytes", "deadline", "effect-contradiction"} {
				t.Run(defect, func(t *testing.T) {
					if check(pair, records) != nil {
						t.Fatal("adjacent bound control refused")
					}
					proofs := slices.Clone(records)
					e := proofs[1].Execution
					if defect == "effect-contradiction" {
						p := records[0].Execution.runnerProof
						o := *p.observation
						effects := *o.observation.Runner
						o.observation.Runner = &effects
						o.outcome = runner.Outcome{Status: 69, Kind: runner.OutcomeSourceConflict}
						effects.Status, effects.LocalConflict = 69, true
						if o.validate(p.input, true, true) {
							t.Fatal("source refusal accepted with positive broker effects")
						}
						return
					}
					if defect == "deadline" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						fresh := newRowExecution()
						fresh.Launched = true
						p := e.runnerProof
						fresh.waited(p.observation.trace.State)
						x := runnerArtifact(ctx, t.TempDir(), p.input, p.observation, &fresh, time.Millisecond)
						if x.Executed || x.ExitCode != -1 || len(x.Artifacts) != 0 || fresh.credit(false) {
							t.Fatal("expired runner artifact credited")
						}
						return
					}
					if defect == "artifact" {
						mustTestimony(t, os.Remove(path))
						defer os.WriteFile(path, original, 0600)
						if check(pair, records) == nil {
							t.Fatal("missing runner artifact accepted")
						}
						e.artifact = ""
						if e.credit(false) {
							t.Fatal("artifact-free execution credited")
						}
						return
					}
					if defect == "private-proof" || defect == "join" || defect == "preparatory" {
						switch defect {
						case "private-proof":
							e.runnerProof = nil
						case "join":
							p := *e.runnerProof
							o := *p.observation
							o.trace.State = nil
							p.observation, e.runnerProof = &o, &p
						case "preparatory":
							e.attested = false
						}
						if e.credit(false) {
							t.Fatal("unproved runner execution credited", defect)
						}
						proofs[1].Execution = e
						if check(pair, proofs) == nil {
							t.Fatal("unproved runner artifact accepted", defect)
						}
						return
					}
					var a rowArtifact
					mustTestimony(t, wire.Decode(original, &a))
					switch defect {
					case "class":
						a.Execution.Runner.Class = "kernel-observed-call"
					case "missing-class":
						a.Execution.Runner = nil
					case "image":
						a.Execution.Runner.CaseImage = strings.Repeat("a", 64)
					case "outcome":
						a.Execution.Runner.CommandStatus, a.Execution.Runner.CommandOutcome = 0, "success"
					case "bytes":
						a.Incomplete = true
					}
					b, err := wire.Encode(a)
					mustTestimony(t, err)
					mustTestimony(t, os.WriteFile(path, b, 0600))
					defer os.WriteFile(path, original, 0600)
					bad := pair
					bad.Negative.Artifacts = []string{qualification.Hash(b)}
					if defect != "bytes" {
						// Expose semantic checks beyond the existing exact-byte gate;
						// only test-owned public fields/hash are refreshed, never proof.
						proofs[1].Execution.Runner = a.Execution.Runner
						proofs[1].Execution.artifact = qualification.Hash(b)
					}
					if check(bad, proofs) == nil {
						t.Fatal("substituted runner artifact accepted", defect)
					}
				})
			}
		})
	}
}

// Claim: complete preparatory observation cannot choose its own accepted image.
// Missing/wrong pins and failed artifact creation cannot earn credit or
// overwrite an existing file. Each is next to the same executable with explicit
// private acceptance. A joined case 17 with valid testimony is FAIL, not UNRUN.
func TestRunnerArtifactAcceptance(t *testing.T) {
	worker, fake := runnerFaultTool(t, "case-status"), rowTool(t, "../runner/testdata/appserver")
	for _, pin := range []string{"accepted", "missing", "wrong", "artifact"} {
		t.Run(pin, func(t *testing.T) {
			_, c, root := setup(t)
			d := acceptedRunnerDriver(t, worker, fake)
			if pin == "missing" {
				d.runnerAcceptedImage = ""
			} else if pin == "wrong" {
				d.runnerAcceptedImage = strings.Repeat("a", 64)
			}
			if pin == "artifact" {
				mustTestimony(t, os.WriteFile(rowFile(root, "source-conflict", "negative"), []byte("existing"), 0600))
			}
			var o runnerObservation
			var records []rowExecutionRecord
			d.executions = &records
			control := d.runRowObserved(context.Background(), c.Policy, root, "source-conflict", "negative", &o)
			if !o.available || len(records) != 1 || records[0].Execution.HelperExit != 17 {
				t.Fatal("real preparatory control unavailable", records)
			}
			if pin == "accepted" {
				if !control.Executed || control.Verdict != "failed" || control.ExitCode != 17 || !records[0].Execution.credit(false) || records[0].Execution.Runner.CommandStatus != 69 {
					t.Fatal("genuine separate failure lost", control, records)
				}
				forged := records[0].Execution
				forged.HelperExit, forged.WorkerExit, forged.CaseExit = 0, 0, 0
				if forged.credit(false) {
					t.Fatal("real wait replaced by claimed status")
				}
				pair := qualification.Case{ID: "source-conflict"}
				d.runRunnerPair(context.Background(), c.Policy, t.TempDir(), &pair)
				if pair.Positive.Verdict != "failed" || pair.Positive.ExitCode != 17 || pair.Negative.Executed || records[len(records)-1].Execution.Launched {
					t.Fatal("failed positive erased or neighbor launched", pair, records)
				}
			} else if pin == "artifact" {
				b, err := os.ReadFile(rowFile(root, "source-conflict", "negative"))
				mustTestimony(t, err)
				if string(b) != "existing" || control.Executed || control.ExitCode != -1 || len(control.Artifacts) != 0 || records[0].Execution.credit(false) || records[0].Execution.CaseExit != -1 {
					t.Fatal("artifact write failure gained credit or overwrote evidence", control, records)
				}
			} else {
				assertOriginPending(t, root, "source-conflict", control)
				if records[0].Execution.credit(false) {
					t.Fatal("unaccepted image credited")
				}
			}
		})
	}
}

// Claim: measuring the trusted parent for acceptance leaves the retained image
// ready for the separate child measurement; this checks bytes, not CLI routing.
func TestRunnerParentImageMeasurement(t *testing.T) {
	f, err := os.Open("/proc/self/exe")
	mustTestimony(t, err)
	defer f.Close()
	accepted, err := runnerParentImage(f)
	mustTestimony(t, err)
	measured, err := descriptorDigest(f)
	mustTestimony(t, err)
	if accepted != measured || len(accepted) != 64 || accepted == qualification.Hash(nil) {
		t.Fatal("parent image acceptance consumed retained bytes")
	}
}

// Claim: this accepted fixture performs a real Command parse refusal and authentic
// post-return exchange. Zero parent effects yield FAIL with Command 64/case 0;
// its adjacent ordinary positive still passes. Substitutions are tested above.
func TestRunnerUnexpectedOutcome(t *testing.T) {
	worker, fake := runnerFaultTool(t, "unexpected"), rowTool(t, "../runner/testdata/appserver")
	_, c, root := setup(t)
	d := acceptedRunnerDriver(t, worker, fake)
	var records []rowExecutionRecord
	d.executions = &records
	pair := qualification.Case{ID: "source-conflict"}
	d.runRunnerPair(context.Background(), c.Policy, root, &pair)
	if pair.Positive.Verdict != "passed" || pair.Negative.Verdict != "failed" || pair.Negative.ExitCode != 0 || !pair.Negative.Executed || len(records) != 2 {
		t.Fatal("authentic unexpected outcome lost FAIL", pair, records)
	}
	e := records[1].Execution
	if !e.credit(false) || e.Runner.CommandStatus != 64 || e.Runner.CommandOutcome != "failure" || e.CaseExit != 0 || validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, pair, records) != nil {
		t.Fatal("authentic unexpected outcome lost separate status", e)
	}
}
