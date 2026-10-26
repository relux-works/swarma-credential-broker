//go:build linux

package qualify

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const runnerEvidenceClass = "measured-code-testimony"

// This closed report schema separates Command testimony from the consuming wait.
// The digest identifies audited bytes under the documented trusted-code premise.
type runnerEvidence struct {
	Class          string `json:"class"`
	CaseImage      string `json:"case_image_sha256"`
	CommandStatus  int    `json:"command_status"`
	CommandOutcome string `json:"command_outcome"`
}

type runnerArtifactProof struct {
	observation *runnerObservation
	input       rowInput
	accepted    string
	evidence    runnerEvidence // value snapshot, never aliases serialized fields
}

// Acceptance of the trusted parent's current image is independent of a private
// test replacement. Preserve the retained descriptor for the child's measurement.
func runnerParentImage(f *os.File) (string, error) {
	digest, err := descriptorDigest(f)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	return digest, err
}

func runnerEvidenceFor(o *runnerObservation) runnerEvidence {
	kind := map[runner.OutcomeKind]string{runner.OutcomeSuccess: "success", runner.OutcomeSourceConflict: "credential_source_conflict", runner.OutcomeFailure: "failure"}[o.outcome.Kind]
	return runnerEvidence{runnerEvidenceClass, o.image, o.outcome.Status, kind}
}

func (p *runnerArtifactProof) valid() bool {
	return p != nil && p.observation != nil && p.observation.available && policy.Hash(p.accepted) && p.accepted == p.evidence.CaseImage && runnerEvidenceFor(p.observation) == p.evidence && p.observation.validate(p.input, true, true)
}

func (e rowExecution) runnerCredit() bool {
	return e.Runner != nil && e.runnerProof.valid() && e.Runner.Class == runnerEvidenceClass && e.Runner.CaseImage == e.runnerProof.evidence.CaseImage && e.Runner.CommandStatus == e.runnerProof.evidence.CommandStatus && e.Runner.CommandOutcome == e.runnerProof.evidence.CommandOutcome && e.HelperExit == e.runnerProof.observation.trace.State.ExitCode() && e.artifact != ""
}

// Seal only after trace, exchange, server, observers and actual wait have joined.
// Artifact bytes alone can never reconstruct this private proof or acceptance pin.
func runnerArtifact(ctx context.Context, root string, in rowInput, o *runnerObservation, e *rowExecution, elapsed time.Duration) qualification.Control {
	pending := pendingRowControl()
	proof := &runnerArtifactProof{observation: o, input: in, accepted: o.accepted, evidence: runnerEvidenceFor(o)}
	if ctx.Err() != nil || !proof.valid() || !e.Joined || e.HelperExit != o.trace.State.ExitCode() || e.HelperExit < 0 || elapsed <= 0 || elapsed > 30*time.Second {
		return pending
	}
	e.Runner = new(runnerEvidence)
	*e.Runner = proof.evidence
	e.runnerProof = proof
	e.attested, e.Handshake, e.Started, e.Completed = true, true, true, true
	e.WorkerExit, e.CaseExit, e.Diagnostic = e.HelperExit, e.HelperExit, ""
	control := pendingRowControl()
	control.Executed, control.ExitCode, control.Verdict = true, e.CaseExit, runnerVerdict(*e)
	control.Command, control.DurationNS = qualification.CaseCommand(in.ID, in.Side), int64(elapsed)
	a := rowArtifact{Kind: "qualification-row-control/1", Candidate: in.ApprovedDigest, ID: in.ID, Side: in.Side, Control: control, Observation: o.observation, Network: map[string]egress.Counts{}, Execution: e}
	b, err := wire.Encode(a)
	if err == nil {
		err = writeRunnerArtifact(rowFile(root, in.ID, in.Side), b)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		e.attested, e.Handshake, e.Started, e.Completed = false, false, false, false
		e.WorkerExit, e.CaseExit, e.Diagnostic = -1, -1, "observation_unavailable"
		e.Runner, e.runnerProof = nil, nil
		return pending
	}
	e.artifact = qualification.Hash(b)
	if !e.credit(false) {
		return pending
	}
	control.Artifacts = []string{e.artifact}
	return control
}

func writeRunnerArtifact(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func runnerArtifactMatches(a rowArtifact) bool {
	e := a.Execution
	return e != nil && e.runnerCredit() && e.runnerProof.input.ID == a.ID && e.runnerProof.input.Side == a.Side && e.runnerProof.input.ApprovedDigest == a.Candidate && reflect.DeepEqual(a.Observation, e.runnerProof.observation.observation)
}

// Authentic unexpected outcomes are failures; public outcome substitutions never
// reach this classifier because the private proof gate has already rejected them.
func runnerVerdict(e rowExecution) string {
	want := runner.Outcome{Status: 0, Kind: runner.OutcomeSuccess}
	if e.runnerProof.input.Side == "negative" {
		want = runner.Outcome{Status: 69, Kind: runner.OutcomeSourceConflict}
	}
	if e.CaseExit == 0 && e.runnerProof.observation.outcome == want {
		return "passed"
	}
	return "failed"
}
