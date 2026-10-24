//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func rowTool(t *testing.T, pkg string) string {
	t.Helper()
	tool := filepath.Join(t.TempDir(), "worker")
	cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", tool, pkg)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if os.Chmod(tool, 0700) != nil {
		t.Fatal("protect worker")
	}
	return tool
}
func rowConfiguration(t *testing.T, p policy.Policy, root string) string {
	t.Helper()
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := wire.Encode(fixtureConfiguration{u.Username, u.Username, "unavailable-fixture-role", p.Accounts[0].Label, true})
	path := filepath.Join(root, "roles.json")
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("roles")
	}
	return path
}

// Claim: all six transport rows run their exact positive and negative descriptor
// commands; unresolved rows gain no execution, and no worker home survives.
// The synthetic approved descriptor is measured, never executed as Codex.
func TestRowsHarness(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	path, c, root := setup(t)
	configuration := rowConfiguration(t, c.Policy, filepath.Dir(path))
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = worker
	var out bytes.Buffer
	if code := d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--fixtures", "--fixture-config", configuration, "--evidence-dir", root}, &out); code != 69 {
		t.Fatal("fixture publication gate", code)
	}
	var r report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil || r.Disposition != "pending" {
		t.Fatal("report")
	}
	expected := map[string]string{"frame-oversized": "frame_too_large", "frame-zero-length": "closed", "frame-truncated-header": "closed", "frame-malformed-first": "closed", "profile-unsupported": "version_unsupported", "peer-identity-unavailable": "peer_identity_unavailable"}
	n := 0
	for _, row := range r.Cases {
		want, implemented := expected[row.ID]
		if !implemented {
			if row.Positive.Executed || row.Negative.Executed || row.Positive.Verdict != "pending" || row.Negative.Verdict != "pending" || len(row.Positive.Artifacts)+len(row.Negative.Artifacts) != 0 {
				t.Fatal("pending row credited", row.ID)
			}
			continue
		}
		n++
		t.Run(row.ID, func(t *testing.T) {
			if row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed" || validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, row) != nil {
				t.Fatalf("paired controls: %+v", row)
			}
			for side, control := range map[string]qualification.Control{"positive": row.Positive, "negative": row.Negative} {
				b, e := os.ReadFile(rowFile(root, row.ID, side))
				var a rowArtifact
				if e != nil || wire.Decode(b, &a) != nil {
					t.Fatal("artifact")
				}
				refusal := "hello"
				if side == "negative" {
					refusal = want
				}
				if !reflect.DeepEqual(control.Command, qualification.CaseCommand(row.ID, side)) || control.ExitCode != 0 || !control.Executed || a.Observation.Refusal != refusal || !a.Observation.NoEffects {
					t.Fatal("exact command/refusal/effects")
				}
			}
		})
	}
	if n != 6 {
		t.Fatal("implemented registry drift", n)
	}
	homes, e := filepath.Glob(filepath.Join(os.TempDir(), "qualification-row-*"))
	if e != nil || len(homes) != 0 {
		t.Fatal("worker teardown", homes)
	}
	if _, e := os.Lstat(filepath.Join(qualification.Directory(path), "qualified.json")); !os.IsNotExist(e) {
		t.Fatal("published")
	}
	if len(r.Unavailable) == 0 {
		t.Fatal("properties gate opened")
	}
	row := r.Cases[25] // frame-oversized in the fixed required registry
	if row.ID != "frame-oversized" {
		t.Fatal("registry assumption")
	}
	if row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed" {
		t.Fatal("paired controls required for evidence baseline")
	}
	// Claim: each evidence defect independently refuses an otherwise green row.
	for _, defect := range []string{"positive", "missing", "case", "digest", "observation", "duration", "envelope-missing", "envelope-kind", "envelope-id", "envelope-size", "envelope-code", "envelope-message", "envelope-result", "envelope-generation", "envelope-variant"} {
		t.Run("evidence-"+defect, func(t *testing.T) {
			bad := row
			file := rowFile(root, row.ID, "negative")
			if defect == "envelope-generation" {
				file = rowFile(root, row.ID, "positive")
			}
			original, _ := os.ReadFile(file)
			defer os.WriteFile(file, original, 0600)
			switch defect {
			case "positive":
				bad.Positive = qualification.Control{}
			case "missing":
				if os.Remove(file) != nil {
					t.Fatal("plant")
				}
			case "case":
				bad.ID = "profile-unsupported"
			case "digest":
				bad.Negative.Artifacts = []string{qualification.Hash([]byte("tampered"))}
			case "duration":
				bad.Negative.DurationNS = bad.Negative.BoundNS + 1
			case "observation":
				var a rowArtifact
				wire.Decode(original, &a)
				a.Observation.ID = "profile-unsupported"
				b, _ := wire.Encode(a)
				os.WriteFile(file, b, 0600)
				bad.Negative.Artifacts = []string{qualification.Hash(b)}
			default:
				// Rehashing edited facts cannot hide an invalid envelope, even
				// when the refusal label and exit code remain correct.
				var a rowArtifact
				if wire.Decode(original, &a) != nil {
					t.Fatal("artifact")
				}
				f := &a.Observation.Envelopes[0]
				switch defect {
				case "envelope-missing":
					a.Observation.Envelopes = []rowEnvelope{}
				case "envelope-kind":
					f.Kind = "hello"
				case "envelope-id":
					id := "fixture-hello"
					f.RequestID = &id
				case "envelope-size":
					f.PayloadBytes++
				case "envelope-code":
					f.Refusal.Code = "peer_identity_unavailable"
				case "envelope-message":
					f.Refusal.Message = "unexpected"
				case "envelope-result":
					f.Hello = &rowHello{}
				case "envelope-generation":
					f.Hello.Generation++
				case "envelope-variant":
					a.Observation.Envelopes = append(a.Observation.Envelopes, *f)
				}
				b, e := wire.Encode(a)
				if e != nil || os.WriteFile(file, b, 0600) != nil || qualification.Hash(b) == qualification.Hash(original) {
					t.Fatal("envelope fact plant")
				}
				if defect == "envelope-generation" {
					bad.Positive.Artifacts = []string{qualification.Hash(b)}
				} else {
					bad.Negative.Artifacts = []string{qualification.Hash(b)}
				}
			}
			if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, bad) == nil {
				t.Fatal("evidence defect credited", defect)
			}
		})
	}
	// Claim: public path/shell entry cannot impersonate the descriptor worker.
	for _, args := range [][]string{{"qualification-case", "frame-oversized", "positive"}, {"qualification-case", "frame-oversized; true", "positive"}, {"qualification-case", "frame-oversized", "positive; true"}} {
		cmd := exec.Command(worker, args...)
		if e := cmd.Run(); e == nil || cmd.ProcessState.ExitCode() != 125 {
			t.Fatal("path/shell dispatch accepted", e)
		}
	}
	// Claim: missing or undeclared same-user roles leave every body pending.
	for _, config := range []string{"", filepath.Join(root, "missing")} {
		cases := qualification.Pending(qualification.Identity{}).Cases
		d.runRows(context.Background(), config, c.Policy, root, cases)
		for _, row := range cases {
			if row.Positive.Executed || row.Negative.Executed {
				t.Fatal("unconfigured roles executed")
			}
		}
	}
	u, _ := user.Current()
	invalid, _ := wire.Encode(fixtureConfiguration{u.Username, u.Username, "unavailable-fixture-role", c.Policy.Accounts[0].Label, false})
	if os.WriteFile(configuration, invalid, 0600) != nil {
		t.Fatal("role declaration plant")
	}
	if _, e := fixturePolicy(configuration, c.Policy); e == nil {
		t.Fatal("undeclared same-user role accepted")
	}

}

// Claim: even a worker that reports successful controls loses all pass credit
// when it attempts an external connect; the boundary refuses that syscall.
// The probe uses an invalid FD, so a mutant cannot transmit a packet either.
func TestRowIsolationRefusal(t *testing.T) {
	worker := rowTool(t, "./testdata/rowprobe")
	_, c, root := setup(t)
	d := driver{rowExecutable: worker}
	control := d.runRow(context.Background(), c.Policy, root, "frame-oversized", "positive")
	b, e := os.ReadFile(rowFile(root, "frame-oversized", "positive"))
	var a rowArtifact
	if e != nil || wire.Decode(b, &a) != nil || !a.IsolationFailed || a.Network["external"].Refused != 1 {
		t.Fatal("external fault did not fire", e)
	}
	if !control.Executed || control.ExitCode != 0 || control.Verdict != "failed" {
		t.Fatal("isolation refusal credited", control)
	}
	// The validator also rejects a fabricated pass with a self-consistent hash.
	a.Control.Verdict = "passed"
	a.IsolationFailed = false
	b, _ = wire.Encode(a)
	os.WriteFile(rowFile(root, a.ID, a.Side), b, 0600)
	control.Verdict = "passed"
	control.Artifacts = []string{qualification.Hash(b)}
	if rowIsolated(a) {
		t.Fatal("external summary credited")
	}
}

// Claim: cancellation before client launch leaves no socket/home or fabricated
// execution evidence, including when the parent listener is still starting.
func TestRowCancelled(t *testing.T) {
	_, c, root := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	control := (driver{}).runRow(ctx, c.Policy, root, "frame-oversized", "positive")
	if control.Executed || control.Verdict != "pending" || control.ExitCode != -1 || len(control.Artifacts) != 0 {
		t.Fatal("cancelled launch credited")
	}
	homes, _ := filepath.Glob(filepath.Join(os.TempDir(), "qualification-row-*"))
	if len(homes) != 0 {
		t.Fatal("cancelled launch retained home")
	}
}
