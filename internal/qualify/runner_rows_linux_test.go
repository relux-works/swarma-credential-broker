//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func configureRunner(t *testing.T, path, executable string) {
	t.Helper()
	b, e := os.ReadFile(path)
	var f fixtureConfiguration
	if e != nil || wire.Decode(b, &f) != nil {
		t.Fatal("configuration")
	}
	f.Runner = executable
	b, _ = wire.Encode(f)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("configuration")
	}
}

// Claim: each real runner control earns only measured-code-testimony credit
// with an explicitly accepted image, joined exchange, effects and artifact.
func TestRunnerRowFixtures(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"home-auth-present", "source-conflict"} {
		for _, side := range []string{"positive", "negative"} {
			t.Run(id+"/"+side, func(t *testing.T) {
				_, c, root := setup(t)
				var records []rowExecutionRecord
				d := acceptedRunnerDriver(t, worker, fake)
				d.executions = &records
				control := d.runRow(context.Background(), c.Policy, root, id, side)
				if !control.Executed || control.Verdict != "passed" || control.ExitCode != 0 || len(control.Artifacts) != 1 {
					t.Fatal("runner control unavailable", control)
				}
				if len(records) != 1 || !records[0].Execution.Joined || records[0].Execution.HelperExit != 0 || records[0].Execution.Diagnostic != "" || records[0].Execution.Runner == nil {
					t.Fatal("runner origin", records)
				}
			})
		}
	}
}

// Claim: fixture inputs get the production typed refusal, including an empty
// reserved variable; the same clean configuration returns a real fingerprint.
// This complements Command's effect assertions rather than fabricating wire data.
func TestRunnerSourceTypes(t *testing.T) {
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"home-auth-present", "source-conflict"} {
		for _, side := range []string{"positive", "negative"} {
			t.Run(id+"/"+side, func(t *testing.T) {
				_, c, _ := setup(t)
				root := t.TempDir()
				if os.Mkdir(filepath.Join(root, "home"), 0700) != nil {
					t.Fatal("home")
				}
				in := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: id, Side: side})
				f, fixture, e := prepareRunnerRow(root, fake, &in)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				defer fixture.close()
				o, e := runner.Parse(runnerArgs(root))
				if e != nil {
					t.Fatal(e)
				}
				env := runnerEnvironment(o.LaunchHome)
				if id == "source-conflict" && side == "negative" {
					env = append(env, "OPENAI_API_KEY=")
				}
				digest, e := runner.ConfigurationDigest(o, env)
				if side == "negative" {
					r, ok := e.(*runner.Refusal)
					if !ok || r.Code != "credential_source_conflict" || r.Status != 69 || digest != "" {
						t.Fatal("typed source refusal", e)
					}
				} else if e != nil || digest != in.RunnerConfig || !policy.Hash(digest) {
					t.Fatal("clean source fingerprint", e)
				}
			})
		}
	}
}
