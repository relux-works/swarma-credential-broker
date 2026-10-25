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

// Claim: actual Command preflight rejects both established sources before any
// authority/broker/owner/child work; clean neighbors complete synthetic login
// through the existing app-server fixture under the real egress boundary.
func TestRunnerRowFixtures(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"home-auth-present", "source-conflict"} {
		for _, side := range []string{"positive", "negative"} {
			t.Run(id+"/"+side, func(t *testing.T) {
				_, c, root := setup(t)
				d := driver{rowExecutable: worker, runnerExecutable: fake}
				control := d.runRow(context.Background(), c.Policy, root, id, side)
				b, e := os.ReadFile(rowFile(root, id, side))
				var a rowArtifact
				if e != nil || wire.Decode(b, &a) != nil || control.Verdict != "passed" || !validRunnerEffects(a.Observation) || !validAdmissionEffects(a.Observation) {
					t.Fatalf("runner source verdict/effects: %+v %v", control, e)
				}
				if len(a.Observation.Envelopes) != 0 {
					t.Fatal("local refusal invented wire frame")
				}
				original := a.Observation.Runner
				for _, defect := range []string{"missing", "status", "login", "resolve", "state"} {
					copy := *original
					a.Observation.Runner = &copy
					switch defect {
					case "missing":
						a.Observation.Runner = nil
					case "status":
						copy.Status++
					case "login":
						copy.Login++
					case "resolve":
						copy.Resolves++
					case "state":
						copy.StateVerified = false
					}
					if validRunnerEffects(a.Observation) {
						t.Fatal("runner evidence defect credited", defect)
					}
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
