//go:build linux

package runner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	static "github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type publicationObserver struct {
	qualification.NativeObserver
	path     string
	platform string
	catalog  qualification.Catalog
	missing  bool
}

func (o *publicationObserver) Version(context.Context) (string, error) { return "0.163.0", nil }
func (o *publicationObserver) Schema(context.Context) (qualification.Measurement, error) {
	if o.missing {
		return qualification.Measurement{}, qualification.ErrUnavailable
	}
	return qualification.Measurement{Observer: "schema/1", SHA256: qualification.Hash([]byte("fixture schema"))}, nil
}
func (o *publicationObserver) Properties(context.Context) (qualification.Measurement, error) {
	return qualification.Measurement{Observer: "properties/1", SHA256: qualification.Hash([]byte("fixture properties"))}, nil
}
func (o *publicationObserver) Platform(context.Context) (qualification.Measurement, error) {
	return qualification.Measurement{Observer: "platform/1", SHA256: qualification.Hash([]byte(o.platform))}, nil
}
func (o *publicationObserver) Configuration(ctx context.Context) (qualification.Measurement, error) {
	c, e := static.Load(o.path, uint32(os.Geteuid()))
	if e != nil {
		return qualification.Measurement{}, e
	}
	b, e := wire.Encode(c)
	if e != nil {
		return qualification.Measurement{}, e
	}
	return (qualification.NativeObserver{StaticPolicy: b}).Configuration(ctx)
}
func (o *publicationObserver) Catalog(context.Context) (qualification.Measurement, qualification.Catalog, error) {
	b, e := wire.Encode(o.catalog)
	return qualification.Measurement{Observer: "catalog/1", SHA256: qualification.Hash(b)}, o.catalog, e
}

// newPublishedAuthority exists only in tests. It uses the production protected
// list/evidence reader with a current fixture observer, never an in-memory grant.
func newPublishedAuthority(path string, o qualification.IdentityObserver) Dependencies {
	a := &protectedAuthority{path: path, observer: o}
	return Dependencies{Authority: a, Connect: a.connect, Supervisor: supervisorPath}
}
func publishFixtureRecord(t *testing.T, path string, o qualification.IdentityObserver) qualification.Record {
	t.Helper()
	identity, _, missing := qualification.Observe(context.Background(), o)
	if len(missing) > 0 {
		t.Fatal("fixture observation missing")
	}
	r := qualification.Repository{Path: qualification.Directory(path), UID: uint32(os.Geteuid()), Observer: o}
	rec := qualification.Pending(identity)
	rec.Mode = "live"
	rec.Disposition = "accepted"
	rec.OperatorAccepted = true
	rec.AccountCheck = "matched"
	ref, e := r.PutApproval(qualification.Approval{Kind: "qualification-approval/1", Identity: identity, AccountCheck: "matched", Accepted: true})
	must(t, e)
	rec.Approval = ref
	for n, c := range rec.Cases {
		for _, side := range []string{"positive", "negative"} {
			x := qualification.Control{Verdict: "passed", Executed: true, Command: qualification.CaseCommand(c.ID, side), ExitCode: 0, Artifacts: []string{}, DurationNS: 1, BoundNS: int64(time.Second)}
			ref, e := r.PutArtifact(qualification.Artifact{Kind: "qualification-case/1", Identity: identity, CaseID: c.ID, Side: side, Result: x})
			must(t, e)
			x.Artifacts = []string{ref}
			if side == "positive" {
				rec.Cases[n].Positive = x
			} else {
				rec.Cases[n].Negative = x
			}
		}
	}
	must(t, r.Publish(context.Background(), rec))
	return rec
}

// Claim: one protected published synthetic record qualifies the same exact
// tuple through real daemon admission and run-codex, refresh and durable release.
// Binary/config/platform drift, absent evidence and unavailable observations
// fail both readers before any vendor process or material delivery.
func TestPublishedQualification(t *testing.T) {
	for _, mode := range []string{"binary", "configuration", "platform", "missing-evidence", "missing-artifact", "unavailable", "fenced", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, map[string]any{"RefreshCount": 1, "Echo": true})
			// Never alter the shared fake: every binary-drift case owns its copy.
			raw, e := os.ReadFile(fakePath)
			must(t, e)
			candidate := filepath.Join(f.root, "candidate")
			must(t, os.WriteFile(candidate, raw, 0700))
			f.a.p.Executable = candidate
			path := filepath.Join(f.root, "policy.json")
			observer := &publicationObserver{NativeObserver: qualification.NativeObserver{ExecutablePath: candidate}, path: path, platform: "fixture-platform", catalog: qualification.Catalog{Models: []qualification.Model{{Name: f.o.Model, Efforts: []string{f.o.ReasoningEffort}}}}}
			gate := func(ctx context.Context, p static.Policy) error {
				c, e := static.Load(path, p.BrokerUID)
				if e != nil || !reflect.DeepEqual(c.Policy, p) {
					return qualification.ErrUnavailable
				}
				_, _, e = c.Qualified(ctx, path, observer)
				return e
			}
			daemon := integratedFixture(t, f, false, false, gate)
			rec := publishFixtureRecord(t, path, observer)
			f.d = newPublishedAuthority(path, observer)
			c, e := static.Load(path, uint32(os.Geteuid()))
			must(t, e)
			switch mode {
			case "binary":
				must(t, os.WriteFile(candidate, append(raw, '\n'), 0700))
			case "configuration":
				c.Policy.MaxLeaseSeconds--
				writeStatic(t, path, c)
			case "platform":
				observer.platform = "changed-platform"
			case "missing-evidence":
				b, _ := wire.Encode(rec)
				must(t, os.Remove(filepath.Join(qualification.Directory(path), "record-"+qualification.Hash(b)+".json")))
			case "missing-artifact":
				must(t, os.Remove(filepath.Join(qualification.Directory(path), "artifact-"+rec.Cases[0].Positive.Artifacts[0]+".json")))
			case "unavailable":
				observer.missing = true
			case "fenced":
				must(t, os.WriteFile(filepath.Join(qualification.Directory(path), "in-progress"), []byte("fixture fence\n"), 0600))
			}
			if mode != "valid" {
				// Bypass runner preflight as a separate negative control: the daemon must
				// independently reject the same tuple, rather than relying on its client.
				client, e := DialBroker(context.Background(), c.SocketPath)
				must(t, e)
				defer client.Close()
				clientHello(t, client)
				p := f.a.p
				b := c.Policy.Binding(p.UID, c.Policy.Accounts[0], f.o.Profile)
				_, e = client.Request(context.Background(), LeaseRequest{Harness: "codex_cli", Profile: f.o.Profile, Account: f.o.Account, Channel: "external-token", LaunchID: "fixture-launch", CredentialBinding: Binding{Digest: b.Digest, Harness: b.Harness, Profile: b.Profile, Account: b.Account, Channel: b.Channel, Endpoint: b.Endpoint, ExecutableSHA256: b.ExecutableSHA256, PolicyGeneration: b.PolicyGeneration}, Executor: Executor{Capabilities: []string{"credential-injection/1"}, Version: Version}})
				refusalCode(t, e, "lease_harness_unqualified", 69)
			}
			got := f.run()
			if mode == "valid" {
				requireStatus(t, got, 0, f.err.String())
				if n, _ := daemon.owner.Counts(); n != 1 {
					t.Fatal("published refresh did not reach owner")
				}
				account, e := daemon.disk.Account(f.o.Account, false)
				must(t, e)
				records, e := account.Records()
				must(t, e)
				released := 0
				for _, raw := range records {
					m, e := wire.Parse(raw)
					must(t, e)
					if m["state"] == "released" {
						released++
					}
				}
				if released != 1 {
					t.Fatal("published lease not durably released")
				}
				if _, e := os.Stat(filepath.Join(f.home, "version-probe")); e != nil {
					t.Fatal("qualified version probe absent")
				}
			} else {
				requireStatus(t, got, 69, f.err.String())
				if !strings.Contains(f.err.String(), "lease_harness_unqualified") {
					t.Fatal("qualification refusal lost")
				}
				if n, _ := daemon.owner.Counts(); n != 0 {
					t.Fatal("unqualified tuple refreshed")
				}
				assertAbsent(t, filepath.Join(f.home, "server-pid"))
				assertAbsent(t, filepath.Join(f.home, "version-probe"))
				assertAbsent(t, f.output)
			}
		})
	}
}

// Claim: qualification's static identity excludes per-launch paths, while the
// existing launch configuration fingerprint continues to bind each launch.
func TestQualificationConfigurationScope(t *testing.T) {
	f := newFixture(t, nil)
	path, c := staticFixture(t, f)
	raw, e := wire.Encode(c)
	must(t, e)
	observer := qualification.NativeObserver{ExecutablePath: c.Policy.Executable, StaticPolicy: raw}
	first, e := observer.Configuration(context.Background())
	must(t, e)
	changed := f.o
	changed.LaunchHome = filepath.Join(f.root, "different-home")
	changed.Cwd = filepath.Join(f.root, "different-work")
	must(t, os.Mkdir(changed.LaunchHome, 0700))
	must(t, os.Mkdir(changed.Cwd, 0700))
	launchA, e := ConfigurationDigest(f.o, nil)
	must(t, e)
	launchB, e := ConfigurationDigest(changed, nil)
	must(t, e)
	if launchA == launchB {
		t.Fatal("launch paths did not affect launch fingerprint")
	}
	second, e := observer.Configuration(context.Background())
	must(t, e)
	if first != second {
		t.Fatal("per-launch paths affected static identity")
	}
	c.Policy.Generation++
	writeStatic(t, path, c)
	raw, e = wire.Encode(c)
	must(t, e)
	observer.StaticPolicy = raw
	third, e := observer.Configuration(context.Background())
	must(t, e)
	if first == third {
		t.Fatal("policy change did not affect static identity")
	}
}
