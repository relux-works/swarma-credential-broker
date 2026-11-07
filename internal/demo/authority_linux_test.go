//go:build linux

package demo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func publicRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("synthetic root filesystem fixture requires an isolated user namespace")
	}
	// Require a disposable namespace mount. Ordinary root runs must never modify
	// a real operator installation just to exercise source-only fixtures.
	if _, e := os.Stat("/etc/os-release"); e == nil {
		t.Skip("requires a disposable empty /etc mount")
	}
	if e := os.MkdirAll("/etc/swarma-demo", 0755); e != nil {
		t.Fatal(e)
	}
	os.Chmod("/etc/swarma-demo", 0755)
	t.Cleanup(func() { os.RemoveAll("/etc/swarma-demo"); os.RemoveAll("/run/swarma-demo") })
}
func putRoot(t *testing.T, path string, v any, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(path, raw(t, v), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}
func projectionFixture() Projection {
	return Projection{"/run/swarma-demo/broker/socket", 1102, wire.Binding{Digest: strings.Repeat("a", 64), Harness: "codex_cli", Profile: "demo", Account: "fixture-account", Channel: "external-token", Endpoint: "https://example.invalid/inference", ExecutableSHA256: strings.Repeat("b", 64), PolicyGeneration: 1}, RosterPath}
}
func TestProjectionExactClosedAndQualificationAbsent(t *testing.T) {
	publicRoot(t)
	p := projectionFixture()
	putRoot(t, AuthorityPath, p, 0644)
	if _, e := ReadProjection(); e != nil {
		t.Fatal("protected closed projection refused")
	}
	if _, e := ReadQualification(); e == nil {
		t.Fatal("absent qualification admitted")
	}
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["qualified"] = true }, func(m map[string]any) { m["store_root"] = "/private" }, func(m map[string]any) { m["broker_uid"] = 1101 }, func(m map[string]any) { m["roster_path"] = "/other" }, func(m map[string]any) { delete(m, "binding") }, func(m map[string]any) { m["socket_path"] = "/run/../socket" },
	} {
		var m map[string]any
		if e := json.Unmarshal(raw(t, p), &m); e != nil {
			t.Fatal(e)
		}
		mutate(m)
		putRoot(t, AuthorityPath, m, 0644)
		if _, e := ReadProjection(); e == nil {
			t.Fatal("projection widened")
		}
	}
}
func syntheticQualification() Qualification {
	measurement := func(name string) qualification.Measurement {
		return qualification.Measurement{Observer: name + "/1", SHA256: strings.Repeat("a", 64)}
	}
	identity := qualification.Identity{Version: "0.163.0", Executable: measurement("executable"), Schema: measurement("schema"), Runner: measurement("runner"), Platform: measurement("platform"), Configuration: measurement("configuration"), Properties: measurement("properties"), Catalog: measurement("catalog")}
	q := Qualification{ChatGPTAccountID: "synthetic-account", AccountReference: "human@example.invalid", Executable: "/fixture/codex", Release: "codex-cli 0.163.0", SchemaSHA256: identity.Schema.SHA256, ConfigSHA256: strings.Repeat("b", 64), Catalog: qualification.Catalog{Models: []qualification.Model{{Name: "fixture-model", Efforts: []string{"medium"}}}}}
	b, _ := wire.Encode(q.Catalog)
	identity.Catalog.SHA256 = Hash(b)
	// Synthetic testimony exercises only parsing; it is never exported as live
	// qualification and never used to call a provider or privileged service.
	r := qualification.Pending(identity)
	r.Mode = "live"
	r.Disposition = "accepted"
	r.OperatorAccepted = true
	r.Approval = strings.Repeat("c", 64)
	r.AccountCheck = "matched"
	for i := range r.Cases {
		for j, side := range []string{"positive", "negative"} {
			c := qualification.Control{Verdict: "passed", Executed: true, Command: qualification.CaseCommand(r.Cases[i].ID, side), ExitCode: 0, Artifacts: []string{strings.Repeat("d", 64)}, DurationNS: 1, BoundNS: 2}
			if j == 0 {
				r.Cases[i].Positive = c
			} else {
				r.Cases[i].Negative = c
			}
		}
	}
	q.Evidence = r
	return q
}
func TestQualificationRejectsFakePendingAndWrongCustody(t *testing.T) {
	publicRoot(t)
	q := syntheticQualification()
	putRoot(t, QualificationPath, q, 0644)
	if _, e := ReadQualification(); e != nil {
		t.Fatal("synthetic protected complete testimony refused")
	}
	for name, mutate := range map[string]func(*Qualification){
		"fake": func(q *Qualification) { q.Evidence.Mode = "fake"; q.Evidence.Approval = "" }, "pending": func(q *Qualification) { q.Evidence.Disposition = "pending" }, "unaccepted": func(q *Qualification) { q.Evidence.OperatorAccepted = false }, "account": func(q *Qualification) { q.AccountReference = "" }, "schema": func(q *Qualification) { q.SchemaSHA256 = strings.Repeat("e", 64) }, "catalog": func(q *Qualification) { q.Catalog.Models[0].Name = "other" }, "pin": func(q *Qualification) { q.Release = "codex-cli 0.164.0" },
	} {
		t.Run(name, func(t *testing.T) {
			v := syntheticQualification()
			mutate(&v)
			putRoot(t, QualificationPath, v, 0644)
			if _, e := ReadQualification(); e == nil {
				t.Fatal("unqualified record admitted")
			}
		})
	}
	putRoot(t, QualificationPath, q, 0600)
	if _, e := ReadQualification(); e == nil {
		t.Fatal("wrong public qualification mode accepted")
	}
}
func TestAdmissionWitnessOnlyCanonicalRosterStaysClosed(t *testing.T) {
	publicRoot(t)
	r := fixtureRoster()
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	r.BootID = strings.TrimSpace(string(b))
	putRoot(t, RosterPath, r, 0644)
	if e = os.MkdirAll(LaunchDirectory, 0755); e != nil {
		t.Fatal(e)
	}
	os.Chmod("/run/swarma-demo", 0755)
	os.Chmod(LaunchDirectory, 0755)
	l := LaunchRecord{"EX-fixture", r.Accounts[0].UID, r.Accounts[0].Generation, strings.Repeat("a", 64), r.BootID}
	path, _ := LaunchPath(l.ExecutionID)
	putRoot(t, path, l, 0444)
	a := NewAdmission()
	if e = a.Check(context.Background(), l.UID, l.PlanSHA256); e == nil {
		t.Fatal("witness-only roster admitted a Codex lease")
	}
	wrote := false
	if e = a.Publish(context.Background(), l.UID, l.PlanSHA256, func(context.Context) error { wrote = true; return nil }); e == nil || wrote {
		t.Fatal("witness-only roster published Codex material")
	}
	r.Accounts[0].Generation = strings.Repeat("9", 32)
	putRoot(t, RosterPath, r, 0644)
	if e = a.Check(context.Background(), l.UID, l.PlanSHA256); e == nil {
		t.Fatal("roster replacement admitted")
	}
	r = fixtureRoster()
	r.BootID = l.BootID
	putRoot(t, RosterPath, r, 0644)
	if e = a.Check(context.Background(), l.UID, l.PlanSHA256); e == nil {
		t.Fatal("observed replacement did not latch refusal")
	}
}
func TestAuthorityRefusesIndependentLaunchMismatch(t *testing.T) {
	publicRoot(t)
	a := Authority{UID: 30000, Launch: LaunchRecord{ExecutionID: "EX-fixture", UID: 30000}}
	if _, e := a.Resolve(context.Background(), runner.Options{Cwd: filepath.Join("/srv/swarma-demo/work", "swarma-demo-01")}); e == nil {
		t.Fatal("missing public authority admitted")
	}
}
