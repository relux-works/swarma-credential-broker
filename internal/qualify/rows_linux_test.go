//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
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
	b, _ := wire.Encode(fixtureConfiguration{Broker: u.Username, Allowed: u.Username, Foreign: "unavailable-fixture-role", Account: p.Accounts[0].Label, SameUser: true})
	path := filepath.Join(root, "roles.json")
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("roles")
	}
	return path
}

// Claim: every emitted row remains pending without artifacts, and each
// unavailable invocation suppresses its neighbour. No approved candidate runs.
func TestRowsHarness(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	path, c, root := setup(t)
	config := rowConfiguration(t, c.Policy, filepath.Dir(path))
	configureRunner(t, config, rowTool(t, "../runner/testdata/appserver"))
	configurePeers(t, config)
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = worker
	var out bytes.Buffer
	if code := d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--fixtures", "--fixture-config", config, "--evidence-dir", root}, &out); code != 69 {
		t.Fatal("publication gate", code)
	}
	var r report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil || r.Disposition != "pending" {
		t.Fatal("report")
	}
	for _, row := range r.Cases {
		assertOriginPending(t, root, row.ID, row.Positive)
		assertOriginPending(t, root, row.ID, row.Negative)
	}
	for _, record := range r.Executions {
		if record.Execution.Started || record.Execution.Completed || record.Execution.CaseExit != -1 {
			t.Fatal("origin credit", record)
		}
		suppressed := record.Side == "negative" && record.ID != "peer-denied" || record.Side == "positive" && record.ID == "peer-denied"
		if suppressed && record.Execution.Launched {
			t.Fatal("neighbor launched", record)
		}
	}
	homes, e := filepath.Glob(filepath.Join(os.TempDir(), "qualification-row-*"))
	if e != nil || len(homes) != 0 {
		t.Fatal("worker teardown", homes)
	}
	if _, e := os.Lstat(filepath.Join(qualification.Directory(path), "qualified.json")); !os.IsNotExist(e) {
		t.Fatal("published")
	}
	if len(r.Unavailable) == 0 || len(r.Cases) != 46 {
		t.Fatal("registry/properties gate")
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
	invalid, _ := wire.Encode(fixtureConfiguration{Broker: u.Username, Allowed: u.Username, Foreign: "unavailable-fixture-role", Account: c.Policy.Accounts[0].Label, SameUser: false})
	if os.WriteFile(config, invalid, 0600) != nil {
		t.Fatal("role declaration plant")
	}
	if _, e := fixturePolicy(config, c.Policy); e == nil {
		t.Fatal("undeclared same-user role accepted")
	}

}

// Claim: an unverified worker gains no artifact, and the independent
// isolation predicate continues to reject an external-refusal summary.
func TestRowIsolationRefusal(t *testing.T) {
	worker := rowTool(t, "./testdata/rowprobe")
	_, c, root := setup(t)
	control := (driver{rowExecutable: worker}).runRow(context.Background(), c.Policy, root, "frame-oversized", "positive")
	assertOriginPending(t, root, "frame-oversized", control)
	// The origin gate suppresses artifacts; test the retained isolation predicate
	// directly without claiming the uncredited worker supplied attested evidence.
	a := rowArtifact{Network: map[string]egress.Counts{"external": {Refused: 1}}}
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
