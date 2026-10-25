//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the command driver with protected policy/roles and an owned evidence
// directory constructs both authorities and records attested grant/refusal pairs.
// Missing --fixtures or missing/unprotected roles cannot execute any row. The
// observer is test-only; the candidate is synthetic and is never executed.
func TestQualificationAuthorityProtectedInputs(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	for _, input := range []string{"protected", "missing-mode", "missing-roles", "unprotected-roles"} {
		t.Run(input, func(t *testing.T) {
			path, c, root := setup(t)
			config := rowConfiguration(t, c.Policy, filepath.Dir(path))
			d := newFixtureDriver(path, "0.163.0")
			d.rowExecutable = worker
			args := []string{"--executable", c.Policy.Executable, "--evidence-dir", root, "--fixture-config", config}
			want := 69 // Other required rows remain pending even for valid fixtures.
			if input != "missing-mode" {
				args = append(args, "--fixtures")
			} else {
				want = 64
			}
			switch input {
			case "missing-roles":
				if os.Remove(config) != nil {
					t.Fatal("remove synthetic roles")
				}
			case "unprotected-roles":
				if os.Chmod(config, 0644) != nil {
					t.Fatal("roles protection plant")
				}
			}
			var out bytes.Buffer
			if code := d.run(context.Background(), args, &out); code != want {
				t.Fatal("qualification authority containment: command status", code)
			}
			if input == "missing-mode" {
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 || out.Len() != 0 {
					t.Fatal("invalid mode constructed fixture")
				}
				return
			}
			var report report
			if wire.Decode(bytes.TrimSpace(out.Bytes()), &report) != nil {
				t.Fatal("qualification report missing")
			}
			seen := 0
			for _, row := range report.Cases {
				if input != "protected" {
					if row.Positive.Executed || row.Negative.Executed || len(row.Positive.Artifacts)+len(row.Negative.Artifacts) != 0 {
						t.Fatal("unprotected fixture constructed authority", row.ID)
					}
					continue
				}
				if row.ID == "account-denied" || row.ID == "renew-unknown-digest" {
					if row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed" || !row.Positive.Executed || !row.Negative.Executed || row.Positive.ExitCode != 0 || row.Negative.ExitCode != 0 || len(row.Positive.Artifacts) != 1 || len(row.Negative.Artifacts) != 1 {
						t.Fatal("protected single/multi authority unavailable", row.ID)
					}
					seen++
				}
			}
			completed := map[string]bool{}
			for _, record := range report.Executions {
				if record.ID != "account-denied" && record.ID != "renew-unknown-digest" {
					continue
				}
				e := record.Execution
				key := record.ID + "/" + record.Side
				if completed[key] || (record.Side != "positive" && record.Side != "negative") || !e.Launched || !e.Handshake || !e.Started || !e.Completed || !e.Joined || e.CaseExit != 0 || e.WorkerExit != 0 || e.HelperExit != 0 {
					t.Fatal("protected authority process status missing")
				}
				completed[key] = true
			}
			if input == "protected" && len(completed) != 4 {
				t.Fatal("single/multi authority pair statuses absent")
			}
			if input == "protected" && seen != 2 || input != "protected" && len(report.Executions) != 0 {
				t.Fatal("qualification authority containment: execution scope")
			}
		})
	}
}
