//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
)

func assertOriginPending(t *testing.T, root, id string, c qualification.Control) {
	t.Helper()
	if c.Executed || c.ExitCode != -1 || c.Verdict != "pending" || len(c.Artifacts) != 0 {
		t.Fatal("unattested origin gained execution", c)
	}
	for _, side := range []string{"positive", "negative"} {
		if _, e := os.Lstat(rowFile(root, id, side)); !os.IsNotExist(e) {
			t.Fatal("unattested origin produced artifact", id, side, e)
		}
	}
}

// Claim: each normative table row rejects both lifecycle metadata and a receipt
// without canonical entry. TestCaseCompletionStatus and the real fixture tests
// contrast genuine invocations: they too remain UNRUN until origin is attested.
func TestExecutionOrigin(t *testing.T) {
	for path, id := range map[string]string{"peer": "peer-denied", "transport": "frame-oversized", "admission": "account-unknown", "runner": "home-auth-present"} {
		t.Run(path, func(t *testing.T) {
			for _, variant := range []string{"metadataonly", "receiptonly"} {
				t.Run(variant, func(t *testing.T) {
					worker := rowTool(t, "./testdata/"+variant)
					_, c, root := setup(t)
					var records []rowExecutionRecord
					d := driver{rowExecutable: worker, executions: &records}
					if path == "runner" {
						d.runnerExecutable = rowTool(t, "../runner/testdata/appserver")
					}
					if path == "peer" {
						f := configuredPeerRow(t)
						f.PeerHelper = worker
						row := qualification.Case{ID: id}
						d.runPeerRows(context.Background(), f, c.Policy, root, &row)
						assertOriginPending(t, root, id, row.Negative)
						assertOriginPending(t, root, id, row.Positive)
						if len(records) != 2 || records[1].Execution.Launched {
							t.Fatal("unattested neighbor launched", records)
						}
					} else {
						control := d.runRow(context.Background(), c.Policy, root, id, "positive")
						assertOriginPending(t, root, id, control)
					}
					for _, r := range records {
						if r.Execution.Handshake || r.Execution.Started || r.Execution.Completed || r.Execution.CaseExit != -1 || r.Execution.WorkerExit != -1 {
							t.Fatal("unobserved case entry credited", r)
						}
					}
				})
			}
		})
	}
}
