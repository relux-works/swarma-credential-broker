//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: each new row executes one real positive/refusal pair through canonical
// dispatch and attested parent wait, with exact envelopes, bounded queue state,
// parent refresh/generation counters and released records. Hash-consistent
// counter/envelope tampering cannot supply those claims. No candidate is run.
func TestLeaseProtocolRows(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	for _, id := range []string{"renew-unknown-digest", "renew-contention", "queue-full"} {
		t.Run(id, func(t *testing.T) {
			_, c, root := setup(t)
			var records []rowExecutionRecord
			d := driver{rowExecutable: worker, executions: &records}
			pair := qualification.Case{ID: id}
			pair.Positive = d.runRow(context.Background(), c.Policy, root, id, "positive")
			pair.Negative = d.runRow(context.Background(), c.Policy, root, id, "negative")
			if pair.Positive.Verdict != "passed" || pair.Negative.Verdict != "passed" || validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, pair, records) != nil {
				t.Fatal("lease protocol refusal invariant", id, pair, records)
			}
			if len(records) != 2 {
				t.Fatal("pair completion proof missing")
			}
			for _, r := range records {
				if !r.Execution.credit(false) || r.Execution.CaseExit != 0 {
					t.Fatal("actual case status missing", r)
				}
			}
			path := rowFile(root, id, "negative")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, defect := range []string{"generation", "refresh", "writer", "queue", "guard", "envelope"} {
				var artifact rowArtifact
				if wire.Decode(original, &artifact) != nil {
					t.Fatal("artifact decode")
				}
				switch defect {
				case "generation":
					artifact.Observation.LeaseProtocol.Generation++
				case "refresh":
					artifact.Observation.LeaseProtocol.Refreshes++
				case "writer":
					artifact.Observation.LeaseProtocol.Writers++
				case "queue":
					artifact.Observation.LeaseProtocol.PeakPending++
				case "guard":
					artifact.Observation.LeaseProtocol.GuardVerified = false
				case "envelope":
					artifact.Observation.Envelopes = artifact.Observation.Envelopes[:len(artifact.Observation.Envelopes)-1]
				}
				b, e := wire.Encode(artifact)
				if e != nil || os.WriteFile(path, b, 0600) != nil {
					t.Fatal("counter plant")
				}
				bad := pair
				bad.Negative.Artifacts = []string{qualification.Hash(b)}
				proofs := slices.Clone(records)
				for i := range proofs {
					if proofs[i].Side == "negative" {
						proofs[i].Execution.artifact = qualification.Hash(b)
					}
				}
				if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, bad, proofs) == nil {
					t.Fatal("untrusted lease counter or envelope accepted", defect)
				}
			}
			if os.WriteFile(path, original, 0600) != nil {
				t.Fatal("restore artifact")
			}
			if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, pair, nil) == nil {
				t.Fatal("helper-only evidence credited")
			}
		})
	}
}
