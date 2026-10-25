//go:build linux && amd64

package qualify

import (
	"context"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: selection of a pathname creates no socket before the exec callback;
// invoking that callback creates the listener. Exec callback authority itself
// is covered by TestOriginExecIdentity; actual exchanges by TestRowsHarness.
func TestOriginListenerEpoch(t *testing.T) {
	_, c, root := setup(t)
	image, e := os.Open("/proc/self/exe")
	if e != nil {
		t.Fatal(e)
	}
	defer image.Close()
	proof := &rowOrigin{}
	proof.origin, e = egress.NewCaseOrigin(image, func() error { return proof.bind() })
	if e != nil {
		t.Fatal(e)
	}
	defer proof.origin.Close()
	var pid atomic.Int64
	path, closeRow, e := startTransportRow(context.Background(), root, rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: "frame-oversized", Side: "positive"}, &pid, proof)
	if e != nil {
		t.Fatal(e)
	}
	defer closeRow()
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("listener exists before verified exec")
	}
	if c, e := net.Dial("unix", path); e == nil {
		c.Close()
		t.Fatal("pre-exec connection queued")
	}
	if proof.origin.Live(os.Getpid()) {
		t.Fatal("unentered origin live")
	}
	if e = proof.bind(); e != nil {
		t.Fatal(e)
	}
	if info, e := os.Lstat(path); e != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("verified callback did not bind listener", e)
	}
	pid.Store(int64(os.Getpid())) // matching real peer PID, still no case entry
	if code, _, e := transportExchangeFacts(path, "peer-identity-unavailable", "negative", c.Policy.Generation); e != nil || code != "peer_identity_unavailable" {
		t.Fatal("unentered sender admitted", code, e)
	}
}

func attestedPair(t *testing.T, worker, id string) (string, policy.Policy, qualification.Case, []rowExecutionRecord) {
	t.Helper()
	_, c, root := setup(t)
	var records []rowExecutionRecord
	d := driver{rowExecutable: worker, executions: &records}
	row := qualification.Case{ID: id}
	row.Positive = d.runRow(context.Background(), c.Policy, root, id, "positive")
	row.Negative = d.runRow(context.Background(), c.Policy, root, id, "negative")
	if row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed" || validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, row, records) != nil {
		t.Fatal("valid attested pair rejected", row, records)
	}
	return root, c.Policy, row, records
}

// Claim: both real control artifacts and their private parent proofs are needed.
// Hash-consistent tampering cannot replace identity, timing, closed envelopes,
// parent effect counters, grant bounds, or genuine lifecycle status.
func TestRowArtifactPair(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	for _, id := range []string{"profile-unsupported", "account-unknown"} {
		root, p, pair, records := attestedPair(t, worker, id)
		_, _, _, fresh := attestedPair(t, worker, id)
		if validateRow(root, p.ExecutableSHA256, p.Generation, pair, fresh) == nil {
			t.Fatal("replayed artifact accepted for new run")
		}
		for _, side := range []string{"positive", "negative"} {
			path := rowFile(root, id, side)
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if os.Remove(path) != nil {
				t.Fatal("remove control")
			}
			if validateRow(root, p.ExecutableSHA256, p.Generation, pair, records) == nil {
				t.Fatal("missing paired artifact accepted", side)
			}
			if os.WriteFile(path, original, 0600) != nil {
				t.Fatal("restore control")
			}
		}
		for _, defect := range []string{"identity", "row", "side", "duration", "bound", "command", "hash", "isolation", "status", "refusal", "variant", "field", "effects", "grant"} {
			t.Run(id+"/"+defect, func(t *testing.T) {
				side := "negative"
				if defect == "grant" {
					side = "positive"
				}
				path := rowFile(root, id, side)
				original, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				defer os.WriteFile(path, original, 0600)
				var a rowArtifact
				if wire.Decode(original, &a) != nil {
					t.Fatal("decode original")
				}
				switch defect {
				case "identity":
					a.Candidate = "wrong"
				case "row":
					a.ID = "frame-zero-length"
				case "side":
					a.Side = "positive"
				case "bound":
					a.Control.BoundNS++
				case "command":
					a.Control.Command = []string{"/invalid"}
				case "isolation":
					a.Network["external"] = egress.Counts{Allowed: 1}
				case "duration":
					a.Control.DurationNS = a.Control.BoundNS + 1
				case "status":
					a.Execution.CaseExit = 17
				case "refusal":
					a.Observation.Refusal = "wrong"
				case "variant":
					a.Observation.Envelopes = a.Observation.Envelopes[:1]
				case "field":
					a.Observation.Envelopes[0].RequestID = nil
				case "effects":
					a.Observation.NoEffects = false
					if a.Observation.Admission != nil {
						a.Observation.NoEffects = true
						a.Observation.Admission.Snapshots++
					}
				case "grant":
					if a.Observation.Admission != nil {
						a.Observation.Envelopes[1].Lease.Until = a.Observation.Envelopes[1].Lease.Expires
					} else {
						a.Observation.Envelopes[0].Hello.Generation++
					}
				}
				b, e := wire.Encode(a)
				if e != nil || os.WriteFile(path, b, 0600) != nil {
					t.Fatal("plant")
				}
				bad := pair
				x := a.Control
				x.Artifacts = []string{qualification.Hash(b)}
				if defect == "hash" {
					x.Artifacts = []string{"wrong"}
				}
				if side == "negative" {
					bad.Negative = x
				} else {
					bad.Positive = x
				}
				// Deliberately refresh only the test-owned hash so semantic gates,
				// rather than the production byte-binding gate, see each defect.
				proofs := slices.Clone(records)
				for i := range proofs {
					if proofs[i].Side == side {
						proofs[i].Execution.artifact = qualification.Hash(b)
					}
				}
				if validateRow(root, p.ExecutableSHA256, p.Generation, bad, proofs) == nil {
					t.Fatal("tampered paired artifact accepted", defect)
				}
			})
		}
		if validateRow(root, p.ExecutableSHA256, p.Generation, pair) == nil {
			t.Fatal("serialized metadata substituted for parent proof")
		}
	}
}

// Claim: all ten real negative exchanges yield their independently specified
// refusal, with a successful adjacent positive and verified closed variants.
// These are synthetic transport/admission controls, not peer or runner credit.
func TestRowRefusalEnvelope(t *testing.T) {
	worker := rowTool(t, "../../cmd/swarma-credential-broker")
	for id, want := range map[string]string{
		"frame-oversized": "frame_too_large", "frame-zero-length": "closed", "frame-truncated-header": "closed", "frame-malformed-first": "closed", "profile-unsupported": "version_unsupported", "peer-identity-unavailable": "peer_identity_unavailable",
		"account-denied": "lease_not_authorised", "account-unknown": "lease_account_unknown", "release-unqualified": "lease_harness_unqualified", "lease-ended": "lease_not_active",
	} {
		t.Run(id, func(t *testing.T) {
			root, _, _, _ := attestedPair(t, worker, id)
			b, e := os.ReadFile(rowFile(root, id, "negative"))
			var a rowArtifact
			if e != nil || wire.Decode(b, &a) != nil || a.Observation.Refusal != want {
				t.Fatal("required refusal envelope missing", want)
			}
		})
	}
}
