//go:build linux

package authowner

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// Claim: withdrawing independent freshness after a completed durable write
// cannot authorize the next intent, unit start or resolution checkpoint.
// The store's existing completed-directory-sync hook models this timing
// condition without replacing production code or returning an I/O error.
// Valid controls resolve safe nonrotation; revocation at completed absence is
// an adjacent control for the existing resolution revalidation.
func TestDurableEffectTimeBoundaryProbe(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
	}{{"pending-before-intent", 1}, {"intent-before-unit", 2}, {"absence-before-resolution", 6}, {"resolution-before-checkpoint", 7}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revoke := range []bool{false, true} {
				name := "valid-control"
				if revoke {
					name = "freshness-withdrawn"
				}
				t.Run(name, func(t *testing.T) {
					var f *fixture
					armed := false
					writes := 0
					triggered := false
					hook := func(stage string) error {
						if !armed || stage != "directory-sync" {
							return nil
						}
						writes++
						if writes == tc.at {
							triggered = true
							if revoke {
								f.t.mu.Lock()
								f.t.fresh = false
								f.t.mu.Unlock()
							}
						}
						return nil
					}
					f = fixtureHook(t, "safe", hook)
					armed = true
					s, err := f.refresh()
					records, readErr := f.disk.Records()
					if readErr != nil {
						t.Fatal(readErr)
					}
					var cp Checkpoint
					if json.Unmarshal(records["owner-checkpoint.json"], &cp) != nil {
						t.Fatal("checkpoint")
					}
					intents, resolved := 0, 0
					for _, raw := range records {
						var v struct{ Kind, Phase string }
						if json.Unmarshal(raw, &v) != nil {
							t.Fatal("record")
						}
						if v.Kind == "attempt-intent/1" {
							intents++
						}
						if v.Phase == "resolved" {
							resolved++
						}
					}
					if !triggered {
						t.Fatal("completed-write boundary not exercised")
					}
					if !revoke {
						if err != nil || s.State != owner.Transient || f.m.count() != 1 || cp.PendingAttempt != "" || resolved != 1 || writes != 8 {
							t.Fatal("valid durable sequence failed", err, writes)
						}
						return
					}
					if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
						t.Error("revoked freshness released material")
					}
					if tc.at == 1 && intents != 0 {
						t.Errorf("intent published after freshness withdrawal: intents=%d", intents)
					}
					if tc.at <= 2 && f.m.count() != 0 {
						t.Errorf("writer started after freshness withdrawal: starts=%d", f.m.count())
					}
					if tc.at == 6 && resolved != 0 {
						t.Error("resolution published after freshness withdrawal")
					}
					if cp.PendingAttempt == "" || cp.RetainedAttempts != 0 || cp.State != owner.Unavailable {
						t.Errorf("resolution checkpoint published after freshness withdrawal: retained=%d state=%s pending=%t", cp.RetainedAttempts, cp.State, cp.PendingAttempt != "")
					}
				})
			}
		})
	}
}
