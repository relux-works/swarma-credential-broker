//go:build linux

package authowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// Claim: withdrawal at each completed owner-record write permits no later
// protected write, start or admission. The completed prefix remains on disk;
// any started fixture writer is stopped without unloading pending retention.
// Once freshness returns, conclusive RPC prefixes recover exactly once; earlier
// ambiguous prefixes remain unavailable. A completed final checkpoint is kept,
// not rolled back: only its later material/lifecycle admission is refused.
func TestDurableStepTimeRevalidation(t *testing.T) {
	steps := []string{"pending-checkpoint", "intent", "submitted", "running", "stopping", "absence", "resolved", "final-checkpoint"}
	for index, step := range steps {
		t.Run(step, func(t *testing.T) {
			for _, revoke := range []bool{false, true} {
				name := "valid-control"
				if revoke {
					name = "freshness-withdrawn"
				}
				t.Run(name, func(t *testing.T) {
					var f *fixture
					armed, triggered := false, false
					writes := 0
					hook := func(stage string) error {
						if !armed || stage != "directory-sync" {
							return nil
						}
						writes++
						if writes == index+1 {
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
					if !triggered {
						t.Fatal("completed durable step not exercised")
					}
					records, readErr := f.disk.Records()
					if readErr != nil {
						t.Fatal(readErr)
					}
					var cp Checkpoint
					if json.Unmarshal(records["owner-checkpoint.json"], &cp) != nil {
						t.Fatal("checkpoint fixture")
					}
					phases := map[string]int{}
					intents := 0
					var resolved Evidence
					for _, raw := range records {
						var v Evidence
						if json.Unmarshal(raw, &v) != nil {
							t.Fatal("retained fixture record")
						}
						if v.Kind == "attempt-intent/1" {
							intents++
						}
						if v.Kind == "attempt-evidence/1" {
							phases[v.Phase]++
							if v.Phase == "resolved" {
								resolved = v
							}
						}
					}
					if !revoke {
						if err != nil || s.State != owner.Transient || s.AccessToken != f.token || writes != 8 || f.m.count() != 1 || cp.PendingAttempt != "" || cp.RetainedAttempts != 1 || phases["resolved"] != 1 || cp.Failures != 1 || !cp.RetryAt.Equal(resolved.ResolvedAt.Add(time.Second)) {
							t.Fatal("valid durable lifecycle refused", err, writes)
						}
						return
					}
					if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || writes != index+1 {
						t.Fatal("next protected effect ran after withdrawal", err, writes)
					}
					wantIntents := 1
					if index == 0 {
						wantIntents = 0
					}
					if intents != wantIntents {
						t.Fatal("intent boundary not retained")
					}
					order := []string{"submitted", "running", "stopping", "absent", "resolved"}
					for at, phase := range order {
						want := 0
						if index >= at+2 {
							want = 1
						}
						if phases[phase] != want {
							t.Fatal("unexpected retained evidence phase", phase)
						}
					}
					if index < 7 {
						if cp.PendingAttempt == "" || cp.State != owner.Unavailable || cp.RetainedAttempts != 0 || cp.LastAttempt != "" {
							t.Fatal("pending checkpoint replaced after withdrawal")
						}
					} else if cp.PendingAttempt != "" || cp.State != owner.Transient || cp.RetainedAttempts != 1 {
						t.Fatal("completed final checkpoint was changed")
					}
					starts := 0
					if index >= 2 {
						starts = 1
					}
					if f.m.count() != starts {
						t.Fatal("unexpected writer count")
					}
					f.m.mu.Lock()
					retainedUnits := len(f.m.units)
					stopped := true
					for _, o := range f.m.observation {
						if o.Active != "inactive" || !o.StopCompleted || !o.Empty || !o.PopulatedZero {
							stopped = false
						}
					}
					f.m.mu.Unlock()
					if !stopped {
						t.Fatal("started fixture writer not stopped on refusal")
					}
					wantRetained := starts
					if index == 7 {
						wantRetained = 0
					}
					if retainedUnits != wantRetained {
						t.Fatal("pending retention released or completed retention leaked")
					}
					label := f.c.Accounts[0].Label
					if s, err = f.snapshot(); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
						t.Fatal("refusal admitted material")
					}
					if err = f.e.AdmitFreshHome(context.Background(), label); !errors.Is(err, ErrUnavailable) {
						t.Fatal("refusal admitted fresh home")
					}
					if _, err = f.refresh(); !errors.Is(err, ErrUnavailable) || f.m.count() != starts {
						t.Fatal("refusal started another writer")
					}
					after, readErr := f.disk.Records()
					if readErr != nil || len(after) != len(records) || writes != index+1 {
						t.Fatal("refusal changed retained prefix")
					}
					for name, raw := range records {
						if !bytes.Equal(raw, after[name]) {
							t.Fatal("refusal overwrote retained evidence")
						}
					}

					// Independent authority returns; it does not supply missing RPC proof.
					armed = false
					f.t.mu.Lock()
					f.t.fresh = true
					f.t.mu.Unlock()
					f.t.advance(3 * time.Second)
					replacement := f.replacement(t)
					s, err = replacement.Snapshot(context.Background(), label)
					if index < 4 {
						if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
							t.Fatal("ambiguous prefix guessed successful recovery")
						}
					} else {
						if err != nil || s.State != owner.Transient || s.AccessToken != f.token || s.Generation != 1 {
							t.Fatal("conclusive retained prefix failed recovery", err)
						}
						recovered, err := f.disk.Records()
						if err != nil {
							t.Fatal(err)
						}
						if json.Unmarshal(recovered["owner-checkpoint.json"], &cp) != nil {
							t.Fatal("recovery checkpoint")
						}
						for _, raw := range recovered {
							var v Evidence
							if json.Unmarshal(raw, &v) == nil && v.Phase == "resolved" {
								resolved = v
							}
						}
						if cp.Failures != 1 || cp.PendingAttempt != "" || cp.RetainedAttempts != 1 || !cp.RetryAt.Equal(resolved.ResolvedAt.Add(time.Second)) {
							t.Fatal("recovery duplicated outcome or moved durable schedule")
						}
						for name, raw := range records {
							if name != "owner-checkpoint.json" && !bytes.Equal(raw, recovered[name]) {
								t.Fatal("recovery changed immutable prefix")
							}
						}
					}
					if f.m.count() != starts {
						t.Fatal("recovery started another writer")
					}
				})
			}
		})
	}
}

// Claim: the common wrapper commits once only with prior authority, and refuses
// its result after post-commit withdrawal. A failed commit never supplies time;
// no retry or rollback can hide an already completed operation.
func TestCommitTimeBoundary(t *testing.T) {
	for _, name := range []string{"valid-control", "withdraw-before", "withdraw-after", "commit-error"} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			good := TimeEvidence{Now: now, AuthorityUntil: now.Add(time.Hour), Trusted: true, Fresh: true}
			bad := good
			bad.Fresh = false
			clock := &revokingTimeProbe{good: good, bad: good, allowed: 100}
			if name == "withdraw-before" {
				clock.good = bad
			}
			e := &Engine{confidence: clock}
			commits := 0
			result, err := e.commitThenRevalidate(context.Background(), &account{}, Checkpoint{Watermark: now}, func() error {
				commits++
				if name == "withdraw-after" {
					clock.good = bad
				}
				if name == "commit-error" {
					return fmt.Errorf("synthetic commit failure")
				}
				return nil
			})
			wantCommits := 1
			if name == "withdraw-before" {
				wantCommits = 0
			}
			if commits != wantCommits {
				t.Fatal("unexpected persistence count")
			}
			if name == "valid-control" {
				if err != nil || !result.Now.Equal(now) || clock.calls != 2 {
					t.Fatal("valid boundary refused", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || !result.Now.IsZero() {
				t.Fatal("invalid boundary supplied authority", err)
			}
		})
	}
}

// Claim: actual synthetic material flushing is enclosed by the common boundary;
// a valid pre-flush check cannot return material after a failed post-flush check.
func TestMaterialDurabilityTimeRevalidation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint("withdraw-", revoke), func(t *testing.T) {
			f := newFixture(t, "safe")
			good := TimeEvidence{Now: f.t.now, AuthorityUntil: f.t.now.Add(time.Hour), Trusted: true, Fresh: true}
			bad := good
			if revoke {
				bad.Fresh = false
			}
			clock := &revokingTimeProbe{good: good, bad: bad, allowed: 1}
			f.e.confidence = clock
			m, err := f.e.durableMaterial(context.Background(), f.e.accounts[f.c.Accounts[0].Label])
			if clock.calls != 2 {
				t.Fatal("material flush boundary not exercised")
			}
			if revoke {
				if !errors.Is(err, ErrUnavailable) || m.Token != "" {
					t.Fatal("flushed material released after withdrawal")
				}
			} else if err != nil || m.Token != f.token {
				t.Fatal("valid flushed material refused", err)
			}
		})
	}
}
