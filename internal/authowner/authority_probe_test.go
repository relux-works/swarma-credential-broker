//go:build linux

package authowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func authorityRecordPath(f *fixture, name string) string {
	key := sha256.Sum256([]byte(f.c.Accounts[0].Label))
	return filepath.Join(f.root, "store", "account-"+hex.EncodeToString(key[:]), name)
}
func authorityPut(t *testing.T, f *fixture, name string, v any) {
	t.Helper()
	b, err := wire.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(authorityRecordPath(f, name), b, 0600); err != nil {
		t.Fatal(err)
	}
}

// Claim: safe nonrotation preserves the last committed plan. Substituting a
// different allowed enum cannot release contradictory plan metadata or admit
// another writer; valid committed/safe chains remain serviceable.
func TestCheckpointPlanHistoryProbe(t *testing.T) {
	for _, entry := range []string{"snapshot", "fresh-home", "writer"} {
		t.Run(entry, func(t *testing.T) {
			for _, reopen := range []bool{false, true} {
				name := "live"
				if reopen {
					name = "replacement"
				}
				t.Run(name, func(t *testing.T) {
					for _, fault := range []bool{false, true} {
						name := "control"
						if fault {
							name = "plan-substitution"
						}
						t.Run(name, func(t *testing.T) {
							f := newFixture(t, "rotate")
							label := f.c.Accounts[0].Label
							if _, err := f.refresh(); err != nil {
								t.Fatal("committed control", err)
							}
							if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte("safe"), 0600); err != nil {
								t.Fatal(err)
							}
							if _, err := f.e.Refresh(context.Background(), label, 2); err != nil {
								t.Fatal("safe control", err)
							}
							f.t.advance(time.Second)
							records, err := f.disk.Records()
							if err != nil {
								t.Fatal(err)
							}
							var cp Checkpoint
							if json.Unmarshal(records["owner-checkpoint.json"], &cp) != nil || cp.Plan != "plus" {
								t.Fatal("baseline plan")
							}
							if fault {
								cp.Plan = "pro"
								authorityPut(t, f, "owner-checkpoint.json", cp)
							}
							e := f.e
							if reopen {
								e = f.replacement(t)
							}
							starts := f.m.count()
							var s owner.Snapshot
							switch entry {
							case "snapshot":
								s, err = e.Snapshot(context.Background(), label)
							case "fresh-home":
								err = e.AdmitFreshHome(context.Background(), label)
							case "writer":
								s, err = e.Refresh(context.Background(), label, 2)
							}
							if !fault {
								if err != nil || entry != "fresh-home" && s.PlanType != "plus" {
									t.Fatal("valid chain refused", err)
								}
								if entry == "writer" && f.m.count() != starts+1 {
									t.Fatal("writer control did not start")
								}
								return
							}
							if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || f.m.count() != starts {
								t.Errorf("contradictory plan admitted: entry=%s error_unavailable=%t plan=%s starts_before=%d starts_after=%d", entry, errors.Is(err, ErrUnavailable), s.PlanType, starts, f.m.count())
							}
						})
					}
				})
			}
		})
	}
}

// Claim: pending resolution metadata cannot move trusted completion time into
// the future or admit a schedule that fresh independent time has not reached.
// A durable original resolution is a neighboring positive recovery control.
func TestPendingResolutionTimeProbe(t *testing.T) {
	for _, mode := range []string{"safe", "rotate"} {
		t.Run(mode, func(t *testing.T) {
			for _, fault := range []bool{false, true} {
				name := "control"
				if fault {
					name = "future-resolution"
				}
				t.Run(name, func(t *testing.T) {
					f := newFixture(t, mode)
					label := f.c.Accounts[0].Label
					before := f.e.accounts[label].checkpoint
					if _, err := f.refresh(); err != nil {
						t.Fatal(err)
					}
					settled := f.e.accounts[label].checkpoint
					pending := before
					pending.Revision = settled.Revision - 1
					pending.State = owner.Unavailable
					pending.PendingAttempt = settled.LastAttempt
					authorityPut(t, f, "owner-checkpoint.json", pending)
					if fault {
						records, err := f.disk.Records()
						if err != nil {
							t.Fatal(err)
						}
						changed := false
						for name, raw := range records {
							var ev Evidence
							if json.Unmarshal(raw, &ev) != nil || ev.Phase != "resolved" {
								continue
							}
							ev.ResolvedAt = f.t.now.Add(30 * time.Minute)
							authorityPut(t, f, name, ev)
							changed = true
						}
						if !changed {
							t.Fatal("missing resolution")
						}
					}
					e := f.replacement(t)
					s, err := e.Snapshot(context.Background(), label)
					if fault {
						if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
							t.Fatal("future resolution admitted")
						}
					} else if err != nil {
						t.Fatal("valid pending control refused", err)
					}
				})
			}
		})
	}
}

// Claim: recovery preserves the checkpointed committed plan across pending
// safe/rejected resolutions. Changing only that plan must refuse recovery and
// fresh-home authority; the same pending prefix without the fault is valid.
func TestPendingPlanHistoryProbe(t *testing.T) {
	for _, mode := range []string{"safe", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			for _, fault := range []bool{false, true} {
				name := "control"
				if fault {
					name = "pending-plan-substitution"
				}
				t.Run(name, func(t *testing.T) {
					f := newFixture(t, "rotate")
					label := f.c.Accounts[0].Label
					if _, err := f.refresh(); err != nil {
						t.Fatal("commit control", err)
					}
					before := f.e.accounts[label].checkpoint
					if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte(mode), 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := f.e.Refresh(context.Background(), label, 2); err != nil {
						t.Fatal("resolution control", err)
					}
					settled := f.e.accounts[label].checkpoint
					pending := before
					pending.Revision = settled.Revision - 1
					pending.State = owner.Unavailable
					pending.PendingAttempt = settled.LastAttempt
					if fault {
						pending.Plan = "pro"
					}
					authorityPut(t, f, "owner-checkpoint.json", pending)
					e := f.replacement(t)
					s, err := e.Snapshot(context.Background(), label)
					fresh := e.AdmitFreshHome(context.Background(), label)
					if fault {
						if !errors.Is(err, ErrUnavailable) || !errors.Is(fresh, ErrUnavailable) || s.AccessToken != "" {
							t.Errorf("contradictory pending plan admitted: snapshot_unavailable=%t fresh_home_unavailable=%t state=%s plan=%s", errors.Is(err, ErrUnavailable), errors.Is(fresh, ErrUnavailable), s.State, s.PlanType)
						}
					} else {
						if err != nil || fresh != nil || mode == "safe" && s.PlanType != "plus" || mode == "rejected" && s.State != owner.Reauth {
							t.Fatal("valid pending plan refused", err, fresh)
						}
					}
				})
			}
		})
	}
}
