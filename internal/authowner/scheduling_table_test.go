//go:build linux

package authowner

import (
	"bytes"
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

// Claim: single checkpoint scheduling faults, including nonzero shortened times
// and inconsistent nonzero counts, close every admission boundary without
// changing records or starting a writer. Controls cover initial, committed,
// consecutive-safe and rejected prefixes; pending prefixes are checked below.
func TestSchedulingChainTable(t *testing.T) {
	for _, history := range []string{"initial", "committed", "safe-one", "safe-two", "rejected", "safe-rejected"} {
		t.Run(history, func(t *testing.T) {
			mode := "safe"
			if history == "committed" {
				mode = "rotate"
			}
			if history == "rejected" {
				mode = "rejected"
			}
			f := newFixture(t, mode)
			if history != "initial" {
				if _, err := f.refresh(); err != nil {
					t.Fatal(err)
				}
			}
			if history == "safe-two" || history == "safe-rejected" {
				f.t.advance(time.Second)
				if history == "safe-rejected" {
					if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte("rejected"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := f.refresh(); err != nil {
					t.Fatal(err)
				}
			}
			f.e.Close()
			baseline, err := f.disk.Records()
			if err != nil {
				t.Fatal(err)
			}
			var cp Checkpoint
			if json.Unmarshal(baseline["owner-checkpoint.json"], &cp) != nil {
				t.Fatal("checkpoint")
			}
			key := sha256.Sum256([]byte(f.c.Accounts[0].Label))
			path := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(key[:]), "owner-checkpoint.json")
			faults := []string{"control", "count-nonzero", "retry-nonzero", "proactive-nonzero"}
			if cp.Failures > 0 {
				faults = append(faults, "count-zero", "retry-zero", "retry-shortened-nonzero", "retry-conservative-control")
			}
			if !cp.NextProactive.IsZero() {
				faults = append(faults, "proactive-zero", "proactive-shortened-nonzero")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					for _, entry := range []string{"load", "snapshot", "fresh-home", "writer", "due"} {
						t.Run(entry, func(t *testing.T) {
							changed := cp
							switch fault {
							case "count-nonzero":
								changed.Failures += 2
							case "count-zero":
								changed.Failures = 0
							case "retry-nonzero":
								if cp.RetryAt.IsZero() {
									changed.RetryAt = cp.Watermark.Add(time.Second)
								} else {
									changed.RetryAt = cp.RetryAt.Add(-time.Nanosecond)
								}
							case "retry-conservative-control":
								changed.RetryAt = cp.RetryAt.Add(time.Second)
							case "retry-zero":
								changed.RetryAt = time.Time{}
							case "retry-shortened-nonzero":
								changed.RetryAt = cp.RetryAt.Add(-time.Nanosecond)
							case "proactive-nonzero":
								changed.NextProactive = cp.NextProactive.Add(time.Second)
							case "proactive-zero":
								changed.NextProactive = time.Time{}
							case "proactive-shortened-nonzero":
								changed.NextProactive = cp.NextProactive.Add(-time.Nanosecond)
							}
							raw, err := wire.Encode(changed)
							if err != nil {
								t.Fatal(err)
							}
							if fault != "control" && bytes.Equal(raw, baseline["owner-checkpoint.json"]) {
								t.Fatal("fault not applied")
							}
							open := func() *Engine {
								t.Helper()
								r, err := New(context.Background(), f.c, f.m, f.t, fakeClassifier{})
								if err != nil {
									t.Fatal(err)
								}
								return r
							}
							var r *Engine
							if entry != "load" {
								r = open()
							}
							if err := os.WriteFile(path, raw, 0600); err != nil {
								t.Fatal(err)
							}
							if entry == "load" {
								r = open()
							}
							defer func() {
								r.Close()
								if err := os.WriteFile(path, baseline["owner-checkpoint.json"], 0600); err != nil {
									t.Fatal(err)
								}
							}()
							starts := f.m.count()
							before, err := f.disk.Records()
							if err != nil {
								t.Fatal(err)
							}
							var s owner.Snapshot
							switch entry {
							case "fresh-home":
								err = r.AdmitFreshHome(context.Background(), cp.Account)
							case "writer":
								// The valid writer neighbors use a stale generation and release the
								// current snapshot; exact new-writer interval controls are separate.
								s, err = r.Refresh(context.Background(), cp.Account, 0)
							case "due":
								_, err = r.Due(context.Background(), cp.Account)
							default:
								s, err = r.Snapshot(context.Background(), cp.Account)
							}
							if fault == "control" || fault == "retry-conservative-control" {
								if err != nil {
									t.Fatal("valid scheduling refused", err)
								}
							} else {
								if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
									t.Fatal("scheduling fault admitted", err)
								}
								after, readErr := f.disk.Records()
								if readErr != nil || len(after) != len(before) {
									t.Fatal("refusal changed records")
								}
								for n, b := range before {
									if !bytes.Equal(b, after[n]) {
										t.Fatal("refusal changed protected record")
									}
								}
							}
							if f.m.count() != starts {
								t.Fatal("scheduling fault started writer")
							}
						})
					}
				})
			}
		})
	}
}

// Claim: valid safe retries retain exactly 1/2/4/8/16/32/60/60-second
// intervals, across replacement and at the nanosecond boundary; a later commit
// resets backoff. Trusted completion time, not attempt start, anchors retries.
func TestSchedulingExactRetryIntervals(t *testing.T) {
	f := newFixture(t, "safe")
	label := f.c.Accounts[0].Label
	for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second} {
		if _, err := f.e.Refresh(context.Background(), label, 1); err != nil {
			t.Fatal(err)
		}
		c := f.e.accounts[label].checkpoint
		if c.Failures != uint64(i+1) || !c.RetryAt.Equal(f.t.now.Add(delay)) {
			t.Fatal("wrong exact retry interval")
		}
		if i == 1 {
			f.e = f.replacement(t)
		}
		starts := f.m.count()
		f.t.advance(delay - time.Nanosecond)
		if _, err := f.e.Refresh(context.Background(), label, 1); err != nil || f.m.count() != starts {
			t.Fatal("early safe retry")
		}
		f.t.advance(time.Nanosecond)
	}
	if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte("rotate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Refresh(context.Background(), label, 1); err != nil {
		t.Fatal(err)
	}
	c := f.e.accounts[label].checkpoint
	if c.Failures != 0 || !c.RetryAt.IsZero() {
		t.Fatal("commit retained safe backoff")
	}
}

// Claim: proactive scheduling is exactly the later of half remaining lifetime
// and configured window start, survives replacement/time-watermark advances,
// refuses one nanosecond early, and becomes due exactly at the bound.
func TestSchedulingExactProactiveIntervals(t *testing.T) {
	for _, window := range []time.Duration{48 * time.Hour, time.Hour} {
		t.Run(window.String(), func(t *testing.T) {
			f := newFixture(t, "rotate")
			f.c.ProactiveWindow = window
			f.e = f.replacement(t)
			start := f.t.now
			if _, err := f.refresh(); err != nil {
				t.Fatal(err)
			}
			want := start.Add(150 * time.Minute)
			if window == time.Hour {
				want = start.Add(4 * time.Hour)
			}
			label := f.c.Accounts[0].Label
			if !f.e.accounts[label].checkpoint.NextProactive.Equal(want) {
				t.Fatal("wrong exact proactive interval")
			}
			f.e = f.replacement(t)
			f.t.advance(want.Sub(start) - time.Nanosecond)
			if due, err := f.e.Due(context.Background(), label); err != nil || due {
				t.Fatal("early proactive work", err)
			}
			f.t.advance(time.Nanosecond)
			if due, err := f.e.Due(context.Background(), label); err != nil || !due {
				t.Fatal("proactive bound did not open", err)
			}
		})
	}
}

// Claim: pending checkpoints preserve the resolved prefix's schedule, even
// when a later durable resolution exists. Recovery reuses that resolution's
// trusted time rather than rescheduling at restart; contradictory scheduling
// is rejected by the same validator before recovery can mutate records.
func TestSchedulingPendingResolution(t *testing.T) {
	for _, mode := range []string{"safe", "rotate"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			before := f.e.accounts[f.c.Accounts[0].Label].checkpoint
			if _, err := f.refresh(); err != nil {
				t.Fatal(err)
			}
			a := f.e.accounts[before.Account]
			settled := a.checkpoint
			pending := before
			pending.Revision = settled.Revision - 1
			pending.State = owner.Unavailable
			pending.PendingAttempt = settled.LastAttempt
			a.checkpoint = pending
			if err := f.e.validateChain(a); err != nil {
				t.Fatal("valid pending prefix refused", err)
			}
			for _, field := range []string{"count", "retry", "proactive"} {
				a.checkpoint = pending
				switch field {
				case "count":
					a.checkpoint.Failures = 1
				case "retry":
					a.checkpoint.RetryAt = f.t.now
				case "proactive":
					a.checkpoint.NextProactive = f.t.now
				}
				if !errors.Is(f.e.validateChain(a), ErrUnavailable) {
					t.Fatal("pending schedule contradicted prefix", field)
				}
			}
			a.checkpoint = settled
			key := sha256.Sum256([]byte(before.Account))
			path := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(key[:]), "owner-checkpoint.json")
			raw, err := wire.Encode(pending)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f.t.advance(10 * time.Second)
			f.e = f.replacement(t)
			got := f.e.accounts[before.Account].checkpoint
			if got.Failures != settled.Failures || !got.RetryAt.Equal(settled.RetryAt) || !got.NextProactive.Equal(settled.NextProactive) {
				t.Fatal("recovery moved durable schedule")
			}
			if _, err := f.e.Snapshot(context.Background(), before.Account); err != nil {
				t.Fatal("recovered resolution unavailable", err)
			}
		})
	}
}
