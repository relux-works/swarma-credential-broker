//go:build linux

package authowner

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Claim: time observed after a completed watermark write may close token expiry,
// but a later trusted clock correction must not revive that same expired token.
// This uses public Snapshot and New with a non-error completed-write hook;
// the covered-step control keeps a token that has never been observed expired.
func TestPostCommitClockCorrectionProbe(t *testing.T) {
	for _, mode := range []string{"live", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			for _, expired := range []bool{false, true} {
				name := "covered-control"
				if expired {
					name = "forward-expiry"
				}
				t.Run(name, func(t *testing.T) {
					var f *fixture
					armed, triggered := false, false
					step := 250 * time.Millisecond
					if expired {
						step = 2 * time.Second
					}
					hook := func(stage string) error {
						if armed && !triggered && stage == "directory-sync" {
							triggered = true
							f.t.advance(step)
						}
						return nil
					}
					f = fixtureHook(t, "safe", hook)
					f.t.advance(4*time.Hour - time.Second)
					corrected := f.t.now
					armed = true
					first, err := f.snapshot()
					if !triggered {
						t.Fatal("watermark completion not exercised")
					}
					if expired {
						if !errors.Is(err, ErrUnavailable) || first.AccessToken != "" {
							t.Fatal("forward expiry did not close material")
						}
					} else if err != nil || first.AccessToken != f.token {
						t.Fatal("covered forward control refused", err)
					}
					records, err := f.disk.Records()
					if err != nil {
						t.Fatal(err)
					}
					var cp Checkpoint
					if json.Unmarshal(records["owner-checkpoint.json"], &cp) != nil {
						t.Fatal("checkpoint")
					}
					observed := corrected.Add(step)
					armed = false
					f.t.mu.Lock()
					f.t.now = corrected
					f.t.mu.Unlock()
					current := f.e
					if mode == "replacement" {
						current = f.replacement(t)
					}
					after, err := current.Snapshot(context.Background(), f.c.Accounts[0].Label)
					if expired && (!errors.Is(err, ErrUnavailable) || after.AccessToken != "") {
						t.Errorf("expired material revived after clock correction: material=%t unavailable=%t watermark_before_observed=%t", after.AccessToken != "", errors.Is(err, ErrUnavailable), cp.Watermark.Before(observed))
					}
					if !expired && (err != nil || after.AccessToken != f.token) {
						t.Fatal("covered clock correction refused", err)
					}
					if f.m.count() != 0 {
						t.Fatal("snapshot started writer")
					}
				})
			}
		})
	}
}
