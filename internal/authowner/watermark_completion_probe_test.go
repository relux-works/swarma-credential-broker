//go:build linux

package authowner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// Claim: a completed watermark write cannot authorize material or fresh-home
// admission after the independent freshness source has been withdrawn.
// Due is an adjacent control because it revalidates after the inner snapshot.
func TestWatermarkCompletionAdmissionProbe(t *testing.T) {
	for _, entry := range []string{"snapshot", "fresh-home", "due"} {
		t.Run(entry, func(t *testing.T) {
			for _, revoke := range []bool{false, true} {
				name := "valid-control"
				if revoke {
					name = "freshness-withdrawn"
				}
				t.Run(name, func(t *testing.T) {
					var f *fixture
					armed, triggered := false, false
					hook := func(stage string) error {
						if armed && stage == "directory-sync" {
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
					f.t.advance(time.Second)
					armed = true
					label := f.c.Accounts[0].Label
					var result owner.Snapshot
					var due bool
					var err error
					switch entry {
					case "snapshot":
						result, err = f.e.Snapshot(context.Background(), label)
					case "fresh-home":
						err = f.e.AdmitFreshHome(context.Background(), label)
					case "due":
						due, err = f.e.Due(context.Background(), label)
					}
					if !triggered {
						t.Fatal("completed watermark write not exercised")
					}
					if !revoke {
						if err != nil || entry == "snapshot" && result.AccessToken == "" || entry == "due" && !due {
							t.Fatal("valid admission failed", err)
						}
						return
					}
					if !errors.Is(err, ErrUnavailable) || result.AccessToken != "" || due {
						t.Errorf("admission after freshness withdrawal: unavailable=%t material=%t due=%t", errors.Is(err, ErrUnavailable), result.AccessToken != "", due)
					}
					if f.m.count() != 0 {
						t.Fatal("admission started writer")
					}
				})
			}
		})
	}
}
