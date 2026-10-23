//go:build linux

package authowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Claim: durable scheduling fields must remain coherent with resolved history.
// A single canonical checkpoint fault cannot erase safe backoff, reset its
// failure sequence or reopen proactive work immediately after commitment.
// Valid checkpoint neighbors retain the documented retry/spacing behavior.
func TestSchedulingChainFieldProbe(t *testing.T) {
	for _, mode := range []string{"safe-control", "retry-time-erasure", "failure-count-reset", "proactive-control", "proactive-time-erasure"} {
		t.Run(mode, func(t *testing.T) {
			for _, reopen := range []bool{false, true} {
				name := "live"
				if reopen {
					name = "replacement"
				}
				t.Run(name, func(t *testing.T) {
					scenario := "safe"
					proactive := mode == "proactive-control" || mode == "proactive-time-erasure"
					if proactive {
						scenario = "rotate"
					}
					f := newFixture(t, scenario)
					if _, err := f.refresh(); err != nil {
						t.Fatal("initial control", err)
					}
					records, err := f.disk.Records()
					if err != nil {
						t.Fatal(err)
					}
					var c Checkpoint
					if json.Unmarshal(records["owner-checkpoint.json"], &c) != nil {
						t.Fatal("checkpoint")
					}
					fault := mode != "safe-control" && mode != "proactive-control"
					switch mode {
					case "retry-time-erasure":
						c.RetryAt = time.Time{}
					case "failure-count-reset":
						c.Failures = 0
					case "proactive-time-erasure":
						c.NextProactive = time.Time{}
					}
					if fault {
						b, err := wire.Encode(c)
						if err != nil {
							t.Fatal(err)
						}
						label := sha256.Sum256([]byte(f.c.Accounts[0].Label))
						path := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(label[:]), "owner-checkpoint.json")
						if os.WriteFile(path, b, 0600) != nil {
							t.Fatal("checkpoint fault")
						}
					}
					engine := f.e
					if reopen {
						engine = f.replacement(t)
					}
					label := f.c.Accounts[0].Label
					s, readErr := engine.Snapshot(context.Background(), label)
					freshErr := engine.AdmitFreshHome(context.Background(), label)
					if fault {
						if !errors.Is(readErr, ErrUnavailable) || s.AccessToken != "" {
							t.Error("contradictory scheduling checkpoint admitted material")
						}
						if !errors.Is(freshErr, ErrUnavailable) {
							t.Error("contradictory scheduling checkpoint admitted fresh home")
						}
					} else if readErr != nil || proactive && s.State != owner.Active || !proactive && s.State != owner.Transient || freshErr != nil {
						t.Fatal("valid control refused")
					}
					starts := f.m.count()
					if proactive {
						due, err := engine.Due(context.Background(), label)
						if fault && err == nil && due {
							t.Error("erased proactive spacing became immediately due")
						}
						if !fault && (err != nil || due) {
							t.Fatal("proactive control lost spacing")
						}
						return
					}
					if mode == "failure-count-reset" || mode == "safe-control" {
						f.t.advance(time.Second)
						if _, err := engine.Refresh(context.Background(), label, 1); err != nil && !fault {
							t.Fatal("scheduled retry control failed", err)
						}
						starts = f.m.count()
						f.t.advance(time.Second)
					}
					_, refreshErr := engine.Refresh(context.Background(), label, 1)
					if f.m.count() != starts {
						t.Errorf("checkpoint fault bypassed retry interval: starts_before=%d starts_after=%d error_unavailable=%t", starts, f.m.count(), errors.Is(refreshErr, ErrUnavailable))
					}
				})
			}
		})
	}
}
