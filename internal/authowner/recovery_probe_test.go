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
	"strings"
	"testing"
)

// Claim: a changed boot/manager epoch must keep fresh-home admission closed;
// a same-epoch fully resolved history is the neighboring admissible control.
func TestProbeFreshHomeEpochFence(t *testing.T) {
	for _, mode := range []string{"same-epoch-control", "boot-change", "manager-change"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "rotate")
			if _, err := f.refresh(); err != nil {
				t.Fatal("fixture refresh", err)
			}
			f.e.Close()
			if mode == "boot-change" {
				f.m.identity.Boot = id()
			}
			if mode == "manager-change" {
				f.m.identity.Epoch = id()
			}
			r := f.replacement(t)
			s, err := r.Snapshot(context.Background(), f.c.Accounts[0].Label)
			if mode == "same-epoch-control" {
				if err != nil || s.State != owner.Active {
					t.Fatal("control snapshot", err)
				}
				if err = r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label); err != nil {
					t.Fatal("control admission", err)
				}
				return
			}
			unavailable(t, s, err)
			if err = r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label); err == nil {
				t.Fatal("fresh-home admission accepted retained absence from a different epoch")
			}
		})
	}
}

// Claim: every retained observed phase must bind one writer identity even after
// checkpoint resolution. This injects protected-record faults, not hostile writes.
func TestProbeRetainedObservationBinding(t *testing.T) {
	for _, phase := range []string{"submitted", "running", "stopping", "absent", "resolved"} {
		t.Run(phase, func(t *testing.T) {
			for _, mode := range []string{"consistent-control", "invocation", "cgroup", "path", "properties", "boot", "epoch"} {
				t.Run(mode, func(t *testing.T) {
					f := newFixture(t, "rotate")
					if _, err := f.refresh(); err != nil {
						t.Fatal(err)
					}
					f.e.Close()
					records, err := f.disk.Records()
					if err != nil {
						t.Fatal(err)
					}
					var running Observation
					for _, raw := range records {
						var ev Evidence
						if json.Unmarshal(raw, &ev) == nil && ev.Phase == "running" {
							running = ev.Observation
						}
					}
					found := false
					for name, raw := range records {
						if !strings.HasPrefix(name, "owner-attempt-") {
							continue
						}
						var ev Evidence
						if json.Unmarshal(raw, &ev) != nil || ev.Phase != phase {
							continue
						}
						found = true
						// Empty submitted observations are already covered by every normal chain;
						// an observed submitted record must obey the same identity contract.
						if phase == "submitted" {
							ev.Observation = running
						}
						switch mode {
						case "invocation":
							ev.Observation.Invocation = id()
						case "cgroup":
							ev.Observation.CgroupID = id()
						case "path":
							ev.Observation.Cgroup += "-changed"
						case "properties":
							ev.Observation.Properties = id()
						case "boot":
							ev.Observation.Identity.Boot = id()
						case "epoch":
							ev.Observation.Identity.Epoch = id()
						}
						b, err := wire.Encode(ev)
						if err != nil {
							t.Fatal(err)
						}
						label := sha256.Sum256([]byte(f.c.Accounts[0].Label))
						path := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(label[:]), name)
						if err = os.WriteFile(path, b, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if !found {
						t.Fatal("retained phase unavailable")
					}
					r := f.replacement(t)
					snapshot, err := r.Snapshot(context.Background(), f.c.Accounts[0].Label)
					if mode == "consistent-control" {
						if err != nil || snapshot.State != owner.Active {
							t.Fatal("control refused", err)
						}
						return
					}
					if !errors.Is(err, ErrUnavailable) || snapshot.AccessToken != "" {
						t.Fatal("contradictory retained observation admitted active material")
					}
					if err = r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label); !errors.Is(err, ErrUnavailable) {
						t.Fatal("contradictory history admitted fresh home")
					}
					if _, err = r.Refresh(context.Background(), f.c.Accounts[0].Label, 2); !errors.Is(err, ErrUnavailable) || f.m.count() != 1 {
						t.Fatal("contradictory history admitted another writer")
					}
				})
			}
		})
	}
}

// Claim: unchanged access material reports renew_failed even if the vendor
// rewrites non-token store metadata; a byte-identical store is the control.
func TestProbeUnchangedTokenMetadata(t *testing.T) {
	for _, mode := range []string{"unchanged", "metadata-only"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			if err := os.WriteFile(filepath.Join(f.home, "next-token"), []byte(f.token), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := f.refresh()
			if !errors.Is(err, owner.ErrRenewFailed) {
				t.Fatalf("unchanged access material returned %v, want renew_failed", err)
			}
			s, err := f.snapshot()
			unavailable(t, s, err)
			f.refresh()
			if f.m.count() != 1 {
				t.Fatal("unchanged result retried")
			}
		})
	}
}

// This helper writes only the synthetic vendor fixture created by newFixture.
func probeMetadata(home, token string) error {
	b, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh", "account_id": "fixture-account"}, "last_refresh": "2026-01-01T00:00:00Z"})
	if err != nil {
		return err
	}
	pending := filepath.Join(home, "probe-pending")
	file, err := os.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(b); err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return err
	}
	if err = os.Rename(pending, filepath.Join(home, "auth.json")); err != nil {
		return err
	}
	dir, err := os.Open(home)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
