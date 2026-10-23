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

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: terminal history cannot certify an active unit or a successful outcome
// whose durable stopping evidence says unknown. These are single-field faults
// in synthetic protected records, with an unchanged neighboring control.
func TestProbeRetainedRecordConsistency(t *testing.T) {
	for _, mode := range []string{"consistent-control", "absent-active", "resolved-active", "stopping-unknown", "absent-unknown"} {
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
			changed := false
			for name, raw := range records {
				var ev Evidence
				if json.Unmarshal(raw, &ev) != nil || ev.Kind != "attempt-evidence/1" {
					continue
				}
				edit := false
				switch mode {
				case "absent-active":
					if ev.Phase == "absent" {
						ev.Observation.Active = "active"
						edit = true
					}
				case "resolved-active":
					if ev.Phase == "resolved" {
						ev.Observation.Active = "active"
						edit = true
					}
				case "stopping-unknown":
					if ev.Phase == "stopping" {
						ev.RPC = Unknown
						edit = true
					}
				case "absent-unknown":
					if ev.Phase == "absent" {
						ev.RPC = Unknown
						edit = true
					}
				}
				if !edit {
					continue
				}
				encoded, err := wire.Encode(ev)
				if err != nil {
					t.Fatal(err)
				}
				label := sha256.Sum256([]byte(f.c.Accounts[0].Label))
				path := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(label[:]), name)
				if err = os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
				changed = true
			}
			if mode != "consistent-control" && !changed {
				t.Fatal("fault not applied")
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
				t.Error("contradictory terminal history admitted active material")
			}
			if mode == "absent-active" || mode == "resolved-active" {
				if err = r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label); !errors.Is(err, ErrUnavailable) {
					t.Error("contradictory terminal observation admitted a fresh home")
				}
			}
		})
	}
}
