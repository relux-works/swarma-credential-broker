//go:build linux

package authowner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type sharedAdmissionConfidence struct {
	base, later time.Time
	second      string
}

func (s *sharedAdmissionConfidence) Validate(_ context.Context, label, _ string, _ uint64, _ time.Time) (TimeEvidence, error) {
	if label == s.second {
		return TimeEvidence{Now: s.later, AuthorityUntil: s.base.Add(3 * time.Hour), Trusted: true, Fresh: true}, nil
	}
	return TimeEvidence{Now: s.base, AuthorityUntil: s.base.Add(time.Hour), Trusted: true, Fresh: true}, nil
}

type sharedAdmissionManager struct {
	Manager
	duringIdentity func()
}

func (m *sharedAdmissionManager) Identity(ctx context.Context) (Identity, error) {
	if m.duringIdentity != nil {
		fn := m.duringIdentity
		m.duringIdentity = nil
		fn()
	}
	return m.Manager.Identity(ctx)
}

// Claim: a public second-account Snapshot completing while a first-account
// manager-identity read is pending must narrow that first account's fresh-home
// admission against its own exclusive AuthorityUntil. This is a completed-call
// interleaving, not a claim of atomic revocation between machine instructions.
// A covered shared-time control still admits; material Snapshot is also checked
// as a neighboring public entry point. All homes and tokens are synthetic.
func TestFreshHomeSharedFloorProbe(t *testing.T) {
	for _, entry := range []string{"fresh-home", "snapshot"} {
		for _, crossed := range []bool{false, true} {
			name := "covered-control"
			if crossed {
				name = "authority-end"
			}
			t.Run(entry+"/"+name, func(t *testing.T) {
				first := newFixture(t, "safe")
				second := newFixture(t, "safe")
				first.e.Close()
				second.e.Close()
				base := first.t.now
				ac := second.c.Accounts[0]
				ac.Label = "example/codex/second"
				ac.VendorID = "fixture-second-account"
				claims, _ := json.Marshal(map[string]any{"exp": base.Add(4 * time.Hour).Unix(), "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": ac.VendorID}})
				token := "fixture." + base64.RawURLEncoding.EncodeToString(claims) + ".unsigned"
				raw, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh-second", "account_id": ac.VendorID}})
				if err := os.WriteFile(filepath.Join(ac.Home, "auth.json"), raw, 0600); err != nil {
					t.Fatal("synthetic fixture write", err)
				}
				material, err := load(ac, true)
				if err != nil {
					t.Fatal("synthetic second fixture", err)
				}
				cp := sequenceCheckpoint(t, second)
				disk, err := second.s.Account(ac.Label, true)
				if err != nil {
					t.Fatal("second labeled fixture store", err)
				}
				ac.Disk, second.disk = disk, disk
				prior := uint64(0)
				cp.Revision = 1
				cp.Account = ac.Label
				cp.VendorID = ac.VendorID
				cp.StoreDigest = material.Digest
				cp.TokenDigest = digestToken(token)
				cp.Watermark = base
				if err := ac.Disk.Put("owner-checkpoint.json", prior, cp); err != nil {
					t.Fatal("second fixture checkpoint", err)
				}
				source := &sharedAdmissionConfidence{base: base, later: base, second: ac.Label}
				manager := &sharedAdmissionManager{Manager: first.m}
				c := first.c
				c.DaemonInstance = id()
				c.Accounts = append(c.Accounts, ac)
				current, err := New(context.Background(), c, manager, source, fakeClassifier{})
				if err != nil {
					t.Fatal("two-account engine", err)
				}
				t.Cleanup(current.Close)
				label := c.Accounts[0].Label
				if err := current.AdmitFreshHome(context.Background(), label); err != nil {
					t.Fatal("initial valid admission", err)
				}
				later := base.Add(30 * time.Minute)
				if crossed {
					later = base.Add(time.Hour)
				}
				observed := false
				manager.duringIdentity = func() {
					source.later = later
					s, err := current.Snapshot(context.Background(), ac.Label)
					if err != nil || s.AccessToken != token {
						t.Fatal("second public snapshot", err)
					}
					observed = true
				}
				before := sequenceCheckpoint(t, first)
				var callErr error
				released := false
				if entry == "fresh-home" {
					callErr = current.AdmitFreshHome(context.Background(), label)
				} else {
					s, err := current.Snapshot(context.Background(), label)
					callErr = err
					released = s.AccessToken != ""
				}
				after := sequenceCheckpoint(t, first)
				if !observed {
					t.Fatal("completed second-account sample not observed")
				}
				current.clock.mu.Lock()
				effective := current.clock.observed
				current.clock.mu.Unlock()
				secondCheckpoint := sequenceCheckpoint(t, second)
				if !effective.Equal(later) || secondCheckpoint.Watermark.Before(later) {
					t.Fatal("second public operation did not establish its expected time")
				}
				t.Logf("entry=%s shared_floor_reached_authority=%t admitted=%t material=%t first_account_writes=%d", entry, !effective.Before(base.Add(time.Hour)), callErr == nil, released, after.Revision-before.Revision)
				if crossed {
					if !errors.Is(callErr, ErrUnavailable) || released {
						t.Error("first account admitted at uncovered shared effective time")
					}
				} else if callErr != nil {
					t.Fatal("covered shared-time control refused", callErr)
				}
				if first.m.count() != 0 || second.m.count() != 0 {
					t.Fatal("admission started writer")
				}
			})
		}
	}
}
