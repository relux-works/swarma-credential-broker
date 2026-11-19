//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// Claim: accept rows may override either manifest identity field, and the same
// lookup/assertion path accepts a different active journal UID and generation.
func TestManagedPerCasePrincipal(t *testing.T) {
	manifest := managedCases(t)
	var item managedFixtureCase
	if err := wire.Decode([]byte(`{"check":"service","file":"additional.json","generation":"33333333333333333333333333333333","name":"additional","uid":40002,"verdict":"accept"}`), &item); err != nil {
		t.Fatal(err)
	}
	want := managedExpectedPrincipal(manifest, item)
	if want.UID != 40002 || want.Generation != "33333333333333333333333333333333" {
		t.Fatal("per-case expected identity ignored")
	}
	fixture := newManagedFixture(t)
	raw := managedBytes(t, manifest.Journal)
	var verified genjournal.View
	for _, state := range []string{"creating", "active"} {
		line, next, err := genjournal.Propose(raw, genjournal.Floor{Hash: genjournal.ZeroHash}, int64(want.UID), want.Generation, state, "user-manager", "2026-11-19T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, line...)
		verified = next
	}
	document := managedDocument{Format: "swarma-managed-identities/1", JournalHead: verified.Tail.Hash, Accounts: []managedAccount{{UID: want.UID, Kind: "service", Name: Gateway, Class: "trusted", Placement: "local", Generation: want.Generation, State: "active"}}}
	managedWrite(t, filepath.Join(fixture.journal, "journal"), raw)
	managedWrite(t, filepath.Join(fixture.parent, "identities.json"), encode(t, document))
	principal, err := managedPrincipal(fixture.authority, want.UID)
	if err != nil || principal != want {
		t.Fatalf("additional accept row: got %#v, %v; want %#v", principal, err, want)
	}
	wrong := item
	wrong.Generation = manifest.Generation
	if principal == managedExpectedPrincipal(manifest, wrong) {
		t.Fatal("wrong per-case generation matched")
	}
	wrong = item
	wrong.UID = &manifest.UID
	if principal == managedExpectedPrincipal(manifest, wrong) {
		t.Fatal("wrong per-case UID matched")
	}
	defaults := managedExpectedPrincipal(manifest, managedFixtureCase{})
	if defaults.UID != manifest.UID || defaults.Generation != manifest.Generation {
		t.Fatal("manifest defaults changed")
	}
	uidOnly := managedExpectedPrincipal(manifest, managedFixtureCase{UID: item.UID})
	generationOnly := managedExpectedPrincipal(manifest, managedFixtureCase{Generation: item.Generation})
	if uidOnly.UID != want.UID || uidOnly.Generation != manifest.Generation || generationOnly.UID != manifest.UID || generationOnly.Generation != want.Generation {
		t.Fatal("independent per-case field defaults changed")
	}
}

// Claim: invalid nonselected records close the entire projection; the selected
// service remains unchanged and each fault has a valid multi-record control.
func TestManagedNonselectedRecords(t *testing.T) {
	for _, fault := range []string{"retired-service-name", "agent-class", "workplace-class", "agent-state", "agent-placement", "agent-kind", "agent-generation", "agent-name", "retired-duplicate-uid", "unknown-member", "duplicate-key"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newManagedFixture(t)
			var document managedDocument
			if err := json.Unmarshal(managedBytes(t, "valid.json"), &document); err != nil {
				t.Fatal(err)
			}
			other := managedAccount{UID: 40001, Kind: "agent", Name: "synthetic-secondary", Class: "trusted", Placement: "local", Generation: "22222222222222222222222222222222", State: "retired"}
			if fault == "retired-service-name" {
				other.Kind, other.Name = "service", Gateway
			}
			if fault == "workplace-class" {
				other.Kind = "workplace"
			}
			document.Accounts = append(document.Accounts, other)
			if fault == "retired-duplicate-uid" {
				other.UID++
				document.Accounts = append(document.Accounts, other)
			}
			path := filepath.Join(fixture.parent, "identities.json")
			managedWrite(t, path, encode(t, document))
			managedPositive(t, fixture.authority)
			switch fault {
			case "retired-service-name":
				document.Accounts[1].Name = "unknown-service"
			case "agent-class", "workplace-class":
				document.Accounts[1].Class = "unknown"
			case "agent-state":
				document.Accounts[1].State = "unknown"
			case "agent-placement":
				document.Accounts[1].Placement = "unknown"
			case "agent-kind":
				document.Accounts[1].Kind = "unknown"
			case "agent-generation":
				document.Accounts[1].Generation = "invalid"
			case "agent-name":
				document.Accounts[1].Name = ""
			case "retired-duplicate-uid":
				document.Accounts[2].UID = document.Accounts[1].UID
			}
			raw := encode(t, document)
			if fault == "unknown-member" || fault == "duplicate-key" {
				member := `,"unknown":true`
				if fault == "duplicate-key" {
					member = `,"uid":40001`
				}
				changed := bytes.Replace(raw, []byte(`"uid":40001}`), []byte(`"uid":40001`+member+`}`), 1)
				if bytes.Equal(raw, changed) {
					t.Fatal("nonselected mutation not applied")
				}
				raw = changed
			}
			accounts, err := decodeManaged(raw, document.JournalHead)
			refused(t, err, "principal_ledger_mismatch")
			if accounts != nil {
				t.Fatal("invalid nonselected record returned an account map")
			}
			managedWrite(t, path, raw)
			before := managedSnapshot(t, fixture.authority.root)
			called := false
			err = fixture.authority.WithIdentity(context.Background(), func(View) error { called = true; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if called || managedSnapshot(t, fixture.authority.root) != before {
				t.Fatal("invalid nonselected record admitted a callback or changed evidence")
			}
		})
	}
}

func managedWriter(t *testing.T, fixture *managedFixture, name string) *os.File {
	t.Helper()
	file, err := os.Open(filepath.Join(fixture.journal, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func managedWriterExcluded(t *testing.T, file *os.File) {
	t.Helper()
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		t.Fatalf("exclusive writer was not excluded: %v", err)
	}
}

func managedWriterAvailable(t *testing.T, file *os.File) {
	t.Helper()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("exclusive writer control unavailable: %v", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

// Claim: the initial pending check precedes lock work, and a marker appearing
// between that check and gate acquisition is rechecked before callback entry.
func TestManagedPendingAtReadBoundary(t *testing.T) {
	for _, initial := range []bool{false, true} {
		name := "published-before-gate"
		if initial {
			name = "initial-marker"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, fixture.authority)
			marker := filepath.Join(fixture.journal, "writer.pending")
			if initial {
				managedWrite(t, marker, []byte("synthetic pending"))
			}
			boundaryCalled, called := false, false
			err := fixture.authority.withManagedAtBoundary(context.Background(), false, func(stage string) {
				if stage == "after-first-pending" {
					boundaryCalled = true
					managedWrite(t, marker, []byte("synthetic pending"))
				}
			}, func(View) error { called = true; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if called || boundaryCalled == initial {
				t.Fatal("pending-marker ordering or refusal violated")
			}
		})
	}
}

// Claim: a competing exclusive writer cannot enter at the pre-data boundary;
// data acquisition precedes gate release, and callback return releases data.
func TestManagedGateDataOrdering(t *testing.T) {
	fixture := newManagedFixture(t)
	managedPositive(t, fixture.authority)
	gate := managedWriter(t, fixture, "gate.lock")
	data := managedWriter(t, fixture, "data.lock")
	managedWriterAvailable(t, gate)
	managedWriterAvailable(t, data)
	stages := make(map[string]bool)
	err := fixture.authority.withManagedAtBoundary(context.Background(), false, func(stage string) {
		stages[stage] = true
		switch stage {
		case "before-data-lock":
			managedWriterExcluded(t, gate)
			managedWriterAvailable(t, data)
		case "data-locked":
			managedWriterExcluded(t, gate)
			managedWriterExcluded(t, data)
		}
	}, func(view View) error {
		managedWriterAvailable(t, gate)
		managedWriterExcluded(t, data)
		_, err := view.Principal(managedFixtureUID)
		return err
	})
	if err != nil || !stages["before-data-lock"] || !stages["data-locked"] {
		t.Fatalf("reader boundary control failed: %v", err)
	}
	managedWriterAvailable(t, gate)
	managedWriterAvailable(t, data)
}

// Claim: the budget starts at data acquisition and expires before identity-kind
// memory or callback effects, even when local reading or decoding is delayed.
func TestManagedReadDeadlineBeforeEffects(t *testing.T) {
	for _, pause := range []string{"data-locked", "projection-read"} {
		t.Run(pause, func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, newManagedFixture(t).authority)
			paused, called := false, false
			err := fixture.authority.withManagedAtBoundary(context.Background(), false, func(stage string) {
				if stage == pause {
					paused = true
					time.Sleep(genjournal.ReaderHold + 50*time.Millisecond)
				}
			}, func(View) error { called = true; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if !paused || called || len(fixture.authority.kinds) != 0 {
				t.Fatal("expired read changed identity memory or entered callback")
			}
		})
	}
}

// Claim: same-descriptor metadata changes during either protected file read
// refuse, while the unchanged bytes and metadata are accepted controls.
func TestManagedReadMetadataChange(t *testing.T) {
	for _, leaf := range []string{"identities.json", "journal"} {
		t.Run(leaf, func(t *testing.T) {
			fixture := newManagedFixture(t)
			parent := fixture.parent
			if leaf == "journal" {
				parent = fixture.journal
			}
			directory, err := os.Open(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if _, err := fixture.authority.readAt(directory, leaf, managedIdentityLimit); err != nil {
				t.Fatal("unchanged file refused", err)
			}
			changed := false
			raw, err := fixture.authority.readAtBoundary(directory, leaf, managedIdentityLimit, func() {
				stamp := time.Unix(42, 0)
				if err := os.Chtimes(filepath.Join(parent, leaf), stamp, stamp); err != nil {
					t.Fatal(err)
				}
				changed = true
			})
			refused(t, err, "principal_ledger_mismatch")
			if !changed || raw != nil {
				t.Fatal("metadata plant not applied or bytes returned after mutation")
			}
		})
	}
}
