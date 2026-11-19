//go:build linux

package service

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Claim: an active generation belonging to another journal UID cannot authorize
// the queried service UID; the adjacent valid pair returns the exact Principal.
// The consumer-only refusal copies sealed bytes into a temporary document;
// cases.json queries 30002 for those bytes, not the projection UID 30001.
func TestManagedJournalPairUIDBinding(t *testing.T) {
	for _, item := range []struct {
		name       string
		document   string
		journal    string
		journalUID uint32
	}{
		{"valid-control", "valid.json", "journal.jsonl", managedFixtureUID},
		{"different-uid", "unknown-service-uid.json", "journal-unknown-service-uid.jsonl", 30002},
	} {
		t.Run(item.name, func(t *testing.T) {
			raw := managedBytes(t, item.journal)
			journal, err := genjournal.Verify(bytes.NewReader(raw), genjournal.Floor{Hash: genjournal.ZeroHash})
			if err != nil || journal.Active(int64(item.journalUID), managedFixtureGeneration) != nil {
				t.Fatalf("fixture must bind the active generation to UID %d: %v", item.journalUID, err)
			}
			document := managedBytes(t, item.document)
			accounts, err := decodeManaged(document, journal.Tail.Hash)
			if err != nil || accounts[managedFixtureUID].Generation != managedFixtureGeneration {
				t.Fatalf("fixture must project the queried UID and generation against the journal head: %v", err)
			}
			fixture := newManagedFixture(t)
			managedWrite(t, filepath.Join(fixture.journal, "journal"), raw)
			managedWrite(t, filepath.Join(fixture.parent, "identities.json"), document)
			before := managedSnapshot(t, fixture.authority.root)
			if item.journalUID == managedFixtureUID {
				managedPositive(t, fixture.authority)
			} else {
				principal, err := managedPrincipal(fixture.authority, managedFixtureUID)
				refused(t, err, "principal_ledger_mismatch")
				if principal != (Principal{}) {
					t.Fatalf("journal UID mismatch returned a Principal: %#v", principal)
				}
			}
			if managedSnapshot(t, fixture.authority.root) != before {
				t.Fatal("principal lookup changed the protected fixture")
			}
		})
	}
}
