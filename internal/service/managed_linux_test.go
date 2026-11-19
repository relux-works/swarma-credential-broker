//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

const managedFixtureDirectory = "testdata/identities-v1"
const managedFixtureUID = 30001
const managedFixtureGeneration = "11111111111111111111111111111111"

type managedFixture struct {
	authority *ManagedAuthority
	parent    string
	journal   string
}

type managedFixtureCase struct {
	Check       string                   `json:"check"`
	Condition   string                   `json:"condition,omitempty"`
	File        string                   `json:"file"`
	Name        string                   `json:"name"`
	Previous    string                   `json:"previous,omitempty"`
	Verdict     string                   `json:"verdict"`
	UID         *uint32                  `json:"uid,omitempty"`
	Generation  string                   `json:"generation,omitempty"`
	Consumer    string                   `json:"consumer"`
	Journal     string                   `json:"journal,omitempty"`
	JournalHead string                   `json:"journal_head,omitempty"`
	Principal   *managedFixturePrincipal `json:"principal,omitempty"`
}

type managedFixturePrincipal struct {
	UID        uint32 `json:"uid"`
	Generation string `json:"generation"`
	Service    string `json:"service"`
}

type managedFixtureManifest struct {
	Cases       []managedFixtureCase `json:"cases"`
	Format      string               `json:"format"`
	Generation  string               `json:"generation"`
	Journal     string               `json:"journal"`
	JournalHead string               `json:"journal_head"`
	UID         uint32               `json:"uid"`
}

func managedCases(t *testing.T) managedFixtureManifest {
	t.Helper()
	var manifest managedFixtureManifest
	raw := managedBytes(t, "cases.json")
	if _, err := wire.Parse(raw); err != nil || wire.Decode(raw, &manifest) != nil || manifest.Format != "swarma-identities-fixtures/1" || manifest.Journal != "journal.jsonl" || len(manifest.Cases) == 0 || !managedHex(manifest.Generation, 32) {
		t.Fatal("invalid shared fixture manifest")
	}
	journal, err := genjournal.Verify(bytes.NewReader(managedBytes(t, manifest.Journal)), genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil || journal.Tail.Hash != manifest.JournalHead || journal.Active(int64(manifest.UID), manifest.Generation) != nil {
		t.Fatal("manifest does not identify the active journal vector")
	}
	if err := managedFixtureContract(manifest); err != nil {
		t.Fatal(err)
	}
	if err := managedFixtureInventory(managedFixtureDirectory, manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func managedFixtureContract(manifest managedFixtureManifest) error {
	journals := map[string]bool{manifest.Journal: true}
	for _, item := range manifest.Cases {
		if item.Verdict != "accept" && item.Verdict != "principal_ledger_mismatch" {
			return fmt.Errorf("unknown fixture verdict: %s", item.Name)
		}
		consumer := map[string]string{"decode": "decode", "service": "View.Principal", "transition": "none", "custody": "custody"}[item.Check]
		if consumer == "" || item.Consumer != consumer {
			return fmt.Errorf("invalid consumer kind: %s", item.Name)
		}
		if (item.Check == "transition") != (item.Previous != "") || (item.Check == "custody") != (item.Condition != "") {
			return fmt.Errorf("invalid case precondition: %s", item.Name)
		}
		if item.Check != "service" {
			if item.UID != nil || item.Generation != "" || item.Principal != nil || item.Journal != "" || item.JournalHead != "" {
				return fmt.Errorf("nonservice principal promise: %s", item.Name)
			}
			continue
		}
		if item.UID == nil || item.Journal == "" || filepath.Base(item.Journal) != item.Journal || journals[item.Journal] || !managedHex(item.JournalHead, 64) {
			return fmt.Errorf("invalid service journal or UID: %s", item.Name)
		}
		journals[item.Journal] = true
		if item.Verdict == "accept" {
			if item.Principal == nil || item.Principal.UID != *item.UID || item.Principal.Generation != item.Generation || !managedHex(item.Generation, 32) || item.Principal.Service != Gateway {
				return fmt.Errorf("invalid service principal promise: %s", item.Name)
			}
		} else if item.Principal != nil || item.Generation != "" {
			return fmt.Errorf("refusal promises a principal: %s", item.Name)
		}
	}
	return nil
}

func managedFixtureInventory(directory string, manifest managedFixtureManifest) error {
	listed := map[string]bool{"README.md": true, "SHA256SUMS": true, "cases.json": true, manifest.Journal: true}
	names := make(map[string]bool)
	for _, item := range manifest.Cases {
		if item.Name == "" || names[item.Name] || item.File == "" || filepath.Base(item.File) != item.File {
			return fmt.Errorf("duplicate or invalid fixture case: %s", item.Name)
		}
		names[item.Name], listed[item.File] = true, true
		if item.Journal != "" {
			if filepath.Base(item.Journal) != item.Journal {
				return fmt.Errorf("invalid fixture journal: %s", item.Journal)
			}
			listed[item.Journal] = true
		}
	}
	for _, item := range manifest.Cases {
		if item.Previous != "" && !listed[item.Previous] {
			return fmt.Errorf("unlisted previous fixture: %s", item.Previous)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !listed[entry.Name()] || !entry.Type().IsRegular() {
			return fmt.Errorf("unlisted or nonregular fixture: %s", entry.Name())
		}
		delete(listed, entry.Name())
	}
	for name := range listed {
		return fmt.Errorf("missing listed fixture: %s", name)
	}
	return nil
}

func managedExpectedPrincipal(manifest managedFixtureManifest, item managedFixtureCase) Principal {
	if item.Principal != nil {
		return Principal{UID: item.Principal.UID, Generation: item.Principal.Generation, Service: item.Principal.Service, Role: "service"}
	}
	uid, generation := manifest.UID, manifest.Generation
	if item.UID != nil {
		uid = *item.UID
	}
	if item.Generation != "" {
		generation = item.Generation
	}
	return Principal{UID: uid, Generation: generation, Service: Gateway, Role: "service"}
}

func managedApplyCase(t *testing.T, fixture *managedFixture, manifest managedFixtureManifest, item managedFixtureCase) {
	t.Helper()
	if item.Check == "service" {
		journal, err := genjournal.Verify(bytes.NewReader(managedBytes(t, item.Journal)), genjournal.Floor{Hash: genjournal.ZeroHash})
		if err != nil || journal.Tail.Hash != item.JournalHead {
			t.Fatal("service case journal head mismatch")
		}
		if item.Verdict == "accept" {
			want := managedExpectedPrincipal(manifest, item)
			if journal.Active(int64(want.UID), want.Generation) != nil {
				t.Fatal("service accept does not identify an active case journal pair")
			}
		}
		managedWrite(t, filepath.Join(fixture.journal, "journal"), managedBytes(t, item.Journal))
	}
	path := filepath.Join(fixture.parent, "identities.json")
	managedWrite(t, path, managedBytes(t, item.File))
	switch item.Check {
	case "decode", "service":
		if item.Condition != "" || item.Previous != "" {
			t.Fatal("unexpected case precondition")
		}
	case "transition":
		t.Fatal("producer-only transition must not run as a consumer check")
	case "custody":
		var err error
		switch item.Condition {
		case "missing-file":
			err = os.Remove(path)
		case "unreadable-file":
			if os.Geteuid() == 0 {
				t.Fatal("unreadable-file requires the unprivileged private environment")
			}
			err = os.Chmod(path, 0000)
		case "wrong-owner":
			fixture.authority.policy.uid++
		case "wrong-group":
			fixture.authority.policy.gid++
		case "wrong-mode":
			err = os.Chmod(path, 0600)
		case "symlink":
			if err = os.Rename(path, path+".real"); err == nil {
				err = os.Symlink(path+".real", path)
			}
		case "hardlink":
			err = os.Link(path, path+".extra")
		case "not-regular":
			if err = os.Remove(path); err == nil {
				err = os.Mkdir(path, 0755)
			}
		default:
			t.Fatalf("unknown custody condition: %s", item.Condition)
		}
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown fixture check: %s", item.Check)
	}
}

func managedCaseUnchanged(t *testing.T, fixture *managedFixture, item managedFixtureCase, before string) {
	t.Helper()
	if managedSnapshot(t, fixture.authority.root) != before {
		t.Fatal("identity refusal changed protected filesystem state")
	}
	if item.Condition == "unreadable-file" {
		path := filepath.Join(fixture.parent, "identities.json")
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, managedBytes(t, item.File)) {
			t.Fatal("unreadable projection bytes changed")
		}
	}
}

func managedBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(managedFixtureDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func managedWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
}

func newManagedFixture(t *testing.T) *managedFixture {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "lib/user-manager")
	journal := filepath.Join(parent, "generations")
	if err := os.MkdirAll(journal, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journal, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gate.lock", "data.lock"} {
		managedWrite(t, filepath.Join(journal, name), nil)
	}
	managedWrite(t, filepath.Join(journal, "journal"), managedBytes(t, "journal.jsonl"))
	managedWrite(t, filepath.Join(parent, "identities.json"), managedBytes(t, "valid.json"))
	authority, err := NewManagedAuthority(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority.policy = managedPolicy{anchor: root, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	return &managedFixture{authority: authority, parent: parent, journal: journal}
}

func managedPrincipal(authority Authority, uid uint32) (Principal, error) {
	var principal Principal
	err := authority.WithIdentity(context.Background(), func(view View) error {
		var err error
		principal, err = view.Principal(uid)
		return err
	})
	return principal, err
}

func managedPositive(t *testing.T, authority Authority) {
	t.Helper()
	principal, err := managedPrincipal(authority, managedFixtureUID)
	want := Principal{UID: managedFixtureUID, Generation: managedFixtureGeneration, Service: Gateway, Role: "service"}
	if err != nil || principal != want {
		t.Fatalf("valid protected service record: got %#v, %v; want %#v", principal, err, want)
	}
}

func managedSnapshot(t *testing.T, root string) string {
	t.Helper()
	var snapshot strings.Builder
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		fmt.Fprintf(&snapshot, "%s:%o:%d:%d:%d\n", path, stat.Mode, stat.Uid, stat.Gid, stat.Nlink)
		if entry.Type().IsRegular() && stat.Mode&0444 != 0 {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(&snapshot, "%s:%x\n", path, sha256.Sum256(raw))
		} else if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(&snapshot, "%s:%s\n", path, target)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.String()
}

// Claim: shared verdicts apply only to their declared consumer operation;
// services use their own journals and exact triples, with no protected writes.
// Producer-only pairwise transitions are explicitly skipped, not consumer passes.
func TestManagedSharedFixtures(t *testing.T) {
	manifest := managedCases(t)
	for _, item := range manifest.Cases {
		t.Run(item.Name, func(t *testing.T) {
			if item.Check == "transition" {
				t.Skip("consumer=none: producer-only ValidateTransition; no broker pairwise transition API")
			}
			managedPositive(t, newManagedFixture(t).authority)
			fixture := newManagedFixture(t)
			managedApplyCase(t, fixture, manifest, item)
			before := managedSnapshot(t, fixture.authority.root)
			if item.Check == "decode" {
				accounts, err := decodeManaged(managedBytes(t, item.File), manifest.JournalHead)
				if item.Verdict == "accept" {
					if err != nil || accounts == nil {
						t.Fatalf("valid decode: got %#v, %v", accounts, err)
					}
				} else {
					refused(t, err, item.Verdict)
					if accounts != nil {
						t.Fatal("decode refusal returned accounts")
					}
				}
				managedCaseUnchanged(t, fixture, item, before)
				t.Logf("check=decode consumer=decode verdict=%s effect=none", item.Verdict)
				return
			}
			want := managedExpectedPrincipal(manifest, item)
			uid := manifest.UID
			if item.Check == "service" {
				uid = *item.UID
			}
			principal, err := managedPrincipal(fixture.authority, uid)
			if item.Verdict == "accept" {
				if err != nil || principal != want {
					t.Fatalf("valid fixture: got %#v, %v; want %#v", principal, err, want)
				}
			} else {
				if item.Verdict != "principal_ledger_mismatch" {
					t.Fatal("unknown fixture verdict")
				}
				refused(t, err, item.Verdict)
				if principal != (Principal{}) {
					t.Fatal("refusal returned a principal")
				}
			}
			managedCaseUnchanged(t, fixture, item, before)
			t.Logf("check=%s consumer=%s verdict=%s effect=none principal=%#v", item.Check, item.Consumer, item.Verdict, principal)
		})
	}
}

// Claim: cases.json names every projection and service journal; repeated file
// references are valid, but missing/unlisted files and duplicate case names fail.
func TestManagedFixtureInventory(t *testing.T) {
	manifest := managedCases(t)
	for _, fault := range []string{"extra", "missing", "missing-journal", "directory", "duplicate", "unlisted-previous"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			entries, err := os.ReadDir(managedFixtureDirectory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				managedWrite(t, filepath.Join(directory, entry.Name()), nil)
			}
			candidate := manifest
			candidate.Cases = append([]managedFixtureCase(nil), manifest.Cases...)
			switch fault {
			case "extra":
				managedWrite(t, filepath.Join(directory, "unlisted.json"), nil)
			case "missing", "missing-journal", "directory":
				path := filepath.Join(directory, candidate.Cases[0].File)
				if fault == "missing-journal" {
					path = filepath.Join(directory, candidate.Cases[0].Journal)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if fault == "directory" {
					if err := os.Mkdir(path, 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "duplicate":
				candidate.Cases = append(candidate.Cases, candidate.Cases[0])
			case "unlisted-previous":
				candidate.Cases[0].Previous = "unlisted.json"
			}
			if err := managedFixtureInventory(directory, candidate); err == nil || !strings.Contains(err.Error(), map[string]string{"extra": "unlisted or nonregular", "missing": "missing listed", "missing-journal": "missing listed", "directory": "unlisted or nonregular", "duplicate": "duplicate or invalid", "unlisted-previous": "unlisted previous"}[fault]) {
				t.Fatalf("inventory control did not detect %s: %v", fault, err)
			}
			if err := managedFixtureInventory(managedFixtureDirectory, manifest); err != nil {
				t.Fatalf("valid inventory refused: %v", err)
			}
		})
	}
}

// Claim: removing any canonical file fails inventory, including metadata and
// per-service journals; an added file also fails, beside the intact control.
func TestManagedFixtureFileSet(t *testing.T) {
	manifest := managedCases(t)
	directory := t.TempDir()
	entries, err := os.ReadDir(managedFixtureDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		managedWrite(t, filepath.Join(directory, entry.Name()), nil)
	}
	if err := managedFixtureInventory(directory, manifest); err != nil {
		t.Fatalf("intact inventory refused: %v", err)
	}
	for _, entry := range entries {
		t.Run("missing-"+entry.Name(), func(t *testing.T) {
			path := filepath.Join(directory, entry.Name())
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := managedFixtureInventory(directory, manifest); err == nil || err.Error() != "missing listed fixture: "+entry.Name() {
				t.Fatalf("missing file not detected: %v", err)
			}
			managedWrite(t, path, nil)
			if err := managedFixtureInventory(directory, manifest); err != nil {
				t.Fatalf("restored inventory refused: %v", err)
			}
		})
	}
	managedWrite(t, filepath.Join(directory, "unlisted.json"), nil)
	if err := managedFixtureInventory(directory, manifest); err == nil || err.Error() != "unlisted or nonregular fixture: unlisted.json" {
		t.Fatalf("extra file not detected: %v", err)
	}
}

// Claim: consumer metadata cannot change the operation, invent a service
// promise, reuse the shared journal or omit the UID and exact output fields.
func TestManagedFixtureConsumerContract(t *testing.T) {
	manifest := managedCases(t)
	for _, fault := range []string{"consumer", "uid-missing", "uid-mismatch", "generation", "service", "journal-missing", "journal-shared", "journal-head", "principal-missing", "verdict", "nonservice-promise"} {
		t.Run(fault, func(t *testing.T) {
			candidate := manifest
			candidate.Cases = append([]managedFixtureCase(nil), manifest.Cases...)
			item := &candidate.Cases[0]
			principal := *item.Principal
			item.Principal = &principal
			wantError := "invalid service principal promise"
			switch fault {
			case "consumer":
				item.Consumer = "decode"
				wantError = "invalid consumer kind"
			case "uid-missing":
				item.UID = nil
				wantError = "invalid service journal or UID"
			case "uid-mismatch":
				item.Principal.UID++
			case "generation":
				item.Principal.Generation = "22222222222222222222222222222222"
			case "service":
				item.Principal.Service = "unknown-service"
			case "journal-missing":
				item.Journal = ""
				wantError = "invalid service journal or UID"
			case "journal-shared":
				item.Journal = manifest.Journal
				wantError = "invalid service journal or UID"
			case "journal-head":
				item.JournalHead = "invalid"
				wantError = "invalid service journal or UID"
			case "principal-missing":
				item.Principal = nil
			case "verdict":
				item.Verdict = "unknown"
				wantError = "unknown fixture verdict"
			case "nonservice-promise":
				item.Check, item.Consumer = "decode", "decode"
				wantError = "nonservice principal promise"
			}
			if err := managedFixtureContract(candidate); err == nil || !strings.HasPrefix(err.Error(), wantError+":") {
				t.Fatalf("invalid %s contract not detected: %v", fault, err)
			}
			if err := managedFixtureContract(manifest); err != nil {
				t.Fatalf("valid contract refused: %v", err)
			}
		})
	}
}

// Claim: the producer seal covers every case, cases.json and every journal;
// only SHA256SUMS itself and the explanatory producer README are unsealed.
func TestManagedFixtureChecksums(t *testing.T) {
	entries, err := os.ReadDir(managedFixtureDirectory)
	if err != nil {
		t.Fatal(err)
	}
	sealed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(managedBytes(t, "SHA256SUMS")), "\n"), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || filepath.Base(parts[1]) != parts[1] || sealed[parts[1]] {
			t.Fatal("invalid checksum entry")
		}
		digest := sha256.Sum256(managedBytes(t, parts[1]))
		if hex.EncodeToString(digest[:]) != parts[0] {
			t.Fatalf("fixture checksum mismatch: %s", parts[1])
		}
		sealed[parts[1]] = true
	}
	for _, entry := range entries {
		if entry.Name() != "SHA256SUMS" && entry.Name() != "README.md" && (entry.IsDir() || !sealed[entry.Name()]) {
			t.Fatalf("unsealed fixture: %s", entry.Name())
		}
	}
	if len(sealed) != len(entries)-2 {
		t.Fatal("checksum inventory differs from fixture inventory")
	}
}

// Claim: schema rejection is independent of selecting a principal; closed
// sets and members cannot hide behind an unrelated valid service record.
func TestManagedClosedDocument(t *testing.T) {
	manifest := managedCases(t)
	var valid managedDocument
	if json.Unmarshal(managedBytes(t, "valid.json"), &valid) != nil {
		t.Fatal("fixture decode")
	}
	if _, err := decodeManaged(managedBytes(t, "valid.json"), valid.JournalHead); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		if item.Check != "decode" {
			continue
		}
		t.Run(item.Name, func(t *testing.T) {
			_, err := decodeManaged(managedBytes(t, item.File), valid.JournalHead)
			if item.Verdict == "accept" {
				if err != nil {
					t.Fatalf("valid decode refused: %v", err)
				}
			} else {
				refused(t, err, item.Verdict)
			}
		})
	}
}

// Claim: zero UID, zero generation and NUL names refuse decoding for every
// supported kind, beside valid controls; rejected documents return no accounts.
func TestManagedIdentityScalars(t *testing.T) {
	for _, kind := range []string{"service", "agent", "workplace"} {
		for _, fault := range []string{"uid-zero", "generation-zero", "name-nul"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				var document managedDocument
				if err := json.Unmarshal(managedBytes(t, "valid.json"), &document); err != nil {
					t.Fatal(err)
				}
				document.Accounts[0].Kind = kind
				if _, err := decodeManaged(encode(t, document), document.JournalHead); err != nil {
					t.Fatalf("valid scalar control refused: %v", err)
				}
				switch fault {
				case "uid-zero":
					document.Accounts[0].UID = 0
				case "generation-zero":
					document.Accounts[0].Generation = "00000000000000000000000000000000"
				case "name-nul":
					document.Accounts[0].Name += "\x00suffix"
				}
				accounts, err := decodeManaged(encode(t, document), document.JournalHead)
				refused(t, err, "principal_ledger_mismatch")
				if accounts != nil {
					t.Fatal("invalid scalar returned accounts")
				}
			})
		}
	}
}

// Claim: consumer-only malformed and missing-field variants refuse independently
// of principal selection; these generated bytes do not extend the shared set.
func TestManagedConsumerOnlyDocuments(t *testing.T) {
	valid := string(managedBytes(t, "valid.json"))
	var document managedDocument
	if err := json.Unmarshal([]byte(valid), &document); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		old  string
		new  string
	}{
		{"missing-head", `,"journal_head":"` + document.JournalHead + `"`, ""},
		{"missing-uid", `,"uid":30001`, ""},
		{"empty-name", `"name":"credential-gateway"`, `"name":""`},
		{"null-kind", `"kind":"service"`, `"kind":null`},
		{"uid-negative", `"uid":30001`, `"uid":-1`},
		{"uppercase-generation", `"generation":"` + managedFixtureGeneration + `"`, `"generation":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`},
		{"malformed", valid, "{"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if strings.Count(valid, item.old) != 1 {
				t.Fatal("consumer-only fixture mutation did not apply exactly once")
			}
			_, err := decodeManaged([]byte(strings.Replace(valid, item.old, item.new, 1)), document.JournalHead)
			refused(t, err, "principal_ledger_mismatch")
			if _, err := decodeManaged([]byte(valid), document.JournalHead); err != nil {
				t.Fatalf("adjacent valid document refused: %v", err)
			}
		})
	}
}

// Claim: descriptor reads reject absent, linked, special or incorrectly moded
// projection, journal and lock leaves before entering a consumer callback.
func TestManagedProtectedFiles(t *testing.T) {
	for _, leaf := range []string{"identities.json", "journal", "gate.lock", "data.lock"} {
		for _, fault := range []string{"missing", "symlink", "hardlink", "private-mode", "writable-mode", "special-mode", "fifo", "directory"} {
			t.Run(leaf+"/"+fault, func(t *testing.T) {
				fixture := newManagedFixture(t)
				managedPositive(t, fixture.authority)
				directory := fixture.journal
				if leaf == "identities.json" {
					directory = fixture.parent
				}
				path := filepath.Join(directory, leaf)
				var err error
				switch fault {
				case "missing":
					err = os.Remove(path)
				case "symlink":
					if err = os.Rename(path, path+".real"); err == nil {
						err = os.Symlink(path+".real", path)
					}
				case "hardlink":
					err = os.Link(path, path+".extra")
				case "private-mode":
					err = os.Chmod(path, 0600)
				case "writable-mode":
					err = os.Chmod(path, 0664)
				case "special-mode":
					err = os.Chmod(path, 0644|os.ModeSetuid)
				case "fifo", "directory":
					if err = os.Remove(path); err == nil {
						if fault == "fifo" {
							err = unix.Mkfifo(path, 0644)
						} else {
							err = os.Mkdir(path, 0644)
						}
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				called := false
				err = fixture.authority.WithIdentity(context.Background(), func(View) error { called = true; return nil })
				refused(t, err, "principal_ledger_mismatch")
				if called {
					t.Fatal("unprotected leaf reached consumer")
				}
			})
		}
	}
}

// Claim: production fixes both owner IDs at zero; the private test seam uses
// disposable user-owned inodes and exercises the same leaf UID/GID predicates.
// This does not qualify a root-owned installed tree or host ACLs.
func TestManagedLeafOwner(t *testing.T) {
	fixture := newManagedFixture(t)
	production, err := NewManagedAuthority(fixture.authority.root, nil)
	if err != nil || production.policy != (managedPolicy{anchor: "/"}) {
		t.Fatal("production owner policy is configurable")
	}
	directory, err := os.Open(fixture.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	for _, field := range []string{"owner", "group"} {
		t.Run(field, func(t *testing.T) {
			original := fixture.authority.policy
			if _, err := fixture.authority.readAt(directory, "identities.json", managedIdentityLimit); err != nil {
				t.Fatal("valid leaf control refused")
			}
			if field == "owner" {
				fixture.authority.policy.uid++
			} else {
				fixture.authority.policy.gid++
			}
			_, err := fixture.authority.readAt(directory, "identities.json", managedIdentityLimit)
			fixture.authority.policy = original
			refused(t, err, "principal_ledger_mismatch")
		})
	}
	if os.Geteuid() != 0 {
		_, err = managedPrincipal(production, managedFixtureUID)
		refused(t, err, "principal_ledger_mismatch")
	}
}

// Claim: no directory component can be a symlink or group-writable ancestor;
// the generations leaf must have the published exact mode.
func TestManagedProtectedDirectories(t *testing.T) {
	for _, relative := range []string{"lib", "lib/user-manager", "lib/user-manager/generations"} {
		for _, fault := range []string{"symlink", "writable"} {
			t.Run(relative+"/"+fault, func(t *testing.T) {
				fixture := newManagedFixture(t)
				managedPositive(t, fixture.authority)
				path := filepath.Join(fixture.authority.root, relative)
				var err error
				if fault == "symlink" {
					if err = os.Rename(path, path+".real"); err == nil {
						err = os.Symlink(path+".real", path)
					}
				} else {
					err = os.Chmod(path, 0775)
				}
				if err != nil {
					t.Fatal(err)
				}
				_, err = managedPrincipal(fixture.authority, managedFixtureUID)
				refused(t, err, "principal_ledger_mismatch")
			})
		}
	}
	fixture := newManagedFixture(t)
	managedPositive(t, fixture.authority)
	if err := os.Chmod(fixture.journal, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := managedPrincipal(fixture.authority, managedFixtureUID)
	refused(t, err, "principal_ledger_mismatch")
}

// Claim: the published journal gate/data protocol excludes writers for the
// whole callback, never queues on a writer, and refuses every pending marker.
func TestManagedWriterFences(t *testing.T) {
	for _, fault := range []string{"gate.lock", "data.lock", "writer.pending", "dangling-pending", "directory-pending", "nonempty-lock"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, fixture.authority)
			if fault == "dangling-pending" {
				if err := os.Symlink("absent-target", filepath.Join(fixture.journal, "writer.pending")); err != nil {
					t.Fatal(err)
				}
			} else if fault == "directory-pending" {
				if err := os.Mkdir(filepath.Join(fixture.journal, "writer.pending"), 0755); err != nil {
					t.Fatal(err)
				}
			} else if fault == "writer.pending" || fault == "nonempty-lock" {
				leaf := fault
				if fault == "nonempty-lock" {
					leaf = "data.lock"
				}
				managedWrite(t, filepath.Join(fixture.journal, leaf), []byte("synthetic pending"))
			} else {
				file, err := os.Open(filepath.Join(fixture.journal, fault))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				defer unix.Flock(int(file.Fd()), unix.LOCK_UN)
			}
			called := false
			err := fixture.authority.WithIdentity(context.Background(), func(View) error { called = true; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if called {
				t.Fatal("writer fence bypassed")
			}
		})
	}
}

// Claim: a view is valid only inside its locked read pass; a second pass reads
// new projection bytes rather than trusting a cached principal or head.
func TestManagedReadWindow(t *testing.T) {
	fixture := newManagedFixture(t)
	var retained View
	writer, err := os.Open(filepath.Join(fixture.journal, "data.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	err = fixture.authority.WithIdentity(context.Background(), func(view View) error {
		retained = view
		if _, err := view.Principal(managedFixtureUID); err != nil {
			return err
		}
		err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Flock(int(writer.Fd()), unix.LOCK_UN)
			t.Fatal("writer entered an active read pass")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = retained.Principal(managedFixtureUID)
	refused(t, err, "principal_ledger_mismatch")
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("reader did not release data lock")
	}
	managedWrite(t, filepath.Join(fixture.parent, "identities.json"), managedBytes(t, "stale-journal-head.json"))
	_ = unix.Flock(int(writer.Fd()), unix.LOCK_UN)
	_, err = managedPrincipal(fixture.authority, managedFixtureUID)
	refused(t, err, "principal_ledger_mismatch")
}

// Claim: an observed UID never changes kind, even across a valid fresh read;
// this in-process check does not replace the producer lifetime invariant.
func TestManagedUIDKindContinuity(t *testing.T) {
	fixture := newManagedFixture(t)
	managedWrite(t, filepath.Join(fixture.parent, "identities.json"), managedBytes(t, "agent-as-service.json"))
	_, err := managedPrincipal(fixture.authority, managedFixtureUID)
	refused(t, err, "principal_ledger_mismatch")
	managedWrite(t, filepath.Join(fixture.parent, "identities.json"), managedBytes(t, "valid.json"))
	_, err = managedPrincipal(fixture.authority, managedFixtureUID)
	refused(t, err, "principal_ledger_mismatch")
	managedPositive(t, newManagedFixture(t).authority)
}

// Claim: a matching head is insufficient when the protected chain is invalid
// or the journal has retired the projected generation.
func TestManagedJournalAuthority(t *testing.T) {
	for _, fault := range []string{"partial", "broken-chain", "retired", "oversize", "projection-oversize"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, fixture.authority)
			raw := managedBytes(t, "journal.jsonl")
			var projection managedDocument
			if json.Unmarshal(managedBytes(t, "valid.json"), &projection) != nil {
				t.Fatal("fixture projection")
			}
			switch fault {
			case "partial":
				raw = raw[:len(raw)-1]
			case "broken-chain":
				raw = bytes.Replace(raw, []byte(`"prev":"0000`), []byte(`"prev":"ffff`), 1)
			case "retired":
				verified, err := genjournal.Verify(bytes.NewReader(raw), genjournal.Floor{Hash: genjournal.ZeroHash})
				if err != nil {
					t.Fatal(err)
				}
				line, err := genjournal.Encode(genjournal.Record{Seq: verified.Tail.Seq + 1, Prev: projection.JournalHead, UID: managedFixtureUID, Generation: managedFixtureGeneration, State: "retiring", Writer: "user-manager", Time: "2026-11-19T00:00:00Z"})
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, line...)
				projection.JournalHead = genjournal.Digest(line)
				managedWrite(t, filepath.Join(fixture.parent, "identities.json"), encode(t, projection))
			case "oversize":
				raw = bytes.Repeat([]byte("x"), genjournal.MaxFile+1)
			case "projection-oversize":
				managedWrite(t, filepath.Join(fixture.parent, "identities.json"), bytes.Repeat([]byte("x"), managedIdentityLimit+1))
			}
			managedWrite(t, filepath.Join(fixture.journal, "journal"), raw)
			_, err := managedPrincipal(fixture.authority, managedFixtureUID)
			refused(t, err, "principal_ledger_mismatch")
		})
	}
}

// Claim: absent use facts cannot invoke a current-use callback; identity-only
// checks remain usable and every unsupported fact stays closed.
func TestManagedUnavailableFacts(t *testing.T) {
	fixture := newManagedFixture(t)
	managedPositive(t, fixture.authority)
	called := false
	err := fixture.authority.WithCurrent(context.Background(), func(View) error { called = true; return nil })
	refused(t, err, "revocation_state_unavailable")
	if called {
		t.Fatal("missing use facts invoked callback")
	}
	err = fixture.authority.WithIdentity(context.Background(), func(view View) error {
		refused(t, view.Service(wire.ServiceBinding{}), "service_binding_mismatch")
		until, binding, err := view.Caller(wire.ServiceBinding{}, wire.ServiceCaller{})
		refused(t, err, "revocation_state_unavailable")
		if !until.IsZero() || binding != "" || view.Owner(0, "") || view.OperatorAct(Principal{}, "", nil) || view.Event(nil) || view.Sequence() != nil {
			t.Fatal("identity evidence granted absent use/operator facts")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Claim: the protected projection, not a supplied fact providers principal
// map, selects service identity; the remaining methods preserve supplied facts
// and caller expiry exactly, without requiring current-use facts for identity.
func TestManagedFactsDelegation(t *testing.T) {
	fixture := newManagedFixture(t)
	broker := newBrokerFixture(t, nil)
	fixture.authority.facts = broker.a
	broker.a.available = false
	managedPositive(t, fixture.authority)
	called := false
	if err := fixture.authority.WithCurrent(context.Background(), func(View) error { called = true; return nil }); err == nil || called {
		t.Fatal("unavailable supplied facts were bypassed")
	}
	broker.a.available = true
	err := fixture.authority.WithCurrent(context.Background(), func(view View) error {
		if _, err := view.Principal(managedFixtureUID); err != nil {
			return err
		}
		if err := view.Service(broker.a.binding); err != nil {
			return err
		}
		until, binding, err := view.Caller(broker.a.binding, broker.a.caller)
		if err != nil || until != broker.a.callerUntil || binding != broker.a.bindingID || !view.Owner(broker.owner, fixtureAccount) || !view.OperatorAct(Principal{}, "synthetic", nil) || !view.Event(json.RawMessage(`{"class":"auth","kind":"credential_error"}`)) || !bytes.Equal(view.Sequence(), broker.a.Sequence()) {
			t.Fatal("supplied protected facts changed")
		}
		_, err = view.Principal(broker.operator)
		refused(t, err, "principal_ledger_mismatch")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Claim: cancellation inside a read pass immediately invalidates the view and
// makes the callback result unusable, even if the callback itself returns nil.
func TestManagedCancellationInsidePass(t *testing.T) {
	fixture := newManagedFixture(t)
	managedPositive(t, fixture.authority)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := fixture.authority.WithIdentity(ctx, func(view View) error {
		cancel()
		_, err := view.Principal(managedFixtureUID)
		refused(t, err, "principal_ledger_mismatch")
		return nil
	})
	refused(t, err, "principal_ledger_mismatch")
}

// Claim: concurrent readers retain correct triples without races, and canceled
// or invalid root selections fail without a consumer callback.
func TestManagedConcurrentAndCanceled(t *testing.T) {
	fixture := newManagedFixture(t)
	var readers sync.WaitGroup
	for index := 0; index < 8; index++ {
		readers.Add(1)
		go func() { defer readers.Done(); managedPositive(t, fixture.authority) }()
	}
	readers.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := fixture.authority.WithIdentity(ctx, func(View) error { called = true; return nil })
	refused(t, err, "principal_ledger_mismatch")
	if called {
		t.Fatal("canceled read invoked callback")
	}
	for _, root := range []string{"", "relative", "/root/../root", "/root/"} {
		_, err := NewManagedAuthority(root, nil)
		refused(t, err, "principal_ledger_mismatch")
	}
}

// Claim: a valid protected identity can drive the existing bounded material
// path with supplied synthetic use facts; every shared identity refusal blocks
// open and already-connected calls with no publication, custody or lease effect.
func TestManagedRefusalsBeforeMaterial(t *testing.T) {
	manifest := managedCases(t)
	cases := []managedFixtureCase{{Name: "missing", Check: "custody", Condition: "missing-file", File: "valid.json", Verdict: "principal_ledger_mismatch"}}
	for _, item := range manifest.Cases {
		if item.Verdict == "principal_ledger_mismatch" {
			cases = append(cases, item)
		}
	}
	for _, item := range cases {
		t.Run(item.Name, func(t *testing.T) {
			if item.Check == "transition" {
				t.Skip("consumer=none: producer-only transition verdict does not govern broker material calls")
			}
			fixture := newManagedFixture(t)
			broker := newBrokerFixture(t, nil)
			delete(broker.a.principals, broker.uid)
			broker.uid = managedFixtureUID
			principal := Principal{UID: managedFixtureUID, Generation: managedFixtureGeneration, Service: Gateway, Role: "service"}
			broker.a.principals[broker.uid] = principal
			broker.a.binding.UID = broker.uid
			broker.a.binding.Generation = principal.Generation
			broker.bind(t)
			fixture.authority.facts = broker.a
			broker.b.authority = fixture.authority
			broker.issue(t)
			managedApplyCase(t, fixture, manifest, item)
			uid := broker.uid
			if item.Check == "service" {
				uid = *item.UID
				principal.UID = uid
			}
			before, leases := broker.custody.entries, len(broker.b.leases)
			state := managedSnapshot(t, broker.root)
			identities := managedSnapshot(t, fixture.authority.root)
			_, err := broker.b.Open(context.Background(), uid)
			refused(t, err, "principal_ledger_mismatch")
			replies := 0
			err = broker.b.Call(context.Background(), principal, "service.lease.request", encode(t, broker.request()), func(any) error { replies++; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if broker.custody.entries != before || replies != 0 || len(broker.b.leases) != leases || managedSnapshot(t, broker.root) != state {
				t.Fatal("refused managed identity changed material or durable state")
			}
			managedCaseUnchanged(t, fixture, item, identities)
		})
	}
}
