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
		if !entry.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(&snapshot, "%s:%x\n", path, sha256.Sum256(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.String()
}

// Claim: every shared consumer verdict has its sealed exact bytes; successful
// cases map the exact service triple, and refusals leave protected bytes intact.
func TestManagedSharedFixtures(t *testing.T) {
	var manifest struct {
		Cases []struct {
			Expect string `json:"expect"`
			File   string `json:"file"`
			UID    uint32 `json:"uid"`
		} `json:"cases"`
		Journal string `json:"journal"`
	}
	raw := managedBytes(t, "manifest.json")
	if _, err := wire.Parse(raw); err != nil || wire.Decode(raw, &manifest) != nil || manifest.Journal != "journal.jsonl" || len(manifest.Cases) < 20 {
		t.Fatal("invalid shared fixture manifest")
	}
	for _, item := range manifest.Cases {
		t.Run(strings.TrimSuffix(item.File, ".json"), func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, fixture.authority)
			managedWrite(t, filepath.Join(fixture.parent, "identities.json"), managedBytes(t, item.File))
			fixture.authority.kinds = make(map[uint32]string)
			before := managedSnapshot(t, fixture.authority.root)
			principal, err := managedPrincipal(fixture.authority, item.UID)
			if item.Expect == "ok" {
				managedPositive(t, fixture.authority)
				if err != nil || principal.UID != item.UID {
					t.Fatalf("valid fixture refused: %v", err)
				}
			} else {
				if item.Expect != "principal_ledger_mismatch" {
					t.Fatal("unknown fixture verdict")
				}
				refused(t, err, item.Expect)
				if principal != (Principal{}) {
					t.Fatal("refusal returned a principal")
				}
			}
			if after := managedSnapshot(t, fixture.authority.root); after != before {
				t.Fatal("identity read changed protected state")
			}
		})
	}
}

// Claim: SHA256SUMS covers every fixture and no checksum can silently name a
// missing, extra, duplicate or path-escaping file.
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
		if entry.Name() != "SHA256SUMS" && (entry.IsDir() || !sealed[entry.Name()]) {
			t.Fatalf("unsealed fixture: %s", entry.Name())
		}
	}
	if len(sealed) != len(entries)-1 {
		t.Fatal("checksum inventory differs from fixture inventory")
	}
}

// Claim: schema rejection is independent of selecting a principal; closed
// sets and members cannot hide behind an unrelated valid service record.
func TestManagedClosedDocument(t *testing.T) {
	var valid managedDocument
	if json.Unmarshal(managedBytes(t, "valid.json"), &valid) != nil {
		t.Fatal("fixture decode")
	}
	if _, err := decodeManaged(managedBytes(t, "valid.json"), valid.JournalHead); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unknown-placement", "unknown-kind", "unknown-class", "unknown-state", "unknown-service", "unknown-member", "unknown-document-member", "missing-member", "missing-head", "duplicate-key", "duplicate-document-key", "duplicate-uid", "duplicate-service", "noncanonical", "malformed", "null-accounts", "uid-overflow", "stale-head"} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeManaged(managedBytes(t, name+".json"), valid.JournalHead)
			refused(t, err, "principal_ledger_mismatch")
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
	for _, fault := range []string{"gate.lock", "data.lock", "writer.pending", "nonempty-lock"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newManagedFixture(t)
			managedPositive(t, fixture.authority)
			if fault == "writer.pending" || fault == "nonempty-lock" {
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
	managedWrite(t, filepath.Join(fixture.parent, "identities.json"), managedBytes(t, "stale-head.json"))
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
				line, err := genjournal.Encode(genjournal.Record{Seq: 7, Prev: projection.JournalHead, UID: managedFixtureUID, Generation: managedFixtureGeneration, State: "retiring", Writer: "user-manager", Time: "2026-11-19T00:00:00Z"})
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
	var manifest struct {
		Cases []struct {
			Expect string `json:"expect"`
			File   string `json:"file"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(managedBytes(t, "manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	names := []string{"missing"}
	for _, item := range manifest.Cases {
		if item.Expect == "principal_ledger_mismatch" {
			names = append(names, strings.TrimSuffix(item.File, ".json"))
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
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
			path := filepath.Join(fixture.parent, "identities.json")
			if name == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				managedWrite(t, path, managedBytes(t, name+".json"))
			}
			before, leases := broker.custody.entries, len(broker.b.leases)
			state := managedSnapshot(t, broker.root)
			_, err := broker.b.Open(context.Background(), broker.uid)
			refused(t, err, "principal_ledger_mismatch")
			replies := 0
			err = broker.b.Call(context.Background(), principal, "service.lease.request", encode(t, broker.request()), func(any) error { replies++; return nil })
			refused(t, err, "principal_ledger_mismatch")
			if broker.custody.entries != before || replies != 0 || len(broker.b.leases) != leases || managedSnapshot(t, broker.root) != state {
				t.Fatal("refused managed identity changed material or durable state")
			}
		})
	}
}
