package authorityv0

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type authorityFixture struct {
	reader   *Reader
	document assemblyv0.AuthorityDocument
	passwd   string
	group    string
}

func write(test *testing.T, path string, contents []byte, mode os.FileMode) {
	test.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		test.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		test.Fatal(err)
	}
}

func (fixture *authorityFixture) publish(test *testing.T) {
	test.Helper()
	contents, err := wire.Encode(fixture.document)
	if err != nil {
		test.Fatal(err)
	}
	write(test, fixture.reader.paths.authority, contents, 0640)
}

func newFixture(test *testing.T) *authorityFixture {
	test.Helper()
	contents, err := os.ReadFile("../assemblyv0/testdata/construction-v0/authority.json")
	if err != nil {
		test.Fatal(err)
	}
	var document assemblyv0.AuthorityDocument
	if err := wire.Decode(contents, &document); err != nil {
		test.Fatal(err)
	}
	document.Broker.UID, document.Broker.GID = uint32(os.Getuid()), uint32(os.Getgid())
	config := policy.Config{SocketPath: SocketPath, StoreRoot: StoreRoot, Policy: policy.Policy{
		Installation: document.InstallationID, BrokerUID: document.Broker.UID,
		ObserverUIDs: []uint32{document.Observer.UID}, Accounts: []policy.Account{{Label: document.Accounts[0].Account, Enabled: true}},
	}}
	reader := New(config)
	root := test.TempDir()
	reader.rootUID, reader.rootGID = uint32(os.Getuid()), uint32(os.Getgid())
	reader.paths = paths{authority: filepath.Join(root, "configuration", "authority-v0.json"), lock: filepath.Join(root, "configuration", "authority.lock"), passwd: filepath.Join(root, "passwd"), group: filepath.Join(root, "group"), directory: filepath.Join(root, "configuration"), data: filepath.Join(root, "data"), store: filepath.Join(root, "data", "store")}
	for _, directory := range []string{reader.paths.directory, reader.paths.data, reader.paths.store} {
		if err := os.Mkdir(directory, 0700); err != nil {
			test.Fatal(err)
		}
	}
	if err := os.Chmod(reader.paths.directory, 0750); err != nil {
		test.Fatal(err)
	}
	fixture := &authorityFixture{reader: reader, document: document}
	fixture.passwd = fmt.Sprintf("%s:x:%d:%d::%s:/usr/sbin/nologin\n", document.Broker.Name, document.Broker.UID, document.Broker.GID, document.Broker.Home)
	for index, pin := range append([]assemblyv0.PrincipalPin{document.Operator, document.Observer}, document.TerminalCallers...) {
		fixture.passwd += fmt.Sprintf("%s:x:%d:%d::%s:/usr/sbin/nologin\n", pin.Name, pin.UID, 5100+index, pin.Home)
	}
	fixture.group = fmt.Sprintf("%s:x:%d:\n", document.Broker.Name, document.Broker.GID)
	write(test, reader.paths.passwd, []byte(fixture.passwd), 0644)
	write(test, reader.paths.group, []byte(fixture.group), 0644)
	write(test, reader.paths.lock, nil, 0640)
	fixture.publish(test)
	return fixture
}

func validWindow(test *testing.T, fixture *authorityFixture) StartupPins {
	test.Helper()
	document, pins, err := fixture.reader.Load(context.Background())
	if err != nil || document.Revision != fixture.document.Revision || pins.AuthorityDigest == "" {
		test.Fatalf("valid identical protected bytes/directory joins refused: %v", err)
	}
	called := false
	err = fixture.reader.WithPinned(context.Background(), pins, func(ctx context.Context, document assemblyv0.AuthorityDocument) error { called = true; return nil })
	if err != nil || !called {
		test.Fatalf("valid pinned callback refused: %v", err)
	}
	called = false
	err = fixture.reader.WithIdentity(context.Background(), func(ctx context.Context, document assemblyv0.AuthorityDocument) error { called = true; return nil })
	if err != nil || !called {
		test.Fatalf("valid current identity callback refused: %v", err)
	}
	return pins
}

// Claim: ACTIVATE-DRIFT compares exact current bytes, not revision alone; changed/missing/invalid bytes and fabricated pins never invoke the use callback beside the unchanged control.
func TestACTIVATEDriftCurrentBytes(test *testing.T) {
	for _, name := range []string{"same-revision-bytes", "revision", "missing", "malformed", "noncanonical", "unknown-member", "null-array", "pin-digest", "pin-revision", "foreign-reader", "zero-pins"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			pins := validWindow(test, fixture)
			switch name {
			case "same-revision-bytes":
				fixture.document.TerminalAuth.LauncherDigest = digest([]byte("changed inert launcher"))
				fixture.publish(test)
			case "revision":
				fixture.document.Revision++
				fixture.publish(test)
			case "missing":
				if err := os.Remove(fixture.reader.paths.authority); err != nil {
					test.Fatal(err)
				}
			case "malformed":
				write(test, fixture.reader.paths.authority, []byte("{"), 0640)
			case "noncanonical":
				contents, err := os.ReadFile(fixture.reader.paths.authority)
				if err != nil {
					test.Fatal(err)
				}
				write(test, fixture.reader.paths.authority, append(contents, byte(10)), 0640)
			case "unknown-member", "null-array":
				contents, err := os.ReadFile(fixture.reader.paths.authority)
				if err != nil {
					test.Fatal(err)
				}
				object, err := wire.Parse(contents)
				if err != nil {
					test.Fatal(err)
				}
				if name == "unknown-member" {
					object["unknown"] = "no"
				} else {
					object["dispatchers"] = nil
				}
				contents, err = wire.Encode(object)
				if err != nil {
					test.Fatal(err)
				}
				write(test, fixture.reader.paths.authority, contents, 0640)
			case "pin-digest":
				pins.AuthorityDigest = digest([]byte("unrelated"))
			case "pin-revision":
				pins.Revision++
			case "foreign-reader":
				other := newFixture(test)
				pins = validWindow(test, other)
			case "zero-pins":
				pins = StartupPins{}
			}
			called := false
			err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
			if !errors.Is(err, ErrIdentityChanged) || called {
				test.Fatalf("changed exact authority bytes/pins admitted: %v callback=%v", err, called)
			}
		})
	}
}

// Claim: AUTHORITY-LOCUS equality is exact and bidirectional, including empty exposed-lane grants, the observer set and installed paths; no configuration or root precedence exists.
func TestAUTHORITYLOCUSEquality(test *testing.T) {
	for _, name := range []string{"installation", "broker", "observer", "extra-observer", "duplicate-observer", "account", "extra-account", "disabled", "static-allowlist", "socket", "store", "account-owner", "harness", "kind", "mode", "root-key", "operator-key"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			config := &fixture.reader.config
			switch name {
			case "installation":
				config.Policy.Installation = "other"
			case "broker":
				config.Policy.BrokerUID++
			case "observer":
				config.Policy.ObserverUIDs[0]++
			case "extra-observer":
				config.Policy.ObserverUIDs = append(config.Policy.ObserverUIDs, config.Policy.ObserverUIDs[0]+1)
			case "duplicate-observer":
				config.Policy.ObserverUIDs = append(config.Policy.ObserverUIDs, config.Policy.ObserverUIDs[0])
			case "account":
				config.Policy.Accounts[0].Label = "other"
			case "extra-account":
				config.Policy.Accounts = append(config.Policy.Accounts, policy.Account{Label: "other", Enabled: true})
			case "disabled":
				config.Policy.Accounts[0].Enabled = false
			case "static-allowlist":
				config.Policy.Accounts[0].AllowedUIDs = []uint32{fixture.document.Operator.UID}
			case "socket":
				config.SocketPath += "-other"
			case "store":
				config.StoreRoot += "-other"
			case "account-owner":
				fixture.document.Accounts[0].OwnerUID++
			case "harness":
				fixture.document.Accounts[0].Harness = "other"
			case "kind":
				fixture.document.Accounts[0].Kind = "other"
			case "mode":
				fixture.document.Accounts[0].Mode = "exposed"
			case "root-key":
				fixture.document.RootKeys = []assemblyv0.PublicKey{}
			case "operator-key":
				fixture.document.OperatorKey = "ed25519:invalid"
			}
			fixture.publish(test)
			document, pins, err := fixture.reader.Load(context.Background())
			if !errors.Is(err, ErrIdentityChanged) || document.Format != "" || pins.owner != nil {
				test.Fatalf("mismatched configuration/authority leaked a result: %v", err)
			}
		})
	}
}

// Claim: the U02 AUTH-ROLE directory slice checks actual protected passwd/group equality, uniqueness and present dedicated GID membership; it proves no account creation/history or authentication provenance.
func TestAUTHROLEDirectoryPins(test *testing.T) {
	for _, name := range []string{"uid", "name", "home", "broker-gid", "duplicate-uid", "duplicate-name", "missing-pin", "group-id", "group-name", "group-member", "primary-group-member", "role-overlap", "caller-home", "broker-home"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			switch name {
			case "uid":
				fixture.passwd = strings.Replace(fixture.passwd, ":4002:", ":4402:", 1)
			case "name":
				fixture.passwd = strings.Replace(fixture.passwd, "swarma-operator:", "other-operator:", 1)
			case "home":
				fixture.passwd = strings.Replace(fixture.passwd, fixture.document.Operator.Home, "/var/empty/other", 1)
			case "broker-gid":
				fixture.document.Broker.GID++
			case "duplicate-uid":
				fixture.passwd += "other:x:4002:5500::/var/empty/other:/usr/sbin/nologin\n"
			case "duplicate-name":
				fixture.passwd += "swarma-operator:x:4402:5500::/var/empty/other:/usr/sbin/nologin\n"
			case "missing-pin":
				fixture.passwd = strings.Join(strings.Split(fixture.passwd, "\n")[:2], "\n") + "\n"
			case "group-id":
				fixture.group = "swarma-credential-broker:x:65000:\n"
			case "group-name":
				fixture.group = strings.Replace(fixture.group, "swarma-credential-broker", "other", 1)
			case "group-member":
				fixture.group = strings.TrimSuffix(fixture.group, "\n") + "swarma-operator\n"
			case "primary-group-member":
				fixture.passwd += fmt.Sprintf("other:x:4402:%d::/var/empty/other:/usr/sbin/nologin\n", fixture.document.Broker.GID)
			case "role-overlap":
				fixture.document.Operator.UID = fixture.document.Observer.UID
			case "caller-home":
				fixture.document.TerminalCallers[0].Home = "/var/empty/other"
			case "broker-home":
				fixture.document.Broker.Home = "/var/empty/other"
			}
			fixture.publish(test)
			write(test, fixture.reader.paths.passwd, []byte(fixture.passwd), 0644)
			write(test, fixture.reader.paths.group, []byte(fixture.group), 0644)
			called := false
			err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
			if !errors.Is(err, ErrIdentityChanged) || called {
				test.Fatalf("wrong current directory pin admitted: %v callback=%v", err, called)
			}
		})
	}
}

// Claim: the U02 protected-facts slice refuses unsafe or missing source/directory/lock facts before any callback; valid kernel-backed facts are the adjacent control.
func TestVIEWProtectedFactsAndLockContinuity(test *testing.T) {
	for _, name := range []string{"authority-mode", "passwd-mode", "group-mode", "configuration-mode", "data-mode", "store-mode", "missing-directory", "lock-replacement", "lock-missing", "authority-link", "passwd-symlink"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			pins := validWindow(test, fixture)
			var err error
			switch name {
			case "authority-mode":
				err = os.Chmod(fixture.reader.paths.authority, 0600)
			case "passwd-mode":
				err = os.Chmod(fixture.reader.paths.passwd, 0664)
			case "group-mode":
				err = os.Chmod(fixture.reader.paths.group, 0664)
			case "configuration-mode":
				err = os.Chmod(fixture.reader.paths.directory, 0755)
			case "data-mode":
				err = os.Chmod(fixture.reader.paths.data, 0750)
			case "store-mode":
				err = os.Chmod(fixture.reader.paths.store, 0750)
			case "missing-directory":
				err = os.Remove(fixture.reader.paths.store)
			case "lock-replacement":
				write(test, fixture.reader.paths.lock+"-new", nil, 0640)
				err = os.Rename(fixture.reader.paths.lock+"-new", fixture.reader.paths.lock)
			case "lock-missing":
				err = os.Remove(fixture.reader.paths.lock)
			case "authority-link":
				err = os.Link(fixture.reader.paths.authority, fixture.reader.paths.authority+"-link")
			case "passwd-symlink":
				err = os.Rename(fixture.reader.paths.passwd, fixture.reader.paths.passwd+"-real")
				if err == nil {
					err = os.Symlink(fixture.reader.paths.passwd+"-real", fixture.reader.paths.passwd)
				}
			}
			if err != nil {
				test.Fatal(err)
			}
			called := false
			err = fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
			expected := ErrIdentityChanged
			switch name {
			case "configuration-mode", "lock-replacement":
				expected = protectedio.ErrProtection
			case "lock-missing":
				expected = fs.ErrNotExist
			}
			if !errors.Is(err, expected) || called {
				test.Fatalf("unsafe protected fact admitted: %v callback=%v", err, called)
			}
		})
	}
}

// Claim: identity-only unmanaged narrowing reads current root/directory pins despite startup-byte and account-policy drift; no activation, journal, managed source or clock fixture exists or is needed.
func TestIdentityOnlyIndependence(test *testing.T) {
	fixture := newFixture(test)
	pins := validWindow(test, fixture)
	fixture.document.Revision++
	fixture.document.Accounts[0].Mode = "exposed"
	fixture.publish(test)
	if err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error {
		test.Fatal("drifted use callback ran")
		return nil
	}); !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("use drift not refused: %v", err)
	}
	called := false
	err := fixture.reader.WithIdentity(context.Background(), func(ctx context.Context, document assemblyv0.AuthorityDocument) error {
		called = true
		if document.Revision != fixture.document.Revision || document.Accounts[0].Mode != "exposed" {
			test.Fatal("identity path returned cached authority")
		}
		return nil
	})
	if err != nil || !called {
		test.Fatalf("independent current identity refused: %v", err)
	}
	fixture.reader.config.Policy.Installation = "unmatched-use-policy"
	if err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { return nil }); err != nil {
		test.Fatalf("use-only config join leaked into identity: %v", err)
	}
	fresh := newFixture(test)
	if err := fresh.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { return nil }); err != nil {
		test.Fatalf("identity path required startup Load: %v", err)
	}
}

// Claim: final local checks detect callback-time file drift and cancellation, preserve callback errors, and shared readers retain race-free immutable startup pins.
func TestVIEWFinalRecheckAndConcurrentReaders(test *testing.T) {
	fixture := newFixture(test)
	pins := validWindow(test, fixture)
	sentinel := errors.New("inert callback refusal")
	if err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { return sentinel }); !errors.Is(err, sentinel) {
		test.Fatal("callback error hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.reader.WithPinned(ctx, pins, func(context.Context, assemblyv0.AuthorityDocument) error {
		test.Fatal("cancelled callback ran")
		return nil
	}); !errors.Is(err, context.Canceled) {
		test.Fatalf("cancellation not retained: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if err := fixture.reader.WithPinned(ctx, pins, func(context.Context, assemblyv0.AuthorityDocument) error {
		cancel()
		return nil
	}); !errors.Is(err, context.Canceled) {
		test.Fatalf("callback cancellation not retained: %v", err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 4)
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { return nil })
		}()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			test.Fatal(err)
		}
	}
	err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error {
		fixture.document.TerminalAuth.LauncherDigest = digest([]byte("changed during bounded fixture callback"))
		fixture.publish(test)
		return nil
	})
	if !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("final authority-byte recheck accepted drift: %v", err)
	}
}

// Claim: an unaccepted C selector remains an explicit stop, not a substituted production selector or a fabricated qualified fixture.
func TestOtherContinuityStaysOpen(test *testing.T) {
	fixture := newFixture(test)
	validWindow(test, fixture)
	fixture.document.Continuity.Kind = "test-c"
	fixture.publish(test)
	if _, _, err := fixture.reader.Load(context.Background()); !errors.Is(err, ErrContinuity) {
		test.Fatalf("unaccepted continuity did not stop: %v", err)
	}
}

// Claim: replacement of an authority file with identical checked bytes is not lock-inode replacement or policy drift; returned documents cannot mutate the private startup-byte pin.
func TestIdenticalReplacementAndDefensivePins(test *testing.T) {
	fixture := newFixture(test)
	document, pins, err := fixture.reader.Load(context.Background())
	if err != nil {
		test.Fatal(err)
	}
	document.RootKeys[0] = "not-an-authority-key"
	document.Accounts[0].Mode = "exposed"
	contents, err := os.ReadFile(fixture.reader.paths.authority)
	if err != nil {
		test.Fatal(err)
	}
	write(test, fixture.reader.paths.authority+"-new", contents, 0640)
	if err := os.Rename(fixture.reader.paths.authority+"-new", fixture.reader.paths.authority); err != nil {
		test.Fatal(err)
	}
	if err := fixture.reader.WithPinned(context.Background(), pins, func(ctx context.Context, current assemblyv0.AuthorityDocument) error {
		if current.Accounts[0].Mode != "secret-free" {
			test.Fatal("returned document mutated protected source")
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
}
