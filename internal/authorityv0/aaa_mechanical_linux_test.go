package authorityv0

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the composed reader's valid controls and nil-input refusals do not panic or silently lose callbacks/results.
func TestMechanicalAuthorityDecisionControls(test *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			test.Fatalf("mechanical authority decision panicked: %v", recovered)
		}
	}()
	fixture := newFixture(test)
	pins := validWindow(test, fixture)
	if err := fixture.reader.WithPinned(context.Background(), pins, nil); !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("mechanical nil pinned callback admitted: %v", err)
	}
	if err := fixture.reader.WithIdentity(context.Background(), nil); !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("mechanical nil identity callback admitted: %v", err)
	}
	if err := fixture.reader.window(context.Background(), nil, false, nil); !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("mechanical nil internal callback admitted: %v", err)
	}
	if err := fixture.reader.window(nil, nil, false, func(context.Context, snapshot) error { return nil }); !errors.Is(err, ErrIdentityChanged) {
		test.Fatalf("mechanical nil window context admitted: %v", err)
	}
}

// Claim: fresh startup and identity-only windows reject decodable but noncanonical authority bytes, independently of immutable startup-pin equality.
func TestMechanicalCanonicalCurrent(test *testing.T) {
	for _, method := range []string{"Load", "WithIdentity"} {
		test.Run(method, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			contents, err := os.ReadFile(fixture.reader.paths.authority)
			if err != nil {
				test.Fatal(err)
			}
			contents = append(contents, '\n')
			var document assemblyv0.AuthorityDocument
			if err := wire.Decode(contents, &document); err != nil {
				test.Fatalf("mechanical noncanonical decode control refused: %v", err)
			}
			if _, err := wire.Parse(contents); err == nil {
				test.Fatal("mechanical noncanonical source precondition failed")
			}
			write(test, fixture.reader.paths.authority, contents, 0640)
			if method == "Load" {
				if _, _, err := fixture.reader.Load(context.Background()); !errors.Is(err, ErrIdentityChanged) {
					test.Fatalf("mechanical noncanonical startup admitted: %v", err)
				}
			} else {
				called := false
				if err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil }); !errors.Is(err, ErrIdentityChanged) || called {
					test.Fatalf("mechanical noncanonical identity admitted: %v callback=%v", err, called)
				}
			}
		})
	}
}

// Claim: even digest-consistent empty startup pins refuse before any source call, beside an owned valid pinned window.
func TestMechanicalEmptyPinTrace(test *testing.T) {
	fixture := newFixture(test)
	pins := validWindow(test, fixture)
	recorder := &recordingReader{}
	fixture.reader.files, fixture.reader.newGate = recorder, recorder.newGate
	called := false
	if err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil }); err != nil || !called || len(recorder.calls) == 0 {
		test.Fatalf("mechanical empty-pin valid control refused: %v", err)
	}
	recorder.calls = nil
	called = false
	pins.contents = nil
	pins.AuthorityDigest = digest(nil)
	if err := fixture.reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil }); !errors.Is(err, ErrIdentityChanged) || called || len(recorder.calls) != 0 {
		test.Fatalf("mechanical empty pin performed source calls or callback: %v calls=%d", err, len(recorder.calls))
	}
}

// Claim: independently valid passwd/group changes during an identity callback still refuse the final exact-byte comparison, beside unchanged valid windows.
func TestMechanicalDirectoryByteContinuity(test *testing.T) {
	for _, source := range []string{"passwd", "group"} {
		test.Run(source, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			called := false
			err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error {
				called = true
				if source == "passwd" {
					write(test, fixture.reader.paths.passwd, []byte(fixture.passwd+"unrelated:x:8001:8002::/unrelated:/sbin/nologin\n"), 0644)
				} else {
					write(test, fixture.reader.paths.group, []byte(fixture.group+"unrelated:x:8002:\n"), 0644)
				}
				if _, err := fixture.reader.current(context.Background(), false); err != nil {
					test.Fatalf("mechanical changed directory join control refused: %v", err)
				}
				return nil
			})
			if !errors.Is(err, ErrIdentityChanged) || !called {
				test.Fatalf("mechanical %s byte continuity admitted: %v callback=%v", source, err, called)
			}
		})
	}
}

// Claim: passwd/group join predicates reject malformed and conflicting inert rows beside accepted unrelated rows and both permitted membership forms.
func TestMechanicalDirectoryJoinPredicates(test *testing.T) {
	for _, name := range []string{"passwd-fields", "passwd-empty-name", "passwd-name-duplicate", "passwd-uid-duplicate", "passwd-uid-invalid", "passwd-gid-invalid", "passwd-foreign-broker-group", "broker-name", "broker-home", "broker-gid", "broker-missing", "principal-name", "principal-home", "principal-missing", "group-fields", "group-empty-name", "group-name-duplicate", "group-gid-duplicate", "group-gid-invalid", "group-broker-name", "group-broker-gid", "group-members"} {
		test.Run(name, func(test *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					test.Fatalf("mechanical directory predicate panicked: %v", recovered)
				}
			}()
			fixture := newFixture(test)
			fixture.group += "unrelated:x:9002:\n"
			if !directoryJoins(fixture.document, []byte(fixture.passwd), []byte(fixture.group)) {
				test.Fatal("mechanical directory unrelated-row valid control refused")
			}
			explicit := strings.Replace(fixture.group, ":\n", ":"+fixture.document.Broker.Name+"\n", 1)
			if !directoryJoins(fixture.document, []byte(fixture.passwd), []byte(explicit)) {
				test.Fatal("mechanical directory explicit-member valid control refused")
			}
			passwd, group := fixture.passwd, fixture.group
			change := func(source string, index, field int, value string) string {
				lines := strings.Split(source, "\n")
				fields := strings.Split(lines[index], ":")
				fields[field] = value
				lines[index] = strings.Join(fields, ":")
				return strings.Join(lines, "\n")
			}
			switch name {
			case "passwd-fields":
				passwd += "unrelated:x:8001:8002::/unrelated:/sbin/nologin:extra\n"
			case "passwd-empty-name":
				passwd += ":x:8001:8002::/unrelated:/sbin/nologin\n"
			case "passwd-name-duplicate":
				passwd += "unrelated:x:8001:8002::/unrelated:/sbin/nologin\nunrelated:x:8003:8002::/unrelated:/sbin/nologin\n"
			case "passwd-uid-duplicate":
				passwd += "first:x:8001:8002::/unrelated:/sbin/nologin\nsecond:x:8001:8002::/unrelated:/sbin/nologin\n"
			case "passwd-uid-invalid":
				passwd += "unrelated:x:invalid:8002::/unrelated:/sbin/nologin\n"
			case "passwd-gid-invalid":
				passwd += "unrelated:x:8001:invalid::/unrelated:/sbin/nologin\n"
			case "passwd-foreign-broker-group":
				passwd += "unrelated:x:8001:" + strconv.FormatUint(uint64(fixture.document.Broker.GID), 10) + "::/unrelated:/sbin/nologin\n"
			case "broker-name":
				passwd = change(passwd, 0, 0, "wrong")
			case "broker-home":
				passwd = change(passwd, 0, 5, "/wrong")
			case "broker-gid":
				passwd = change(passwd, 0, 3, "8002")
			case "broker-missing":
				passwd = strings.Join(strings.Split(passwd, "\n")[1:], "\n")
			case "principal-name":
				passwd = change(passwd, 1, 0, "wrong")
			case "principal-home":
				passwd = change(passwd, 1, 5, "/wrong")
			case "principal-missing":
				lines := strings.Split(passwd, "\n")
				passwd = strings.Join(append(lines[:1], lines[2:]...), "\n")
			case "group-fields":
				group += "other:x:8001::extra\n"
			case "group-empty-name":
				group += ":x:8001:\n"
			case "group-name-duplicate":
				group += "other:x:8001:\nother:x:8002:\n"
			case "group-gid-duplicate":
				group += "other:x:8001:\nsecond:x:8001:\n"
			case "group-gid-invalid":
				group += "other:x:invalid:\n"
			case "group-broker-name":
				group = change(group, 0, 0, "wrong")
			case "group-broker-gid":
				group = change(group, 0, 2, "8001")
			case "group-members":
				group = change(group, 0, 3, "wrong")
			}
			if directoryJoins(fixture.document, []byte(passwd), []byte(group)) {
				test.Fatalf("mechanical directory %s admitted", name)
			}
		})
	}
}

// Claim: each identity predicate's malformed argument refuses beside a direct valid control, including dispatchers that the ordinary fixture leaves empty.
func TestMechanicalIdentityPredicates(test *testing.T) {
	for _, name := range []string{"format", "installation", "revision-zero", "revision-upper", "event-schema", "broker-name", "broker-home", "operator-name", "observer-name", "entry-path", "entry-digest", "pam-service", "login-duplicate", "login-kind", "login-implementation", "login-executable", "login-config", "principal-duplicate", "principal-zero", "principal-name", "principal-delimiter", "principal-home", "dispatcher-duplicate", "dispatcher-zero", "dispatcher-generation-length", "dispatcher-generation-shape", "dispatcher-key"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			document := fixture.document
			document.Dispatchers = []assemblyv0.DispatcherPin{{UID: 6001, Generation: assemblyv0.Generation(strings.Repeat("a", 32)), Key: document.OperatorKey}}
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			if !validIdentity(document, uid, gid) {
				test.Fatal("mechanical identity valid control refused")
			}
			switch name {
			case "format":
				document.Format = "wrong"
			case "installation":
				document.InstallationID = ""
			case "revision-zero":
				document.Revision = 0
			case "revision-upper":
				document.Revision = assemblyv0.MaxSafeInteger + 1
			case "event-schema":
				document.EventSchema = "wrong"
			case "broker-name":
				document.Broker.Name = "wrong"
			case "broker-home":
				document.Broker.Home = "/wrong"
			case "operator-name":
				document.Operator.Name = "wrong"
			case "observer-name":
				document.Observer.Name = "wrong"
			case "entry-path":
				document.OperatorEntry.Path = "/wrong"
			case "entry-digest":
				document.OperatorEntry.Digest = "wrong"
			case "pam-service":
				document.TerminalAuth.PAMService = ""
			case "login-duplicate":
				document.TerminalAuth.LoginPaths = append(document.TerminalAuth.LoginPaths, document.TerminalAuth.LoginPaths[0])
			case "login-kind":
				document.TerminalAuth.LoginPaths[0].Kind = "wrong"
			case "login-implementation":
				document.TerminalAuth.LoginPaths[0].Implementation = ""
			case "login-executable":
				document.TerminalAuth.LoginPaths[0].ExecutableDigest = "wrong"
			case "login-config":
				document.TerminalAuth.LoginPaths[0].ConfigDigest = "wrong"
			case "principal-duplicate":
				document.TerminalCallers[0].UID = document.Operator.UID
			case "principal-zero":
				document.TerminalCallers[0].UID = 0
			case "principal-name":
				document.TerminalCallers[0].Name = ""
			case "principal-delimiter":
				document.TerminalCallers[0].Name = "invalid:name"
			case "principal-home":
				document.TerminalCallers[0].Home = "relative"
			case "dispatcher-duplicate":
				document.Dispatchers[0].UID = document.Operator.UID
			case "dispatcher-zero":
				document.Dispatchers[0].UID = 0
			case "dispatcher-generation-length":
				document.Dispatchers[0].Generation = assemblyv0.Generation(strings.Repeat("a", 31))
			case "dispatcher-generation-shape":
				document.Dispatchers[0].Generation = assemblyv0.Generation(strings.Repeat("z", 32))
			case "dispatcher-key":
				document.Dispatchers[0].Key = "wrong"
			}
			if validIdentity(document, uid, gid) {
				test.Fatalf("mechanical identity %s admitted", name)
			}
		})
	}
}

// Claim: pure configuration equality refuses malformed roots, account rows and selected account sets without relying on document decoding.
func TestMechanicalConfigurationPredicates(test *testing.T) {
	for _, name := range []string{"invalid-operator-key", "invalid-root-key", "account-empty", "account-duplicate", "account-owner", "account-harness", "account-kind", "account-mode", "selection-absent", "selection-disabled", "observer-count"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			if !fixture.reader.equalConfig(fixture.document) {
				test.Fatal("mechanical configuration valid control refused")
			}
			switch name {
			case "invalid-operator-key":
				fixture.document.OperatorKey = "invalid"
				fixture.document.RootKeys = []assemblyv0.PublicKey{"invalid"}
			case "invalid-root-key":
				fixture.document.RootKeys = append(fixture.document.RootKeys, "invalid")
			case "account-empty":
				fixture.document.Accounts[0].Account = ""
				fixture.reader.config.Policy.Accounts[0].Label = ""
			case "account-duplicate":
				fixture.document.Accounts = append(fixture.document.Accounts, fixture.document.Accounts[0])
				fixture.reader.config.Policy.Accounts = append(fixture.reader.config.Policy.Accounts, policy.Account{Label: "other", Enabled: true})
			case "account-owner":
				fixture.document.Accounts[0].OwnerUID++
			case "account-harness":
				fixture.document.Accounts[0].Harness = "wrong"
			case "account-kind":
				fixture.document.Accounts[0].Kind = "wrong"
			case "account-mode":
				fixture.document.Accounts[0].Mode = "wrong"
			case "selection-absent":
				fixture.reader.config.Policy.Accounts[0].Label = "absent"
			case "selection-disabled":
				fixture.reader.config.Policy.Accounts[0].Enabled = false
			case "observer-count":
				fixture.reader.config.Policy.ObserverUIDs = append(fixture.reader.config.Policy.ObserverUIDs, 6001)
			}
			if fixture.reader.equalConfig(fixture.document) {
				test.Fatalf("mechanical configuration %s admitted", name)
			}
		})
	}
}

// Claim: direct pure predicate controls reject malformed paths, non-32-byte keys and noncanonical directory numbers independently of higher-level decoding.
func TestMechanicalAuthorityPredicates(test *testing.T) {
	if !absolute("/inert/path") {
		test.Fatal("mechanical absolute path valid control refused")
	}
	for _, path := range []string{"", "relative", "/inert/../path", "/inert\x00path", "/inert\rpath", "/inert\npath"} {
		if absolute(path) {
			test.Fatal("mechanical invalid absolute path admitted")
		}
	}
	valid := "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if !publicKey(assemblyv0.PublicKey(valid)) {
		test.Fatal("mechanical public key valid control refused")
	}
	for _, key := range []string{"", strings.TrimPrefix(valid, "ed25519:"), valid[:20] + "\n" + valid[20:], valid[:20] + "\r" + valid[20:], "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 31)), "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 33))} {
		if publicKey(assemblyv0.PublicKey(key)) {
			test.Fatal("mechanical invalid public key admitted")
		}
	}
	if value, valid := number("12"); !valid || value != 12 {
		test.Fatal("mechanical directory number valid control refused")
	}
	for _, value := range []string{"", "00", "012", "+12", "-1", "4294967296"} {
		if _, valid := number(value); valid {
			test.Fatal("mechanical invalid directory number admitted")
		}
	}
	if !validDigest(assemblyv0.Digest("sha256:" + strings.Repeat("a", 64))) {
		test.Fatal("mechanical digest valid control refused")
	}
	for _, value := range []string{strings.Repeat("a", 64), "sha256:", "sha256:" + strings.Repeat("z", 64)} {
		if validDigest(assemblyv0.Digest(value)) {
			test.Fatal("mechanical malformed digest admitted")
		}
	}
}
