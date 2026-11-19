package assemblyv0

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Claim: these concrete invalid neighbors violate the cited wire/value contracts, not a runtime/provenance gate.
func TestConstructionRefusals(test *testing.T) {
	cases := []struct {
		name     string
		vector   string
		location []any
		member   string
		value    any
	}{
		{"lifetime-zero", "activation-default.json", nil, "service_lease_max_lifetime_seconds", int64(0)},
		{"lifetime-over-ceiling", "activation-default.json", nil, "service_lease_max_lifetime_seconds", int64(901)},
		{"lifetime-negative", "activation-default.json", nil, "service_lease_max_lifetime_seconds", int64(-1)},
		{"lifetime-null", "activation-default.json", nil, "service_lease_max_lifetime_seconds", nil},
		{"lifetime-string", "activation-default.json", nil, "service_lease_max_lifetime_seconds", "900"},
		{"lifetime-conflict", "activation-default.json", nil, "max_lease_seconds", int64(900)},
		{"disabled-still-validated", "activation-default.json", nil, "format", "unknown/1"},
		{"no-c-selector", "activation-default.json", []any{"continuity"}, "kind", "test-c"},
		{"no-c-placeholder", "activation-default.json", []any{"continuity"}, "machine_id", "fixture-machine"},
		{"mixed-utc-boottime", "act-bind.body.json", []any{"freshness"}, "boot_id", fixtureBoot},
		{"mixed-boottime-utc", "act-unbind.body.json", []any{"freshness"}, "expires_at", "2030-01-01T00:05:00Z"},
		{"utc-empty", "act-bind.body.json", []any{"freshness"}, "expires_at", "2030-01-01T00:00:00Z"},
		{"utc-too-long", "act-bind.body.json", []any{"freshness"}, "expires_at", "2030-01-01T00:05:01Z"},
		{"boottime-empty", "act-unbind.body.json", []any{"freshness"}, "expires_at_ms", int64(1000)},
		{"boottime-too-long", "act-unbind.body.json", []any{"freshness"}, "expires_at_ms", int64(301001)},
		{"boottime-unsafe", "act-unbind.body.json", []any{"freshness"}, "expires_at_ms", int64(-1)},
		{"boot-id-invalid", "act-unbind.body.json", []any{"freshness"}, "boot_id", "not-a-boot-uuid"},
		{"unbind-cannot-demand-utc", "act-unbind.body.json", nil, "freshness", fixtureTree(constructionVectors()["act-bind.body.json"].bytes)["freshness"]},
		{"widening-cannot-use-boottime", "act-bind.body.json", nil, "freshness", fixtureTree(constructionVectors()["act-unbind.body.json"].bytes)["freshness"]},
		{"inner-body-mismatch", "act-bind.body.json", []any{"arguments"}, "operation_id", "ffeeddccbbaa99887766554433221100"},
		{"no-fifth-method", "act-bind.body.json", nil, "method", "grant.put"},
		{"enrol-no-issued-at", "act-enrol-null.body.json", []any{"arguments"}, "issued_at", "2030-01-01T00:00:00Z"},
		{"enrol-fraction", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "2030-02-01T00:00:00.1Z"},
		{"enrol-fraction-zero", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "2030-02-01T00:00:00.000Z"},
		{"enrol-offset", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "2030-02-01T00:00:00+00:00"},
		{"enrol-zero", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "0001-01-01T00:00:00Z"},
		{"enrol-invalid-date", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "2030-02-30T00:00:00Z"},
		{"enrol-out-of-range", "act-enrol-expiry.body.json", []any{"arguments"}, "token_expires_at", "10000-01-01T00:00:00Z"},
		{"enrol-result-unresolved", "act-enrol-null.body.json", []any{"arguments"}, "result", map[string]any{}},
		{"candidate-no-prefix", "candidate-enrol.json", []any{"arguments"}, "token_sha256_prefix", "00112233445566778899aabbccddeeff"},
		{"producer-proof-unresolved", "authority.json", nil, "admissions", []any{}},
		{"principal-roles-overlap", "authority.json", []any{"observer"}, "uid", int64(4002)},
		{"account-owner-not-caller", "authority.json", []any{"accounts", 0}, "owner_uid", int64(4004)},
		{"relative-pin-home", "authority.json", []any{"operator"}, "home", "relative/operator"},
		{"root-key-required", "authority.json", nil, "root_keys", []any{}},
		{"duplicate-root-key", "authority.json", nil, "root_keys", []any{string(fixtureAuthority().OperatorKey), string(fixtureAuthority().OperatorKey)}},
		{"terminal-role-overlap", "authority.json", []any{"terminal_callers", 0}, "uid", int64(4003)},
		{"no-console", "authority.json", []any{"terminal_auth", "login_paths", 0}, "kind", "vt"},
		{"uid-overflow", "authority.json", []any{"operator"}, "uid", int64(4294967296)},
		{"revision-zero", "authority.json", nil, "revision", int64(0)},
		{"nonce-case", "act-bind.body.json", nil, "nonce", "AABBCCDDEEFF00112233445566778899"},
		{"wrong-envelope-id", "act-bind.envelope.json", nil, "id", string(digestBytes([]byte("wrong fixture id")))},
		{"signature-padding", "act-bind.envelope.json", nil, "sig", strings.Repeat("A", 86) + "=="},
		{"receipt-nonce-mismatch", "act-bind.request.json", nil, "receipt_nonce", "ffeeddccbbaa99887766554433221100"},
		{"token-on-bind", "act-bind.request.json", nil, "token", fixtureToken},
		{"enrol-token-null", "act-enrol-null.request.json", nil, "token", nil},
		{"receipt-no-token", "act-bind.receipt.json", nil, "token", fixtureToken},
		{"receipt-no-arguments", "act-bind.receipt.json", nil, "arguments", map[string]any{}},
		{"receipt-confirmation-kind", "act-unbind.receipt.json", nil, "confirmation", "exact-content"},
		{"unbind-session-no-policy", "session-unbind.json", nil, "account_policy", map[string]any{"account": fixtureAccount, "test_subscription": false}},
		{"event-no-extra-class", "event-lease_expiring.json", nil, "class", "auth"},
		{"event-class-closed", "event-error-auth.json", nil, "class", "temporary"},
	}
	vectors := constructionVectors()
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			vector := vectors[entry.vector]
			control := reflect.New(reflect.TypeOf(vector.value)).Interface()
			if decodeFixture(vector.bytes, control) != nil {
				test.Fatal("valid adjacent control refused")
			}
			modified := fixtureTree(vector.bytes)
			objectAt(modified, entry.location)[entry.member] = entry.value
			before := canonicalBytes(modified)
			target := reflect.New(reflect.TypeOf(vector.value)).Interface()
			if !errors.Is(decodeFixture(before, target), errFixture) {
				test.Fatal("specified invalid neighbor accepted")
			}
			if !bytes.Equal(before, canonicalBytes(modified)) {
				test.Fatal("refusal altered input state")
			}
		})
	}
	for _, literal := range []string{"1.0", "9007199254740992", "-0"} {
		data := strings.Replace(string(vectors["activation-900.json"].bytes), `"service_lease_max_lifetime_seconds":900`, `"service_lease_max_lifetime_seconds":`+literal, 1)
		var target ActivationDocument
		if !errors.Is(decodeFixture([]byte(data), &target), errFixture) {
			test.Fatal("noncanonical lifetime accepted")
		}
	}
}

// Claim: every fixture act/activation commits the complete exact authority document, including non-account pin changes.
func TestDocumentDigestJoins(test *testing.T) {
	vectors := constructionVectors()
	digest := digestBytes(vectors["authority.json"].bytes)
	for _, vector := range vectors {
		switch typed := vector.value.(type) {
		case OperatorBody:
			if typed.AuthorityDigest != digest {
				test.Fatal("act authority digest mismatch")
			}
		case ActivationDocument:
			if typed.AuthorityDigest != digest {
				test.Fatal("activation authority digest mismatch")
			}
		}
	}
	changed := fixtureAuthority()
	changed.TerminalAuth.LauncherDigest = digestBytes([]byte("changed synthetic launcher"))
	if digestBytes(canonicalBytes(changed)) == digest {
		test.Fatal("full authority digest omitted an enforcement pin")
	}
	if !bytes.Equal(canonicalBytes(changed.Accounts), canonicalBytes(fixtureAuthority().Accounts)) {
		test.Fatal("control changed account policy")
	}
}

func checkInactiveImports(filename string, contents []byte) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, contents, parser.ImportsOnly)
	if err != nil {
		return errFixture
	}
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return errFixture
		}
		if strings.HasSuffix(importPath, "/internal/assemblyv0") || strings.HasSuffix(importPath, "/internal/statev0") {
			if !strings.HasPrefix(filepath.ToSlash(filename), "internal/statev0/") {
				return errFixture
			}
		}
		if strings.HasPrefix(filepath.ToSlash(filename), "internal/assemblyv0/") && strings.HasPrefix(importPath, "github.com/") {
			return errFixture
		}
		if strings.HasPrefix(filepath.ToSlash(filename), "internal/statev0/") && strings.HasPrefix(importPath, "github.com/") && importPath != "github.com/relux-works/swarma-credential-broker/internal/assemblyv0" && importPath != "github.com/relux-works/swarma-credential-broker/internal/wire" {
			return errFixture
		}
	}
	return nil
}

// Claim: no production package imports the inactive declarations, and shared values cannot depend back on runtime consumers.
func TestInactiveImportGraph(test *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".temp" || entry.Name() == "testdata" || entry.Name() == "vendor") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		return checkInactiveImports(relative, contents)
	})
	if err != nil {
		test.Fatal("inactive import boundary violated")
	}
}

// Claim: the import-boundary instrument detects actual forbidden imports beside a valid unchanged transport import.
func TestImportBoundaryControls(test *testing.T) {
	valid := []byte(`package daemon; import _ "github.com/relux-works/swarma-credential-broker/internal/wire"`)
	plant := []byte(`package daemon; import _ "github.com/relux-works/swarma-credential-broker/internal/assemblyv0"`)
	if checkInactiveImports("cmd/daemon.go", valid) != nil || !errors.Is(checkInactiveImports("cmd/daemon.go", plant), errFixture) {
		test.Fatal("import checker failed its bounded control")
	}
}

// Claim: unresolved complete schemas have no declaration masquerading as a closed type; this does not publish their missing encodings.
func TestUnresolvedDeclarationsAbsent(test *testing.T) {
	for _, directory := range []string{".", "../statev0"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			test.Fatal("cannot inspect declaration directory")
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, 0)
			if err != nil {
				test.Fatal("cannot inspect declarations")
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				declaration, ok := node.(*ast.TypeSpec)
				if ok {
					switch declaration.Name.Name {
					case "EnrolResult", "OperatorOutcome", "AuthorityState", "CallerState", "BindingRecord", "ReceiverEffect", "AuthorityJournal", "CallerJournal":
						test.Fatal("unresolved complete schema was declared")
					}
				}
				return true
			})
		}
	}
}
