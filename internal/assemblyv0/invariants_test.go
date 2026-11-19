package assemblyv0

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
		{"session-installed-socket", "session-unbind.json", nil, "socket_path", "/run/swarma/credential-broker/broker.sock"},
		{"session-arbitrary-socket", "session-unbind.json", nil, "socket_path", "/tmp/anything.sock"},
		{"widening-session-needs-policy", "session-widening.json", nil, "account_policy", nil},
		{"widening-session-needs-continuity", "session-widening.json", nil, "continuity", nil},
		{"widening-session-cannot-use-boottime", "session-widening.json", nil, "freshness", fixtureTree(constructionVectors()["act-unbind.body.json"].bytes)["freshness"]},
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

var inactiveImportConsumers = []struct {
	prefix  string
	imports []string
}{
	{prefix: "internal/assemblyv0/"},
	{prefix: "internal/statev0/", imports: []string{"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"}},
	{prefix: "internal/activationv0/", imports: []string{"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"}},
}

func checkInactiveImports(filename string, contents []byte) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, contents, parser.ImportsOnly)
	if err != nil {
		return errFixture
	}
	imports := make([]string, 0, len(parsed.Imports))
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return errFixture
		}
		imports = append(imports, importPath)
	}
	return checkInactivePackageImports(filepath.ToSlash(filepath.Dir(filename))+"/", imports)
}

func checkInactivePackageImports(directory string, imports []string) error {
	for _, consumer := range inactiveImportConsumers {
		if directory != consumer.prefix && strings.HasPrefix(directory, consumer.prefix) {
			return errFixture
		}
	}
	for _, importPath := range imports {
		for _, target := range inactiveImportConsumers {
			if !strings.HasSuffix(importPath, "/"+strings.TrimSuffix(target.prefix, "/")) && !strings.Contains(importPath, "/"+target.prefix) {
				continue
			}
			allowed := false
			for _, consumer := range inactiveImportConsumers {
				if directory == consumer.prefix {
					for _, permitted := range consumer.imports {
						if importPath == permitted {
							allowed = true
						}
					}
				}
			}
			if !allowed {
				return errFixture
			}
		}
		if directory == "internal/assemblyv0/" && strings.HasPrefix(importPath, "github.com/") {
			return errFixture
		}
		if directory == "internal/statev0/" && strings.HasPrefix(importPath, "github.com/") && importPath != "github.com/relux-works/swarma-credential-broker/internal/assemblyv0" && importPath != "github.com/relux-works/swarma-credential-broker/internal/wire" {
			return errFixture
		}
	}
	return nil
}

// Claim: toolchain-selected production packages cannot reach inactive declarations; test-only imports grant no production admission.
func TestInactiveImportGraph(test *testing.T) {
	if err := checkInactiveImportGraph(filepath.Join("..", "..")); err != nil {
		test.Fatalf("inactive import boundary violated: %v", err)
	}
}

// Claim: production forwarding paths and undeclared inactive subpackages refuse beside valid exact-consumer and wire controls; test-only edges stay outside the guard.
func TestInactiveImportGraphForwardingControls(test *testing.T) {
	cases := []struct {
		name     string
		filename string
		target   string
	}{
		{"activation-subpackage", "internal/activationv0/nested/probe.go", "assemblyv0"},
		{"assembly-subpackage", "internal/assemblyv0/nested/probe.go", "activationv0"},
		{"state-subpackage", "internal/statev0/nested/probe.go", "assemblyv0"},
		{"activation-sibling-prefix", "internal/activationv0-other/probe.go", "assemblyv0"},
		{"assembly-sibling-prefix", "internal/assemblyv0-other/probe.go", "assemblyv0"},
		{"state-sibling-prefix", "internal/statev0-other/probe.go", "activationv0"},
		{"runtime-forwarder", "internal/forwarder/probe.go", "activationv0"},
		{"fixture-directory-forwarder", "internal/forwarder/testdata/nested/probe.go", "activationv0"},
		{"public-forwarder", "brokerclient/forwarder/probe.go", "assemblyv0"},
		{"undeclared-activation-package", "internal/activationv0/nested/probe.go", "time"},
		{"undeclared-assembly-package", "internal/assemblyv0/nested/probe.go", "time"},
		{"undeclared-state-package", "internal/statev0/nested/probe.go", "time"},
	}
	for _, item := range cases {
		test.Run(item.name, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			if err := checkInactiveImportGraph(root); err != nil {
				test.Fatal("valid exact-consumer and wire controls refused")
			}
			writeSource("internal/server/probe_test.go", importBoundarySource("activationv0"))
			if err := checkInactiveImportGraph(root); err != nil {
				test.Fatal("test-only inactive import control refused")
			}
			writeSource(item.filename, importBoundarySource(item.target))
			forwarder := strings.TrimSuffix(item.filename, "/probe.go")
			importPath := "github.com/relux-works/swarma-credential-broker/" + forwarder
			writeSource("internal/bridge/probe.go", []byte("package probe; import _ "+strconv.Quote(importPath)))
			writeSource("internal/server/probe.go", importBoundarySource("bridge"))
			if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
				test.Fatalf("production forwarding plant accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: explicit consumer and reverse-edge controls distinguish permitted imports from neighboring forbidden imports.
func TestImportBoundaryControls(test *testing.T) {
	cases := []struct {
		name     string
		filename string
		valid    string
		plant    string
	}{
		{"command", "cmd/daemon.go", "wire", "assemblyv0"},
		{"state-consumer", "internal/statev0/probe.go", "assemblyv0", "activationv0"},
		{"activation-consumer", "internal/activationv0/probe.go", "assemblyv0", "statev0"},
		{"consumer-prefix", "internal/activationv0-other/probe.go", "wire", "assemblyv0"},
		{"consumer-prefix-activation", "internal/activationv0-other/probe.go", "wire", "activationv0"},
		{"runtime-activation-subpackage", "internal/server/probe.go", "wire", "activationv0/nested"},
		{"runtime-assembly-subpackage", "internal/server/probe.go", "wire", "assemblyv0/nested"},
		{"runtime-state-subpackage", "internal/server/probe.go", "wire", "statev0/nested"},
		{"activation-assembly-subpackage", "internal/activationv0/probe.go", "assemblyv0", "assemblyv0/nested"},
		{"reverse-dependency", "internal/assemblyv0/probe.go", "time", "activationv0"},
		{"shared-runtime-dependency", "internal/assemblyv0/probe.go", "time", "policy"},
		{"state-runtime-dependency", "internal/statev0/probe.go", "wire", "policy"},
	}
	for _, item := range cases {
		test.Run(item.name, func(test *testing.T) {
			if checkInactiveImports(item.filename, importBoundarySource(item.valid)) != nil {
				test.Fatal("valid import control refused")
			}
			if !errors.Is(checkInactiveImports(item.filename, importBoundarySource(item.plant)), errFixture) {
				test.Fatal("forbidden import plant accepted")
			}
		})
	}
	for _, consumer := range inactiveImportConsumers {
		test.Run("undeclared-"+strings.Trim(consumer.prefix, "/"), func(test *testing.T) {
			if checkInactiveImports(consumer.prefix+"probe.go", importBoundarySource("time")) != nil {
				test.Fatal("valid exact package control refused")
			}
			if !errors.Is(checkInactiveImports(consumer.prefix+"nested/probe.go", importBoundarySource("time")), errFixture) {
				test.Fatal("undeclared nested package accepted")
			}
		})
	}
}

func importBoundarySource(packageName string) []byte {
	importPath := packageName
	if packageName != "time" {
		importPath = "github.com/relux-works/swarma-credential-broker/internal/" + packageName
	}
	return []byte("package probe; import _ " + strconv.Quote(importPath))
}

// Claim: current cmd/ and internal/ runtime Go packages reject each inactive package beside a valid wire control; synthetic source imports do not activate anything.
func TestRuntimeImportBoundaryControls(test *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		test.Fatal(err)
	}
	directories := map[string]bool{"cmd": true}
	packages, err := listInactiveImportPackages(root)
	if err != nil {
		test.Fatalf("cannot inspect runtime package controls: %v", err)
	}
	for _, listed := range packages {
		if listed.Standard || listed.ForTest != "" {
			continue
		}
		directory, err := filepath.Rel(root, listed.Dir)
		if err != nil {
			test.Fatal(err)
		}
		directory = filepath.ToSlash(directory)
		admitted := false
		for _, consumer := range inactiveImportConsumers {
			if directory+"/" == consumer.prefix {
				admitted = true
			}
		}
		if !admitted && (directory == "cmd" || strings.HasPrefix(directory, "cmd/") || strings.HasPrefix(directory, "internal/")) {
			directories[directory] = true
		}
	}
	for _, required := range []string{"internal/service", "internal/server", "internal/runner"} {
		if !directories[required] {
			test.Fatal("required runtime package control missing")
		}
	}
	names := make([]string, 0, len(directories))
	for directory := range directories {
		names = append(names, directory)
	}
	sort.Strings(names)
	for _, directory := range names {
		for _, consumer := range inactiveImportConsumers {
			packageName := strings.TrimSuffix(strings.TrimPrefix(consumer.prefix, "internal/"), "/")
			test.Run(directory+"/"+packageName, func(test *testing.T) {
				filename := directory + "/probe.go"
				if checkInactiveImports(filename, importBoundarySource("wire")) != nil {
					test.Fatal("valid runtime import control refused")
				}
				if !errors.Is(checkInactiveImports(filename, importBoundarySource(packageName)), errFixture) {
					test.Fatal("inactive import plant accepted in runtime package")
				}
			})
		}
	}
}

// Claim: the named unresolved schemas are absent; this name blocklist cannot detect renamed partial schemas or publish missing encodings.
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
