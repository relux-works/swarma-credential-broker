package assemblyv0

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"
)

// Claim: selected tags and enabled instrumentation are forwarded; disabled and unrelated settings add no flags.
func TestInactiveImportGraphBuildFlagControls(test *testing.T) {
	for _, item := range []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{"none", nil, ""},
		{"tags-race", []debug.BuildSetting{{Key: "-tags", Value: "a,b"}, {Key: "-race", Value: "true"}}, "-tags=a,b -race"},
		{"sanitizers", []debug.BuildSetting{{Key: "-msan", Value: "true"}, {Key: "-asan", Value: "true"}}, "-msan -asan"},
		{"disabled", []debug.BuildSetting{{Key: "-race", Value: "false"}, {Key: "-msan", Value: "false"}, {Key: "-asan", Value: "false"}, {Key: "GOARCH", Value: "arm64"}}, ""},
	} {
		test.Run(item.name, func(test *testing.T) {
			if got := strings.Join(inactiveImportBuildFlags(item.settings), " "); got != item.want {
				test.Fatalf("build flags = %q, want %q", got, item.want)
			}
		})
	}
}

// Claim: one exact consumer-table row supplies its fixture and grant; runtime consumers of that new package still refuse.
func TestInactiveImportGraphConsumerExtensionControls(test *testing.T) {
	original := inactiveImportConsumers
	test.Cleanup(func() { inactiveImportConsumers = original })
	inactiveImportConsumers = append(inactiveImportConsumers[:len(inactiveImportConsumers):len(inactiveImportConsumers)], struct {
		prefix  string
		imports []string
	}{prefix: "internal/extensionv0/", imports: []string{inactiveImportModule + "/internal/assemblyv0", inactiveImportModule + "/internal/statev0"}})
	root, writeSource := inactiveImportFixture(test)
	if err := checkInactiveImportConfigurations(root); err != nil {
		test.Fatalf("valid one-row consumer extension refused: %v", err)
	}
	writeSource("internal/server/probe.go", importBoundarySource("extensionv0"))
	if err := checkInactiveImportConfigurations(root); !errors.Is(err, errFixture) {
		test.Fatalf("runtime import of added consumer accepted or wrong refusal: %v", err)
	}
}

// Claim: direct !cgo/arm64 imports and configuration-only hidden forwarders refuse beside clean release-matrix controls.
func TestInactiveImportGraphReleaseConfigurationControls(test *testing.T) {
	test.Setenv("GOOS", "linux")
	test.Setenv("GOARCH", "amd64")
	test.Setenv("CGO_ENABLED", "1")
	for _, item := range []struct {
		name       string
		filename   string
		constraint string
		hidden     bool
	}{
		{"nocgo-direct", "inactive.go", "!cgo", false},
		{"arm64-direct", "inactive_arm64.go", "", false},
		{"amd64-pure-forwarder", "inactive.go", "linux && amd64 && !cgo", true},
		{"arm64-pure-forwarder", "inactive.go", "linux && arm64 && !cgo", true},
		{"arm64-cgo-forwarder", "inactive.go", "linux && arm64 && cgo", true},
	} {
		test.Run(item.name, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			if err := checkInactiveImportConfigurations(root); err != nil {
				test.Fatalf("valid release-matrix control refused: %v", err)
			}
			contents := importBoundarySource("activationv0")
			if item.hidden {
				writeSource("internal/x/.temp/fwd/probe.go", contents)
				contents = []byte("package probe; import _ " + fmt.Sprintf("%q", inactiveImportModule+"/internal/x/.temp/fwd"))
			}
			if item.constraint != "" {
				contents = append([]byte("//go:build "+item.constraint+"\n\n"), contents...)
			}
			writeSource("internal/server/"+item.filename, contents)
			if err := checkInactiveImportConfigurations(root); !errors.Is(err, errFixture) {
				test.Fatalf("release forwarding plant accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: ignored non-test direct edges refuse in one fixed configuration; ignored test imports and permitted production edges remain valid.
func TestInactiveImportGraphIgnoredFileControls(test *testing.T) {
	environment := []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1"}
	for _, item := range []struct {
		name       string
		filename   string
		constraint string
	}{
		{"nocgo", "inactive.go", "!cgo"},
		{"arm64", "inactive_arm64.go", ""},
		{"custom-tag", "inactive.go", "swarma_inactive_probe"},
	} {
		test.Run(item.name, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			prefix := ""
			if item.constraint != "" {
				prefix = "//go:build " + item.constraint + "\n\n"
			}
			writeSource("internal/server/ignored_test.go", append([]byte("//go:build ignore\n\n"), importBoundarySource("activationv0")...))
			writeSource("internal/server/"+item.filename, append([]byte(prefix), importBoundarySource("wire")...))
			if err := checkInactiveImportGraphEnvironment(root, environment); err != nil {
				test.Fatalf("valid ignored-file controls refused: %v", err)
			}
			writeSource("internal/server/"+item.filename, append([]byte(prefix), importBoundarySource("activationv0")...))
			if err := checkInactiveImportGraphEnvironment(root, environment); !errors.Is(err, errFixture) {
				test.Fatalf("ignored direct-edge plant accepted or wrong refusal: %v", err)
			}
		})
	}
}
