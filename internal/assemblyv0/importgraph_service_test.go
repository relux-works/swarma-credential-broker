package assemblyv0

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Claim: only the exact inactive service consumer gains assembly/state edges; runtime, reverse, nested and sibling imports still refuse beside valid controls.
func TestImportBoundaryServiceControls(test *testing.T) {
	for _, item := range []struct {
		name     string
		filename string
		valid    string
		plant    string
	}{
		{"service-assembly", "internal/servicev0/probe.go", "assemblyv0", "activationv0"},
		{"service-state", "internal/servicev0/probe.go", "statev0", "servicev0/nested"},
		{"runtime", "internal/server/probe.go", "wire", "servicev0"},
		{"command", "cmd/daemon.go", "wire", "servicev0"},
		{"reverse-state", "internal/statev0/probe.go", "assemblyv0", "servicev0"},
		{"reverse-assembly", "internal/assemblyv0/probe.go", "time", "servicev0"},
		{"reverse-activation", "internal/activationv0/probe.go", "assemblyv0", "servicev0"},
		{"sibling", "internal/servicev0-other/probe.go", "wire", "statev0"},
		{"runtime-subpackage", "internal/server/probe.go", "wire", "servicev0/nested"},
	} {
		test.Run(item.name, func(test *testing.T) {
			if err := checkInactiveImports(item.filename, importBoundarySource(item.valid)); err != nil {
				test.Fatalf("valid inactive-service edge refused: %v", err)
			}
			if err := checkInactiveImports(item.filename, importBoundarySource(item.plant)); !errors.Is(err, errFixture) {
				test.Fatalf("inactive-service import plant accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: each inherited/release configuration refuses real runtime, reverse, transitive, subpackage and physical-alias service imports beside an allowed consumer graph.
func TestInactiveImportGraphServiceControls(test *testing.T) {
	configurations := []struct {
		name        string
		environment []string
	}{{name: "inherited"}}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, cgo := range []string{"0", "1"} {
			configurations = append(configurations, struct {
				name        string
				environment []string
			}{
				name: "linux-" + arch + "-cgo" + cgo,
				environment: []string{
					"GOOS=linux", "GOARCH=" + arch, "CGO_ENABLED=" + cgo,
					"GOAMD64=v1", "GOARM64=v8.0", "GOEXPERIMENT=",
					"GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off",
					"GOFLAGS=-mod=readonly -p=2",
				},
			})
		}
	}
	for _, configuration := range configurations {
		test.Run(configuration.name, func(test *testing.T) {
			for _, item := range []struct {
				name         string
				importer     string
				inertService bool
				alias        bool
			}{
				{name: "runtime", importer: "internal/server"},
				{name: "reverse-state", importer: "internal/statev0", inertService: true},
				{name: "reverse-assembly", importer: "internal/assemblyv0", inertService: true},
				{name: "reverse-activation", importer: "internal/activationv0"},
				{name: "transitive", importer: "internal/x/.temp/fwd"},
				{name: "subpackage", importer: "internal/servicev0/wiring"},
				{name: "testdata-subpackage", importer: "internal/servicev0/testdata/wiring"},
				{name: "sibling", importer: "internal/servicev0-other"},
				{name: "alias", importer: "internal/alias", inertService: true, alias: true},
			} {
				test.Run(item.name, func(test *testing.T) {
					root, writeSource := inactiveImportFixture(test)
					if item.inertService {
						writeSource("internal/servicev0/probe.go", importBoundarySource("wire"))
					}
					if item.alias {
						if err := os.Symlink("wire", filepath.Join(root, "internal", "safealias")); err != nil {
							test.Fatal(err)
						}
						writeSource("internal/server/probe.go", importBoundarySource("safealias"))
					}
					if err := checkInactiveImportGraphEnvironment(root, configuration.environment); err != nil {
						test.Fatalf("valid inactive-service consumer graph refused: %v", err)
					}
					if item.alias {
						if err := os.Symlink("servicev0", filepath.Join(root, filepath.FromSlash(item.importer))); err != nil {
							test.Fatal(err)
						}
					} else {
						writeSource(item.importer+"/probe.go", importBoundarySource("servicev0"))
					}
					if item.importer != "internal/server" {
						writeSource("internal/server/probe.go", []byte("package probe; import _ \""+inactiveImportModule+"/"+item.importer+"\""))
					}
					if err := checkInactiveImportGraphEnvironment(root, configuration.environment); !errors.Is(err, errFixture) {
						test.Fatalf("inactive-service runtime plant accepted or wrong refusal: %v", err)
					}
				})
			}
		})
	}
}
