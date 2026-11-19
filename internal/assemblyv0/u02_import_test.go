package assemblyv0

import (
	"errors"
	"testing"
)

// Claim: both U02 packages retain exact permitted consumers and test-only access, while a runtime importer is refused in the inherited configuration and every checked release configuration.
func TestU02ImportBoundaryControls(test *testing.T) {
	for _, target := range []string{"protectedio", "authorityv0"} {
		test.Run(target, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			writeSource("internal/server/probe_test.go", importBoundarySource(target))
			if err := checkInactiveImportConfigurations(root); err != nil {
				test.Fatalf("valid U02 exact-consumer control refused: %v", err)
			}
			writeSource("internal/server/probe.go", importBoundarySource(target))
			if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
				test.Fatalf("runtime U02 importer admitted in inherited configuration: %v", err)
			}
			for _, arch := range []string{"amd64", "arm64"} {
				for _, cgo := range []string{"0", "1"} {
					environment := []string{"GOOS=linux", "GOARCH=" + arch, "CGO_ENABLED=" + cgo, "GOAMD64=v1", "GOARM64=v8.0", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOFLAGS=-mod=readonly -p=2"}
					if err := checkInactiveImportGraphEnvironment(root, environment); !errors.Is(err, errFixture) {
						test.Fatalf("runtime U02 importer admitted for linux/%s cgo=%s: %v", arch, cgo, err)
					}
				}
			}
		})
	}
}
