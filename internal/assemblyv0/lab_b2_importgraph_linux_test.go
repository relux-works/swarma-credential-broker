//go:build linux && broker_lab

package assemblyv0

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Claim: the compiler-selected graph admits a lab command but detects default and tag-selected forwarding into the lab time boundary.
func TestInactiveImportGraphBuildTagControlsLabTime(test *testing.T) {
	previous := inactiveImportConsumers
	test.Cleanup(func() { inactiveImportConsumers = previous })
	inactiveImportConsumers = append(inactiveImportConsumers[:len(inactiveImportConsumers):len(inactiveImportConsumers)],
		struct {
			prefix  string
			imports []string
		}{prefix: "internal/labtimev0/"},
		struct {
			prefix  string
			imports []string
		}{prefix: "cmd/swarma-credential-broker-lab/", imports: []string{inactiveImportModule + "/internal/labtimev0"}},
	)
	root, writeSource := inactiveImportFixture(test)
	for _, directory := range []string{"internal/labtimev0", "cmd/swarma-credential-broker-lab"} {
		if err := os.Remove(filepath.Join(root, directory, "probe.go")); err != nil {
			test.Fatal(err)
		}
	}
	writeSource("internal/labtimev0/lab.go", []byte("//go:build broker_lab\n\npackage probe\n"))
	writeSource("cmd/swarma-credential-broker-lab/lab.go", []byte("//go:build broker_lab\n\npackage main; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/labtimev0")+"; func main() {}\n"))
	if err := checkInactiveImportGraph(root, "-tags=broker_lab"); err != nil {
		test.Fatal("valid lab command", err)
	}
	writeSource("internal/server/lab.go", importBoundarySource("labtimev0"))
	if err := checkInactiveImportGraph(root, "-tags=broker_lab"); !errors.Is(err, errFixture) {
		test.Fatal("default lab import plant not detected", err)
	}
	if err := os.Remove(filepath.Join(root, "internal/server/lab.go")); err != nil {
		test.Fatal(err)
	}
	writeSource("internal/x/.temp/fwd/probe.go", append([]byte("//go:build broker_lab\n\n"), importBoundarySource("labtimev0")...))
	writeSource("internal/server/lab.go", []byte("//go:build broker_lab\n\npackage probe; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/x/.temp/fwd")))
	if err := checkInactiveImportGraph(root, "-tags="); err != nil {
		test.Fatal("inactive tagged forwarder control", err)
	}
	if err := checkInactiveImportGraph(root, "-tags=broker_lab"); !errors.Is(err, errFixture) {
		test.Fatal("tagged lab forwarder not detected", err)
	}
}
