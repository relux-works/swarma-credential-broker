//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the actual production graph/source instrument rejects constructor
// aliases imported by the daemon, including when qualification shares them.
// The identical wrapper is accepted when only the qualification path imports
// it. These small modules are compiled controls for the structural instrument;
// they have no real manager, store, authority material or endpoint.
func TestQualificationContainmentImportedWrapper(t *testing.T) {
	for _, directory := range []string{"testdata", "_fixtures", "vendorlike"} {
		for _, daemon := range []bool{false, true} {
			name := "qualification-only"
			if daemon {
				name = "daemon-shared"
			}
			t.Run(directory+"/"+name, func(t *testing.T) {
				root, wrapper := containmentWrapperFixture(t, directory, daemon)
				graph, err := containmentProductionGraph(t, root)
				if err != nil {
					t.Fatal(err)
				}
				if _, compiled := graph[containmentModule+"/"+wrapper]; !compiled {
					t.Fatal("imported wrapper absent from production graph")
				}
				build := containmentGo(t, root, "build", "-p=1", "-tags=", "-o", filepath.Join(t.TempDir(), "fixture"), "./cmd/swarma-credential-broker")
				if out, err := build.CombinedOutput(); err != nil {
					t.Fatalf("source graph control does not compile: %v %s", err, out)
				}
				issues, err := containmentCheck(root, graph)
				if err != nil {
					t.Fatal("source graph control unavailable", err)
				}
				if !daemon {
					if len(issues) != 0 {
						t.Fatal("qualification-only wrapper rejected", issues)
					}
					return
				}
				for _, constructor := range []string{"NewQualificationAdmission", "NewQualificationLeaseRow"} {
					found := false
					for _, issue := range issues {
						found = found || strings.Contains(issue, constructor+" referenced outside qualification in "+wrapper+"/bridge.go")
					}
					if !found {
						t.Errorf("qualification authority containment: compiled imported-wrapper alias not rejected: %s", constructor)
					}
				}
			})
		}
	}
}

// Claim: a dependency selected by the production graph cannot disappear or
// become unparseable without failing the source instrument. An unresolved
// dependency must fail graph collection instead of yielding partial coverage.
func TestQualificationContainmentSourceFailures(t *testing.T) {
	for _, defect := range []string{"missing-source", "invalid-source", "missing-dependency"} {
		t.Run(defect, func(t *testing.T) {
			root, wrapper := containmentWrapperFixture(t, "testdata", false)
			graph, err := containmentProductionGraph(t, root)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, wrapper, "bridge.go")
			if defect == "invalid-source" {
				if os.WriteFile(file, []byte("package broken\nfunc {"), 0600) != nil {
					t.Fatal("parse control unavailable")
				}
			} else if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			if defect == "missing-dependency" {
				if _, err := containmentProductionGraph(t, root); err == nil || !strings.Contains(err.Error(), "production build graph unavailable") {
					t.Fatal("incomplete production graph accepted", err)
				}
				return
			}
			if _, err := containmentCheck(root, graph); err == nil || !strings.Contains(err.Error(), "production source unreadable or invalid: "+containmentModule+"/"+wrapper) {
				t.Fatal("unavailable compiled source skipped", err)
			}
		})
	}
}

// Claim: qualification-only imports may store constructor aliases, but neither
// init nor a variable initializer may call those aliases at daemon startup.
func TestQualificationContainmentWrapperInitialization(t *testing.T) {
	for _, initializer := range []string{"func init() { Single(); Multi() }", "var Started = func() bool { Single(); Multi(); return true }()"} {
		root, wrapper := containmentWrapperFixture(t, "testdata", false)
		file := filepath.Join(root, wrapper, "bridge.go")
		original, err := os.ReadFile(file)
		if err != nil || os.WriteFile(file, append(original, []byte("\n"+initializer+"\n")...), 0600) != nil {
			t.Fatal("initializer source fixture unavailable")
		}
		graph, err := containmentProductionGraph(t, root)
		if err != nil {
			t.Fatal(err)
		}
		issues, err := containmentCheck(root, graph)
		if err != nil || !strings.Contains(strings.Join(issues, "\n"), "authority call during package initialization in "+wrapper+"/bridge.go") {
			t.Fatal("qualification import initialized authority", issues, err)
		}
	}
}

func containmentWrapperFixture(t *testing.T, directory string, daemon bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	wrapper := "internal/server/" + directory + "/containmentbridge"
	bridgeImport := `bridge "` + containmentModule + "/" + wrapper + `"`
	mainImport, mainReference := "", ""
	if daemon {
		mainImport = bridgeImport
		mainReference = "bridge.Single(); bridge.Multi()"
	}
	files := map[string]string{
		"go.mod": "module " + containmentModule + "\n\ngo 1.25\n",
		"cmd/swarma-credential-broker/main.go": `package main
import (
 "context"
 "os"
 "` + containmentDriver + `"
 "` + containmentModule + `/internal/runner"
 "` + containmentServer + `"
 ` + mainImport + `
)
func main() {
 if handled, code := qualify.CaseMain(os.Args[1:]); handled { os.Exit(code) }
 ctx := context.Background()
 if len(os.Args) > 1 && os.Args[1] == "qualify-codex" { os.Exit(qualify.Command(ctx, os.Args[2:], runner.DefaultPolicyPath, os.Environ(), os.Stdout)) }
 run()
}
func run() { _ = server.New; ` + mainReference + ` }
`,
		"internal/runner/runner.go": "package runner\nconst DefaultPolicyPath = \"\"\n",
		"internal/server/qualification_linux.go": `package server
func NewQualificationAdmission() {}
func NewQualificationLeaseRow() {}
func New() {}
`,
		wrapper + "/bridge.go": `package containmentbridge
import service "` + containmentServer + `"
// CONTROL: imported wrapper constructor aliases added
var Single = service.NewQualificationAdmission
var Multi = service.NewQualificationLeaseRow
`,
		"internal/qualify/command.go": `package qualify
import (
 "context"
 "io"
 ` + bridgeImport + `
)
func Command(context.Context, []string, string, []string, io.Writer) int {
 bridge.Single(); bridge.Multi()
 return 69
}
func CaseMain([]string) (bool, int) { return false, 0 }
`,
	}
	for path, source := range files {
		path = filepath.Join(root, path)
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, []byte(source), 0600) != nil {
			t.Fatal("structural source fixture unavailable")
		}
	}
	return root, wrapper
}
