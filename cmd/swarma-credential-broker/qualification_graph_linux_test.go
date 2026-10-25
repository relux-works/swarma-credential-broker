//go:build linux

package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the compiled writer entry refuses a stubbed entry error before
// composition; the instrument rejects disabled checks and ignored entry errors.
// These closed stubs test the instrument, not the runtime role exchange.
func TestReviewWriterEntryCondition(t *testing.T) {
	containmentEntryVariants(t, "writer", "owner_lifecycle_linux.go", "c, ch, native")
}

// Claim: the owner entry has the same complete conditional/refusal obligation
// as the writer, independently exercised with compiled neighboring controls.
func TestQualificationContainmentOwnerEntryCondition(t *testing.T) {
	containmentEntryVariants(t, "owner", "owner_worker_linux.go", "c, ch")
}

func containmentEntryVariants(t *testing.T, role, file, arguments string) {
	t.Helper()
	entry := "Enter" + strings.ToUpper(role[:1]) + role[1:] + "Role"
	for _, mode := range []string{"normal", "disabled", "ignored-error", "wrong-refusal"} {
		t.Run(mode, func(t *testing.T) {
			root, _ := containmentWrapperFixture(t, "testdata", false)
			origin := "package egress;import \"errors\";func NewOwnerOrigin(){};func " + entry + "(string)error{return errors.New(\"entry refused\")}"
			condition, refusal, want := "egress."+entry+"(args[1]) != nil", "return 125", 125
			switch mode {
			case "disabled":
				condition, want = "false && "+condition, 7
			case "ignored-error":
				refusal, want = "_ = 125", 7
			case "wrong-refusal":
				refusal, want = "return 0", 0
			}
			source := fmt.Sprintf(`package qualify
import "%s/internal/egress"
func %sMain(args []string)int {
 %s := %s
 if %s {%s}
 return %sCompose(%s)
}
func %sCompose(%s int)int{return 7}
`, containmentModule, role, arguments, strings.Repeat("0, ", strings.Count(arguments, ","))+"0", condition, refusal, role, arguments, role, arguments)
			probe := fmt.Sprintf(`package qualify;import "testing";func TestEntry(t *testing.T){if got:=%sMain([]string{"%s","digest"});got!=%d{t.Fatal(got)}}`, role, role, want)
			for path, text := range map[string]string{
				"internal/egress/origin_linux_amd64.go": origin,
				"internal/qualify/" + file:              source,
				"internal/qualify/entry_test.go":        probe,
			} {
				if e := os.WriteFile(filepath.Join(root, path), []byte(text), 0600); e != nil {
					t.Fatal(e)
				}
			}
			cmd := containmentGo(t, root, "test", "-p=1", "./internal/qualify", "-run", "^TestEntry$", "-count=1")
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("compiled entry control unavailable: %v %s", e, out)
			}
			t.Logf("compiled %s entry result confirmed: %d", role, want)
			graph, e := containmentProductionGraph(t, root)
			if e != nil {
				t.Fatal(e)
			}
			issues, e := containmentCheck(root, graph)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "normal" {
				if len(issues) != 0 {
					t.Fatal("valid entry control refused", issues)
				}
			} else if len(issues) != 1 || issues[0] != role+" construction barrier changed" {
				t.Fatal("unsafe "+role+" entry accepted or wrong refusal", issues)
			}
		})
	}
}

// Claim: the actual production graph/source instrument rejects constructor
// aliases imported by the daemon, including the owner-origin factory and
// dependencies shared with qualification.
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
				if !strings.Contains(strings.Join(issues, "\n"), "owner authority outside qualification in "+wrapper+"/bridge.go") {
					t.Error("compiled owner-origin wrapper alias not rejected")
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
	for _, initializer := range []string{"func init() { Single(); Multi(); Origin() }", "var Started = func() bool { Single(); Multi(); Origin(); return true }()"} {
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
		mainReference = "bridge.Single(); bridge.Multi(); bridge.Origin()"
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
		"internal/egress/origin_linux_amd64.go": "package egress\nfunc NewOwnerOrigin() {}\n",
		"internal/runner/runner.go":             "package runner\nconst DefaultPolicyPath = \"\"\n",
		"internal/server/qualification_linux.go": `package server
func NewQualificationAdmission() {}
func NewQualificationLeaseRow() {}
func New() {}
`,
		wrapper + "/bridge.go": `package containmentbridge
import (service "` + containmentServer + `"; origin "` + containmentModule + `/internal/egress")
// CONTROL: imported wrapper constructor aliases added
var Single = service.NewQualificationAdmission
var Multi = service.NewQualificationLeaseRow
var Origin = origin.NewOwnerOrigin
`,
		"internal/qualify/command.go": `package qualify
import (
 "context"
 "io"
 ` + bridgeImport + `
)
func Command(context.Context, []string, string, []string, io.Writer) int {
 bridge.Single(); bridge.Multi(); bridge.Origin()
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

// Claim: the graph scan rejects a compiled fixture implementation or activation
// in any imported directory; declarations alone remain harmless. These bounded
// plants test the same AST instrument used against the real compiled sources.
func TestQualificationTimeFixtureContainment(t *testing.T) {
	for _, plant := range []string{
		"type fixtureWitness struct{}",
		"func leak(){_ = &pathQualification{}}",
		"func leak(){_ = new(pathQualification)}",
		"type Alias=pathQualification;func leak(){_ = Alias{}}",
		"func leak(){c.timePath=q}",
		"func leak(){_ = Consumer{timePath:q}}",
	} {
		f, e := parser.ParseFile(token.NewFileSet(), "plant.go", "package sample;"+plant, 0)
		if e != nil {
			t.Fatal(e)
		}
		sources := []containmentSource{{path: "testdata/bridge.go", pkg: containmentModule + "/testdata", file: f}}
		if len(containmentTimeFixtures(sources)) == 0 {
			t.Fatal("time fixture plant not rejected", plant)
		}
	}
	f, e := parser.ParseFile(token.NewFileSet(), "control.go", "package sample;type pathQualification struct{};func ordinary(){_ = ClosedWitness{}}", 0)
	if e != nil {
		t.Fatal(e)
	}
	if issues := containmentTimeFixtures([]containmentSource{{path: "timeconf/ordinary.go", file: f}}); len(issues) != 0 {
		t.Fatal("declaration/closed backend control rejected", issues)
	}
}

// Claim: a fixture authority planted in an actual compiled dependency is found
// by the production graph instrument. Removing just that declaration produces
// the nearby valid control; unrelated setup/build errors do not satisfy it.
func TestQualificationTimeFixtureCompiledPlant(t *testing.T) {
	root, wrapper := containmentWrapperFixture(t, "testdata", false)
	path := filepath.Join(root, "timeconf")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(path, "fixture.go")
	leak := []byte("package timeconf;type fixtureWitness struct{}")
	if e := os.WriteFile(file, leak, 0600); e != nil {
		t.Fatal(e)
	}
	bridge := filepath.Join(root, wrapper, "time.go")
	if e := os.WriteFile(bridge, []byte(`package containmentbridge;import _ "`+containmentModule+`/timeconf"`), 0600); e != nil {
		t.Fatal(e)
	}
	graph, e := containmentProductionGraph(t, root)
	if e != nil {
		t.Fatal(e)
	}
	build := containmentGo(t, root, "build", "-p=1", "-o", filepath.Join(t.TempDir(), "fixture"), "./cmd/swarma-credential-broker")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("plant build failed: %v %s", e, out)
	}
	issues, e := containmentCheck(root, graph)
	if e != nil || !strings.Contains(strings.Join(issues, "\n"), "test-only time fixture in timeconf/fixture.go") {
		t.Fatal("compiled time fixture plant missed", issues, e)
	}
	if e := os.WriteFile(file, []byte("package timeconf;type ClosedWitness struct{}"), 0600); e != nil {
		t.Fatal(e)
	}
	issues, e = containmentCheck(root, graph)
	if e != nil || len(issues) != 0 {
		t.Fatal("closed witness control rejected", issues, e)
	}
}

// Claim: each new origin/role family independently propagates through a compiled
// alias; daemon sharing and eager initialization are refused, qualification-only
// alias storage is valid. Older constructor families cannot mask this control.
func TestQualificationContainmentTerminationFactories(t *testing.T) {
	for _, factory := range []string{"NewCrashOwnerOrigin", "NewWriterOrigin", "EnterWriterRole"} {
		for _, mode := range []string{"qualified", "daemon", "init"} {
			t.Run(factory+"/"+mode, func(t *testing.T) {
				root, wrapper := containmentWrapperFixture(t, "testdata", mode == "daemon")
				path := filepath.Join(root, "internal/egress/origin_linux_amd64.go")
				if os.WriteFile(path, []byte("package egress;func "+factory+"(){}"), 0600) != nil {
					t.Fatal("origin control")
				}
				text := `package containmentbridge;import origin "` + containmentModule + `/internal/egress";func Single(){};func Multi(){};var Origin=origin.` + factory
				if mode == "init" {
					text += ";func init(){Origin()}"
				}
				if os.WriteFile(filepath.Join(root, wrapper, "bridge.go"), []byte(text), 0600) != nil {
					t.Fatal("alias control")
				}
				graph, e := containmentProductionGraph(t, root)
				if e != nil {
					t.Fatal(e)
				}
				issues, e := containmentCheck(root, graph)
				if e != nil {
					t.Fatal(e)
				}
				expected := "owner authority outside qualification"
				if mode == "init" {
					expected = "owner authority during package initialization"
				}
				if mode == "qualified" {
					if len(issues) != 0 {
						t.Fatal("qualified alias refused", issues)
					}
				} else if !strings.Contains(strings.Join(issues, "\n"), expected) {
					t.Fatal("new origin authority escaped", factory, mode, issues)
				}
			})
		}
	}
}

// Claim: each dispatcher family propagates through aliases and wrappers in a
// compiled fixture. Qualification-only storage is valid; ordinary reachability
// and eager initialization are rejected. Cross-package aliases have separate
// imported-wrapper coverage above.
func TestQualificationContainmentParallelFactories(t *testing.T) {
	for _, family := range []string{"parallelCompose", "parallelMux", "parallelService", "parallelHarness", "parallelRun"} {
		for _, mode := range []string{"qualified", "daemon", "init"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				root, _ := containmentWrapperFixture(t, "testdata", false)
				decl := "func " + family + "(){};func Witness(){" + family + "()}"
				if family != "parallelCompose" && family != "parallelRun" {
					decl = "type " + family + " struct{};func Witness(){_ = &" + family + "{}}"
				}
				text := "package qualify;" + decl + ";var Alias=Witness;func Wrapper(){Alias()}"
				if mode == "init" {
					text += ";func init(){Alias()}"
				}
				if e := os.WriteFile(filepath.Join(root, "internal/qualify/parallel.go"), []byte(text), 0600); e != nil {
					t.Fatal(e)
				}
				if mode == "daemon" {
					path := filepath.Join(root, "cmd/swarma-credential-broker/main.go")
					b, e := os.ReadFile(path)
					if e != nil || os.WriteFile(path, []byte(strings.Replace(string(b), "_ = server.New;", "_ = server.New; qualify.Wrapper();", 1)), 0600) != nil {
						t.Fatal("ordinary wrapper plant unavailable")
					}
				}
				graph, e := containmentProductionGraph(t, root)
				if e != nil {
					t.Fatal(e)
				}
				build := containmentGo(t, root, "build", "-p=1", "-o", filepath.Join(t.TempDir(), "fixture"), "./cmd/swarma-credential-broker")
				if out, e := build.CombinedOutput(); e != nil {
					t.Fatalf("parallel plant does not compile: %v %s", e, out)
				}
				issues, e := containmentCheck(root, graph)
				expected := "owner authority outside qualification"
				if mode == "init" {
					expected = "owner authority during package initialization"
				}
				if e != nil || mode == "qualified" && len(issues) != 0 || mode != "qualified" && !strings.Contains(strings.Join(issues, "\n"), expected) {
					t.Fatal("parallel authority containment", issues, e)
				}
			})
		}
	}
}
