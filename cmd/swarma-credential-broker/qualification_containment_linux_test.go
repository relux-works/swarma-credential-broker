//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type containmentSource struct {
	path string
	pkg  string
	file *ast.File
}

const containmentModule = "github.com/relux-works/swarma-credential-broker"
const containmentCommand = containmentModule + "/cmd/swarma-credential-broker"
const containmentDriver = containmentModule + "/internal/qualify"
const containmentServer = containmentModule + "/internal/server"

type containmentPackage struct {
	ImportPath, Dir string
	CompiledGoFiles []string
	Imports         []string
	Error           *struct{ Err string }
	DepsErrors      []struct{ Err string }
}

type containmentGraph map[string]containmentPackage

func containmentGo(t *testing.T, root string, args ...string) *exec.Cmd {
	t.Helper()
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, goTool, args...)
	cmd.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOOS" && key != "GOARCH" && key != "GOFLAGS" && key != "GOWORK" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	// Match the production target and default tags, without inheriting a test
	// overlay, tag selection or workspace that could hide a shipped dependency.
	cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-trimpath", "GOWORK=off")
	return cmd
}

func containmentProductionGraph(t *testing.T, root string, extraRoots ...string) (containmentGraph, error) {
	t.Helper()
	args := append([]string{"list", "-deps", "-compiled", "-json", "-tags=", "./cmd/swarma-credential-broker", "./internal/server"}, extraRoots...)
	cmd := containmentGo(t, root, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("production build graph unavailable: %w", err)
	}
	graph := containmentGraph{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg containmentPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("production build graph invalid: %w", err)
		}
		if pkg.ImportPath == "" || pkg.Error != nil || len(pkg.DepsErrors) != 0 {
			return nil, fmt.Errorf("production package unavailable: %s", pkg.ImportPath)
		}
		if _, duplicate := graph[pkg.ImportPath]; duplicate {
			return nil, fmt.Errorf("duplicate production package: %s", pkg.ImportPath)
		}
		graph[pkg.ImportPath] = pkg
	}
	for _, path := range []string{containmentCommand, containmentDriver, containmentServer} {
		if _, exists := graph[path]; !exists {
			return nil, fmt.Errorf("production root missing: %s", path)
		}
	}
	return graph, nil
}

func containmentSources(root string, graph containmentGraph) ([]containmentSource, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var sources []containmentSource
	for path, pkg := range graph {
		if path != containmentModule && !strings.HasPrefix(path, containmentModule+"/") {
			continue
		}
		if len(pkg.CompiledGoFiles) == 0 {
			return nil, fmt.Errorf("production sources missing: %s", path)
		}
		for _, name := range pkg.CompiledGoFiles {
			if !filepath.IsAbs(name) {
				name = filepath.Join(pkg.Dir, name)
			}
			rel, err := filepath.Rel(root, name)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("production source outside module: %s", path)
			}
			// No directory filter: imported testdata, underscore and vendor-like
			// trees are checked exactly like any other production dependency.
			file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				return nil, fmt.Errorf("production source unreadable or invalid: %s: %w", path, err)
			}
			sources = append(sources, containmentSource{filepath.ToSlash(rel), path, file})
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("production sources empty")
	}
	return sources, nil
}

// Remove only the command-to-driver edge whose exact syntax is checked below.
// Any dependency also reached through the ordinary entry remains forbidden,
// even when qualification imports that same dependency.
func containmentReachable(graph containmentGraph, roots []string, ordinary bool) (map[string]bool, error) {
	seen := map[string]bool{}
	queue := append([]string(nil), roots...)
	for len(queue) != 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] || path == "C" { // cgo pseudo-import has no package source.
			continue
		}
		pkg, exists := graph[path]
		if !exists {
			return nil, fmt.Errorf("production dependency missing: %s", path)
		}
		seen[path] = true
		for _, dependency := range pkg.Imports {
			if ordinary && path == containmentCommand && dependency == containmentDriver {
				continue
			}
			queue = append(queue, dependency)
		}
	}
	return seen, nil
}

// Claim: every compiled first-party dependency is scanned for the production
// linux/amd64 build with default tags, regardless of directory name. Constructor
// aliases/wrappers are allowed in qualification-only dependencies; ordinary or
// shared dependencies cannot consume either authority. Server-local wrappers
// and exact command dispatch gates are checked separately. This source guard
// does not claim binary exclusion or reflection/unsafe analysis.
func TestQualificationAuthorityContainment(t *testing.T) {
	root := filepath.Join("..", "..")
	graph, err := containmentProductionGraph(t, root)
	if err != nil {
		t.Fatal("qualification authority containment:", err)
	}
	issues, err := containmentCheck(root, graph)
	if err != nil {
		t.Fatal("qualification authority containment:", err)
	}
	for _, issue := range issues {
		t.Error(issue)
	}
}

func containmentCheck(root string, graph containmentGraph) ([]string, error) {
	sources, err := containmentSources(root, graph)
	if err != nil {
		return nil, err
	}
	ordinary, err := containmentReachable(graph, []string{containmentCommand, containmentServer}, true)
	if err != nil {
		return nil, err
	}
	qualification, err := containmentReachable(graph, []string{containmentDriver}, false)
	if err != nil {
		return nil, err
	}
	var issues []string
	ownerIssues := containmentOwnerAuthority(sources, graph, ordinary, qualification)
	issues = append(issues, ownerIssues...)
	issues = append(issues, containmentTimeFixtures(sources)...)
	issues = append(issues, containmentOwnerDiagnostics(sources)...)
	report := func(message string, args ...any) { issues = append(issues, fmt.Sprintf(message, args...)) }
	authority := map[string]bool{"NewQualification": true, "NewQualificationAdmission": true, "NewQualificationLeaseRow": true, "NewQualificationPeerAdmission": true, "newQualificationPeer": true}
	containmentClosure(sources, "internal/server", authority)
	initializerNames := map[string]map[string]bool{}
	for _, source := range sources {
		if !qualification[source.pkg] || ordinary[source.pkg] || initializerNames[source.pkg] != nil {
			continue
		}
		names := map[string]bool{}
		for name := range authority {
			names[name] = true
		}
		containmentClosure(sources, filepath.Dir(source.path), names)
		initializerNames[source.pkg] = names
	}
	gates := map[string]bool{
		`if handled, code := qualify.CaseMain(os.Args[1:]); handled { os.Exit(code) }`:                                                                           false,
		`if len(os.Args) > 1 && os.Args[1] == "qualify-codex" { os.Exit(qualify.Command(ctx, os.Args[2:], runner.DefaultPolicyPath, os.Environ(), os.Stdout)) }`: false,
	}
	// Normalize syntax so whitespace does not change the dispatch assertion.
	normalized := map[string]bool{}
	for text := range gates {
		file, err := parser.ParseFile(token.NewFileSet(), "gate.go", "package main; func main(){"+text+"}", 0)
		if err != nil {
			return nil, err
		}
		normalized[containmentText(file.Decls[0].(*ast.FuncDecl).Body.List[0])] = false
	}
	for _, source := range sources {
		inServer := filepath.Dir(source.path) == "internal/server"
		inQualify := qualification[source.pkg] && !ordinary[source.pkg]
		serverAlias, qualifyAlias := "", ""
		for _, imp := range source.file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path != "github.com/relux-works/swarma-credential-broker/internal/server" && path != "github.com/relux-works/swarma-credential-broker/internal/qualify" {
				continue
			}
			alias := filepath.Base(path)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			if alias == "." || alias == "_" {
				report("qualification authority containment: opaque import in %s", source.path)
			}
			if strings.HasSuffix(path, "/server") {
				serverAlias = alias
			} else {
				qualifyAlias = alias
				if source.path != "cmd/swarma-credential-broker/main.go" || alias != "qualify" {
					report("qualification authority containment: driver import outside command gate in %s", source.path)
				}
			}
		}
		for _, decl := range source.file.Decls {
			// Even a qualification-only import initializes during daemon startup.
			// Function aliases may be stored, but startup may not call authority.
			if inQualify && containmentInitializerCalls(decl, initializerNames[source.pkg]) {
				report("qualification authority containment: authority call during package initialization in %s", source.path)
			}
			if inServer && containmentReferences(decl, authority) {
				fn, ok := decl.(*ast.FuncDecl)
				allowed := source.path == "internal/server/qualification_linux.go" || source.path == "internal/server/qualification_lease_rows_linux.go"
				if !allowed || !ok || fn.Name.Name == "init" {
					report("qualification authority containment: server authority dependency outside fixture constructors in %s", source.path)
				}
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				if statement, ok := node.(*ast.IfStmt); ok && source.path == "cmd/swarma-credential-broker/main.go" {
					if _, exists := normalized[containmentText(statement)]; exists {
						fn, ok := decl.(*ast.FuncDecl)
						if ok && fn.Name.Name == "main" {
							normalized[containmentText(statement)] = true
							return false // Only these complete statements may reference the driver.
						}
					}
				}
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				if pkg.Name == serverAlias && authority[selector.Sel.Name] && !inQualify {
					report("qualification authority containment: %s referenced outside qualification in %s", selector.Sel.Name, source.path)
				}
				if pkg.Name == qualifyAlias {
					report("qualification authority containment: driver reference outside command gate in %s", source.path)
				}
				return true
			})
		}
	}
	for gate, seen := range normalized {
		if !seen {
			report("qualification authority containment: command gate changed: %s", gate)
		}
	}
	return issues, nil
}

func containmentInitializerCalls(decl ast.Decl, names map[string]bool) bool {
	var node ast.Node
	switch decl := decl.(type) {
	case *ast.FuncDecl:
		if decl.Name.Name == "init" {
			node = decl.Body
		}
	case *ast.GenDecl:
		if decl.Tok == token.VAR {
			node = decl
		}
	}
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && containmentReferences(call.Fun, names) {
			found = true
		}
		return true
	})
	return found
}

// Follow local function/variable wrappers, including method selectors. Names
// are deliberately over-approximated: an ambiguous dependency fails closed.
func containmentClosure(sources []containmentSource, directory string, names map[string]bool) {
	for changed := true; changed; {
		changed = false
		for _, source := range sources {
			if filepath.Dir(source.path) != directory {
				continue
			}
			for _, decl := range source.file.Decls {
				if !containmentReferences(decl, names) {
					continue
				}
				for _, name := range containmentNames(decl) {
					if !names[name] {
						names[name], changed = true, true
					}
				}
			}
		}
	}
}

func containmentNames(decl ast.Decl) []string {
	if fn, ok := decl.(*ast.FuncDecl); ok {
		return []string{fn.Name.Name}
	}
	var names []string
	if gen, ok := decl.(*ast.GenDecl); ok {
		for _, spec := range gen.Specs {
			if value, ok := spec.(*ast.ValueSpec); ok {
				for _, name := range value.Names {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}
func containmentReferences(node ast.Node, names map[string]bool) bool {
	found := false
	// Exclude the declaration's own name from dependency discovery.
	if fn, ok := node.(*ast.FuncDecl); ok {
		node = fn.Body
		if fn.Body == nil {
			return false
		}
	}
	ast.Inspect(node, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return true
	})
	return found
}
func containmentText(node ast.Node) string {
	var out bytes.Buffer
	if err := format.Node(&out, token.NewFileSet(), node); err != nil {
		panic(err)
	}
	return out.String()
}

// Claim: the shipped entry rejects fixture flags on daemon/serve and fixture
// fields in daemon configuration. Environment spellings do not route either
// entry to qualification. Refusals leave the synthetic fixture tree unchanged;
// the structural check above rules out construction before those refusals.
// There is currently no serve CLI command: its refusal remains exit 64.
func TestQualificationAuthorityCLIContainment(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(t.TempDir(), "broker")
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	build := exec.Command(goTool, "build", "-p=1", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v %s", err, out)
	}
	config := filepath.Join(root, "config.json")
	fixture := filepath.Join(root, "roles.json")
	configBytes := []byte(`{"fixtures":true,"fixture-config":"synthetic"}`)
	fixtureBytes := []byte(`{"same_user_r2":true}`)
	if os.WriteFile(config, configBytes, 0600) != nil || os.WriteFile(fixture, fixtureBytes, 0600) != nil {
		t.Fatal("protect fixture inputs")
	}
	for _, entry := range []string{"daemon", "serve"} {
		for _, input := range []string{"fixtures", "fixture-config", "config-fields", "environment"} {
			t.Run(entry+"/"+input, func(t *testing.T) {
				args := []string{entry, "--config", config}
				want := 64
				switch input {
				case "fixtures":
					args = append(args, "--fixtures")
				case "fixture-config":
					args = append(args, "--fixture-config", fixture)
				default:
					if entry == "daemon" {
						want = 69
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, args...)
				cmd.Env = []string{"HOME=" + root, "LANG=C"}
				if input == "environment" {
					cmd.Env = append(cmd.Env, "FIXTURES=true", "FIXTURE_CONFIG="+fixture, "SWARMA_FIXTURES=true", "SWARMA_FIXTURE_CONFIG="+fixture)
				}
				var out, diagnostic bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diagnostic
				err := cmd.Run()
				failure, ok := err.(*exec.ExitError)
				if ctx.Err() != nil || !ok || failure.ExitCode() != want || out.Len() != 0 {
					t.Fatal("qualification authority containment: unexpected command outcome", err)
				}
				message := ""
				if entry == "serve" {
					message = "runner: invalid_command\n"
				} else if want == 69 {
					message = "configuration_unavailable\n"
				}
				if diagnostic.String() != message {
					t.Fatal("qualification authority containment: wrong refusal")
				}
				entries, err := os.ReadDir(root)
				a, ea := os.ReadFile(config)
				b, eb := os.ReadFile(fixture)
				if err != nil || len(entries) != 2 || ea != nil || eb != nil || !bytes.Equal(a, configBytes) || !bytes.Equal(b, fixtureBytes) {
					t.Fatal("qualification authority containment: fixture changed")
				}
			})
		}
	}
}

// Track the new synthetic authority by package through aliases/wrappers, even
// in shared compiled dependencies. Ordinary egress operations remain ordinary.
func containmentOwnerAuthority(sources []containmentSource, graph containmentGraph, ordinary, qualification map[string]bool) []string {
	names := map[string]map[string]bool{
		containmentModule + "/internal/egress": {"NewOwnerOrigin": true, "EnterOwnerRole": true, "NewCrashOwnerOrigin": true, "NewWriterOrigin": true, "EnterWriterRole": true},
		containmentDriver:                      {"ownerCompose": true, "ownerSeed": true, "ownerPolicy": true, "ownerAdapter": true, "ownerModel": true, "ownerMain": true, "startOwner": true, "startOwnedRole": true, "writerMain": true, "writerCompose": true, "writerPersist": true, "startWriter": true, "writerPeak": true, "lifecycleClassifier": true, "lifecycleClock": true, "lifecycleModel": true, "lifecycleAudit": true, "lifecycleRun": true, "parallelCompose": true, "parallelMux": true, "parallelService": true, "parallelHarness": true, "parallelRun": true},
	}
	mainGates := map[string]bool{}
	for _, text := range []string{`if handled, code := qualify.CaseMain(os.Args[1:]); handled { os.Exit(code) }`, `if len(os.Args)>1 && os.Args[1]=="qualify-codex" {os.Exit(qualify.Command(ctx,os.Args[2:],runner.DefaultPolicyPath,os.Environ(),os.Stdout))}`} {
		f, _ := parser.ParseFile(token.NewFileSet(), "gate.go", "package main;func main(){"+text+"}", 0)
		mainGates[containmentText(f.Decls[0].(*ast.FuncDecl).Body.List[0])] = true
	}
	// Compare the whole entry statement, including its condition and refusal.
	// Finding the call text alone also admits disabled checks and ignored errors.
	entryGates := map[string]string{}
	for role, call := range map[string]string{"writer": "EnterWriterRole", "owner": "EnterOwnerRole"} {
		f, _ := parser.ParseFile(token.NewFileSet(), "gate.go", "package qualify;func gate(){if egress."+call+"(args[1]) != nil {return 125}}", 0)
		entryGates[role] = containmentText(f.Decls[0].(*ast.FuncDecl).Body.List[0])
	}
	aliases := func(s containmentSource) map[string]string {
		out := map[string]string{}
		for _, imp := range s.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			name := filepath.Base(p)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			out[name] = p
		}
		return out
	}
	references := func(s containmentSource, node ast.Node) bool {
		if f, ok := node.(*ast.FuncDecl); ok {
			node = f.Body
		}
		found := false
		imports := aliases(s)
		ast.Inspect(node, func(n ast.Node) bool {
			if stmt, ok := n.(*ast.IfStmt); ok && s.path == "cmd/swarma-credential-broker/main.go" && mainGates[containmentText(stmt)] {
				return false
			}
			switch n := n.(type) {
			case *ast.Ident:
				if names[s.pkg][n.Name] {
					found = true
				}
			case *ast.SelectorExpr:
				if a, ok := n.X.(*ast.Ident); ok && names[imports[a.Name]][n.Sel.Name] {
					found = true
				}
			}
			return true
		})
		return found
	}
	for changed := true; changed; {
		changed = false
		for _, s := range sources {
			if names[s.pkg] == nil {
				names[s.pkg] = map[string]bool{}
			}
			for _, d := range s.file.Decls {
				if references(s, d) {
					for _, n := range containmentNames(d) {
						if !names[s.pkg][n] {
							names[s.pkg][n] = true
							changed = true
						}
					}
				}
			}
		}
	}
	var issues []string
	for _, s := range sources {
		inOrigin := s.pkg == containmentModule+"/internal/egress"
		allowed := qualification[s.pkg] && !ordinary[s.pkg]
		for _, d := range s.file.Decls {
			if references(s, d) && !allowed && !inOrigin {
				issues = append(issues, "owner authority outside qualification in "+s.path)
			}
			if inOrigin && references(s, d) && s.path != "internal/egress/origin_linux_amd64.go" && s.path != "internal/egress/unsupported.go" {
				issues = append(issues, "owner authority wrapper outside origin implementation in "+s.path)
			}
			startup := false
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "init" {
				startup = references(s, fn)
			}
			if gen, ok := d.(*ast.GenDecl); ok && gen.Tok == token.VAR {
				for _, spec := range gen.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok {
						for _, value := range v.Values {
							switch value.(type) {
							case *ast.Ident, *ast.SelectorExpr:
							default:
								startup = startup || references(s, value)
							}
						}
					}
				}
			}
			if (allowed || inOrigin) && startup {
				issues = append(issues, "owner authority during package initialization in "+s.path)
			}
			if s.path == "internal/qualify/row_worker_linux.go" {
				if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "CaseMain" {
					want := `if len(args) > 0 && args[0] == "qualification-owner" { return true, ownerMain(args) }`
					parsed, _ := parser.ParseFile(token.NewFileSet(), "gate.go", "package qualify;func gate(){"+want+"}", 0)
					if len(f.Body.List) == 0 || containmentText(f.Body.List[0]) != containmentText(parsed.Decls[0].(*ast.FuncDecl).Body.List[0]) {
						issues = append(issues, "owner dispatcher gate changed")
					}
					writer := `if len(args)>0 && args[0]=="qualification-writer" {return true,writerMain(args)}`
					p, _ := parser.ParseFile(token.NewFileSet(), "gate.go", "package qualify;func gate(){"+writer+"}", 0)
					if len(f.Body.List) < 2 || containmentText(f.Body.List[1]) != containmentText(p.Decls[0].(*ast.FuncDecl).Body.List[0]) {
						issues = append(issues, "writer dispatcher gate changed")
					}
				}
			}
			if s.path == "internal/qualify/owner_lifecycle_linux.go" {
				if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "writerMain" {
					body := f.Body.List
					if len(body) < 2 || containmentText(body[len(body)-1]) != "return writerCompose(c, ch, native)" || containmentText(body[len(body)-2]) != entryGates["writer"] {
						issues = append(issues, "writer construction barrier changed")
					} else {
						for _, stmt := range body[:len(body)-2] {
							if references(s, stmt) {
								issues = append(issues, "writer authority before entry")
							}
						}
					}
				}
			}
			if s.path == "internal/qualify/owner_worker_linux.go" {
				if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "ownerMain" {
					body := f.Body.List
					if len(body) < 2 || containmentText(body[len(body)-1]) != "return ownerCompose(c, ch)" || containmentText(body[len(body)-2]) != entryGates["owner"] {
						issues = append(issues, "owner construction barrier changed")
					} else {
						for _, stmt := range body[:len(body)-2] {
							if references(s, stmt) {
								issues = append(issues, "owner authority before entry")
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// No production package may materialize the test-only time path or witness.
// This complements the compiled graph scan; it is not an unsafe/reflection proof.
func containmentTimeFixtures(sources []containmentSource) []string {
	var issues []string
	for _, source := range sources {
		if source.pkg == containmentModule+"/timeconftest" || source.path == "timeconf/consumer_fixture_linux.go" {
			issues = append(issues, "fixture package/source in default build: "+source.path)
		}
		declarations := map[*ast.Ident]bool{}
		ast.Inspect(source.file, func(n ast.Node) bool {
			if spec, ok := n.(*ast.TypeSpec); ok {
				if body, ok := spec.Type.(*ast.StructType); ok {
					if spec.Name.Name == "pathQualification" {
						declarations[spec.Name] = true
					}
					if spec.Name.Name == "Consumer" {
						for _, field := range body.Fields.List {
							if len(field.Names) == 1 && field.Names[0].Name == "timePath" {
								if pointer, ok := field.Type.(*ast.StarExpr); ok {
									if id, ok := pointer.X.(*ast.Ident); ok && id.Name == "pathQualification" {
										declarations[id] = true
									}
								}
							}
						}
					}
				}
			}
			return true
		})
		ast.Inspect(source.file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "pathQualification" && !declarations[id] {
				issues = append(issues, "time activation type used in "+source.path)
			}
			if id, ok := n.(*ast.Ident); ok && (id.Name == "fixtureWitness" || id.Name == "newSettlementFixture" || id.Name == "fixtureLocal" || id.Name == "qualifiedForkFixture" || id.Name == "FixtureConsumer" || id.Name == "NewFixtureConsumer" || id.Name == "VerifyFixtureReceipt" || id.Name == "fixtureRootDigest" || id.Name == "taggedFixtureWitness") {
				issues = append(issues, "test-only time fixture in "+source.path)
			}
			// A qualification literal/new/assignment cannot appear even in a protected
			// driver until a separately reviewed native activation path is implemented.
			if value, ok := n.(*ast.CompositeLit); ok {
				if id, ok := value.Type.(*ast.Ident); ok && id.Name == "pathQualification" {
					issues = append(issues, "time activation materialized in "+source.path)
				}
				for _, element := range value.Elts {
					if kv, ok := element.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "timePath" {
							issues = append(issues, "time activation field in "+source.path)
						}
					}
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "new" && len(call.Args) == 1 {
					if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "pathQualification" {
						issues = append(issues, "time activation materialized in "+source.path)
					}
				}
			}
			if assignment, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range assignment.Lhs {
					if field, ok := lhs.(*ast.SelectorExpr); ok && field.Sel.Name == "timePath" {
						issues = append(issues, "time activation assigned in "+source.path)
					}
				}
			}
			return true
		})
	}
	return issues
}

// The compiled graph may read a test-installed sink, but cannot construct one
// or expose its context key. Complete reader matching also rejects a hidden
// default/fallback installer. This is not an unsafe/reflection proof.
func containmentOwnerDiagnostics(sources []containmentSource) []string {
	var issues []string
	const reader = `func ownerDiagnostics(ctx context.Context) *ownerDiagnosticSink {
 if ctx == nil { return nil }
 sink, _ := ctx.Value(ownerDiagnosticSinkKey{}).(*ownerDiagnosticSink)
 return sink
 }`
	for _, source := range sources {
		allowed := map[*ast.Ident]bool{}
		canonical := source.path == "internal/qualify/owner_diagnostic_linux.go"
		ast.Inspect(source.file, func(n ast.Node) bool {
			if spec, ok := n.(*ast.TypeSpec); ok && canonical {
				if _, ok := spec.Type.(*ast.StructType); ok && (spec.Name.Name == "ownerDiagnosticSink" || spec.Name.Name == "ownerDiagnosticSinkKey") {
					allowed[spec.Name] = true
				}
			}
			if fn, ok := n.(*ast.FuncDecl); ok && canonical {
				if fn.Name.Name == "ownerDiagnostics" && strings.Join(strings.Fields(containmentText(fn)), " ") == strings.Join(strings.Fields(reader), " ") {
					ast.Inspect(fn, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							allowed[id] = true
						}
						return true
					})
				}
				if fn.Recv != nil {
					for _, field := range fn.Recv.List {
						if pointer, ok := field.Type.(*ast.StarExpr); ok {
							if id, ok := pointer.X.(*ast.Ident); ok && id.Name == "ownerDiagnosticSink" {
								allowed[id] = true
							}
						}
					}
				}
			}
			return true
		})
		ast.Inspect(source.file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && ((id.Name == "ownerDiagnosticSink" || id.Name == "ownerDiagnosticSinkKey") && !allowed[id] || id.Name == "withOwnerDiagnostics") {
				issues = append(issues, "test-only owner diagnostic installation in "+source.path)
			}
			return true
		})
	}
	return issues
}
