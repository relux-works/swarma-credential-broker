//go:build linux

package main

import (
	"bytes"
	"context"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
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
	file *ast.File
}

// Claim: shipped sources can reach either synthetic constructor only through
// the qualification package and its explicit command gate. Server wrappers and
// aliases are included; initializers cannot construct authority at daemon startup.
// This is a conservative source dependency check, not binary exclusion or a
// general analysis of reflection/unsafe code. Protected-input execution is paired
// with this check in TestQualificationAuthorityProtectedInputs.
func TestQualificationAuthorityContainment(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var sources []containmentSource
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root || d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err == nil {
			sources = append(sources, containmentSource{filepath.ToSlash(rel), file})
		}
		return err
	})
	if err != nil || len(sources) == 0 {
		t.Fatal("containment source unavailable", err)
	}
	authority := map[string]bool{"NewQualification": true, "NewQualificationAdmission": true, "NewQualificationLeaseRow": true, "NewQualificationPeerAdmission": true, "newQualificationPeer": true}
	containmentClosure(sources, "internal/server", authority)
	gates := map[string]bool{
		`if handled, code := qualify.CaseMain(os.Args[1:]); handled { os.Exit(code) }`:                                                                           false,
		`if len(os.Args) > 1 && os.Args[1] == "qualify-codex" { os.Exit(qualify.Command(ctx, os.Args[2:], runner.DefaultPolicyPath, os.Environ(), os.Stdout)) }`: false,
	}
	// Normalize syntax so whitespace does not change the dispatch assertion.
	normalized := map[string]bool{}
	for text := range gates {
		file, err := parser.ParseFile(token.NewFileSet(), "gate.go", "package main; func main(){"+text+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		normalized[containmentText(file.Decls[0].(*ast.FuncDecl).Body.List[0])] = false
	}
	for _, source := range sources {
		inServer := filepath.Dir(source.path) == "internal/server"
		inQualify := filepath.Dir(source.path) == "internal/qualify"
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
				t.Errorf("qualification authority containment: opaque import in %s", source.path)
			}
			if strings.HasSuffix(path, "/server") {
				serverAlias = alias
			} else {
				qualifyAlias = alias
				if source.path != "cmd/swarma-credential-broker/main.go" || alias != "qualify" {
					t.Errorf("qualification authority containment: driver import outside command gate in %s", source.path)
				}
			}
		}
		for _, decl := range source.file.Decls {
			if inServer && containmentReferences(decl, authority) {
				fn, ok := decl.(*ast.FuncDecl)
				allowed := source.path == "internal/server/qualification_linux.go" || source.path == "internal/server/qualification_lease_rows_linux.go"
				if !allowed || !ok || fn.Name.Name == "init" {
					t.Errorf("qualification authority containment: server authority dependency outside fixture constructors in %s", source.path)
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
					t.Errorf("qualification authority containment: %s referenced outside qualification in %s", selector.Sel.Name, source.path)
				}
				if pkg.Name == qualifyAlias {
					t.Errorf("qualification authority containment: driver reference outside command gate in %s", source.path)
				}
				return true
			})
		}
	}
	for gate, seen := range normalized {
		if !seen {
			t.Errorf("qualification authority containment: command gate changed: %s", gate)
		}
	}
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
