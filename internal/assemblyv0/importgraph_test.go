package assemblyv0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"
)

const inactiveImportModule = "github.com/relux-works/swarma-credential-broker"

type inactiveImportPackage struct {
	Dir            string
	ImportPath     string
	Name           string
	ForTest        string
	Standard       bool
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
	Imports        []string
	Deps           []string
}

func inactiveImportBuildFlags(settings []debug.BuildSetting) []string {
	var flags []string
	for _, setting := range settings {
		if setting.Key == "-tags" {
			flags = append(flags, "-tags="+setting.Value)
		}
		if (setting.Key == "-race" || setting.Key == "-msan" || setting.Key == "-asan") && setting.Value == "true" {
			flags = append(flags, setting.Key)
		}
	}
	return flags
}

func checkInactiveImportConfigurations(root string) error {
	if err := checkInactiveImportGraph(root); err != nil {
		return fmt.Errorf("inherited configuration: %w", err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, cgo := range []string{"0", "1"} {
			environment := []string{
				"GOOS=linux", "GOARCH=" + arch, "CGO_ENABLED=" + cgo,
				"GOAMD64=v1", "GOARM64=v8.0", "GOEXPERIMENT=",
				"GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off",
				"GOFLAGS=-mod=readonly -p=2",
			}
			if err := checkInactiveImportGraphEnvironment(root, environment); err != nil {
				return fmt.Errorf("release linux/%s CGO_ENABLED=%s: %w", arch, cgo, err)
			}
		}
	}
	return nil
}

func listInactiveImportPackages(root string, environment []string, buildFlags ...string) ([]inactiveImportPackage, error) {
	tool := os.Getenv("GO")
	if tool == "" {
		tool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	arguments := []string{"list", "-deps", "-json"}
	if environment == nil {
		if info, present := debug.ReadBuildInfo(); present {
			arguments = append(arguments, inactiveImportBuildFlags(info.Settings)...)
		}
	}
	arguments = append(arguments, buildFlags...)
	list := func(patterns []string) ([]inactiveImportPackage, error) {
		selected := append(append([]string(nil), arguments...), patterns...)
		command := exec.CommandContext(ctx, tool, selected...)
		command.Dir = root
		command.Env = append(os.Environ(), environment...)
		var output, diagnostic bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostic
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("go list failed: %w: %s", err, diagnostic.String())
		}
		decoder := json.NewDecoder(&output)
		var packages []inactiveImportPackage
		for {
			var listed inactiveImportPackage
			if err := decoder.Decode(&listed); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("decode go list: %w", err)
			}
			if listed.ImportPath == "" || listed.Dir == "" {
				return nil, errors.New("go list returned incomplete package metadata")
			}
			packages = append(packages, listed)
		}
		if len(packages) == 0 {
			return nil, errors.New("go list returned no packages")
		}
		return packages, nil
	}
	packages, err := list([]string{"-test", "./..."})
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(packages))
	for _, listed := range packages {
		present[listed.ImportPath] = true
	}
	var missing []string
	for _, listed := range packages {
		if listed.ForTest == "" {
			continue
		}
		original, _, _ := strings.Cut(listed.ImportPath, " [")
		if present[original] {
			continue
		}
		for _, filename := range append(append([]string(nil), listed.GoFiles...), listed.CgoFiles...) {
			if !strings.HasSuffix(filename, "_test.go") {
				missing = append(missing, original)
				present[original] = true
				break
			}
		}
	}
	if len(missing) == 0 {
		return packages, nil
	}
	sort.Strings(missing)
	production, err := list(missing)
	if err != nil {
		return nil, err
	}
	return append(packages, production...), nil
}

func checkInactiveImportGraph(root string, buildFlags ...string) error {
	return checkInactiveImportGraphEnvironment(root, nil, buildFlags...)
}

func checkInactiveImportGraphEnvironment(root string, environment []string, buildFlags ...string) error {
	packages, err := listInactiveImportPackages(root, environment, buildFlags...)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	protected := make(map[string]string)
	for _, consumer := range inactiveImportConsumers {
		directory, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(consumer.prefix)))
		if err != nil {
			return err
		}
		protected[consumer.prefix] = directory
	}
	byImport := make(map[string]inactiveImportPackage, len(packages))
	physical := make(map[string]string, len(packages))
	for _, listed := range packages {
		directory, err := filepath.EvalSymlinks(listed.Dir)
		if err != nil {
			return err
		}
		byImport[listed.ImportPath] = listed
		physical[listed.ImportPath] = directory
	}
	targetOf := func(listed inactiveImportPackage) string {
		for _, consumer := range inactiveImportConsumers {
			directory := protected[consumer.prefix]
			if physical[listed.ImportPath] == directory || strings.HasPrefix(physical[listed.ImportPath], directory+string(filepath.Separator)) {
				return consumer.prefix
			}
			importPath := inactiveImportModule + "/" + strings.TrimSuffix(consumer.prefix, "/")
			if listed.ImportPath == importPath || strings.HasPrefix(listed.ImportPath, importPath+"/") {
				return consumer.prefix
			}
		}
		return ""
	}
	for _, listed := range packages {
		if listed.ForTest != "" {
			continue
		}
		if original, exists := byImport[strings.TrimSuffix(listed.ImportPath, ".test")]; exists && listed.Name == "main" && listed.ImportPath == original.ImportPath+".test" && listed.Dir == original.Dir && len(listed.GoFiles) == 1 && filepath.IsAbs(listed.GoFiles[0]) {
			continue
		}
		relative, err := filepath.Rel(root, listed.Dir)
		if err != nil {
			return err
		}
		directory := filepath.ToSlash(relative) + "/"
		for _, filename := range listed.IgnoredGoFiles {
			if strings.HasSuffix(filename, "_test.go") {
				continue
			}
			contents, err := os.ReadFile(filepath.Join(listed.Dir, filename))
			if err != nil {
				return err
			}
			if err := checkInactiveImports(filepath.Join(relative, filename), contents); err != nil {
				return fmt.Errorf("%w: ignored imports of %s in %s", err, listed.ImportPath, filename)
			}
		}
		if len(listed.GoFiles) == 0 && len(listed.CgoFiles) == 0 {
			continue
		}
		var permitted []string
		admitted := false
		for _, consumer := range inactiveImportConsumers {
			if directory == consumer.prefix && listed.ImportPath == inactiveImportModule+"/"+strings.TrimSuffix(consumer.prefix, "/") && physical[listed.ImportPath] == protected[consumer.prefix] {
				admitted = true
				permitted = consumer.imports
			}
		}
		if targetOf(listed) != "" && !admitted {
			return fmt.Errorf("%w: undeclared inactive package %s", errFixture, listed.ImportPath)
		}
		if admitted {
			if err := checkInactivePackageImports(directory, listed.Imports); err != nil {
				return fmt.Errorf("%w: imports of %s", err, listed.ImportPath)
			}
		}
		for _, dependency := range listed.Deps {
			target, exists := byImport[dependency]
			if !exists {
				return fmt.Errorf("go list omitted dependency %s of %s", dependency, listed.ImportPath)
			}
			if targetOf(target) == "" {
				continue
			}
			allowed := false
			for _, importPath := range permitted {
				if dependency == importPath && physical[dependency] == protected[targetOf(target)] {
					allowed = true
				}
			}
			if !allowed {
				return fmt.Errorf("%w: %s depends on inactive %s", errFixture, listed.ImportPath, dependency)
			}
		}
	}
	return nil
}

func inactiveImportFixture(test *testing.T) (string, func(string, []byte)) {
	test.Helper()
	root := test.TempDir()
	writeSource := func(filename string, contents []byte) {
		test.Helper()
		path := filepath.Join(root, filepath.FromSlash(filename))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			test.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			test.Fatal(err)
		}
	}
	writeSource("go.mod", []byte("module "+inactiveImportModule+"\n\ngo 1.26.0\n"))
	for _, consumer := range inactiveImportConsumers {
		contents := "package probe\n"
		for _, importPath := range consumer.imports {
			contents += fmt.Sprintf("import _ %q\n", importPath)
		}
		writeSource(consumer.prefix+"probe.go", []byte(contents))
	}
	writeSource("internal/wire/probe.go", []byte("package probe\n"))
	writeSource("internal/activationv0-other/probe.go", importBoundarySource("wire"))
	writeSource("internal/bridge/probe.go", importBoundarySource("activationv0-other"))
	writeSource("internal/server/probe.go", importBoundarySource("bridge"))
	return root, writeSource
}

// Claim: compiler-resolved aliases and hidden forwarding paths refuse beside harmless symlink and multi-hop controls.
func TestInactiveImportGraphToolchainControls(test *testing.T) {
	cases := []struct {
		name string
		path string
		link string
	}{
		{"symlink-activation", "internal/fwd", "activationv0"},
		{"symlink-assembly", "internal/fwd", "assemblyv0"},
		{"symlink-state", "internal/fwd", "statev0"},
		{"hidden-forwarder", "internal/x/.temp/fwd", ""},
		{"root-hidden-forwarder", ".temp/fwd", ""},
		{"underscore-forwarder", "internal/_fwd", ""},
	}
	for _, item := range cases {
		test.Run(item.name, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			if err := os.Symlink("wire", filepath.Join(root, "internal", "safealias")); err != nil {
				test.Fatal(err)
			}
			writeSource("internal/activationv0-other/probe.go", importBoundarySource("safealias"))
			if err := checkInactiveImportGraph(root); err != nil {
				test.Fatalf("valid symlink and multi-hop controls refused: %v", err)
			}
			if item.link != "" {
				if err := os.Symlink(item.link, filepath.Join(root, filepath.FromSlash(item.path))); err != nil {
					test.Fatal(err)
				}
			} else {
				writeSource(item.path+"/probe.go", importBoundarySource("activationv0"))
			}
			writeSource("internal/bridge/probe.go", []byte("package probe; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/"+item.path)))
			if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
				test.Fatalf("toolchain forwarding plant accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: selecting a build tag exposes a hidden forwarder; the same tree with that tag inactive remains a valid control.
func TestInactiveImportGraphBuildTagControls(test *testing.T) {
	root, writeSource := inactiveImportFixture(test)
	writeSource("internal/x/.temp/fwd/probe.go", importBoundarySource("activationv0"))
	writeSource("internal/server/tagged.go", append([]byte("//go:build swarma_inactive_probe\n\n"), []byte("package probe; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/x/.temp/fwd"))...))
	if err := checkInactiveImportGraph(root, "-tags="); err != nil {
		test.Fatalf("inactive build-tag control refused: %v", err)
	}
	if err := checkInactiveImportGraph(root, "-tags=swarma_inactive_probe"); !errors.Is(err, errFixture) {
		test.Fatalf("active build-tag forwarding plant accepted or wrong refusal: %v", err)
	}
}

// Claim: internal/external test imports are allowed, but production forwarders reached only by tests are still checked.
func TestInactiveImportGraphTestVariantControls(test *testing.T) {
	for _, packageName := range []string{"probe", "probe_test"} {
		test.Run(packageName, func(test *testing.T) {
			root, writeSource := inactiveImportFixture(test)
			writeSource("internal/server/probe_test.go", []byte("package "+packageName+"; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/activationv0")))
			if err := checkInactiveImportGraph(root); err != nil {
				test.Fatalf("valid test-only inactive import refused: %v", err)
			}
			writeSource("internal/x/.temp/fwd/probe.go", importBoundarySource("activationv0"))
			writeSource("internal/server/probe_test.go", []byte("package "+packageName+"; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/x/.temp/fwd")))
			if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
				test.Fatalf("test-selected production forwarder accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: compiler-selected vendor packages participate in the same dependency rule, with a harmless vendored control.
func TestInactiveImportGraphVendorControls(test *testing.T) {
	root, writeSource := inactiveImportFixture(test)
	forwarder := inactiveImportModule + "/forwarder"
	writeSource("go.mod", []byte("module "+inactiveImportModule+"\n\ngo 1.26.0\n\nrequire "+forwarder+" v0.0.0\n"))
	writeSource("vendor/modules.txt", []byte("# "+forwarder+" v0.0.0\n## explicit; go 1.26.0\n"+forwarder+"\n"))
	writeSource("vendor/"+forwarder+"/probe.go", importBoundarySource("wire"))
	writeSource("internal/bridge/probe.go", []byte("package probe; import _ "+fmt.Sprintf("%q", forwarder)))
	if err := checkInactiveImportGraph(root, "-mod=vendor"); err != nil {
		test.Fatalf("valid vendored forwarder control refused: %v", err)
	}
	writeSource("vendor/"+forwarder+"/probe.go", importBoundarySource("activationv0"))
	if err := checkInactiveImportGraph(root, "-mod=vendor"); !errors.Is(err, errFixture) {
		test.Fatalf("vendored inactive forwarder accepted or wrong refusal: %v", err)
	}
}

// Claim: an ordinary main package ending in .test is not mistaken for the generated test driver.
func TestInactiveImportGraphTestSuffixControls(test *testing.T) {
	root, writeSource := inactiveImportFixture(test)
	writeSource("internal/real.test/probe.go", []byte("package main\n\nfunc main() {}\n"))
	if err := checkInactiveImportGraph(root); err != nil {
		test.Fatalf("valid main package control refused: %v", err)
	}
	writeSource("internal/real.test/probe.go", []byte("package main; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/activationv0")+"; func main() {}"))
	if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
		test.Fatalf("ordinary .test package exempted or wrong refusal: %v", err)
	}
}

// Claim: incomplete toolchain graphs fail as listing errors, not as successful boundary checks or expected plant refusals.
func TestInactiveImportGraphListingFailureControls(test *testing.T) {
	root, writeSource := inactiveImportFixture(test)
	if err := checkInactiveImportGraph(root); err != nil {
		test.Fatalf("valid module control refused: %v", err)
	}
	writeSource("internal/server/probe.go", importBoundarySource("missing"))
	if err := checkInactiveImportGraph(root); err == nil || errors.Is(err, errFixture) || !strings.Contains(err.Error(), "go list failed") {
		test.Fatalf("incomplete graph accepted or misclassified: %v", err)
	}
	writeSource("internal/server/probe.go", importBoundarySource("bridge"))
	for _, item := range []struct {
		name   string
		script string
		want   string
	}{
		{"empty", "exit 0", "no packages"},
		{"failed", "echo listing-refused >&2; exit 7", "go list failed"},
		{"malformed", "printf '{'", "decode go list"},
		{"incomplete", "printf '{}'", "incomplete package metadata"},
	} {
		test.Run(item.name, func(test *testing.T) {
			tool := filepath.Join(test.TempDir(), "go-list")
			if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+item.script+"\n"), 0700); err != nil {
				test.Fatal(err)
			}
			test.Setenv("GO", tool)
			if err := checkInactiveImportGraph(root); err == nil || errors.Is(err, errFixture) || !strings.Contains(err.Error(), item.want) {
				test.Fatalf("listing %s accepted or misclassified: %v", item.name, err)
			}
		})
	}
}

// Claim: a production dependency rebuilt for an external test retains its production boundary despite ForTest variants.
func TestInactiveImportGraphRecompiledDependencyControls(test *testing.T) {
	for _, mode := range []string{"go", "cgo"} {
		test.Run(mode, func(test *testing.T) {
			cgoImport := ""
			if mode == "cgo" {
				enabled := false
				if info, present := debug.ReadBuildInfo(); present {
					for _, setting := range info.Settings {
						if setting.Key == "CGO_ENABLED" && setting.Value == "1" {
							enabled = true
						}
					}
				}
				if !enabled {
					test.Skip("cgo is not selected in this build configuration")
				}
				cgoImport = "import \"C\"; "
			}
			root, writeSource := inactiveImportFixture(test)
			writeSource("internal/server/probe_test.go", importBoundarySource("time"))
			writeSource("internal/server/external_test.go", []byte("package probe_test; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/x/.temp/fwd")))
			control := []byte("package probe; " + cgoImport + "import _ " + fmt.Sprintf("%q", inactiveImportModule+"/internal/server"))
			writeSource("internal/x/.temp/fwd/probe.go", control)
			if err := checkInactiveImportGraph(root); err != nil {
				test.Fatalf("valid recompiled dependency control refused: %v", err)
			}
			writeSource("internal/x/.temp/fwd/probe.go", append(control, []byte("; import _ "+fmt.Sprintf("%q", inactiveImportModule+"/internal/activationv0"))...))
			if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
				test.Fatalf("recompiled inactive dependency accepted or wrong refusal: %v", err)
			}
		})
	}
}

// Claim: an inactive subtree containing only tests adds no production package; adding a production file removes that exemption.
func TestInactiveImportGraphTestOnlyPackageControls(test *testing.T) {
	root, writeSource := inactiveImportFixture(test)
	writeSource("internal/activationv0/testonly/probe_test.go", importBoundarySource("activationv0"))
	if err := checkInactiveImportGraph(root); err != nil {
		test.Fatalf("valid test-only package control refused: %v", err)
	}
	writeSource("internal/activationv0/testonly/probe.go", importBoundarySource("time"))
	if err := checkInactiveImportGraph(root); !errors.Is(err, errFixture) {
		test.Fatalf("undeclared production package exempted or wrong refusal: %v", err)
	}
}
