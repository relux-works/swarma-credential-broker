//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the exact runner constructor file is admitted for qualification calls,
// while compiled daemon references, eager construction and another server file
// are rejected by the production graph checker. These inert fixture plants test
// source containment, not runtime authority or binary exclusion.
func TestQualificationContainmentRunnerConstructor(t *testing.T) {
	for _, mode := range []string{"qualified", "daemon", "server", "init", "variable", "qualification-init", "qualification-variable", "other-file"} {
		t.Run(mode, func(t *testing.T) {
			root, _ := containmentWrapperFixture(t, "testdata", false)
			file := "internal/server/qualification_runner_linux.go"
			text := "package server;func NewQualificationRunnerAdmission(){NewQualificationAdmission()}"
			want := "qualification authority containment: server authority dependency outside fixture constructors in " + file
			switch mode {
			case "daemon":
				path := filepath.Join(root, "cmd/swarma-credential-broker/main.go")
				b, e := os.ReadFile(path)
				if e != nil || os.WriteFile(path, []byte(strings.Replace(string(b), "_ = server.New;", "_ = server.New; _ = server.NewQualificationRunnerAdmission;", 1)), 0600) != nil {
					t.Fatal("daemon plant unavailable")
				}
				want = "qualification authority containment: NewQualificationRunnerAdmission referenced outside qualification in cmd/swarma-credential-broker/main.go"
			case "server":
				if e := os.WriteFile(filepath.Join(root, "internal/server/ordinary.go"), []byte("package server;func ordinary(){NewQualificationRunnerAdmission()}"), 0600); e != nil {
					t.Fatal(e)
				}
				want = "qualification authority containment: server authority dependency outside fixture constructors in internal/server/ordinary.go"
			case "init":
				text += ";func init(){NewQualificationRunnerAdmission()}"
			case "variable":
				text += ";var started=func()bool{NewQualificationRunnerAdmission();return true}()"
			case "other-file":
				file = "internal/server/runner_other.go"
				want = "qualification authority containment: server authority dependency outside fixture constructors in " + file
			}
			if e := os.WriteFile(filepath.Join(root, file), []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			text = "package qualify;import service \"" + containmentServer + "\";func runnerFixture(){service.NewQualificationRunnerAdmission()}"
			if mode == "qualification-init" {
				text += ";func init(){runnerFixture()}"
			} else if mode == "qualification-variable" {
				text += ";var started=func()bool{runnerFixture();return true}()"
			}
			if strings.HasPrefix(mode, "qualification-") {
				want = "qualification authority containment: authority call during package initialization in internal/qualify/runner.go"
			}
			if e := os.WriteFile(filepath.Join(root, "internal/qualify/runner.go"), []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			build := containmentGo(t, root, "build", "-p=1", "-o", filepath.Join(t.TempDir(), "fixture"), "./cmd/swarma-credential-broker")
			if out, e := build.CombinedOutput(); e != nil {
				t.Fatalf("runner containment plant does not compile: %v %s", e, out)
			}
			graph, e := containmentProductionGraph(t, root)
			if e != nil {
				t.Fatal(e)
			}
			issues, e := containmentCheck(root, graph)
			if e != nil || mode == "qualified" && len(issues) != 0 || mode != "qualified" && (len(issues) != 1 || issues[0] != want) {
				t.Fatal("runner constructor containment lost", issues, e)
			}
		})
	}
}
