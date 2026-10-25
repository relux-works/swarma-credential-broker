//go:build linux

package timeconftest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Claim: actual external compilation admits ordinary public construction, but
// rejects private-field assignment, witness arguments, and qualification-path
// injection with the specific compiler diagnostic, under both build modes.
func TestFixtureExternalCompileBoundaries(t *testing.T) {
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	const module = "github.com/relux-works/swarma-credential-broker"
	type sourceCase struct{ name, body, diagnostic string }
	cases := []sourceCase{
		{"public-constructor", `_,_ = tc.NewConsumer(tc.Enrollment{},tc.Policy{},"unused")`, ""},
		{"private-store", `c:=new(tc.Consumer);c.store.witness=nil`, "cannot refer to unexported field store"},
		{"private-enrollment", `c:=new(tc.Consumer);c.enrollment=tc.Enrollment{}`, "cannot refer to unexported field enrollment"},
		{"witness-injection", `_,_ = tc.NewConsumer(tc.Enrollment{},tc.Policy{},"unused",tc.ClosedWitness{})`, "too many arguments in call to tc.NewConsumer"},
		{"private-path-injection", `c:=new(tc.Consumer);c.timePath=nil`, "cannot refer to unexported field timePath"},
	}
	for _, tag := range []string{"", "swarma_timeconf_fixture"} {
		tagCases := cases
		if tag != "" {
			tagCases = append(append([]sourceCase{}, cases...), sourceCase{"private-fixture-consumer", `c:=new(tc.FixtureConsumer);c.consumer=nil`, "cannot refer to unexported field consumer"})
		}
		for _, v := range tagCases {
			t.Run(tag+"/"+v.name, func(t *testing.T) {
				root := t.TempDir()
				files := map[string]string{"go.mod": "module consumer.example/compilecheck\n\ngo 1.25\nrequire " + module + " v0.0.0\nreplace " + module + " => " + filepath.ToSlash(repo) + "\n", "consumer.go": "package consumer\nimport tc \"" + module + "/timeconf\"\nfunc check(){" + v.body + "}\n"}
				for name, source := range files {
					if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				cmd := exec.CommandContext(ctx, goTool, "build", "-mod=mod", "-tags="+tag, ".")
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GOWORK=off")
				out, err := cmd.CombinedOutput()
				if v.diagnostic == "" {
					if err != nil {
						t.Fatalf("positive compilation failed: %v\n%s", err, out)
					}
					return
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), v.diagnostic) {
					t.Fatalf("want compiler exit 1 and %q; got %v\n%s", v.diagnostic, err, out)
				}
			})
		}
	}
}
