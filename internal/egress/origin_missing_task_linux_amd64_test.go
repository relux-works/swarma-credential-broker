//go:build linux && amd64

package egress

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Claim: next refuses a missing seen task on both direct and overtaken leader
// terminal paths. The same real terminal paths without a missing task succeed.
// A test-only hook forces the stop/consume window; production has no hook.
func TestOriginMissingTaskLeaderTransition(t *testing.T) {
	dir := t.TempDir()
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(packageDir, "origin_linux_amd64.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	instrumented := string(source)
	for _, edit := range [][2]string{
		{"func (w *originOwner) next()", "var originAfterTaskPeek func(int, unix.Siginfo)\n\nfunc (w *originOwner) next()"},
		{"\t\ttid, status, terminal, err = w.observedTask(p, si)", "\t\tif originAfterTaskPeek != nil { originAfterTaskPeek(p, si) }\n\t\ttid, status, terminal, err = w.observedTask(p, si)"},
	} {
		if strings.Count(instrumented, edit[0]) != 1 {
			t.Fatal("leader transition instrumentation anchor changed")
		}
		instrumented = strings.Replace(instrumented, edit[0], edit[1], 1)
	}
	guard := "\t\tif err == nil && terminal && missing {\n\t\t\treturn 0, 0, false, unix.ECHILD\n\t\t}\n"
	if strings.Count(instrumented, guard) != 1 {
		t.Fatal("missing-task guard mutation anchor changed")
	}
	for _, knownBad := range []bool{false, true} {
		candidate := instrumented
		if knownBad {
			// Narrowing mutant: only terminal recovery loses the guard;
			// the direct-terminal refusal and both positives stay intact.
			candidate = strings.Replace(candidate, guard, "", 1)
		}
		output, err := runOriginMissingTaskOverlay(t, dir, packageDir, sourcePath, candidate)
		if !knownBad {
			if err != nil || !strings.Contains(output, "--- PASS: TestOriginMissingTaskLeaderOverlay") {
				t.Fatalf("leader transition overlay: %v\n%s", err, output)
			}
		} else if err == nil ||
			!strings.Contains(output, "--- FAIL: TestOriginMissingTaskLeaderOverlay/overtaken/missing") ||
			!strings.Contains(output, "missing seen task accepted after leader stop") ||
			!strings.Contains(output, "--- PASS: TestOriginMissingTaskLeaderOverlay/terminal/missing") ||
			!strings.Contains(output, "--- PASS: TestOriginMissingTaskLeaderOverlay/terminal/positive") ||
			!strings.Contains(output, "--- PASS: TestOriginMissingTaskLeaderOverlay/overtaken/positive") {
			t.Fatalf("missing-task mutant escaped its intended regression or broke controls: %v\n%s", err, output)
		}
		t.Logf("missing-task overlay known_bad=%t exit_error=%v\n%s", knownBad, err, output)
	}
}

func runOriginMissingTaskOverlay(t *testing.T, dir, packageDir, sourcePath, instrumented string) (string, error) {
	t.Helper()
	sourceOverlay := filepath.Join(dir, "origin_linux_amd64.go")
	if err := os.WriteFile(sourceOverlay, []byte(instrumented), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]map[string]string{"Replace": {
		sourcePath: sourceOverlay,
		filepath.Join(packageDir, "origin_missing_task_overlay_test.go"): filepath.Join(packageDir, "testdata/leader-stop-overlay_test.go"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Always instrument this small overlay, including during normal parent runs.
	cmd := exec.CommandContext(ctx, goTool, "test", "-race", "-mod=readonly", "-overlay="+overlayPath,
		"-p=1", "-count=1", "-timeout=45s", "-run=^TestOriginMissingTaskLeaderOverlay$", "-v", ".")
	cmd.Dir = packageDir
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "GOTMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GO", "CGO_ENABLED", "CC", "CXX", "GOMAXPROCS"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "GOPROXY=off", "GOAUTH=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off")
	output, err := cmd.CombinedOutput()
	return string(output), err
}
