//go:build linux

package runner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Register required evidence before any possible skip, including in parent
// tests. Development skips stay explicit; qualification cannot accept them.
func requiredEvidenceRow(t *testing.T) {
	t.Helper()
	if os.Getenv("RUNNER_QUALIFICATION") == "1" {
		t.Cleanup(func() {
			if t.Skipped() {
				t.Errorf("UNVERIFIED: required row %s was skipped", t.Name())
			}
		})
	}
}

// Real subprocess controls prove missing strace and a skipped required row fail
// qualification with a named UNVERIFIED diagnostic, while development may skip.
// They require the intended test verdict, not just any subprocess failure.
func TestQualificationMode(t *testing.T) {
	if os.Getenv("RUNNER_TEST_SKIP_REQUIRED_ROW") == "1" {
		requiredEvidenceRow(t)
		t.Skip("controlled required-row skip")
	}
	self, err := os.Executable()
	must(t, err)
	for _, kind := range []string{"missing-strace", "skipped-row"} {
		for _, mode := range []string{"0", "1"} {
			t.Run(kind+"/mode="+mode, func(t *testing.T) {
				selector := "^TestQualificationMode$"
				row := "TestQualificationMode"
				if kind == "missing-strace" {
					selector = "^TestCommandProcDisappearance$/^follow=false$/^disappear=false$"
					row = "TestCommandProcDisappearance/follow=false/disappear=false"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, self, "-test.run="+selector, "-test.v")
				// Replace only these fixture variables; retain the selected
				// absolute GO path for TestMain's ordinary helper builds.
				for _, entry := range os.Environ() {
					if strings.HasPrefix(entry, "RUNNER_QUALIFICATION=") || strings.HasPrefix(entry, "RUNNER_TEST_SKIP_REQUIRED_ROW=") || (kind == "missing-strace" && strings.HasPrefix(entry, "PATH=")) {
						continue
					}
					cmd.Env = append(cmd.Env, entry)
				}
				cmd.Env = append(cmd.Env, "RUNNER_QUALIFICATION="+mode)
				if kind == "missing-strace" {
					cmd.Env = append(cmd.Env, "PATH="+t.TempDir())
				} else {
					cmd.Env = append(cmd.Env, "RUNNER_TEST_SKIP_REQUIRED_ROW=1")
				}
				output, runErr := cmd.CombinedOutput()
				want := 0
				verdict := "--- SKIP: " + row
				if mode == "1" {
					want = 1
					verdict = "--- FAIL: " + row
				}
				if cmd.ProcessState == nil {
					t.Fatalf("control process did not start: %v", runErr)
				}
				got := cmd.ProcessState.ExitCode()
				t.Logf("child exit=%d, want=%d\n%s", got, want, output)
				if ctx.Err() != nil || got != want || !strings.Contains(string(output), verdict) {
					t.Fatalf("wrong control failure: %v\n%s", runErr, output)
				}
				if mode == "1" && (!strings.Contains(string(output), "UNVERIFIED:") || !strings.Contains(string(output), row)) {
					t.Fatal("qualification did not name its unverified row")
				}
			})
		}
	}
}
