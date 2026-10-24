//go:build linux

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Claim: missing strace and seccomp-denied ptrace skip with a named UNVERIFIED
// cause in development and fail qualification. With tracing available, the real
// disappearance control applies and a later assertion remains a failure.
// The denied control uses the unchanged x86_64 seccomp wrapper; it restricts only
// its subprocess tree, returning EPERM for ptrace and allowing other syscalls.
func TestTraceAvailability(t *testing.T) {
	self, err := os.Executable()
	must(t, err)
	for _, kind := range []string{"missing-strace", "denied-ptrace", "working-tracer"} {
		for _, mode := range []string{"0", "1"} {
			t.Run(kind+"/mode="+mode, func(t *testing.T) {
				requiredEvidenceRow(t)
				args := []string{self, "--fixture-tools", fakePath, supervisorPath, "-test.run=^TestTraceAvailabilityWitness$", "-test.v"}
				if kind == "denied-ptrace" {
					if _, err := exec.LookPath("strace"); err != nil {
						unverifiedTrace(t, err)
					}
					if runtime.GOARCH != "amd64" {
						unverifiedTrace(t, fmt.Errorf("ptrace denial control requires linux/amd64"))
					}
					python, err := exec.LookPath("python3")
					if err != nil {
						unverifiedTrace(t, err)
					}
					args = append([]string{python, filepath.Join("testdata", "ptrace_denied.py")}, args...)
				}
				if kind == "working-tracer" {
					if _, err := exec.LookPath("strace"); err != nil {
						unverifiedTrace(t, err)
					}
					requirePtrace(t)
				}
				cmd := exec.Command(args[0], args[1:]...)
				for _, entry := range os.Environ() {
					if strings.HasPrefix(entry, "RUNNER_QUALIFICATION=") || strings.HasPrefix(entry, "RUNNER_TRACE_WITNESS=") || (kind == "missing-strace" && strings.HasPrefix(entry, "PATH=")) {
						continue
					}
					cmd.Env = append(cmd.Env, entry)
				}
				cmd.Env = append(cmd.Env, "RUNNER_QUALIFICATION="+mode, "RUNNER_TRACE_WITNESS=1")
				if kind == "missing-strace" {
					cmd.Env = append(cmd.Env, "PATH="+t.TempDir())
				}
				output, runErr := cmd.CombinedOutput()
				want, verdict := 1, "--- FAIL: TestTraceAvailabilityWitness"
				if mode == "0" && kind != "working-tracer" {
					want, verdict = 0, "--- SKIP: TestTraceAvailabilityWitness"
				}
				if cmd.ProcessState == nil {
					t.Fatalf("control did not start: %v", runErr)
				}
				t.Logf("child exit=%d, want=%d\n%s", cmd.ProcessState.ExitCode(), want, output)
				if cmd.ProcessState.ExitCode() != want || !strings.Contains(string(output), verdict) {
					t.Fatalf("wrong availability verdict: %v\n%s", runErr, output)
				}
				if kind == "working-tracer" {
					if !strings.Contains(string(output), "applied trace assertion witness") || strings.Contains(string(output), "UNVERIFIED:") {
						t.Fatal("applied assertion failure was misclassified")
					}
				} else {
					cause := "strace unavailable"
					if kind == "denied-ptrace" {
						cause = "ptrace unavailable"
					}
					if !strings.Contains(string(output), "UNVERIFIED: TestTraceAvailabilityWitness:") || !strings.Contains(string(output), cause) {
						t.Fatal("unavailable trace did not name its row and cause")
					}
					if kind == "denied-ptrace" && !strings.Contains(string(output), "operation not permitted") {
						t.Fatal("denied control did not establish EPERM")
					}
				}
			})
		}
	}
}

// Child-only assertion witness: failure is reached only after the actual native
// stat-open/SIGSTOP/ESRCH control succeeds; an unavailable trace exits earlier.
func TestTraceAvailabilityWitness(t *testing.T) {
	if os.Getenv("RUNNER_TRACE_WITNESS") != "1" {
		return
	}
	requiredEvidenceRow(t)
	self, err := os.Executable()
	must(t, err)
	traceProcRead(t, false, true, self, "--fixture-tools", fakePath, supervisorPath, "-test.run=^TestStopRequiresAbsentGroup$", "-test.v")
	t.Fatal("applied trace assertion witness")
}
