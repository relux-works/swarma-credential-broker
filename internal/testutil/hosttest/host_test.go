package hosttest

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Claim: only the exact opt-in value skips a fixture, the skip names its reason,
// and an empty reason fails even in CI. Controls execute the real testing API.
func TestRequire(t *testing.T) {
	for _, tc := range []struct {
		mode, reason, verdict string
		code                  int
	}{
		{"", "fixture prerequisite", "--- PASS: TestRequireWitness", 0},
		{"0", "fixture prerequisite", "--- PASS: TestRequireWitness", 0},
		{"true", "fixture prerequisite", "--- PASS: TestRequireWitness", 0},
		{"1", "fixture prerequisite", "--- SKIP: TestRequireWitness", 0},
		{"1", "", "--- FAIL: TestRequireWitness", 1},
	} {
		t.Run(tc.mode+"/"+tc.reason, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRequireWitness$", "-test.v")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "SWARMA_TEST_UNPRIVILEGED=") && !strings.HasPrefix(entry, "HOST_GATE_WITNESS=") && !strings.HasPrefix(entry, "HOST_GATE_REASON=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "SWARMA_TEST_UNPRIVILEGED="+tc.mode, "HOST_GATE_WITNESS=1", "HOST_GATE_REASON="+tc.reason)
			out, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.code || !strings.Contains(string(out), tc.verdict) {
				t.Fatalf("wrong host fixture verdict: %v\n%s", err, out)
			}
			if tc.mode == "1" && tc.reason != "" && !strings.Contains(string(out), "host fixture unavailable in unprivileged CI: "+tc.reason) {
				t.Fatal("skip omitted its reason")
			}
		})
	}
}

// Child-only witness distinguishes reaching the fixture from a real skip.
func TestRequireWitness(t *testing.T) {
	if os.Getenv("HOST_GATE_WITNESS") != "1" {
		return
	}
	Require(t, os.Getenv("HOST_GATE_REASON"))
	t.Log("fixture reached")
}
