//go:build linux

package claudeworker

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This helper runs only in the positive-control subprocess with an explicitly
// constructed environment. Its fixed output reveals no environment values.
func TestWorkerProcessHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "worker-profile-fixture" {
		return
	}
	for _, v := range os.Environ() {
		assertNoMaterial(t, []byte(v))
	}
	if !strings.HasPrefix(os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"), "swarma-nonsecret-") || os.Getenv("ANTHROPIC_BASE_URL") != "http://127.0.0.1:43123" || os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
		t.Fatal("child profile mismatch")
	}
	if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
		t.Fatal("ready write failed")
	}
	var release [1]byte
	if _, err := os.Stdin.Read(release[:]); err != nil {
		t.Fatal("release read failed")
	}
}

// A real non-gateway child sees only the constructed placeholder environment;
// a candidate containing fixture material is refused before any child starts.
// This proves the fixture boundary, not Claude acceptance or child isolation.
func TestWorkerProcessBoundary(t *testing.T) {
	// An actual parent-side synthetic source must not cross the spawn boundary.
	t.Setenv("ANTHROPIC_API_KEY", fakeToken)
	p := candidate(t)
	env, err := p.Environment()
	if err != nil {
		t.Fatal("environment setup failed")
	}
	bad := append([]string(nil), env...)
	bad[4] = "CLAUDE_CODE_OAUTH_TOKEN=" + fakeToken
	started := false
	if p.ValidateEnvironment(bad) == nil {
		started = true
	}
	if started {
		t.Fatal("material-bearing candidate reached spawn boundary")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestWorkerProcessHelper$", "--", "worker-profile-fixture")
	cmd.Env = env
	cmd.Dir = p.home
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("fixture input failed")
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("fixture output failed")
	}
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal("fixture start failed")
	}
	// Wait always reaps this exact owned child; closing stdin also releases it
	// when a parent assertion fails. No process pattern or foreign PID is used.
	waited := false
	t.Cleanup(func() {
		input.Close()
		if !waited {
			cmd.Wait()
		}
	})
	var ready [6]byte
	if n, err := io.ReadFull(output, ready[:]); err != nil || n != len(ready) || string(ready[:]) != "ready\n" {
		t.Fatal("fixture readiness failed")
	}
	for _, name := range []string{"environ", "cmdline"} {
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), name))
		if err != nil {
			t.Fatal("child process observation unavailable")
		}
		assertNoMaterial(t, b)
	}
	if _, err = input.Write([]byte("x")); err != nil {
		t.Fatal("fixture release failed")
	}
	input.Close()
	var rest bytes.Buffer
	if _, err = rest.ReadFrom(output); err != nil {
		t.Fatal("fixture output read failed")
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatal("fixture failed")
	}
	assertNoMaterial(t, rest.Bytes())
	assertNoMaterial(t, diagnostics.Bytes())
}
