//go:build linux && amd64 && realcandidate

package egress

import (
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/testutil/hosttest"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: the explicitly selected real binary runs only --version with an empty
// fresh home, closed proxies and the live boundary. strace follows independently.
// This is neither release qualification nor a claim about other candidate commands.
func TestRealCandidateVersion(t *testing.T) {
	hosttest.Require(t, "explicit protected real candidate and private evidence directory")
	candidate := os.Getenv("EGRESS_SMOKE_CANDIDATE")
	evidence := os.Getenv("EGRESS_SMOKE_EVIDENCE")
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute candidate and private evidence directory are required")
	}
	if os.Getenv("EGRESS_TRACE_CHILD") != "1" {
		if e := os.MkdirAll(evidence, 0700); e != nil {
			t.Fatal(e)
		}
		self, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/strace", "-f", "-e", "trace=connect", "-o", filepath.Join(evidence, "connect.trace"), self, "-test.run=^TestRealCandidateVersion$", "-test.v")
		cmd.Env = []string{"GO=" + os.Getenv("GO"), "GOTOOLCHAIN=local", "GOMAXPROCS=2", "PATH=/usr/bin:/bin", "TMPDIR=" + os.Getenv("TMPDIR"), "EGRESS_TRACE_CHILD=1", "EGRESS_TEST_LAUNCHER=" + launcher, "EGRESS_SMOKE_CANDIDATE=" + candidate, "EGRESS_SMOKE_EVIDENCE=" + evidence}
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("traced smoke: %v %s", e, b)
		}
		trace, e := os.ReadFile(filepath.Join(evidence, "connect.trace"))
		if e != nil {
			t.Fatal(e)
		}
		// Any attempted connect is made explicit for review; undecodable addresses
		// fail this conservative version-only cross-check rather than being ignored.
		attempts := 0
		for _, line := range strings.Split(string(trace), "\n") {
			if !strings.Contains(line, "connect(") {
				continue
			}
			attempts++
			t.Log("version connect attempt:", line)
			if !strings.Contains(line, "AF_UNIX") && !strings.Contains(line, "127.") && !strings.Contains(line, "::1") {
				t.Fatal("external or undecodable connect in version smoke")
			}
			if !strings.Contains(line, "ECONNREFUSED") {
				t.Fatal("unexpected successful/incomplete connect in version smoke")
			}
		}
		t.Logf("strace connect attempts=%d; external continuations=0", attempts)
		return
	}
	home := t.TempDir()
	entries, e := os.ReadDir(home)
	if e != nil || len(entries) != 0 {
		t.Fatal("home is not fresh")
	}
	// Bind without listen reserves a closed proxy port for this run. This socket
	// remains only in the test supervisor and is never inherited by the candidate.
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); e != nil {
		t.Fatal(e)
	}
	a, e := unix.Getsockname(fd)
	if e != nil {
		t.Fatal(e)
	}
	env, e := ProxyEnvironment([]string{"HOME=" + home, "CODEX_HOME=" + home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, uint16(a.(*unix.SockaddrInet4).Port), nil)
	if e != nil {
		t.Fatal(e)
	}
	out, e := os.Create(filepath.Join(evidence, "version.txt"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := Run(ctx, Config{Launcher: launcher, Executable: candidate, Args: []string{"--version"}, Env: env, Policy: Policy{}, Stdout: out, Stderr: out})
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(evidence, "boundary.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatalf("version boundary run: %v", err)
	}
	for _, v := range r.Events {
		if v.Class == "external" && v.Verdict == "allow" {
			t.Fatal("external call continued")
		}
	}
	// A failed proxy connect is safe, but every attempt must be retained above.
}
