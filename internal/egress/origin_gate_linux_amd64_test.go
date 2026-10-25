//go:build linux && amd64

package egress

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var originBuild sync.Once
var originImage string

func originFixture(t *testing.T, mode string, code int, ready func()) (OriginFacts, Report, *os.ProcessState, int, error) {
	t.Helper()
	originBuild.Do(func() {
		originImage = filepath.Join(tools, "origin-fixture")
		cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", originImage, "./testdata/origin")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("origin fixture build: %v %s", e, b)
		}
	})
	image, e := os.Open(originImage)
	if e != nil {
		t.Fatal(e)
	}
	defer image.Close()
	other, e := os.Open("/bin/true")
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	padR, padW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer padR.Close()
	defer padW.Close()
	o, e := NewCaseOrigin(image, func() error {
		if ready != nil {
			ready()
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if mode == "missing-credentials" {
		if e = unix.SetsockoptInt(int(o.parent.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 0); e != nil {
			t.Fatal(e)
		}
	}
	senderFD := int(o.child.Fd())
	senderDone := make(chan struct{})
	if mode == "wrong-sender" {
		go func() {
			defer close(senderDone)
			b := make([]byte, 32)
			if n, e := unix.Read(senderFD, b); e == nil && n == 32 {
				_, _ = unix.Write(senderFD, b)
			}
		}()
	} else {
		close(senderDone)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var state *os.ProcessState
	callbacks := 0
	started := 0
	owner := unix.Gettid()
	// Run's owner may start on another thread; only the actual Start/Wait pair
	// must stay on the same locked thread, not this calling goroutine's thread.
	cfg := Config{Origin: o, Launcher: originImage, LauncherArgs: []string{"bootstrap", mode, strconv.Itoa(code)}, Executable: "/proc/self/fd/4", Args: []string{"case", mode, strconv.Itoa(code)}, Env: []string{"GOMAXPROCS=2"}, ExtraFiles: []*os.File{image, padR, w, other, padR}, Started: func(pid int) {
		started = pid
		owner = unix.Gettid()
		if mode == "cancelled" {
			cancel()
		}
	}, Waited: func(s *os.ProcessState) {
		state = s
		callbacks++
		if unix.Gettid() != owner || s == nil || s.Pid() != started {
			t.Error("wait callback lost case owner/state")
		}
	}}
	report, err := Run(ctx, cfg)
	_ = unix.Shutdown(senderFD, unix.SHUT_RDWR)
	<-senderDone
	o.child.Close()
	return o.Facts(), report, state, callbacks, err
}

// Claim: the integrated optional path proves measured post-exec entry, services
// the real unchanged seccomp policy, and retains exact 0/17 terminal status.
func TestOriginGate(t *testing.T) {
	for _, code := range []int{0, 17} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f, r, s, n, e := originFixture(t, "valid", code, nil)
			if !f.Verified || !f.Entered || !f.Joined || !f.Nonleader || s == nil || s.ExitCode() != code || n != 1 || code == 0 && e != nil || code == 17 && e == nil {
				t.Fatalf("origin/wait facts: %+v %v %d %v", f, s, n, e)
			}
			event(t, r, "socket", "socket", "allow")
			event(t, r, "connect", "loopback", "refuse")
		})
	}
}

// Claim: unexpected image/argv never reach the verified-exec callback, whereas
// the exact invocation does. This independently detects a skipped identity gate.
func TestOriginExecIdentity(t *testing.T) {
	for _, mode := range []string{"unexpected-exec", "wrong-argv", "oversized-argv", "valid"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			f, _, _, _, e := originFixture(t, mode, 0, func() { calls++ })
			if mode == "valid" {
				if e != nil || !f.Entered || calls != 1 {
					t.Fatal("valid exec rejected")
				}
			} else if calls != 0 || f.Entered || e == nil {
				t.Fatal("unexpected exec reached verified callback")
			}
		})
	}
}

// Claim: a response queued before exec and an actual different-PID writer
// cannot answer for the post-exec case; an actual canonical reply can.
func TestOriginPostExecChallenge(t *testing.T) {
	for _, mode := range []string{"pre-exec", "wrong-sender", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _, e := originFixture(t, mode, 0, nil)
			if mode == "valid" {
				if e != nil || !f.Entered {
					t.Fatal("valid entry rejected", f, e)
				}
			} else if e == nil || f.Entered {
				t.Fatal("pre-case response gained entry")
			}
		})
	}
}

// Claim: missing kernel credentials, malformed and duplicate responses are
// refused; the fixed-size credential-tagged exchange succeeds.
func TestOriginSocketContract(t *testing.T) {
	for _, mode := range []string{"missing-credentials", "malformed", "duplicate", "empty-duplicate", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _, e := originFixture(t, mode, 0, nil)
			if mode == "valid" {
				if e != nil || !f.Entered {
					t.Fatal("valid socket rejected")
				}
			} else if e == nil || f.Verified {
				t.Fatal("invalid origin socket accepted")
			}
		})
	}
}

// Claim: final wait and callback preserve the real case's 0 and 17 statuses,
// including cancellation at the initial trace stop. A helper status is not equivalent.
func TestOriginWaitOwnership(t *testing.T) {
	for _, code := range []int{0, 17} {
		f, _, s, n, _ := originFixture(t, "valid", code, nil)
		if !f.Joined || s == nil || s.ExitCode() != code || n != 1 {
			t.Fatal("actual case wait/status missing", f, s, n)
		}
	}
	f, _, s, n, e := originFixture(t, "cancelled", 0, nil)
	if e == nil || !f.Joined || f.Entered || s == nil || s.ExitCode() != -1 || n != 1 {
		t.Fatal("cancelled trace lost sole terminal wait", f, s, n, e)
	}
}

// Claim: tracing handles non-leader runtime exec and refuses an additional exec;
// the ordinary nil-Origin boundary retains its file-only descriptor contract.
func TestOriginTraceLifecycle(t *testing.T) {
	f, _, _, _, e := originFixture(t, "later-exec", 0, nil)
	if e == nil || f.Verified {
		t.Fatal("later exec accepted")
	}
	f, _, s, n, e := originFixture(t, "descendant", 0, nil)
	if e != nil || !f.Joined || s == nil || s.ExitCode() != 0 || n != 1 {
		t.Fatal("descendant cleanup lost case wait", f, s, n, e)
	}
}

// Claim: the ordinary nil-Origin path retains its notification decisions and
// file-only input contract, including rejection of generic socket descriptors.
func TestOriginDefaultPath(t *testing.T) {
	r, _, e := runProbe(t, Policy{}, "closed", "9")
	if e != nil {
		t.Fatal("default boundary failed", e)
	}
	event(t, r, "connect", "loopback", "refuse")
	TestExplicitInputs(t)
}

// Claim: bounded repeated rejection joins the case even when SIGKILL races
// runtime clone registration; this exercises real tracing, not a waiter stub.
func TestOriginCloneCancellation(t *testing.T) {
	for range 8 {
		f, _, s, n, e := originFixture(t, "wrong-sender", 0, nil)
		if e == nil || f.Entered || !f.Joined || s == nil || s.ExitCode() != -1 || n != 1 {
			t.Fatal("clone cancellation lost actual join", f, s, n, e)
		}
	}
}
