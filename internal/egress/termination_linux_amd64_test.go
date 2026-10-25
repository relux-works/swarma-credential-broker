//go:build linux && amd64

package egress

import (
	"context"
	"crypto/sha256"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func plannedFixture(t *testing.T, writer bool, action string) (TerminationFacts, OriginFacts, Report, error) {
	t.Helper()
	originBuild.Do(func() {
		originImage = filepath.Join(tools, "origin-fixture")
		if b, e := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", originImage, "./testdata/origin").CombinedOutput(); e != nil {
			t.Fatalf("origin fixture: %v %s", e, b)
		}
	})
	image, e := os.Open(originImage)
	if e != nil {
		t.Fatal(e)
	}
	defer image.Close()
	pad, e := os.Open("/bin/true")
	if e != nil {
		t.Fatal(e)
	}
	defer pad.Close()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	in, out, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	defer out.Close()
	mode, role := "planned-owner", "qualification-owner"
	if writer {
		mode, role = "planned-writer", "qualification-writer"
	}
	if action == "wrong-domain" {
		mode += "-wrong-domain"
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(mode)))
	var o *CaseOrigin
	var c *TerminationController
	if writer {
		o, c, e = NewWriterOrigin(image, digest)
	} else {
		o, c, e = NewCrashOwnerOrigin(image, digest)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c.Kill(ctx, digest) == nil {
		t.Fatal("bootstrap authorization accepted")
	}
	done := make(chan struct{})
	started := make(chan int, 1)
	var report Report
	var runErr error
	go func() {
		defer close(done)
		report, runErr = Run(ctx, Config{Origin: o, Launcher: originImage, LauncherArgs: []string{"bootstrap", mode, "0"}, Executable: "/proc/self/fd/4", Args: []string{role, digest}, Env: []string{"GOMAXPROCS=2", "OWNER_MODE=" + mode, "OWNER_DIGEST=" + digest}, ExtraFiles: []*os.File{image, pad, w, pad, in}, Started: func(pid int) { started <- pid; w.Close(); in.Close() }})
	}()
	pid := <-started
	if action == "wrong-domain" {
		r.SetReadDeadline(time.Now().Add(4 * time.Second))
		var b [256]byte
		text := ""
		for {
			n, e := r.Read(b[:])
			text += string(b[:n])
			if strings.Contains(text, "entered") {
				cancel()
				<-done
				t.Fatal("cross-domain writer reached entered role")
			}
			if e != nil {
				break
			}
		}
	} else {
		r.SetReadDeadline(time.Now().Add(4 * time.Second))
		text := ""
		var b [64]byte
		for !strings.Contains(text, "entered") {
			n, e := r.Read(b[:])
			text += string(b[:n])
			if e != nil {
				cancel()
				<-done
				t.Fatal("measured entry missing", e, runErr)
			}
		}
		switch action {
		case "kill":
			if c.Kill(ctx, "bad") == nil {
				t.Fatal("bad gate accepted")
			}
			if e := c.Kill(ctx, digest); e != nil {
				t.Fatal(e)
			}
			if c.Kill(ctx, digest) == nil {
				t.Fatal("gate replay accepted")
			}
		case "clean":
			out.Write([]byte{1})
		case "unarmed":
			unix.Kill(pid, unix.SIGKILL)
		case "cancel":
			cancel()
		}
	}
	<-done
	return c.Facts(), o.Facts(), report, runErr
}

// Claim: only the parent's one-use live-role authorization plus the supervisor's
// actual SIGKILL and sole joined wait creates this separate certificate. Ordinary
// facts/error/report remain invalid/nonzero/incomplete for every signaled exit.
func TestCrashOwnerOrigin(t *testing.T) {
	for _, action := range []string{"kill", "clean", "unarmed", "cancel"} {
		t.Run(action, func(t *testing.T) {
			f, o, r, e := plannedFixture(t, false, action)
			if action == "kill" {
				if !f.Valid() || f.Signal != 9 || f.Exit != -1 || f.Waits != 1 || e == nil || !r.Incomplete || o.Verified || o.Entered || !o.Joined {
					t.Fatalf("planned terminal facts: %+v %+v %+v %v", f, o, r, e)
				}
			} else if f.Valid() {
				t.Fatalf("unplanned terminal accepted: %+v", f)
			}
			if action == "clean" && (e != nil || r.Incomplete || !o.Verified || !o.Entered || !o.Joined) {
				t.Fatal("normal owner semantics changed", o, r, e)
			}
		})
	}
}

// Claim: the writer has an independent measured role domain. An owner-domain
// response cannot enter it or earn a planned-stop certificate.
func TestWriterRoleOrigin(t *testing.T) {
	for _, action := range []string{"kill", "wrong-domain"} {
		t.Run(action, func(t *testing.T) {
			f, o, _, e := plannedFixture(t, true, action)
			if action == "kill" {
				if !f.Valid() || e == nil {
					t.Fatal("writer stop missing", f, e)
				}
			} else if f.Valid() || o.Entered || e == nil {
				t.Fatal("cross-domain entry accepted", f, o, e)
			}
		})
	}
}

// Claim: certificate validation refuses every individually missing lifecycle
// obligation and cannot be constructed from public fields alone.
func TestPlannedTerminationFacts(t *testing.T) {
	base := TerminationFacts{Context: "context", Gate: strings.Repeat("a", 64), PID: 1, Signal: 9, Exit: -1, Waits: 1, WaitError: "signal: killed", Verified: true, Entered: true, SignalSent: true, TraceComplete: true, Joined: true, valid: true}
	if !base.Valid() {
		t.Fatal("valid positive rejected")
	}
	plants := []func(*TerminationFacts){func(f *TerminationFacts) { f.valid = false }, func(f *TerminationFacts) { f.Signal = 15 }, func(f *TerminationFacts) { f.Exit = 137 }, func(f *TerminationFacts) { f.Waits = 2 }, func(f *TerminationFacts) { f.WaitError = "" }, func(f *TerminationFacts) { f.TraceComplete = false }, func(f *TerminationFacts) { f.Joined = false }, func(f *TerminationFacts) { f.SignalSent = false }, func(f *TerminationFacts) { f.Entered = false }, func(f *TerminationFacts) { f.Verified = false }, func(f *TerminationFacts) { f.Gate = "bad" }}
	for i, plant := range plants {
		f := base
		plant(&f)
		if f.Valid() {
			t.Fatalf("missing obligation %d accepted", i)
		}
	}
}
