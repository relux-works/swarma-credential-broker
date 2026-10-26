//go:build linux && amd64

package egress

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var runnerOriginBuild sync.Once
var runnerOriginImage, runnerOriginFake string

func runnerOriginTools(t *testing.T) {
	t.Helper()
	runnerOriginBuild.Do(func() {
		runnerOriginImage, runnerOriginFake = filepath.Join(tools, "runner-origin"), filepath.Join(tools, "runner-fake")
		for _, b := range []struct{ path, pkg string }{{runnerOriginImage, "./testdata/runnerorigin"}, {runnerOriginFake, "../runner/testdata/appserver"}} {
			cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", b.path, b.pkg)
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("fixture build: %v %s", e, out)
			}
			runnerCheck(t, os.Chmod(b.path, 0755))
		}
	})
}
func newRunnerTestOrigin(t *testing.T, args []string) (*RunnerOrigin, *os.File) {
	t.Helper()
	runnerOriginTools(t)
	image, e := os.Open(runnerOriginImage)
	runnerCheck(t, e)
	t.Cleanup(func() { image.Close() })
	data, e := os.ReadFile(runnerOriginImage)
	runnerCheck(t, e)
	o, e := NewRunnerOrigin(image, fmt.Sprintf("%x", sha256.Sum256(data)), append([]string{"/proc/self/fd/3"}, args...))
	runnerCheck(t, e)
	return o, image
}
func traceRunnerTest(t *testing.T, mode string, started func(int)) (*RunnerOrigin, RunnerTraceResult, error) {
	t.Helper()
	args := []string{mode}
	o, _ := newRunnerTestOrigin(t, args)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner, waits := 0, 0
	r, e := TraceRunner(ctx, RunnerTraceConfig{Origin: o, Args: args, Env: []string{"GOMAXPROCS=2"}, Started: func(pid int) {
		owner = unix.Gettid()
		if started != nil {
			started(pid)
		}
	}, Waited: func(s *os.ProcessState) {
		waits++
		if unix.Gettid() != owner {
			t.Error("wait left Start thread")
		}
	}})
	if waits != 1 {
		t.Fatal("missing sole wait", waits)
	}
	return o, r, e
}

// Claim: only the exact image/argv at the direct child's initial exec stop
// passes. Each identity/stop/parent gate is independently rejected. A real
// status consumed after verified exec cannot supply joined origin afterward.
func TestRunnerOriginExecIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "image", "digest", "argv", "missing-stop", "non-child", "stolen-status"} {
		t.Run(mode, func(t *testing.T) {
			o, image := newRunnerTestOrigin(t, []string{"threads"})
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			cmd := exec.Command("/proc/self/fd/3", "threads")
			cmd.ExtraFiles = []*os.File{image}
			cmd.Env = []string{"GOMAXPROCS=2"}
			cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
			runnerCheck(t, cmd.Start())
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			var status unix.WaitStatus
			pid := cmd.Process.Pid
			if p, e := unix.Wait4(pid, &status, 0, nil); e != nil || p != pid {
				t.Fatal("exec stop", p, e)
			}
			switch mode {
			case "image":
				f, e := os.CreateTemp(t.TempDir(), "same-bytes")
				runnerCheck(t, e)
				defer f.Close()
				_, e = io.Copy(f, image)
				runnerCheck(t, e)
				o.image = f
			case "digest":
				o.digest = strings.Repeat("0", 64)
			case "argv":
				o.argv = append(o.argv, "unexpected")
			case "missing-stop":
				status = unix.WaitStatus(uint32(unix.SIGSTOP)<<8 | 0x7f)
			case "non-child":
				w := originOwner{pid: os.Getpid(), fd: -1, tasks: map[int]bool{os.Getpid(): true}}
				_, _, _, e := runnerNext(&w)
				if len(w.tasks) < 2 || !errors.Is(e, ErrRunnerOriginUnavailable) {
					t.Fatal("missing fresh thread inventory or non-child accepted", w.tasks, e)
				}
				if e = runnerChild(os.Getpid()); !errors.Is(e, ErrRunnerOriginUnavailable) {
					t.Fatal("non-child accepted", e)
				}
				return
			}
			e := runnerExecStop(pid, status, o)
			if mode == "stolen-status" {
				runnerCheck(t, e)
				o.verified.Store(true)
				o.pid.Store(int64(pid))
				runnerCheck(t, unix.PtraceDetach(pid))
				if p, e := unix.Wait4(pid, &status, 0, nil); e != nil || p != pid {
					t.Fatal("fault wait", p, e)
				}
				_, e = runnerConsumeWait(cmd, o, true)
				if !errors.Is(e, ErrRunnerOriginUnavailable) || o.Facts().Joined {
					t.Fatal("stolen terminal status supplied origin", e)
				}
			} else if mode == "valid" {
				runnerCheck(t, e)
			} else if !errors.Is(e, ErrRunnerOriginUnavailable) {
				t.Fatal("invalid origin accepted", mode, e)
			}
		})
	}
}

// Claim: actual Go runtime thread clones are retained and resumed; the sole
// parent wait preserves exit 0/17 without changing a valid origin into failure.
func TestRunnerOriginWaitAndThreads(t *testing.T) {
	for mode, want := range map[string]int{"threads": 0, "exit17": 17} {
		t.Run(mode, func(t *testing.T) {
			o, r, e := traceRunnerTest(t, mode, nil)
			f := o.Facts()
			if e != nil || !f.Verified || !f.Joined || r.State == nil || r.State.Pid() != f.PID || r.State.ExitCode() != want || o.Live(f.PID) {
				t.Fatal("origin/wait", f, r, e)
			}
			if mode == "threads" && (r.Threads < 4 || r.Children != 0) {
				t.Fatal("thread topology", r)
			}
			var status unix.WaitStatus
			if _, e := unix.Wait4(f.PID, &status, unix.WNOHANG, nil); e != unix.ECHILD {
				t.Fatal("terminal status not consumed", e)
			}
		})
	}
}

// Claim: death before the initial stop and a later case exec invalidate origin;
// early death still retains the actual consuming signal wait as diagnostics.
func TestRunnerOriginUnavailableLifecycle(t *testing.T) {
	for _, mode := range []string{"before-stop", "exec"} {
		t.Run(mode, func(t *testing.T) {
			arg := mode
			if mode == "before-stop" {
				arg = "threads"
			}
			o, r, e := traceRunnerTest(t, arg, func(pid int) {
				if mode == "before-stop" {
					runnerCheck(t, unix.Kill(pid, unix.SIGKILL))
				}
			})
			if !errors.Is(e, ErrRunnerOriginUnavailable) || o.Facts().Verified || o.Live(o.Facts().PID) {
				t.Fatal("unavailable origin credited", o.Facts(), r, e)
			}
			if mode == "before-stop" && (!o.Facts().Joined || r.State == nil || r.State.ExitCode() != -1) {
				t.Fatal("lost actual early wait", r, e)
			}
		})
	}
}

// Claim: tracing the direct case composes with real runner.Command, session
// supervisor, version probe and nested egress tracer. Only synthetic authority
// and the existing fake app-server are used; this grants no row/vendor credit.
func TestRunnerOriginNestedRunner(t *testing.T) {
	for _, traced := range []bool{false, true} {
		t.Run(fmt.Sprint(traced), func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			project := filepath.Join(root, "project")
			for _, p := range []string{home, project} {
				runnerCheck(t, os.Mkdir(p, 0700))
			}
			runnerCheck(t, os.WriteFile(filepath.Join(project, ".git"), nil, 0600))
			runnerCheck(t, os.WriteFile(filepath.Join(home, "scenario.json"), []byte(`{"Boundary":true}`), 0600))
			runnerOriginTools(t)
			args := []string{"compose", root, runnerOriginFake}
			o, _ := newRunnerTestOrigin(t, args)
			out, e := os.CreateTemp(root, "trace-output")
			runnerCheck(t, e)
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var r RunnerTraceResult
			if traced {
				r, e = TraceRunner(ctx, RunnerTraceConfig{Origin: o, Args: args, Env: []string{"GOMAXPROCS=2"}, Stdout: out, Stderr: out})
			} else {
				cmd := exec.CommandContext(ctx, runnerOriginImage, args...)
				cmd.Env = []string{"GOMAXPROCS=2"}
				cmd.Stdout = out
				cmd.Stderr = out
				e = cmd.Run()
				r.State = cmd.ProcessState
			}
			output, _ := os.ReadFile(out.Name())
			if e != nil || r.State == nil || r.State.ExitCode() != 0 || traced && (!o.Facts().Verified || !o.Facts().Joined || r.Children < 2) {
				t.Fatalf("nested runner: %+v %+v %v %s", o.Facts(), r, e, output)
			}
			answer, e := os.ReadFile(filepath.Join(root, "answer"))
			if e != nil || string(answer) != "answer" {
				t.Fatal("positive session failed", e, string(answer))
			}
			f, e := os.Open(filepath.Join(home, "boundary.jsonl"))
			runnerCheck(t, e)
			defer f.Close()
			decoder := json.NewDecoder(f)
			for range 2 {
				var b Report
				if e := decoder.Decode(&b); e != nil || b.Incomplete || b.Summary == nil {
					t.Fatal("nested trace incomplete", b, e)
				}
				for _, c := range b.Summary {
					if c.Refused != 0 {
						t.Fatal("unexpected boundary refusal", b)
					}
				}
			}
		})
	}
}

func runnerCheck(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

// Claim: the new callback runs at the verified initial stop, before case
// userspace, and callback refusal invalidates origin while preserving sole wait.
func TestRunnerOriginVerifiedCallback(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		o, _ := newRunnerTestOrigin(t, []string{"threads"})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		calls := 0
		r, e := TraceRunner(ctx, RunnerTraceConfig{Origin: o, Args: []string{"threads"}, Env: []string{"GOMAXPROCS=2"}, Verified: func() error {
			calls++
			if !o.Live(o.Facts().PID) {
				t.Error("callback before verified exec")
			}
			if refuse {
				return ErrRunnerOriginUnavailable
			}
			return nil
		}})
		cancel()
		if calls != 1 || r.State == nil || !o.Facts().Joined || (e != nil) != refuse || o.Facts().Verified == refuse {
			t.Fatal("verified callback/wait", calls, o.Facts(), r, e)
		}
	}
}
