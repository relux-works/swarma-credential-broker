//go:build linux && amd64

package egress

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Claim: the production planned-termination recorder grants joined credit only
// for this real child's terminal zero/nonzero/signal state, never a ptrace STOP.
// This is accounting evidence, not a planned Stop certificate or entry claim.
func TestTerminationWaitTerminalOnly(t *testing.T) {
	for _, kind := range []string{"stop", "zero", "nonzero", "signal"} {
		t.Run(kind, func(t *testing.T) {
			state, err := ownedWaitState(t, kind)
			o := &CaseOrigin{}
			o.pid.Store(int64(state.Pid()))
			_, c, _ := plannedOrigin(o)
			c.sent("", false)
			c.joined(state, err, ErrUnavailable, false, 0)
			f := c.Facts()
			if f.Joined != (kind != "stop") {
				t.Fatalf("nonterminal or missing terminal credit: kind=%s joined=%v state=%v", kind, f.Joined, state)
			}
			if f.Valid() {
				t.Fatal("unarmed wait manufactured Stop certificate")
			}
		})
	}
}

func startOwnedWait(t *testing.T, kind string) (*exec.Cmd, int) {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if kind == "nonzero" {
		cmd = exec.Command("/bin/sh", "-c", "exit 17")
	}
	if kind == "stop" {
		cmd = exec.Command("/bin/true")
	}
	if kind == "signal" || kind == "live" {
		cmd = exec.Command("/bin/sleep", "30")
	}
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	fd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &fd, Ptrace: kind == "stop", Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		if fd >= 0 {
			defer unix.Close(fd)
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		}
		// Only this owned child is selected; terminal Wait already consumed it or
		// a real STOP still leaves it waitable. Never signal a numeric reused PID.
		if fd < 0 {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
		defer cmd.Process.Release()
		for {
			var status unix.WaitStatus
			_, err := unix.Wait4(pid, &status, unix.WALL, nil)
			if err == unix.EINTR {
				continue
			}
			if err == unix.ECHILD {
				return
			}
			if err != nil {
				t.Error("owned child reap", err)
				return
			}
			if status.Exited() || status.Signaled() {
				return
			}
			_ = unix.PtraceCont(pid, int(unix.SIGKILL))
		}
	})
	if fd < 0 {
		t.Fatal("fixture missing owned pidfd before wait")
	}
	if kind == "signal" {
		if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	return cmd, fd
}

func ownedWaitState(t *testing.T, kind string) (*os.ProcessState, error) {
	t.Helper()
	cmd, _ := startOwnedWait(t, kind)
	err := cmd.Wait()
	state := cmd.ProcessState
	if state == nil {
		t.Fatal("no actual wait state", err)
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || kind == "stop" && !status.Stopped() || kind == "signal" && (!status.Signaled() || status.Signal() != syscall.SIGKILL) || kind == "zero" && (!status.Exited() || status.ExitStatus() != 0) || kind == "nonzero" && (!status.Exited() || status.ExitStatus() != 17) {
		t.Fatal("wrong real fixture state", state, err)
	}
	t.Logf("actual owned pid=%d state=%q stopped=%v exited=%v signaled=%v", state.Pid(), state.String(), status.Stopped(), status.Exited(), status.Signaled())
	return state, err
}

// Claim: the actual production final-wait component may publish only a terminal
// state of its owned child. A genuine pending ptrace STOP must be drained/reaped,
// never sent to Waited or credited as a terminal result. No wait result is mocked.
func TestOriginFinalWaitTerminalOnly(t *testing.T) {
	for _, kind := range []string{"stop", "zero", "nonzero", "signal"} {
		t.Run(kind, func(t *testing.T) {
			cmd, fd := startOwnedWait(t, kind)
			if kind == "stop" {
				var si unix.Siginfo
				if err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &si, unix.WSTOPPED|unix.WNOWAIT|unix.WALL, nil); err != nil || si.Code != 4 {
					t.Fatal("no real pending trace stop", si.Code, err)
				}
				t.Log("real ptrace STOP remains pending before production final wait")
			}
			o := &CaseOrigin{}
			o.pid.Store(int64(cmd.Process.Pid))
			calls := 0
			err := o.finishWait(cmd, Config{Waited: func(state *os.ProcessState) {
				calls++
				if kind == "stop" {
					if state != nil || o.Facts().Joined {
						t.Errorf("production published nonterminal joined credit: joined=%v state=%v", o.Facts().Joined, state)
					}
					return
				}
				if state == nil {
					t.Error("terminal control lost state")
					return
				}
				status, ok := state.Sys().(syscall.WaitStatus)
				if !ok || !status.Exited() && !status.Signaled() {
					t.Errorf("production published nonterminal joined credit: joined=%v state=%v", o.Facts().Joined, state)
				}
			}}, &originOwner{pid: cmd.Process.Pid, fd: fd, tasks: map[int]bool{cmd.Process.Pid: true}})
			if kind == "stop" {
				var status unix.WaitStatus
				pid, e := unix.Wait4(cmd.Process.Pid, &status, unix.WNOHANG|unix.WALL, nil)
				if calls != 1 || o.Facts().Joined || err == nil || e != unix.ECHILD {
					t.Fatalf("STOP was credited or owned child not terminally reaped: calls=%d joined=%v waitpid=%d status=%v reap=%v err=%v", calls, o.Facts().Joined, pid, status, e, err)
				}
				return
			}
			if calls != 1 || !o.Facts().Joined {
				t.Fatal("actual terminal wait missing", calls, o.Facts(), err)
			}
			st := cmd.ProcessState
			if st == nil {
				t.Fatal("real terminal process state missing", err)
			}
			status := st.Sys().(syscall.WaitStatus)
			if kind == "signal" {
				if !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("cleanup did not preserve genuine signal death", st, err)
				}
			}
			if kind == "zero" && (err != nil || st.ExitCode() != 0) || kind == "nonzero" && (err == nil || st.ExitCode() != 17) {
				t.Fatal("real exit status changed", st, err)
			}
		})
	}
}

// Claim: fresh consumption is required, duplicate finalization emits no second
// callback, and a different real child identity cannot gain this origin's credit.
// All children are owned, and a consumed/missing wait is actual ECHILD evidence.
func TestOriginFinalWaitUnavailable(t *testing.T) {
	for _, kind := range []string{"consumed", "stale-terminal", "stale-stop", "identity", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			childKind := "zero"
			if kind == "stale-stop" {
				childKind = "stop"
			}
			cmd, fd := startOwnedWait(t, childKind)
			owner := &originOwner{pid: cmd.Process.Pid, fd: fd, tasks: map[int]bool{cmd.Process.Pid: true}}
			o := &CaseOrigin{}
			o.pid.Store(int64(cmd.Process.Pid))
			calls := 0
			var observed *os.ProcessState
			cfg := Config{Waited: func(s *os.ProcessState) { calls++; observed = s }}
			if kind == "consumed" {
				var status unix.WaitStatus
				n, e := unix.Wait4(cmd.Process.Pid, &status, 0, nil)
				if e != nil || n != cmd.Process.Pid || !status.Exited() {
					t.Fatal("no genuine consumed terminal wait", n, status, e)
				}
			}
			if kind == "stale-terminal" || kind == "stale-stop" {
				_ = cmd.Wait()
				if cmd.ProcessState == nil {
					t.Fatal("missing stale actual wait")
				}
			}
			var other *exec.Cmd
			otherFD := -1
			if kind == "identity" {
				other, otherFD = startOwnedWait(t, "live")
				o.pid.Store(int64(other.Process.Pid))
			}
			if kind == "duplicate" {
				if err := o.finishWait(cmd, cfg, owner); err != nil || !o.Facts().Joined || observed == nil {
					t.Fatal("intact terminal control", o.Facts(), observed, err)
				}
				if err := o.finishWait(cmd, cfg, owner); !errors.Is(err, ErrUnavailable) || calls != 1 {
					t.Fatal("duplicate finalization credited", calls, err)
				}
				return
			}
			err := o.finishWait(cmd, cfg, owner)
			if !errors.Is(err, ErrUnavailable) || o.Facts().Joined || calls != 1 || observed != nil {
				t.Fatal("unavailable/wrong wait gained credit", kind, o.Facts(), calls, observed, err)
			}
			var status unix.WaitStatus
			if _, e := unix.Wait4(cmd.Process.Pid, &status, unix.WNOHANG|unix.WALL, nil); e != unix.ECHILD {
				t.Fatal("owned child was not reaped", kind, status, e)
			}
			if other != nil {
				if e := unix.PidfdSendSignal(otherFD, 0, nil, 0); e != nil {
					t.Fatal("different live child was affected", e)
				}
			}
		})
	}
}

// Claim: refusal cleanup consumes real SIGKILL terminal status after a ptrace
// stop, without publishing join credit. The no-retained-input case drives the
// private cleanup fallback; it is not a kernel pidfd-missing Start witness.
func TestOriginStoppedReap(t *testing.T) {
	for _, kind := range []string{"retained", "no-retained-input"} {
		t.Run(kind, func(t *testing.T) {
			cmd, fd := startOwnedWait(t, "stop")
			_ = cmd.Wait()
			if cmd.ProcessState == nil || !cmd.ProcessState.Sys().(syscall.WaitStatus).Stopped() {
				t.Fatal("no actual trace stop")
			}
			inputFD := fd
			if kind == "no-retained-input" {
				inputFD = -1
			}
			w := originOwner{pid: cmd.Process.Pid, fd: inputFD, tasks: map[int]bool{cmd.Process.Pid: true}}
			status, err := w.reapStopped()
			if err != nil || !status.Signaled() || status.Signal() != unix.SIGKILL || len(w.tasks) != 0 {
				t.Fatal("real cleanup signal/reap missing", status, err, w.tasks)
			}
			var again unix.WaitStatus
			if _, err = unix.Wait4(cmd.Process.Pid, &again, unix.WNOHANG|unix.WALL, nil); err != unix.ECHILD {
				t.Fatal("cleanup left owned child waitable", again, err)
			}
		})
	}
}

// Claim: terminal proof must name the controller's exact owned child; nil,
// another real child and a duplicate notification cannot grant Stop/join credit.
func TestTerminationWaitUnavailable(t *testing.T) {
	for _, kind := range []string{"missing", "different-child", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			state, err := ownedWaitState(t, "zero")
			o := &CaseOrigin{}
			o.pid.Store(int64(state.Pid()))
			if kind == "different-child" {
				other, _ := startOwnedWait(t, "live")
				o.pid.Store(int64(other.Process.Pid))
			}
			_, c, _ := plannedOrigin(o)
			c.sent("", false)
			if kind == "missing" {
				state = nil
			}
			if kind == "duplicate" {
				c.joined(state, err, nil, true, 0)
				if !c.Facts().Joined {
					t.Fatal("terminal control refused")
				}
			}
			c.joined(state, err, nil, true, 0)
			if c.Facts().Joined || c.Facts().Valid() {
				t.Fatal("missing/wrong/duplicate terminal credit", kind, c.Facts())
			}
		})
	}
}

// Claim: actual Run origin finalization uses the single wait owner and publishes
// the exact terminal child once after valid execution or early cancellation.
// A failed Start has no wait/callback. This drives the caller wiring, not just a
// predicate or source-token assertion; entry/egress behavior uses the old fixture.
func TestRunOriginFinalWaitOwnership(t *testing.T) {
	originBuild.Do(func() {
		originImage = filepath.Join(tools, "origin-fixture")
		if output, err := exec.Command(os.Getenv("GO"), "build", "-p=2", "-o", originImage, "./testdata/origin").CombinedOutput(); err != nil {
			t.Fatalf("origin fixture build: %v %s", err, output)
		}
	})
	for _, kind := range []string{"valid", "cancelled", "missing-launcher"} {
		t.Run(kind, func(t *testing.T) {
			image, err := os.Open(originImage)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			pad, err := os.Open("/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			defer pad.Close()
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			o, err := NewCaseOrigin(image, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started, calls := 0, 0
			var state *os.ProcessState
			config := Config{Origin: o, Launcher: originImage, LauncherArgs: []string{"bootstrap", "valid", "0"}, Executable: "/proc/self/fd/4", Args: []string{"case", "valid", "0"}, Env: []string{"GOMAXPROCS=2", "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}, ExtraFiles: []*os.File{image, pad, w, pad, pad}, Started: func(pid int) {
				started = pid
				if kind == "cancelled" {
					cancel()
				}
			}, Waited: func(s *os.ProcessState) {
				calls++
				state = s
				if !o.waited.Load() {
					t.Error("Run bypassed the single final-wait owner")
				}
				if !terminalWait(s) || s.Pid() != started || !o.Facts().Joined {
					t.Error("Run lost actual owned terminal wait", s, o.Facts())
				}
			}}
			if kind == "missing-launcher" {
				config.Launcher = filepath.Join(t.TempDir(), "missing")
			}
			_, err = Run(ctx, config)
			if kind == "missing-launcher" {
				if err == nil || started != 0 || calls != 0 || o.Facts().Joined {
					t.Fatal("unlaunched child credited", started, calls, o.Facts(), err)
				}
				return
			}
			if calls != 1 || state == nil {
				t.Fatal("Run terminal callback missing", calls, state, err)
			}
			if kind == "valid" && (err != nil || !o.Facts().Entered || state.ExitCode() != 0) {
				t.Fatal("valid entry/wait changed", o.Facts(), state, err)
			}
			if kind == "cancelled" {
				status := state.Sys().(syscall.WaitStatus)
				if err == nil || o.Facts().Entered || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("early cancellation not genuinely joined/refused", o.Facts(), state, err)
				}
			}
			var status unix.WaitStatus
			if _, e := unix.Wait4(started, &status, unix.WNOHANG|unix.WALL, nil); e != unix.ECHILD {
				t.Fatal("Run left its child waitable", status, e)
			}
		})
	}
}

// Claim: cleanup is installed before parent bookkeeping can unwind the Run;
// even a Started callback panic leaves the exact owned child terminally reaped.
// The panic still propagates: it is not converted into success or suppressed.
func TestOriginStartedCallbackCleanup(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	image, err := os.Open("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	o, err := NewCaseOrigin(image, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pid, fd, calls := 0, -1, 0
	defer func() {
		if pid == 0 {
			return
		}
		if fd >= 0 {
			defer unix.Close(fd)
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		} else {
			var si unix.Siginfo
			if e := unix.Waitid(unix.P_PID, pid, &si, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil); e == nil {
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
		for {
			var status unix.WaitStatus
			n, e := unix.Wait4(pid, &status, unix.WALL, nil)
			if e == unix.EINTR {
				continue
			}
			if e == unix.ECHILD {
				return
			}
			if e != nil {
				t.Error("owned callback fixture reap", e)
				return
			}
			if n == pid && (status.Exited() || status.Signaled()) {
				return
			}
			if n == pid && status.Stopped() {
				_ = unix.PtraceCont(pid, int(unix.SIGKILL))
			}
		}
	}()
	panicked := false
	func() {
		defer func() {
			if recovered := recover(); recovered != "owned callback fixture" {
				t.Errorf("callback panic changed: %v", recovered)
			} else {
				panicked = true
			}
		}()
		_, _ = Run(ctx, Config{Origin: o, Launcher: "/bin/true", Executable: "/bin/true", Env: []string{"HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}, ExtraFiles: []*os.File{image, image, image, image, image}, Started: func(n int) {
			pid = n
			var e error
			fd, e = unix.PidfdOpen(pid, 0)
			if e != nil {
				t.Fatal("fixture pidfd", e)
			}
			panic("owned callback fixture")
		}, Waited: func(state *os.ProcessState) {
			calls++
			if !terminalWait(state) || state.Pid() != pid {
				t.Error("callback unwind lost terminal wait", state)
			}
		}})
	}()
	var status unix.WaitStatus
	_, reapErr := unix.Wait4(pid, &status, unix.WNOHANG|unix.WALL, nil)
	if !panicked || calls != 1 || !o.Facts().Joined || reapErr != unix.ECHILD {
		t.Fatal("Started unwind bypassed owned terminal cleanup", panicked, calls, o.Facts(), status, reapErr)
	}
}
