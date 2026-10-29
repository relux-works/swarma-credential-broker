//go:build linux && amd64

package qualify

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
)

// Claim: qualification's actual wait callback records terminal states only;
// a real owned ptrace STOP supplies neither helper joined nor exit credit.
func TestExecutionWaitTerminalOnly(t *testing.T) {
	for _, kind := range []string{"stop", "zero", "nonzero", "signal"} {
		t.Run(kind, func(t *testing.T) {
			state, _ := ownedWaitState(t, kind)
			e := newRowExecution()
			e.waited(state)
			if e.Joined != (kind != "stop") || kind == "stop" && e.HelperExit != -1 {
				t.Fatalf("qualification nonterminal wait gained credit: kind=%s joined=%v exit=%d state=%v", kind, e.Joined, e.HelperExit, state)
			}
		})
	}
}

func ownedWaitState(t *testing.T, kind string) (*os.ProcessState, error) {
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
	if kind == "signal" {
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
	err := cmd.Wait()
	state := cmd.ProcessState
	if state == nil {
		t.Fatal("no actual wait state", err)
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || kind == "stop" && !status.Stopped() || kind == "signal" && (!status.Signaled() || status.Signal() != syscall.SIGKILL) || kind == "zero" && (!status.Exited() || status.ExitStatus() != 0) || kind == "nonzero" && (!status.Exited() || status.ExitStatus() != 17) {
		t.Fatal("wrong real fixture state", state, err)
	}
	t.Logf("actual owned pid=%d state=%q stopped=%v exited=%v signaled=%v", pid, state.String(), status.Stopped(), status.Exited(), status.Signaled())
	return state, err
}

// Claim: missing wait evidence clears earlier terminal diagnostics instead of
// retaining stale joined/exit credit. A real zero wait is the positive control.
func TestExecutionWaitClearsUnavailable(t *testing.T) {
	state, _ := ownedWaitState(t, "zero")
	e := newRowExecution()
	e.waited(state)
	if !e.Joined || e.HelperExit != 0 {
		t.Fatal("real terminal control refused", e)
	}
	e.waited(nil)
	if e.Joined || e.HelperExit != -1 {
		t.Fatal("missing wait retained terminal credit", e)
	}
}
