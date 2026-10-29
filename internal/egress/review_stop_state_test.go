//go:build linux && amd64

package egress

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: a real ptrace STOP ProcessState is neither normal exit nor signal
// death, so observeWait must publish unavailable, never joined/signaled. The
// original reviewer test name is retained; the owned tracee is killed through
// its retained pidfd and reaped on every path after Start, including failures.
func TestReviewObserveWaitStopState(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command("/bin/true")
	cmd.Env = []string{"LANG=C.UTF-8"}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	defer func() {
		defer cmd.Process.Release()
		var err error
		if pidfd >= 0 {
			defer unix.Close(pidfd)
			// The pidfd cannot signal a later process reusing this numeric PID.
			err = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		} else {
			// This setup-failure path runs before cmd.Wait: the unreaped owned
			// child still pins the PID, and no other process is selected.
			err = unix.Kill(pid, unix.SIGKILL)
		}
		if err != nil && err != unix.ESRCH {
			t.Error("owned tracee kill", err)
		}
		for {
			var status unix.WaitStatus
			_, err := unix.Wait4(pid, &status, unix.WALL, nil)
			if err == unix.EINTR {
				continue
			}
			if err == unix.ECHILD { // An unexpected terminal cmd.Wait already reaped it.
				return
			}
			if err != nil {
				t.Error("owned tracee reap", err)
				return
			}
			if status.Exited() || status.Signaled() {
				return
			}
		}
	}()
	if pidfd < 0 {
		t.Fatal("fixture has no owned pidfd")
	}
	err := cmd.Wait() // Go's pidfd waitid(WEXITED) can return the exec stop.
	st := cmd.ProcessState
	if err == nil || st == nil {
		t.Fatal("fixture did not return a stopped ProcessState", err)
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok || !ws.Stopped() || ws.Exited() || ws.Signaled() {
		t.Fatal("fixture did not produce a real stop", st)
	}
	t.Logf("state=%q stopped=%v exited=%v signaled=%v exitcode=%d", st.String(), ws.Stopped(), ws.Exited(), ws.Signaled(), st.ExitCode())
	o := &CaseOrigin{}
	o.observePhase(OriginJoining)
	o.observeWait(st)
	if d := o.Diagnostic(); d != (OriginDiagnostic{}) {
		t.Fatalf("stopped non-exit ProcessState published terminal observation: %+v", d)
	}
}

// Claim: real nonzero normal exit and actual SIGKILL are distinct diagnostic
// classes. No ProcessState is fabricated; each owned child is waited once, with
// kill-and-wait cleanup retained even when a setup/assertion fails.
func TestObserveWaitRealExitClasses(t *testing.T) {
	for _, kind := range []string{"nonzero", "signaled"} {
		t.Run(kind, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", "exit 17")
			want := ExitNonzero
			if kind == "signaled" {
				cmd = exec.Command("/bin/sleep", "30")
				want = ExitSignaled
			}
			cmd.Env = []string{"LANG=C.UTF-8", "PATH=/usr/bin:/bin"}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			if kind == "signaled" {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			err := cmd.Wait()
			waited = true
			if err == nil || cmd.ProcessState == nil {
				t.Fatal("expected real terminal failure", err)
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || kind == "nonzero" && (!status.Exited() || status.ExitStatus() != 17) || kind == "signaled" && (!status.Signaled() || status.Signal() != syscall.SIGKILL) {
				t.Fatal("fixture did not supply intended terminal class", cmd.ProcessState)
			}
			o := &CaseOrigin{}
			o.observeWait(cmd.ProcessState)
			if got := o.Diagnostic(); got != (OriginDiagnostic{OriginJoined, want}) {
				t.Fatal("real terminal class misclassified", got, want)
			}
		})
	}
}

// Claim: a missing wait result clears a formerly known terminal diagnostic,
// instead of retaining stale joined/zero evidence. No fake ProcessState is used.
func TestObserveWaitNilUnavailable(t *testing.T) {
	o := &CaseOrigin{}
	o.diagnostic.Store(uint32(OriginJoined) | uint32(ExitZero)<<8)
	o.observeWait(nil)
	if got := o.Diagnostic(); got != (OriginDiagnostic{}) {
		t.Fatal("nil wait retained terminal observation", got)
	}
}

// Claim: a genuinely consumed normal exit zero retains joined/zero. This is the
// original reviewer positive control under its original test name.
func TestReviewObserveWaitExitControl(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cmd.Env = []string{"LANG=C.UTF-8"}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	o := &CaseOrigin{}
	o.observeWait(cmd.ProcessState)
	if d := o.Diagnostic(); d != (OriginDiagnostic{OriginJoined, ExitZero}) {
		t.Fatalf("control: %+v", d)
	}
}
