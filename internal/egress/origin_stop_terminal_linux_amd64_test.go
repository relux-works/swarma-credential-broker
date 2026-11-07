//go:build linux && amd64

package egress

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The leader's initial real stop is peeked, then SIGKILL is delivered through
// its owned pidfd. The repaired stop path may only peek terminal state; final
// wait must still consume it. A stolen terminal status and a wrong pidfd refuse.
func TestOriginLeaderStopTerminalTransition(t *testing.T) {
	for _, mode := range []string{"terminal", "stolen", "wrong-pidfd"} {
		t.Run(mode, func(t *testing.T) {
			cmd, fd := startOwnedWait(t, "stop")
			pid := cmd.Process.Pid
			var stop unix.Siginfo
			if e := unix.Waitid(unix.P_PID, pid, &stop, unix.WSTOPPED|unix.WNOWAIT|unix.WALL, nil); e != nil || stop.Code != 4 {
				t.Fatal("actual initial stop", stop, e)
			}
			if e := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); e != nil {
				t.Fatal(e)
			}
			deadline := time.Now().Add(3 * time.Second)
			terminal := false
			for time.Now().Before(deadline) {
				var si unix.Siginfo
				e := unix.Waitid(unix.P_PID, pid, &si, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
				if e != nil {
					t.Fatal(e)
				}
				if si.Code >= 1 && si.Code <= 3 {
					terminal = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !terminal {
				t.Fatal("owned terminal publication deadline")
			}
			o := &CaseOrigin{}
			o.pid.Store(int64(pid))
			w := originOwner{pid: pid, fd: fd, tasks: map[int]bool{pid: true}, origin: o}
			if mode == "stolen" {
				var stolen unix.WaitStatus
				if p, e := unix.Wait4(pid, &stolen, unix.WNOHANG|unix.WALL, nil); e != nil || p != pid || !stolen.Signaled() {
					t.Fatal("actual terminal theft", p, stolen, e)
				}
			}
			if mode == "wrong-pidfd" {
				_, otherFD := startOwnedWait(t, "zero")
				w.fd = otherFD
			}
			p, s, done, e := w.observedTask(pid, stop)
			if cmd.ProcessState != nil || o.Facts().Joined {
				t.Fatal("peek manufactured wait credit")
			}
			if mode != "terminal" {
				if e == nil || done || mode == "stolen" && !errors.Is(e, unix.ECHILD) {
					t.Fatal("unavailable leader accepted", p, s, done, e)
				}
				if mode == "wrong-pidfd" {
					// The mismatched pidfd peek consumed neither owned child's terminal state.
					if e := cmd.Wait(); e == nil || cmd.ProcessState == nil {
						t.Fatal("lost leader terminal", e)
					}
					return
				}
			} else if e != nil || !done || p != 0 {
				t.Fatal("leader transition lost", p, s, done, e)
			}
			calls := 0
			e = o.finishWait(cmd, Config{Waited: func(state *os.ProcessState) {
				calls++
				if mode == "stolen" {
					if state != nil {
						t.Error("stolen terminal supplied callback state")
					}
				} else if state == nil || !state.Sys().(syscall.WaitStatus).Signaled() {
					t.Error("lost actual signal wait", state)
				}
			}}, &w)
			if calls != 1 || o.Facts().Joined != (mode == "terminal") || mode == "stolen" && !errors.Is(e, ErrUnavailable) {
				t.Fatal("fresh sole final wait/callback", calls, o.Facts(), e)
			}
			t.Logf("forced leader %s: terminal peek done=%v, sole final callback=%d joined=%v", mode, done, calls, o.Facts().Joined)
		})
	}
}

// An ESRCH recovery is not an error exemption: an unchanged real stop still
// refuses, and an otherwise waitable child outside this owner's task set cannot
// be consumed. These controls use only separate owned inert fixture children.
func TestOriginOvertakenStopRequiresEvidence(t *testing.T) {
	cmd, fd := startOwnedWait(t, "stop")
	pid := cmd.Process.Pid
	w := originOwner{pid: pid, fd: fd, tasks: map[int]bool{pid: true}}
	var stop unix.Siginfo
	if e := unix.Waitid(unix.P_PID, pid, &stop, unix.WSTOPPED|unix.WNOWAIT|unix.WALL, nil); e != nil || stop.Code != 4 {
		t.Fatal("actual unchanged stop", stop, e)
	}
	// A different OS thread is not this child's tracer. Its actual ESRCH
	// cannot excuse the unchanged stop still held by the owning thread.
	failed := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, e := unix.PtraceGetEventMsg(pid)
		failed <- e
	}()
	cause := <-failed
	if cause != unix.ESRCH {
		t.Fatal("wrong-thread event read did not fail ESRCH", cause)
	}
	if _, _, done, e := w.stopOvertaken(pid, cause); e != unix.ESRCH || done {
		t.Fatal("unchanged stop excused ESRCH", done, e)
	}
	other, _ := startOwnedWait(t, "zero")
	var si unix.Siginfo
	if e := unix.Waitid(unix.P_PID, other.Process.Pid, &si, unix.WEXITED|unix.WNOWAIT, nil); e != nil {
		t.Fatal(e)
	}
	b := (*[128]byte)(unsafe.Pointer(&si))
	if int(binary.LittleEndian.Uint32(b[16:20])) != other.Process.Pid {
		t.Fatal("foreign control identity")
	}
	if _, _, done, e := w.observedTask(other.Process.Pid, si); !errors.Is(e, ErrUnavailable) || done {
		t.Fatal("unowned task accepted", done, e)
	}
	if e := other.Wait(); e != nil || other.ProcessState == nil || other.ProcessState.ExitCode() != 0 {
		t.Fatal("unowned task consumed", e)
	}
}
