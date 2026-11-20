package egress

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Claim: a real ECHILD for a retained seen task refuses terminal success even
// when SIGKILL replaces the leader's real stop after next's WNOWAIT peek.
// The missing-task ledger is synthetic; waits and stop replacement are real.
func TestOriginMissingTaskLeaderOverlay(t *testing.T) {
	for _, stage := range []string{"terminal", "overtaken"} {
		for _, missing := range []bool{false, true} {
			name := stage + "/positive"
			if missing {
				name = stage + "/missing"
			}
			t.Run(name, func(t *testing.T) {
				cmd, fd := startOwnedWait(t, "stop")
				pid := cmd.Process.Pid
				var stop unix.Siginfo
				if err := unix.Waitid(unix.P_PID, pid, &stop, unix.WSTOPPED|unix.WNOWAIT|unix.WALL, nil); err != nil || stop.Code != 4 {
					t.Fatal("actual leader stop", stop, err)
				}
				o := &CaseOrigin{}
				w := originOwner{pid: pid, fd: fd, origin: o, tasks: map[int]bool{pid: true}, seen: map[int]bool{}}
				if missing {
					retired, _ := startOwnedWait(t, "zero")
					retiredPID := retired.Process.Pid
					if err := retired.Wait(); err != nil {
						t.Fatal(err)
					}
					w.tasks[retiredPID], w.seen[retiredPID] = true, true
					var si unix.Siginfo
					if err := unix.Waitid(unix.P_PID, retiredPID, &si, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil); err != unix.ECHILD {
						t.Fatal("missing task lacks real ECHILD", err)
					}
				}
				killAndPeek := func() {
					if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
						t.Fatal(err)
					}
					deadline := time.Now().Add(3 * time.Second)
					poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					for {
						remaining := time.Until(deadline)
						if remaining <= 0 {
							t.Fatal("owned terminal publication deadline")
						}
						ready, err := unix.Poll(poll, int((remaining+time.Millisecond-1)/time.Millisecond))
						if err == unix.EINTR {
							continue
						}
						if err != nil || ready != 1 || poll[0].Revents != unix.POLLIN {
							t.Fatal("owned terminal publication event", ready, poll[0].Revents, err)
						}
						break
					}
					var si unix.Siginfo
					if err := unix.Waitid(unix.P_PID, pid, &si, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil); err != nil || si.Code < 1 || si.Code > 3 {
						t.Fatal("owned terminal publication missing after pidfd readiness", si, err)
					}
				}
				calls := 0
				if stage == "overtaken" {
					originAfterTaskPeek = func(observed int, si unix.Siginfo) {
						if observed != pid || si.Code != 4 {
							t.Fatal("hook did not follow real leader stop", observed, si)
						}
						calls++
						killAndPeek()
					}
					defer func() { originAfterTaskPeek = nil }()
				} else {
					killAndPeek()
				}
				p, s, terminal, err := w.next()
				if missing {
					if !errors.Is(err, unix.ECHILD) || terminal || p != 0 || s != 0 {
						t.Fatal("missing seen task accepted after leader stop", p, s, terminal, err)
					}
				} else if err != nil || !terminal || p != 0 {
					t.Fatal("terminal positive refused", p, s, terminal, err)
				}
				if stage == "overtaken" && calls != 1 {
					t.Fatal("stop/consume window was not forced exactly once", calls)
				}
				if cmd.ProcessState != nil || o.Facts() != (OriginFacts{}) {
					t.Fatal("peek granted completion or authority", o.Facts())
				}
				if err := cmd.Wait(); err == nil || cmd.ProcessState == nil || !cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled() {
					t.Fatal("leader terminal state was consumed before final wait", err)
				}
			})
		}
	}
}
