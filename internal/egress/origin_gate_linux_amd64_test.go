//go:build linux && amd64

package egress

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This test-only prototype deliberately bypasses Run's file-only ExtraFiles
// contract. It does not enable row credit or change any production policy.
type originGateResult struct {
	Birth, Pinned, Exec, Image, Argv, Nonleader, Entry, Peek bool
	SocketAllowed, ConnectRefused                            bool
	Waits, Callbacks, Owner                                  int
	State                                                    *os.ProcessState
	Reason                                                   string
}

// Linux/amd64 siginfo_t child fields are hidden in x/sys/unix.Siginfo's union.
// Only the waitid result is decoded; no process memory or environment is read.
func originWaitInfo(si *unix.Siginfo) (pid, status int32) {
	b := (*[128]byte)(unsafe.Pointer(si))
	return int32(binary.LittleEndian.Uint32(b[16:20])), int32(binary.LittleEndian.Uint32(b[24:28]))
}

func originIdentity(pid int, image *os.File, argv []string) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	var want, got unix.Stat_t
	if err = unix.Fstat(int(image.Fd()), &want); err != nil {
		return "", err
	}
	if err = unix.Fstat(int(f.Fd()), &got); err != nil {
		return "", err
	}
	if want.Dev != got.Dev || want.Ino != got.Ino {
		return "image", nil
	}
	cmdline, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}
	defer cmdline.Close()
	b, err := io.ReadAll(io.LimitReader(cmdline, 2049))
	if err != nil {
		return "", err
	}
	if len(b) > 2048 || !bytes.Equal(b, append(bytes.Join(stringBytes(argv), []byte{0}), 0)) {
		return "argv", nil
	}
	return "", nil
}

func stringBytes(argv []string) [][]byte {
	out := make([][]byte, len(argv))
	for i := range argv {
		out[i] = []byte(argv[i])
	}
	return out
}

func originGate(t *testing.T, imagePath, mode string, status int) (r originGateResult) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r.Owner = unix.Gettid()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	image, err := os.Open(imagePath)
	must(err)
	defer image.Close()
	other, err := os.Open("/bin/true")
	must(err)
	defer other.Close()
	bootstrap, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	must(err)
	defer unix.Close(bootstrap[0])
	bootChild := os.NewFile(uintptr(bootstrap[1]), "bootstrap")
	defer bootChild.Close()
	origin, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	must(err)
	defer unix.Close(origin[0])
	originChild := os.NewFile(uintptr(origin[1]), "origin")
	defer originChild.Close()
	must(unix.SetsockoptInt(origin[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1))
	must(unix.SetNonblock(origin[0], true))
	must(unix.SetNonblock(bootstrap[0], true))
	tidR, tidW, err := os.Pipe()
	must(err)
	defer tidR.Close()
	defer tidW.Close()
	code := strconv.Itoa(status)
	cmd := exec.Command(imagePath, "bootstrap", mode, code)
	cmd.Env = []string{"GOMAXPROCS=2"}
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{bootChild, image, originChild, tidW, other}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true, PidFD: &pidfd}
	must(cmd.Start())
	defer unix.Close(pidfd)
	pid := cmd.Process.Pid
	r.Pinned = pidfd >= 0 && unix.PidfdSendSignal(pidfd, 0, nil, 0) == nil
	bootChild.Close()
	tidW.Close()
	listener := -1
	defer func() {
		if listener >= 0 {
			unix.Close(listener)
		}
	}()
	tasks := map[int]bool{pid: true}
	challenge := make([]byte, 32)
	deadline := time.Now().Add(8 * time.Second)
	killed := false
	reject := func(reason string) {
		if r.Reason == "" {
			r.Reason = reason
		}
		if !killed {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			killed = true
		}
	}
	// Cleanup remains with this thread; no goroutine waits or reaps this child.
	defer func() {
		if r.State == nil && r.Waits == 0 {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			for tid := range tasks {
				_ = unix.Kill(tid, unix.SIGKILL)
				_ = unix.PtraceCont(tid, 0)
			}
			r.Waits++
			_ = cmd.Wait()
		}
	}()
	consumeEntry := func() {
		if !r.Exec || !r.Image || !r.Argv || r.Entry || r.Reason != "" {
			return
		}
		b, control := make([]byte, 33), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
		n, o, flags, _, e := unix.Recvmsg(origin[0], b, control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if e == unix.EAGAIN || e == unix.EINTR {
			return
		}
		if e != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			reject("message")
			return
		}
		messages, e := unix.ParseSocketControlMessage(control[:o])
		if e != nil || len(messages) != 1 {
			reject("credentials")
			return
		}
		cred, e := unix.ParseUnixCredentials(&messages[0])
		if e != nil || int(cred.Pid) != pid || int(cred.Uid) != os.Getuid() || int(cred.Gid) != os.Getgid() {
			reject("sender")
			return
		}
		if n != len(challenge) || !bytes.Equal(b[:n], challenge) {
			reject("challenge")
			return
		}
		r.Entry = true
	}
	for time.Now().Before(deadline.Add(2 * time.Second)) {
		if time.Now().After(deadline) {
			reject("deadline")
		}
		if listener < 0 {
			b, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
			n, o, flags, _, e := unix.Recvmsg(bootstrap[0], b, control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
			if e == nil && n > 0 {
				messages, e := unix.ParseSocketControlMessage(control[:o])
				if e != nil || n != 1 || b[0] != 1 || flags&unix.MSG_CTRUNC != 0 || len(messages) != 1 {
					reject("bootstrap")
				} else if fds, e := unix.ParseUnixRights(&messages[0]); e != nil || len(fds) != 1 {
					reject("bootstrap rights")
				} else {
					listener = fds[0]
					_, e = unix.Write(bootstrap[0], []byte{1, 4, 0})
					must(e)
				}
			}
		}
		if listener >= 0 {
			poll := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
			_, err := unix.Poll(poll, 0)
			must(err)
			if poll[0].Revents&unix.POLLIN != 0 {
				var n notification
				if e := ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); e == nil {
					d := (Policy{}).decide(listener, n)
					response := response{ID: n.ID, Error: -int32(d.errno)}
					if d.errno == 0 {
						response.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
					}
					r.SocketAllowed = r.SocketAllowed || n.NR == unix.SYS_SOCKET && d.errno == 0
					r.ConnectRefused = r.ConnectRefused || n.NR == unix.SYS_CONNECT && d.errno == unix.ECONNREFUSED
					if e = ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); e != nil && e != unix.ENOENT {
						reject("notification response")
					}
				} else if e != unix.EINTR && e != unix.ENOENT {
					reject("notification receive")
				}
			}
		}
		consumeEntry()
		for tid := range tasks {
			if unix.Gettid() != r.Owner {
				t.Fatal("lifecycle owner changed")
			}
			var si unix.Siginfo
			err = unix.Waitid(unix.P_PID, tid, &si, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			if err == unix.EINTR || err == unix.ECHILD && tid != pid {
				continue
			}
			must(err)
			gotPID, _ := originWaitInfo(&si)
			if gotPID == 0 {
				continue
			}
			if int(gotPID) != tid {
				t.Fatal("waitid returned another task")
			}
			// CLD_EXITED, CLD_KILLED or CLD_DUMPED, not a ptrace exit stop.
			if si.Code >= 1 && si.Code <= 3 {
				if tid == pid {
					// A second peek must see the same terminal state, still unreaped.
					var again unix.Siginfo
					must(unix.Waitid(unix.P_PIDFD, pidfd, &again, unix.WEXITED|unix.WNOWAIT, nil))
					r.Peek = si == again
					consumeEntry()
					r.Waits++
					e := cmd.Wait() // The sole consuming terminal wait for the case.
					var exit *exec.ExitError
					if e != nil && !errors.As(e, &exit) {
						t.Fatal(e)
					}
					r.State = cmd.ProcessState
					callback := func(s *os.ProcessState) {
						if unix.Gettid() != r.Owner || s != cmd.ProcessState {
							t.Fatal("wait callback lost owner/state")
						}
						r.Callbacks++
					}
					callback(r.State)
					return r
				}
			}
			var ws unix.WaitStatus
			waited, e := unix.Wait4(tid, &ws, unix.WNOHANG|unix.WALL, nil)
			must(e)
			if waited != tid {
				t.Fatal("peeked stop was lost")
			}
			if ws.Exited() || ws.Signaled() {
				delete(tasks, tid)
				continue
			}
			if !r.Birth {
				r.Birth = tid == pid && ws.StopSignal() == unix.SIGTRAP
				must(unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_EXITKILL))
			}
			cause := ws.TrapCause()
			if cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
				newTID, e := unix.PtraceGetEventMsg(tid)
				must(e)
				tasks[int(newTID)] = true
			}
			if cause == unix.PTRACE_EVENT_EXEC {
				former, e := unix.PtraceGetEventMsg(tid)
				must(e)
				if r.Exec || tid != pid {
					reject("unexpected exec")
				} else {
					r.Exec = true
					tidBytes := make([]byte, 32)
					n, e := tidR.Read(tidBytes)
					must(e)
					reportedTID, e := strconv.Atoi(string(tidBytes[:n]))
					must(e)
					r.Nonleader = former > 0 && int(former) == reportedTID && reportedTID != pid
					// Exec has destroyed the old runtime's other threads.
					tasks = map[int]bool{pid: true}
					reason, e := originIdentity(pid, image, []string{"/proc/self/fd/4", "case", mode, code})
					must(e)
					r.Image = reason != "image"
					r.Argv = reason == ""
					if reason != "" {
						reject(reason)
					} else {
						_, e = rand.Read(challenge)
						must(e)
						_, e = unix.Write(origin[0], challenge)
						must(e)
						if mode == "wrong-sender" {
							// A genuinely different kernel PID writes through the same
							// endpoint; no fabricated ucred or validator stub is used.
							_, e = unix.Write(int(originChild.Fd()), challenge)
							must(e)
						}
					}
				}
			}
			sig := 0
			if ws.StopSignal() != unix.SIGTRAP && ws.StopSignal() != unix.SIGSTOP {
				sig = int(ws.StopSignal())
			}
			if e = unix.PtraceCont(tid, sig); e != nil && e != unix.ESRCH {
				must(e)
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owned child did not reach a terminal wait after cancellation")
	return r
}

// Claim: the parent traces from birth, observes a non-leader exec, checks the
// stopped image/argv under its pidfd, authenticates fresh entry, and keeps the
// real 0/17 ProcessState through one terminal cmd.Wait and its callback. Real
// seccomp notifications use the unchanged filters and Policy.decide. This gate
// does not attest a Go function call, a foreign child, or qualification rows.
func TestOriginGate(t *testing.T) {
	image := filepath.Join(t.TempDir(), "origin-fixture")
	build := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", image, "./testdata/origin")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{0, 17} {
		if !t.Run("status-"+strconv.Itoa(code), func(t *testing.T) {
			r := originGate(t, image, "valid", code)
			if r.Reason != "" || !r.Birth || !r.Pinned || !r.Exec || !r.Image || !r.Argv || !r.Nonleader || !r.Entry || !r.Peek || !r.SocketAllowed || !r.ConnectRefused || r.Waits != 1 || r.Callbacks != 1 || r.State == nil || r.State.ExitCode() != code {
				t.Fatalf("origin properties: %+v", r)
			}
			t.Logf("all origin properties demonstrated; actual exit=%d; sole wait=1 callback=1", r.State.ExitCode())
		}) {
			return // A failed required feasibility property stops the gate.
		}
	}
	// Claim: genuine wrong-image exec, altered initial argv, a same-PID queued
	// pre-exec response, and a real different-PID sender each fail at the named
	// origin check while preserving the sole real wait/callback. The wrong sender
	// here is the parent holding the endpoint, not a claimed foreign-user test.
	for _, row := range []struct{ mode, reason string }{{"unexpected-exec", "image"}, {"later-exec", "unexpected exec"}, {"wrong-argv", "argv"}, {"oversized-argv", "argv"}, {"pre-exec", "challenge"}, {"wrong-sender", "sender"}} {
		if !t.Run(row.mode, func(t *testing.T) {
			r := originGate(t, image, row.mode, 0)
			if r.Reason != row.reason || r.Entry || r.State == nil || r.Waits != 1 || r.Callbacks != 1 || !r.Peek {
				t.Fatalf("expected %s rejection with one real wait/callback: %+v", row.reason, r)
			}
			t.Logf("rejected at %s; sole wait=1 callback=1", r.Reason)
		}) {
			return
		}
	}
}
