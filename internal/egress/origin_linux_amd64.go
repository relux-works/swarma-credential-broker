//go:build linux && amd64

package egress

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func NewCaseOrigin(image *os.File, ready func() error) (*CaseOrigin, error) {
	if image == nil || ready == nil {
		return nil, ErrUnavailable
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	o := &CaseOrigin{image: image, parent: os.NewFile(uintptr(pair[0]), "origin-parent"), child: os.NewFile(uintptr(pair[1]), "origin-child"), ready: ready}
	if err = unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err == nil {
		err = unix.SetNonblock(pair[0], true)
	}
	if err != nil {
		o.Close()
		return nil, err
	}
	return o, nil
}

// NewOwnerOrigin binds the private owner dispatcher to a canonical context hash.
// It adds no executable, descriptor or network permission to Run.
func NewOwnerOrigin(image *os.File, digest string) (*CaseOrigin, error) {
	b, err := hex.DecodeString(digest)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != digest {
		return nil, ErrUnavailable
	}
	o, err := NewCaseOrigin(image, func() error { return nil })
	if err == nil {
		o.ownerContext = digest
	}
	return o, err
}

// NewCrashOwnerOrigin adds only a separate planned-termination controller;
// normal owner entry, egress policy and error semantics remain unchanged.
func NewCrashOwnerOrigin(image *os.File, digest string) (*CaseOrigin, *TerminationController, error) {
	o, e := NewOwnerOrigin(image, digest)
	if e != nil {
		return nil, nil, e
	}
	return plannedOrigin(o)
}

// NewWriterOrigin binds the closed synthetic writer to its own role domain.
func NewWriterOrigin(image *os.File, digest string) (*CaseOrigin, *TerminationController, error) {
	o, e := NewOwnerOrigin(image, digest)
	if e != nil {
		return nil, nil, e
	}
	o.writer = true
	return plannedOrigin(o)
}

func writerResponse(challenge []byte, digest string) []byte {
	h := sha256.New()
	h.Write([]byte("qualification-writer/1\x00" + digest + "\x00"))
	h.Write(challenge)
	return h.Sum(nil)
}
func ownerResponse(challenge []byte, digest string) []byte {
	h := sha256.New()
	h.Write([]byte("qualification-owner/1\x00" + digest + "\x00"))
	h.Write(challenge)
	return h.Sum(nil)
}

// EnterOwnerRole accepts only the fixed supervisor endpoint, and answers in a
// separate domain from generic case entry. Construction follows this barrier.
func EnterOwnerRole(digest string) error { return enterRole(digest, false) }

func EnterWriterRole(digest string) error { return enterRole(digest, true) }

// EnterCase accepts no caller-selected descriptor, path or authority. The final
// acknowledgement prevents an exchange racing the parent's live-origin gate.
func EnterCase() error                { return enterOrigin("") }
func enterOrigin(digest string) error { return enterRole(digest, false) }
func enterRole(digest string, writer bool) error {
	unix.CloseOnExec(9)
	b := make([]byte, 32)
	if n, e := unix.Read(9, b); e != nil || n != len(b) {
		return ErrUnavailable
	}
	if digest != "" {
		if writer {
			b = writerResponse(b, digest)
		} else {
			b = ownerResponse(b, digest)
		}
	}
	if n, e := unix.Write(9, b); e != nil || n != len(b) {
		return ErrUnavailable
	}
	ack := make([]byte, 1)
	if n, e := unix.Read(9, ack); e != nil || n != 1 || ack[0] != 1 {
		return ErrUnavailable
	}
	return unix.Close(9)
}

func originIdentity(pid int, image *os.File, argv []string) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	var want, got unix.Stat_t
	if unix.Fstat(int(image.Fd()), &want) != nil || unix.Fstat(int(f.Fd()), &got) != nil || want.Dev != got.Dev || want.Ino != got.Ino {
		return ErrUnavailable
	}
	f, err = os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || len(b) > 2048 || string(b) != strings.Join(argv, "\x00")+"\x00" {
		return ErrUnavailable
	}
	return nil
}

// This owner is locked to the Start thread. WSTOPPED consumes only stops;
// terminal case state stays waitable for the sole final cmd.Wait.
type originOwner struct {
	pid, fd int
	tasks   map[int]bool
	strict  bool
}

func (w *originOwner) next() (tid int, status unix.WaitStatus, terminal bool, err error) {
	for p := range w.tasks {
		var si unix.Siginfo
		err = unix.Waitid(unix.P_PID, p, &si, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
		// A clone event can precede the new task becoming waitable. Retain it
		// until its actual status; dropping it can strand the exec/exit group.
		if err == unix.ECHILD && p != w.pid || err == unix.EINTR {
			err = nil
			continue
		}
		if err != nil {
			return
		}
		// Linux/amd64 siginfo_t child PID, in the union hidden by x/sys.
		b := (*[128]byte)(unsafe.Pointer(&si))
		observed := int(binary.LittleEndian.Uint32(b[16:20]))
		if observed == 0 {
			continue
		}
		if observed != p {
			err = ErrUnavailable
			return
		}
		if si.Code >= 1 && si.Code <= 3 && p == w.pid { // CLD_EXITED/KILLED/DUMPED
			var again unix.Siginfo
			err = unix.Waitid(unix.P_PIDFD, w.fd, &again, unix.WEXITED|unix.WNOWAIT, nil)
			if err == nil && si != again {
				err = ErrUnavailable
			}
			terminal = err == nil
			return
		}
		if si.Code >= 1 && si.Code <= 3 { // Only non-case thread terminal states.
			tid, err = unix.Wait4(p, &status, unix.WNOHANG|unix.WALL, nil)
			if err == nil && tid != p {
				err = ErrUnavailable
			}
			return
		}
		var stopped unix.Siginfo
		err = unix.Waitid(unix.P_PID, p, &stopped, unix.WSTOPPED|unix.WNOHANG|unix.WALL, nil)
		if err != nil {
			return
		}
		b = (*[128]byte)(unsafe.Pointer(&stopped))
		tid = int(binary.LittleEndian.Uint32(b[16:20]))
		if tid == 0 {
			continue
		} // SIGKILL may have overtaken the peeked stop.
		if tid != p || stopped.Code != 4 && stopped.Code != 5 {
			err = ErrUnavailable
			return
		}
		status = unix.WaitStatus(binary.LittleEndian.Uint32(b[24:28])<<8 | 0x7f)

		return
	}
	return
}
func (w *originOwner) resume(tid int, status unix.WaitStatus) error {
	if status.Exited() || status.Signaled() {
		delete(w.tasks, tid)
		return nil
	}
	cause := status.TrapCause()
	if cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
		p, e := unix.PtraceGetEventMsg(tid)
		if e != nil {
			return e
		}
		w.tasks[int(p)] = w.tasks[tid] && cause == unix.PTRACE_EVENT_CLONE
		if w.strict {
			w.tasks[int(p)] = originThread(int(p), w.pid)
			if !w.tasks[int(p)] {
				return ErrUnavailable
			}
		}
	}
	sig := 0
	if status.StopSignal() != unix.SIGTRAP && status.StopSignal() != unix.SIGSTOP {
		sig = int(status.StopSignal())
	}
	err := unix.PtraceCont(tid, sig)
	if err == unix.ESRCH {
		return nil
	}
	return err
}

func (o *CaseOrigin) entry(challenge []byte) error {
	b, control := make([]byte, 33), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, sz, flags, _, err := unix.Recvmsg(int(o.parent.Fd()), b, control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if err == unix.EAGAIN || err == unix.EINTR {
		return nil
	}
	if o.entered.Load() {
		return ErrUnavailable
	}
	messages, parseErr := unix.ParseSocketControlMessage(control[:sz])
	for _, m := range messages {
		if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS {
			fds, _ := unix.ParseUnixRights(&m)
			for _, fd := range fds {
				unix.Close(fd)
			}
		}
	}
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || parseErr != nil || len(messages) != 1 {
		return ErrUnavailable
	}
	cred, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil || int64(cred.Pid) != o.pid.Load() || int(cred.Uid) != os.Getuid() || int(cred.Gid) != os.Getgid() || n != len(challenge) || !bytes.Equal(b[:n], challenge) {
		return ErrUnavailable
	}
	o.entered.Store(true)
	_, err = unix.Write(int(o.parent.Fd()), []byte{1})
	return err
}

func originNotify(listener int, p Policy, report *Report, start time.Time) error {
	poll := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
	if _, e := unix.Poll(poll, 0); e != nil && e != unix.EINTR {
		return e
	}
	if poll[0].Revents&unix.POLLIN == 0 {
		return nil
	}
	var n notification
	if e := ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); e != nil {
		if e == unix.EINTR || e == unix.ENOENT {
			return nil
		}
		return e
	}
	d := p.decide(listener, n)
	r := response{ID: n.ID, Error: -int32(d.errno)}
	verdict := "refuse"
	if d.errno == 0 {
		r.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		verdict = "allow"
	}
	if len(report.Events) >= p.MaxEvents {
		r.Flags = 0
		r.Error = -int32(unix.ECONNREFUSED)
		_ = ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r))
		return ErrEvidenceLimit
	}
	if !valid(listener, n.ID) {
		verdict = "refuse"
		r.Flags = 0
		r.Error = -int32(unix.ECONNREFUSED)
	}
	report.Events = append(report.Events, Event{Syscall: names[n.NR], Family: d.family, Class: d.class, Port: d.port, Verdict: verdict, MonotonicNS: time.Since(start).Nanoseconds()})
	count := report.Summary[d.class]
	if verdict == "allow" {
		count.Allowed++
	} else {
		count.Refused++
	}
	report.Summary[d.class] = count
	if e := ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); e != nil && e != unix.ENOENT {
		return e
	}
	return nil
}

func runOrigin(ctx context.Context, c Config) (report Report, err error) {
	report.Summary = map[string]Counts{}
	o := c.Origin
	defer func() {
		if err != nil {
			if o.ownerContext != "" {
				o.invalid.Store(true)
			}
			report.Incomplete = true
		}
		if !o.joined.Load() || !o.entered.Load() {
			o.invalid.Store(true)
		}
	}()
	if _, ok := ctx.Deadline(); !ok {
		return report, ErrUnavailable
	}
	if err = validate(c); err != nil {
		return
	}
	role := "qualification-owner"
	if o.writer {
		role = "qualification-writer"
	}
	if o.ownerContext != "" && (c.Executable != "/proc/self/fd/4" || strings.Join(c.Args, "\x00") != role+"\x00"+o.ownerContext) {
		return report, ErrUnavailable
	}
	if len(c.ExtraFiles) != 5 || o.parent == nil || o.child == nil || o.image == nil || o.invalid.Load() || !o.used.CompareAndSwap(false, true) {
		return report, ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return
	}
	var sizes [3]uint16
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 || sizes[0] != uint16(unsafe.Sizeof(notification{})) || sizes[1] != uint16(unsafe.Sizeof(response{})) {
		return report, ErrUnavailable
	}
	if c.Policy.MaxEvents == 0 {
		c.Policy.MaxEvents = 1024
	}
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return report, e
	}
	defer unix.Close(pair[0])
	child := os.NewFile(uintptr(pair[1]), "bootstrap")
	defer child.Close()
	if e = unix.SetNonblock(pair[0], true); e != nil {
		return report, e
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd := -1
	argv := append(append([]string{}, c.LauncherArgs...), c.Executable)
	argv = append(argv, c.Args...)
	cmd := exec.Command(c.Launcher, argv...)
	cmd.Env = c.Env
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	cmd.ExtraFiles = append(append([]*os.File{child}, c.ExtraFiles...), o.child)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true, PidFD: &fd}
	if err = cmd.Start(); err != nil {
		return
	}
	child.Close()
	o.pid.Store(int64(cmd.Process.Pid))
	if c.Started != nil {
		c.Started(cmd.Process.Pid)
	}
	if fd < 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if c.Waited != nil {
			c.Waited(cmd.ProcessState)
		}
		return report, ErrUnavailable
	}
	w := originOwner{pid: cmd.Process.Pid, fd: fd, tasks: map[int]bool{cmd.Process.Pid: true}, strict: o.ownerContext != ""}
	defer unix.Close(fd)
	terminal := false
	defer func() {
		o.terminal.Store(true)
		if !terminal {
			o.invalid.Store(true)
		}
		// Signal while the unreaped group leader still pins this owned group.
		_ = unix.Kill(-w.pid, unix.SIGKILL)
		_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		for len(w.tasks) != 0 {
			if !terminal {
				// SIGKILL can overtake a clone event before its new TID was
				// reported. Drain every thread of this still-pinned case group.
				entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.pid))
				if e != nil {
					err = errors.Join(err, e)
					break
				}
				for _, entry := range entries {
					if p, e := strconv.Atoi(entry.Name()); e == nil {
						w.tasks[p] = true
					}
				}
			}
			if terminal {
				// The final process wait owns the dying thread group's state.
				for p, thread := range w.tasks {
					if thread {
						delete(w.tasks, p)
					}
				}
			}
			if len(w.tasks) == 0 {
				break
			}
			tid, status, done, e := w.next()
			if e != nil {
				err = errors.Join(err, e)
				break
			}
			terminal = terminal || done
			if tid != 0 {
				if e = w.resume(tid, status); e != nil {
					err = errors.Join(err, e)
				}
			}
			if tid == 0 && !done {
				time.Sleep(time.Millisecond)
			}
		}
		waitErr := cmd.Wait() // Exactly one consuming terminal wait, on this owner.
		if cmd.ProcessState != nil {
			o.joined.Store(true)
		}
		if c.Waited != nil {
			c.Waited(cmd.ProcessState)
		}
		if o.termination != nil {
			signal := 0
			if cmd.ProcessState != nil {
				if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					signal = int(status.Signal())
				}
			}
			o.termination.joined(cmd.ProcessState, waitErr, err, terminal && len(w.tasks) == 0, signal)
		}
		err = errors.Join(err, waitErr)
	}()
	listener := -1
	defer func() {
		if listener >= 0 {
			unix.Close(listener)
		}
	}()
	birth := false
	challenge := make([]byte, 32)
	start := time.Now()
	expected := challenge
	traceEvents := 0
	for !terminal {
		if err = ctx.Err(); err != nil {
			return
		}
		if o.termination != nil {
			select {
			case gate := <-o.termination.request:
				if !o.Live(w.pid) {
					return report, ErrUnavailable
				}
				e := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
				o.termination.sent(gate, e == nil)
				if e != nil {
					return report, e
				}
			default:
			}
		}
		if listener < 0 {
			b, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
			n, sz, flags, _, e := unix.Recvmsg(pair[0], b, control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
			if e != nil && e != unix.EAGAIN && e != unix.EINTR {
				return report, e
			}
			if e == nil && n > 0 {
				messages, e := unix.ParseSocketControlMessage(control[:sz])
				if e != nil || n != 1 || b[0] != 1 || flags&unix.MSG_CTRUNC != 0 || len(messages) != 1 {
					return report, ErrUnavailable
				}
				fds, e := unix.ParseUnixRights(&messages[0])
				if e != nil || len(fds) != 1 {
					for _, f := range fds {
						unix.Close(f)
					}
					return report, ErrUnavailable
				}
				listener = fds[0]
				if _, e = unix.Write(pair[0], []byte{1, 6, 0}); e != nil {
					return report, e
				}
			}
		}
		if listener >= 0 {
			if err = originNotify(listener, c.Policy, &report, start); err != nil {
				return
			}
		}
		if o.verified.Load() {
			if err = o.entry(expected); err != nil {
				o.invalid.Store(true)
				return
			}
		}
		tid, status, done, e := w.next()
		if e != nil {
			return report, e
		}
		terminal = done
		if terminal {
			o.terminal.Store(true)
			if o.verified.Load() {
				err = o.entry(expected)
				if err != nil {
					o.invalid.Store(true)
				}
			}
			return
		}
		if tid == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if !birth {
			if tid != w.pid || status.StopSignal() != unix.SIGTRAP {
				return report, ErrUnavailable
			}
			birth = true
			if err = unix.PtraceSetOptions(w.pid, unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_EXITKILL); err != nil {
				return
			}
		}
		if status.TrapCause() == unix.PTRACE_EVENT_EXEC {
			if o.verified.Load() || tid != w.pid {
				o.invalid.Store(true)
				return report, ErrUnavailable
			}
			former, e := unix.PtraceGetEventMsg(tid)
			if e != nil {
				return report, e
			}
			o.nonleader.Store(former > 0 && int(former) != w.pid)
			for p, thread := range w.tasks {
				if thread {
					delete(w.tasks, p)
				}
			}
			w.tasks[w.pid] = true
			if err = originIdentity(w.pid, o.image, append([]string{c.Executable}, c.Args...)); err != nil {
				return
			}
			o.verified.Store(true)
			if err = o.ready(); err != nil {
				return
			}
			if _, err = rand.Read(challenge); err != nil {
				return
			}
			if o.ownerContext != "" {
				expected = ownerResponse(challenge, o.ownerContext)
				if o.writer {
					expected = writerResponse(challenge, o.ownerContext)
				}
			}
			if _, err = unix.Write(int(o.parent.Fd()), challenge); err != nil {
				return
			}
		}
		if o.ownerContext != "" {
			traceEvents++
			if traceEvents > 4096 {
				return report, ErrEvidenceLimit
			}
			if tid != w.pid && !status.Exited() && !status.Signaled() {
				if !originThread(tid, w.pid) {
					o.invalid.Store(true)
					return report, ErrUnavailable
				}
				w.tasks[tid] = true
			}
		}
		if err = w.resume(tid, status); err != nil {
			return
		}
	}
	return
}

// Check the stopped task's actual thread group; CLONE alone also creates processes.
func originThread(tid, leader int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Tgid:" {
			return fields[1] == strconv.Itoa(leader)
		}
	}
	return false
}
