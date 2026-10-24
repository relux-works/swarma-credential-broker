//go:build linux && amd64

package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func validate(c Config) error {
	if len(c.ExtraFiles) > 256 {
		return ErrUnavailable
	}
	if !filepath.IsAbs(c.Launcher) || !filepath.IsAbs(c.Executable) || c.Env == nil {
		return ErrUnavailable
	}
	keys := map[string]bool{}
	for _, e := range c.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || keys[k] || strings.ContainsRune(e, 0) {
			return ErrUnavailable
		}
		keys[k] = true
	}
	for _, args := range [][]string{c.LauncherArgs, c.Args} {
		for _, a := range args {
			if strings.ContainsRune(a, 0) {
				return ErrUnavailable
			}
		}
	}
	for _, p := range c.Policy.Ports {
		if p == 0 {
			return ErrUnavailable
		}
	}
	for _, p := range c.Policy.UnixPaths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, 0) || len(p) > 107 {
			return ErrUnavailable
		}
	}
	if c.Policy.MaxEvents < 0 || c.Policy.MaxEvents > 65536 {
		return ErrUnavailable
	}
	for _, f := range append([]*os.File{c.Stdin, c.Stdout, c.Stderr}, c.ExtraFiles...) {
		if f == nil {
			continue
		}
		var s unix.Stat_t
		if unix.Fstat(int(f.Fd()), &s) != nil || (s.Mode&unix.S_IFMT != unix.S_IFREG && s.Mode&unix.S_IFMT != unix.S_IFIFO) {
			return ErrUnavailable
		}
	}
	for _, f := range c.ExtraFiles {
		if f == nil {
			return ErrUnavailable
		}
	}
	return nil
}

// Run supervises the entire candidate lifetime. The launcher must be built from
// this package and trusted by the caller, just like the supervisor itself.
// Errors never trigger an unfiltered retry. Callers must supply a deadline.
func Run(ctx context.Context, c Config) (report Report, err error) {
	report.Summary = map[string]Counts{}
	defer func() {
		if err != nil {
			report.Incomplete = true
		}
	}()
	if _, ok := ctx.Deadline(); !ok {
		return report, ErrUnavailable
	}
	if err = validate(c); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if c.Policy.MaxEvents == 0 {
		c.Policy.MaxEvents = 1024
	}
	var sizes [3]uint16
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 || sizes[0] != uint16(unsafe.Sizeof(notification{})) || sizes[1] != uint16(unsafe.Sizeof(response{})) {
		return report, ErrUnavailable
	}
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return report, e
	}
	parent := pair[0]
	child := os.NewFile(uintptr(pair[1]), "bootstrap")
	defer unix.Close(parent)
	if err = unix.SetNonblock(parent, true); err != nil {
		child.Close()
		return report, err
	}
	argv := append([]string{}, c.LauncherArgs...)
	argv = append(argv, c.Executable)
	argv = append(argv, c.Args...)
	cmd := exec.Command(c.Launcher, argv...)
	cmd.Env = append([]string{}, c.Env...)
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	cmd.ExtraFiles = append([]*os.File{child}, c.ExtraFiles...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		child.Close()
		return report, err
	}
	child.Close()
	// Setpgid gives this run a private child process group; never use a name/pattern kill.
	defer func() { _ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if c.Started != nil {
		c.Started(cmd.Process.Pid)
	}

	listener := -1
	for listener < 0 {
		select {
		case err = <-done:
			report.Incomplete = true
			return report, errors.Join(ErrUnavailable, err)
		default:
		}
		if err = ctx.Err(); err != nil {
			cmd.Process.Kill()
			<-done
			report.Incomplete = true
			return report, err
		}
		p := []unix.PollFd{{Fd: int32(parent), Events: unix.POLLIN}}
		if _, e = unix.Poll(p, 20); e != nil && e != unix.EINTR {
			cmd.Process.Kill()
			<-done
			return report, e
		}
		if p[0].Revents&unix.POLLIN == 0 {
			continue
		}
		data := make([]byte, 1)
		control := make([]byte, unix.CmsgSpace(4))
		n, o, flags, _, e := unix.Recvmsg(parent, data, control, unix.MSG_CMSG_CLOEXEC)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil || n != 1 || data[0] != 1 || flags&unix.MSG_CTRUNC != 0 {
			cmd.Process.Kill()
			<-done
			return report, ErrUnavailable
		}
		messages, e := unix.ParseSocketControlMessage(control[:o])
		if e != nil || len(messages) != 1 {
			cmd.Process.Kill()
			<-done
			return report, ErrUnavailable
		}
		fds, e := unix.ParseUnixRights(&messages[0])
		if e != nil || len(fds) != 1 {
			for _, fd := range fds {
				unix.Close(fd)
			}
			cmd.Process.Kill()
			<-done
			return report, ErrUnavailable
		}
		listener = fds[0]
	}
	defer unix.Close(listener)
	ack := make([]byte, 3)
	ack[0] = 1
	binary.LittleEndian.PutUint16(ack[1:], uint16(len(c.ExtraFiles)))
	if _, e = unix.Write(parent, ack); e != nil {
		cmd.Process.Kill()
		<-done
		return report, e
	}
	start := time.Now()
	for {
		if err = ctx.Err(); err != nil {
			cmd.Process.Kill()
			<-done
			report.Incomplete = true
			return report, err
		}
		p := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		_, e = unix.Poll(p, 20)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			cmd.Process.Kill()
			<-done
			report.Incomplete = true
			return report, e
		}
		if p[0].Revents&unix.POLLIN != 0 {
			var n notification
			e = ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n))
			if e == unix.ENOENT || e == unix.EINTR {
				continue
			}
			if e != nil {
				cmd.Process.Kill()
				<-done
				report.Incomplete = true
				return report, e
			}
			d := c.Policy.decide(listener, n)
			r := response{ID: n.ID, Error: -int32(d.errno)}
			verdict := "refuse"
			if d.errno == 0 {
				r.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
				verdict = "allow"
			}
			if len(report.Events) >= c.Policy.MaxEvents {
				r.Flags = 0
				r.Error = -int32(unix.ECONNREFUSED)
				_ = ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r))
				cmd.Process.Kill()
				<-done
				report.Incomplete = true
				return report, ErrEvidenceLimit
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
			e = ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r))
			if e != nil && e != unix.ENOENT {
				cmd.Process.Kill()
				<-done
				report.Incomplete = true
				return report, e
			}
		}
		select {
		case err = <-done:
			return report, err
		default:
		}
	}
}
