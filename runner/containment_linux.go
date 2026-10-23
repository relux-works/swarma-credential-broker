//go:build linux

package runner

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const supervisorArg = "--internal-run-codex-supervisor"

// SupervisorMain is called before CLI parsing by the embedding executable.
// The guard is a session/group leader and Linux child subreaper. Only its
// lifeline and home-lock descriptors are inherited; neither reaches Codex.
// Parent death closes the lifeline even for SIGKILL. The guard stays alive to
// kill and reap its group before releasing the launch-home lock. An unresolved
// intent also fences home reuse if the guard itself dies unexpectedly.
func SupervisorMain(args []string) (bool, int) {
	if len(args) == 0 || args[0] != supervisorArg {
		return false, 0
	}
	if len(args) < 3 || args[1] != "--" {
		return true, 75
	}
	if syscall.Getpgrp() != os.Getpid() {
		return true, 75
	}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0) // PR_SET_CHILD_SUBREAPER
	if errno != 0 {
		return true, 75
	}
	life := os.NewFile(3, "lifeline")
	lock := os.NewFile(4, "launch-lock")
	if life == nil || lock == nil {
		return true, 75
	}
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	defer lock.Close()
	executable := os.NewFile(5, "pinned-executable")
	if executable == nil {
		return true, 75
	}
	defer executable.Close()
	syscall.CloseOnExec(5)
	defer life.Close()
	dead := make(chan struct{})
	go func() { var b [1]byte; life.Read(b[:]); close(dead) }()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	cmd := exec.Command("/proc/self/fd/3", args[3:]...)
	cmd.Args[0] = args[2]
	cmd.ExtraFiles = []*os.File{executable}
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return true, 75
	}
	// This goroutine alone reaps all direct/adopted children; cmd.Wait must not
	// race wait4. Reaping adopted grandchildren avoids persistent zombie groups.
	exited := make(chan int, 1)
	go func() {
		status := 75
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, 0, nil)
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				break
			}
			if pid == cmd.Process.Pid {
				if ws.Exited() {
					status = ws.ExitStatus()
				}
				exited <- status
				return
			}
		}
	}()
	result := 0
	select {
	case <-dead:
	case <-signals:
	case result = <-exited:
	}
	// Keep the guard/group identity alive while observing and killing members.
	// Only own group members or direct adopted children are signalled.
	until := time.Now().Add(3 * time.Second)
	termSent := false
	for time.Now().Before(until) {
		members, err := ownedMembers(os.Getpid())
		if err != nil {
			return true, 75
		}
		if len(members) == 1 && members[0] == os.Getpid() {
			var ws syscall.WaitStatus
			pid, e := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if e == syscall.ECHILD {
				return true, result
			}
			if e != nil && e != syscall.EINTR {
				return true, 75
			}
			// Orphans can be adopted after a snapshot. Rescan until wait4
			// proves ECHILD; zero means a live child, never absence.
			if pid == 0 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		for _, pid := range members {
			if pid == os.Getpid() {
				continue
			}
			sig := syscall.SIGKILL
			if !termSent {
				sig = syscall.SIGTERM
			}
			if e := signalOwned(pid, os.Getpid(), os.Getpid(), sig); e != nil {
				return true, 75
			}
		}
		termSent = true
		// The first wait goroutine may have returned on main-child exit; reap any
		// newly adopted children here. Concurrent waits only consume our children.
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true, 75
}

// groupMembers requires a complete successful proc scan. Permission/read/parse
// failure is unknown, never empty. Disappearing PIDs are the sole benign race.
func groupMembers(group int) ([]int, error) { return scanGroup("/proc", group) }
func scanGroup(root string, group int) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var members []int
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		raw, e := os.ReadFile(root + "/" + entry.Name() + "/stat")
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		end := strings.LastIndexByte(string(raw), ')')
		if end < 0 {
			return nil, errors.New("invalid process metadata")
		}
		fields := strings.Fields(string(raw[end+1:]))
		if len(fields) < 3 {
			return nil, errors.New("partial process metadata")
		}
		pgrp, e := strconv.Atoi(fields[2])
		if e != nil {
			return nil, e
		}
		if pgrp == group {
			members = append(members, pid)
		}
	}
	return members, nil
}

type process struct {
	cmd   *exec.Cmd
	in    *os.File
	out   *os.File
	life  *os.File
	done  chan error
	group int
}

func startProcess(d Dependencies, o Options, h *homeGuard, p Policy, args []string) (*process, error) {
	executable, err := openPinned(p)
	if err != nil {
		return nil, err
	}
	defer executable.Close()
	self := d.Supervisor
	if self == "" {
		var err error
		self, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		lifeR.Close()
		lifeW.Close()
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		lifeR.Close()
		lifeW.Close()
		inR.Close()
		inW.Close()
		return nil, err
	}
	argv := append([]string{supervisorArg, "--", p.Executable}, args...)
	cmd := exec.Command(self, argv...)
	cmd.Env = cleanEnvironment(o.LaunchHome)
	cmd.Dir = o.Cwd
	cmd.Stdin = inR
	cmd.Stdout = outW
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{lifeR, h.lock, executable}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	lifeR.Close()
	inR.Close()
	outW.Close()
	if err != nil {
		lifeW.Close()
		inW.Close()
		outR.Close()
		return nil, err
	}
	proc := &process{cmd: cmd, in: inW, out: outR, life: lifeW, done: make(chan error, 1), group: cmd.Process.Pid}
	go func() { proc.done <- cmd.Wait(); close(proc.done) }()
	return proc, nil
}
func (p *process) stop(ctx context.Context) error {
	p.in.Close()
	// Let the peer consume already-written denial/interrupt frames and EOF.
	// This is bounded transport drain, not a vendor completion wait.
	grace := time.NewTimer(100 * time.Millisecond)
	defer grace.Stop()
	var waitErr error
	var waited bool
	select {
	case <-ctx.Done():
		p.life.Close()
		p.out.Close()
		return ctx.Err()
	case waitErr = <-p.done:
		waited = true
	case <-grace.C:
	}
	p.life.Close()
	if !waited {
		select {
		case <-ctx.Done():
			p.out.Close()
			return ctx.Err()
		case waitErr = <-p.done:
		}
	}
	p.out.Close()
	if waitErr != nil {
		return errors.New("guard failure")
	}
	members, err := groupMembers(p.group)
	if err != nil || len(members) != 0 {
		return errors.New("containment unknown")
	}
	if err = syscall.Kill(-p.group, 0); err != syscall.ESRCH {
		return errors.New("group still present")
	}
	return nil
}

// A pidfd binds the signal to one process incarnation. Recheck membership after
// opening it: PID reuse can then yield ESRCH or a refused nonmember, never a
// signal to a replacement process from another session.
func signalMember(pid, group int, sig syscall.Signal) error { return signalOwned(pid, group, 0, sig) }
func signalOwned(pid, group, parent int, sig syscall.Signal) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err == syscall.ESRCH {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	current, err := syscall.Getpgid(pid)
	if err == syscall.ESRCH {
		return nil
	}
	if err != nil {
		return err
	}
	if current != group {
		if parent == 0 {
			return errors.New("group membership changed")
		}
		raw, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		_, ppid, e := metadata(raw)
		if e != nil {
			return e
		}
		if ppid != parent {
			return errors.New("ownership changed")
		}
	}
	err = unix.PidfdSendSignal(fd, unix.Signal(sig), nil, 0)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// Group members are stopped first; escaped or double-forked descendants are
// adopted by the subreaper when their parents die. Direct adopted children are
// also stopped, regardless of their session/group. ECHILD is required before
// guard success, so a group escape cannot become false absence evidence.
func ownedMembers(owner int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var members []int
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		raw, e := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		group, parent, e := metadata(raw)
		if e != nil {
			return nil, e
		}
		if group == owner || parent == owner {
			members = append(members, pid)
		}
	}
	return members, nil
}
func metadata(raw []byte) (group, parent int, err error) {
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, 0, errors.New("invalid process metadata")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 3 {
		return 0, 0, errors.New("partial process metadata")
	}
	parent, err = strconv.Atoi(fields[1])
	if err != nil {
		return
	}
	group, err = strconv.Atoi(fields[2])
	return
}
