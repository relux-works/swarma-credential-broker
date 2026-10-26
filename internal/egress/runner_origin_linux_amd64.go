//go:build linux && amd64

package egress

import (
	"context"
	"crypto/sha256"
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

	"golang.org/x/sys/unix"
)

func NewRunnerOrigin(image *os.File, digest string, argv []string) (*RunnerOrigin, error) {
	b, err := hex.DecodeString(digest)
	if image == nil || err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != digest || len(argv) == 0 || len(strings.Join(argv, "\x00"))+1 > 2048 {
		return nil, ErrRunnerOriginUnavailable
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return nil, ErrRunnerOriginUnavailable
		}
	}
	return &RunnerOrigin{image: image, digest: digest, argv: append([]string(nil), argv...)}, nil
}

func runnerImage(image *os.File, digest string) error {
	if image == nil {
		return ErrRunnerOriginUnavailable
	}
	s, e := image.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() <= 0 || s.Size() > 256<<20 {
		return ErrRunnerOriginUnavailable
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.NewSectionReader(image, 0, s.Size())); e != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrRunnerOriginUnavailable
	}
	return nil
}

// The initial TRACEME exec trap precedes any userspace in the case image.
// A generic later stop, an adopted process or an untraced PID cannot replace it.
func runnerExecStop(pid int, status unix.WaitStatus, o *RunnerOrigin) error {
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP || status.TrapCause() != 0 {
		return ErrRunnerOriginUnavailable
	}
	if e := runnerChild(pid); e != nil {
		return e
	}
	if e := originIdentity(pid, o.image, o.argv); e != nil {
		return ErrRunnerOriginUnavailable
	}
	return runnerImage(o.image, o.digest)
}

func runnerChild(pid int) error {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if e != nil {
		return ErrRunnerOriginUnavailable
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			values[f[0]] = f[1]
		}
	}
	if values["PPid:"] != strconv.Itoa(os.Getpid()) || values["TracerPid:"] != strconv.Itoa(unix.Gettid()) || values["Tgid:"] != strconv.Itoa(pid) {
		return ErrRunnerOriginUnavailable
	}
	return nil
}

// runnerNext preserves originOwner's exact PID/pidfd peek and stop consumption.
// ECHILD, including a terminal status taken by another waiter, is unavailable.
func runnerNext(w *originOwner) (int, unix.WaitStatus, bool, error) {
	// A dying group can lose the parent's clone-event stop while the new
	// thread remains trace-owned. Discover it before waiting for the leader;
	// otherwise its unreaped terminal status can block the whole group.
	entries, scanErr := os.ReadDir(fmt.Sprintf("/proc/%d/task", w.pid))
	if scanErr != nil && !os.IsNotExist(scanErr) {
		return 0, 0, false, errors.Join(ErrRunnerOriginUnavailable, scanErr)
	}
	for _, entry := range entries {
		p, e := strconv.Atoi(entry.Name())
		if e != nil || len(w.tasks) > 128 {
			return 0, 0, false, ErrRunnerOriginUnavailable
		}
		if _, known := w.tasks[p]; !known {
			w.tasks[p] = false
		}
	}
	p, s, done, e := w.next()
	if e != nil {
		e = errors.Join(ErrRunnerOriginUnavailable, e)
	}
	return p, s, done, e
}

// TraceRunner owns Start, ptrace and the only consuming cmd.Wait on one locked
// OS thread. Distinct child processes are detached at their initial stop, before
// userspace; their parent retains its normal wait and nested trace ownership.
// Runtime threads stay traced. Callers cannot attach this API to an existing PID.
func TraceRunner(ctx context.Context, c RunnerTraceConfig) (result RunnerTraceResult, err error) {
	o := c.Origin
	if o == nil {
		return result, ErrRunnerOriginUnavailable
	}
	defer func() {
		if err != nil {
			o.invalid.Store(true)
			err = errors.Join(ErrRunnerOriginUnavailable, err)
		}
	}()
	if _, ok := ctx.Deadline(); !ok {
		return result, ErrRunnerOriginUnavailable
	}
	if !o.used.CompareAndSwap(false, true) || c.Env == nil {
		return result, ErrRunnerOriginUnavailable
	}
	if err = runnerImage(o.image, o.digest); err != nil {
		return
	}
	if err = validate(Config{Launcher: "/proc/self/fd/3", Executable: "/proc/self/fd/3", Args: c.Args, Env: c.Env, Stdin: c.Stdin, Stdout: c.Stdout, Stderr: c.Stderr, ExtraFiles: c.ExtraFiles}); err != nil {
		return
	}
	if err = ctx.Err(); err != nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd := -1
	cmd := exec.Command("/proc/self/fd/3", c.Args...)
	cmd.Dir, cmd.Env = c.Dir, c.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.ExtraFiles = append([]*os.File{o.image}, c.ExtraFiles...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, PidFD: &fd}
	if err = cmd.Start(); err != nil {
		return
	}
	o.pid.Store(int64(cmd.Process.Pid))
	w := originOwner{pid: cmd.Process.Pid, fd: fd, tasks: map[int]bool{cmd.Process.Pid: true}}
	terminal := false
	defer func() {
		// Invalidate admission before stopping this pinned process. Detached
		// subtrees are joined by their runner-owned supervisor, not by P.
		o.terminal.Store(true)
		if !terminal {
			o.invalid.Store(true)
			if fd >= 0 {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			} else {
				_ = cmd.Process.Kill()
			}
			for !terminal && fd >= 0 {
				p, s, done, e := runnerNext(&w)
				if e != nil {
					err = errors.Join(err, e)
					break
				}
				terminal = done
				o.terminal.Store(done)
				if p != 0 {
					if e = runnerResume(&w, p, s, &result); e != nil {
						err = errors.Join(err, e)
					}
				} else if !done {
					time.Sleep(time.Millisecond)
				}
			}
		}
		// No goroutine or wildcard wait can consume this process's terminal status.
		var waitErr error
		result.State, waitErr = runnerConsumeWait(cmd, o, terminal)
		err = errors.Join(err, waitErr)
		if !o.verified.Load() {
			err = errors.Join(err, ErrRunnerOriginUnavailable)
		}
		if c.Waited != nil {
			c.Waited(result.State)
		}
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	if c.Started != nil {
		c.Started(w.pid)
	}
	if fd < 0 {
		return result, ErrRunnerOriginUnavailable
	}
	birth := false
	events := 0
	for !terminal {
		if err = ctx.Err(); err != nil {
			return
		}
		p, s, done, e := runnerNext(&w)
		if e != nil {
			return result, e
		}
		terminal = done
		o.terminal.Store(done)
		if done {
			if !birth {
				return result, ErrRunnerOriginUnavailable
			}
			return
		}
		if p == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		events++
		if events > 4096 {
			return result, ErrEvidenceLimit
		}
		if !birth {
			if p != w.pid || runnerExecStop(p, s, o) != nil {
				return result, ErrRunnerOriginUnavailable
			}
			if err = unix.PtraceSetOptions(p, unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_EXITKILL); err != nil {
				return
			}
			birth = true
			o.verified.Store(true)
			if c.Verified != nil {
				if err = c.Verified(); err != nil {
					return
				}
			}
		} else if s.TrapCause() == unix.PTRACE_EVENT_EXEC {
			return result, ErrRunnerOriginUnavailable
		}
		if err = runnerResume(&w, p, s, &result); err != nil {
			return
		}
	}
	return
}

func runnerResume(w *originOwner, tid int, s unix.WaitStatus, result *RunnerTraceResult) error {
	if s.Exited() || s.Signaled() {
		delete(w.tasks, tid)
		return nil
	}
	if !w.tasks[tid] {
		if s.StopSignal() != unix.SIGSTOP {
			return ErrRunnerOriginUnavailable
		}
		if originThread(tid, w.pid) {
			w.tasks[tid] = true
			result.Threads++
		} else {
			// The newborn is stopped before its first userspace instruction.
			// It must not inherit this tracer when its own tracer starts.
			if e := unix.PtraceDetach(tid); e != nil {
				return e
			}
			delete(w.tasks, tid)
			result.child(tid)
			return nil
		}
	}
	cause := s.TrapCause()
	if cause == unix.PTRACE_EVENT_CLONE || cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
		p, e := unix.PtraceGetEventMsg(tid)
		if e != nil || p == 0 || len(w.tasks) >= 128 {
			return ErrRunnerOriginUnavailable
		}
		// Count creation before the parent resumes, even if group exit overtakes
		// the newborn stop. Deduplication also covers stop-before-event ordering.
		if !w.tasks[int(p)] && (cause != unix.PTRACE_EVENT_CLONE || !originThread(int(p), w.pid)) {
			result.child(int(p))
		}
		if _, known := w.tasks[int(p)]; !known {
			w.tasks[int(p)] = false
		}
	}
	sig := 0
	if s.StopSignal() != unix.SIGTRAP && s.StopSignal() != unix.SIGSTOP {
		sig = int(s.StopSignal())
	}
	if e := unix.PtraceCont(tid, sig); e != nil && e != unix.ESRCH {
		return e
	}
	return nil
}

func runnerConsumeWait(cmd *exec.Cmd, o *RunnerOrigin, terminal bool) (*os.ProcessState, error) {
	e := cmd.Wait()
	s := cmd.ProcessState
	if s == nil || s.Pid() != int(o.pid.Load()) || !terminal {
		return s, errors.Join(ErrRunnerOriginUnavailable, e)
	}
	o.joined.Store(true)
	return s, nil
}

func (r *RunnerTraceResult) child(pid int) {
	if r.children == nil {
		r.children = map[int]bool{}
	}
	r.children[pid] = true
	r.Children = uint64(len(r.children))
}
