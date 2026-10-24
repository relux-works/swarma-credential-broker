//go:build linux

package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An unrelated PID disappearing after stat is opened cannot fail a public
// Command lifecycle. strace stops after the real open, never substitutes an errno;
// the test reaps only its own helper after the successful open. Separate cases
// exercise the parent scan and guard scan, with a live-helper positive control.
func TestCommandProcDisappearance(t *testing.T) {
	requiredEvidenceRow(t)
	for _, follow := range []bool{false, true} {
		for _, disappear := range []bool{false, true} {
			t.Run(fmt.Sprintf("follow=%v/disappear=%v", follow, disappear), func(t *testing.T) {
				requiredEvidenceRow(t)
				f := newFixture(t, nil)
				self, err := os.Executable()
				must(t, err)
				traceProcRead(t, follow, disappear, self, "--fixture-parent", f.root, fakePath, supervisorPath)
				data, err := os.ReadFile(f.output)
				must(t, err)
				if string(data) != "answer" {
					t.Fatal("successful lifecycle did not publish final output")
				}
			})
		}
	}
}

// Replay the formerly failing stop test under the same real ESRCH race. This
// establishes a causal reproduction, not the provenance of an untraced old run.
func TestStopProcDisappearance(t *testing.T) {
	requiredEvidenceRow(t)
	self, err := os.Executable()
	must(t, err)
	traceProcRead(t, false, true, self, "--fixture-tools", fakePath, supervisorPath, "-test.run=^TestStopRequiresAbsentGroup$", "-test.v")
}

func traceProcRead(t *testing.T, follow, disappear bool, command ...string) {
	t.Helper()
	tracer, err := exec.LookPath("strace")
	if err != nil {
		unverifiedTrace(t, fmt.Errorf("strace unavailable: %w", err))
	}
	requirePtrace(t)
	helper := exec.Command("/bin/cat")
	helperInput, err := helper.StdinPipe()
	must(t, err)
	must(t, helper.Start())
	defer helperInput.Close()
	defer func() {
		if helper.ProcessState == nil {
			helper.Process.Kill()
			helper.Wait()
		}
	}()
	path := fmt.Sprintf("/proc/%d/stat", helper.Process.Pid)
	trace := filepath.Join(t.TempDir(), "proc.trace")
	traceRead, traceWrite, err := os.Pipe()
	must(t, err)
	defer traceRead.Close()
	defer traceWrite.Close()
	// The path filter also limits injection to this helper's stat opens. SIGSTOP
	// is delivered after open completes; a traced group-stop acknowledges that
	// no read can follow until we reap the helper and explicitly send SIGCONT.
	args := []string{"-f", "-e", "trace=openat,read", "-e", "raw=read", "-P", path,
		"-e", "inject=openat:signal=SIGSTOP", "-o", "/proc/self/fd/3"}
	args = append(args, command...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, tracer, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = []*os.File{traceWrite}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	must(t, cmd.Start())
	must(t, traceWrite.Close())
	defer func() {
		// This process group was allocated by cmd.Start above, never discovered by
		// name. It contains only this trace and its fixture descendants.
		if cmd.ProcessState == nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			cmd.Wait()
		}
	}()
	wantOpen := 1
	for _, arg := range command[1:] {
		if strings.HasPrefix(arg, "-test.run=") {
			wantOpen = 2 // first stop intentionally rejects a live group
		}
	}
	observed, opens := false, 0
	target := map[int]bool{}
	pending := map[int]bool{}
	var evidence strings.Builder
	scanner := bufio.NewScanner(traceRead)
	for scanner.Scan() {
		line := scanner.Text()
		evidence.WriteString(line + "\n")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		tid, parseErr := strconv.Atoi(fields[0])
		if parseErr != nil {
			continue
		}
		if strings.Contains(line, "openat(") && strings.Contains(line, path) && strings.Contains(line, ") = ") && !strings.Contains(line, "= -1") {
			executable, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", tid))
			pending[tid] = true
			target[tid] = (follow && executable == supervisorPath) || (!follow && executable == command[0])
			if target[tid] {
				opens++
			}
		}
		if !strings.Contains(line, "stopped by SIGSTOP") || !pending[tid] {
			continue
		}
		// A Go syscall may run on any thread; signal the pinned thread group's
		// leader rather than treating a thread ID as a process ID.
		delete(pending, tid)
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
		must(t, err)
		tgid := 0
		for _, field := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(field, "Tgid:") {
				tgid, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(field, "Tgid:")))
				must(t, err)
			}
		}
		if tgid == 0 {
			t.Fatal("stopped tracee group identity missing")
		}
		fd, err := unix.PidfdOpen(tgid, 0)
		must(t, err)
		if target[tid] && opens >= wantOpen && !observed {
			if disappear {
				must(t, helper.Process.Kill())
				if err := helper.Wait(); err == nil {
					t.Fatal("helper unexpectedly exited successfully")
				}
			}
			observed = true
		}
		err = unix.PidfdSendSignal(fd, syscall.SIGCONT, nil, 0)
		unix.Close(fd)
		must(t, err)
	}
	must(t, scanner.Err())
	runErr := cmd.Wait()
	must(t, os.WriteFile(trace, []byte(evidence.String()), 0600))
	data, err := os.ReadFile(trace)
	must(t, err)
	if !observed {
		t.Fatalf("stat-open control did not apply: %v\n%s\n%s", runErr, output.String(), data)
	}
	if disappear && !strings.Contains(string(data), "ESRCH") {
		t.Fatalf("real ESRCH control did not apply: %v\n%s\n%s", runErr, output.String(), data)
	}
	if runErr != nil {
		t.Fatalf("lifecycle failed after proc observation: %v\n%s\n%s", runErr, output.String(), data)
	}
}

func requirePtrace(t *testing.T) {
	t.Helper()
	if probeErr := ptraceAvailability(); probeErr != nil {
		if errors.Is(probeErr, syscall.EPERM) || errors.Is(probeErr, syscall.EACCES) || errors.Is(probeErr, syscall.ENOSYS) {
			unverifiedTrace(t, fmt.Errorf("ptrace unavailable: %w", probeErr))
		}
		t.Fatalf("ptrace probe failed: %v", probeErr)
	}
}

func unverifiedTrace(t *testing.T, cause error) {
	t.Helper()
	if os.Getenv("RUNNER_QUALIFICATION") == "1" {
		t.Fatalf("UNVERIFIED: %s: %v", t.Name(), cause)
	}
	t.Skipf("UNVERIFIED: %s: %v", t.Name(), cause)
}

// Probe both native attach mechanisms used by strace before launching it.
// Start/ptrace return typed errno, so no tracer-output text is classified.
// ptrace ownership belongs to an OS thread, including wait and detach.
func ptraceAvailability() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ptraceTraceMe(); err != nil {
		return fmt.Errorf("PTRACE_TRACEME: %w", err)
	}
	if err := ptraceSeize(); err != nil {
		return fmt.Errorf("PTRACE_SEIZE: %w", err)
	}
	return nil
}

func ptraceTraceMe() error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	var status syscall.WaitStatus
	for {
		_, err := syscall.Wait4(cmd.Process.Pid, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if !status.Stopped() {
		return fmt.Errorf("tracee did not acknowledge attach: %v", status)
	}
	if err := syscall.PtraceDetach(cmd.Process.Pid); err != nil {
		return err
	}
	return cmd.Wait()
}

func ptraceSeize() error {
	// The held stdin keeps only this owned tracee alive until attach completes.
	cmd := exec.Command("/bin/cat")
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	if err := unix.PtraceSeize(cmd.Process.Pid); err != nil {
		return err
	}
	if err := unix.PtraceInterrupt(cmd.Process.Pid); err != nil {
		return err
	}
	var status syscall.WaitStatus
	for {
		_, err := syscall.Wait4(cmd.Process.Pid, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if !status.Stopped() {
		return fmt.Errorf("tracee did not acknowledge seize: %v", status)
	}
	if err := unix.PtraceDetach(cmd.Process.Pid); err != nil {
		return err
	}
	input.Close()
	return cmd.Wait()
}

// Blocked stdout preserves cancellation/deadline status, cleanup still wins,
// writable output succeeds, and a real EPIPE remains an output failure.
func TestCommandOutputCancellation(t *testing.T) {
	for _, kind := range []string{"signal", "deadline", "writable", "broken-pipe", "broken-pipe-cancel", "release-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, map[string]any{"LargeOutput": true})
			f.o.Timeout = 1500 * time.Millisecond
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			rd, wr, err := os.Pipe()
			must(t, err)
			defer rd.Close()
			defer wr.Close()
			conn, err := wr.SyscallConn()
			must(t, err)
			must(t, conn.Control(func(fd uintptr) { _, err = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, 4096) }))
			must(t, err)
			if kind == "broken-pipe" {
				must(t, rd.Close())
			}
			if kind == "release-failure" {
				f.b.releaseErr = errors.New("fixture release failure")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out io.Writer = wr
			if kind == "broken-pipe-cancel" {
				out = cancelBrokenWriter{cancel}
			}
			var workers sync.WaitGroup
			defer func() { cancel(); rd.Close(); wr.Close(); workers.Wait() }()
			done := make(chan int, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				done <- Command(ctx, f.args(), IO{strings.NewReader("prompt"), out, &f.err}, f.d)
			}()
			if kind == "signal" || kind == "release-failure" || kind == "deadline" {
				awaitPipeFull(t, rd)
				if kind != "deadline" {
					cancel()
				}
			}
			drained := make(chan struct{})
			if kind == "writable" {
				workers.Add(1)
				go func() { defer workers.Done(); io.Copy(io.Discard, rd); close(drained) }()
			}
			got := <-done
			wr.Close()
			if kind == "writable" {
				<-drained
			}
			want := map[string]int{"signal": 130, "deadline": 124, "writable": 0, "broken-pipe": 75, "broken-pipe-cancel": 75, "release-failure": 75}[kind]
			requireStatus(t, got, want, f.err.String())
			pid := readPID(t, filepath.Join(f.home, "server-pid"))
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("child remains after output cancellation")
			}
			releases := 0
			for _, call := range f.b.calls {
				if call == "release" {
					releases++
				}
			}
			if releases != 1 {
				t.Fatalf("release count = %d", releases)
			}
			data, err := os.ReadFile(f.output)
			must(t, err)
			if kind == "writable" {
				if len(data) != 64<<10 {
					t.Fatal("writable control lost final output")
				}
			} else if string(data) != "old" {
				t.Fatal("failed run replaced old final output")
			}
		})
	}
}

// The embedding writer reports a genuine EPIPE while cancellation also arrives;
// a broad "context cancelled means every write error is cancellation" is wrong.
type cancelBrokenWriter struct{ cancel context.CancelFunc }

func (w cancelBrokenWriter) Write([]byte) (int, error) {
	w.cancel()
	return 0, syscall.EPIPE
}

// A held proc descriptor returns real ESRCH after reaping; missing per-PID
// metadata is benign, but directory and partial/unreadable evidence stay unknown.
func TestProcReadEvidence(t *testing.T) {
	helper := exec.Command("/bin/sleep", "30")
	must(t, helper.Start())
	defer func() {
		if helper.ProcessState == nil {
			helper.Process.Kill()
			helper.Wait()
		}
	}()
	fd, err := os.Open(fmt.Sprintf("/proc/%d/stat", helper.Process.Pid))
	must(t, err)
	defer fd.Close()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(helper.Process.Pid))
	must(t, os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "stat")
	must(t, os.Symlink(fmt.Sprintf("/proc/self/fd/%d", fd.Fd()), path))
	for _, scan := range []func(string, int) ([]int, error){scanGroup, scanOwned} {
		_, err = scan(root, -1)
		must(t, err)
	}
	must(t, helper.Process.Kill())
	helper.Wait()
	_, err = os.ReadFile(path)
	if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("expected real ESRCH, got %v", err)
	}
	for i, scan := range []func(string, int) ([]int, error){scanGroup, scanOwned} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err := scan(root, -1)
			must(t, err)
			missing := t.TempDir()
			must(t, os.Mkdir(filepath.Join(missing, "101"), 0700))
			_, err = scan(missing, -1)
			must(t, err)
			stat := filepath.Join(missing, "101", "stat")
			// A directory where stat should be is unreadable even as root.
			must(t, os.Mkdir(stat, 0700))
			if _, err = scan(missing, -1); err == nil {
				t.Fatal("unreadable metadata accepted")
			}
			must(t, os.Remove(stat))
			must(t, os.WriteFile(stat, []byte("101 (fixture) S"), 0600))
			if _, err = scan(missing, -1); err == nil {
				t.Fatal("partial metadata accepted")
			}
			if _, err = scan(stat, -1); err == nil {
				t.Fatal("failed enumeration accepted")
			}
			must(t, os.WriteFile(stat, []byte("101 (fixture) S 99 99 99"), 0600))
			members, err := scan(missing, 99)
			must(t, err)
			if len(members) != 1 || members[0] != 101 {
				t.Fatal("live member control lost")
			}
		})
	}
}
