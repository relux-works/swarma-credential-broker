//go:build linux

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An unrelated PID disappearing after stat is opened cannot fail a public
// Command lifecycle. strace delays the real read, never substitutes an errno;
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
	traceProcRead(t, false, true, self, "-test.run=^TestStopRequiresAbsentGroup$", "-test.v")
}

func traceProcRead(t *testing.T, follow, disappear bool, command ...string) {
	t.Helper()
	tracer, err := exec.LookPath("strace")
	if err != nil {
		if os.Getenv("RUNNER_QUALIFICATION") == "1" {
			t.Fatalf("UNVERIFIED: %s requires strace: %v", t.Name(), err)
		}
		t.Skipf("UNVERIFIED: %s requires strace: %v", t.Name(), err)
	}
	helper := exec.Command("/bin/sleep", "30")
	must(t, helper.Start())
	defer func() {
		if helper.ProcessState == nil {
			helper.Process.Kill()
			helper.Wait()
		}
	}()
	path := fmt.Sprintf("/proc/%d/stat", helper.Process.Pid)
	trace := filepath.Join(t.TempDir(), "proc.trace")
	args := []string{"-f", "-e", "trace=openat,read", "-e", "raw=read", "-P", path,
		"-e", "inject=read:delay_enter=100ms", "-o", trace}
	args = append(args, command...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tracer, args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	must(t, cmd.Start())
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	// Trace all threads; identify the parent by its test executable rather
	// than a particular thread. Guard processes use a different executable.
	wantOpen := 1
	if len(command) > 1 && strings.HasPrefix(command[1], "-test.run=") {
		wantOpen = 2 // first stop intentionally rejects a live group
	}
	observed := false
	var runErr error
loop:
	for {
		data, _ := os.ReadFile(trace)
		// A completed open pins this process incarnation before it is reaped.
		opens := 0
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "openat(") && strings.Contains(line, path) && strings.Contains(line, ") = ") && !strings.Contains(line, "= -1") {
				if !follow {
					fields := strings.Fields(line)
					executable, _ := os.Readlink("/proc/" + fields[0] + "/exe")
					if executable != command[0] {
						continue
					}
				}
				opens++
				if opens < wantOpen {
					continue
				}
				if !observed && disappear {
					must(t, helper.Process.Kill())
					if err := helper.Wait(); err == nil {
						t.Fatal("helper unexpectedly exited successfully")
					}
				}
				observed = true
			}
		}
		select {
		case runErr = <-ended:
			break loop
		case <-time.After(time.Millisecond):
		}
	}
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
			done := make(chan int, 1)
			go func() { done <- Command(ctx, f.args(), IO{strings.NewReader("prompt"), out, &f.err}, f.d) }()
			if kind == "signal" || kind == "release-failure" || kind == "deadline" {
				until := time.Now().Add(time.Second)
				full := false
				for time.Now().Before(until) {
					n, e := unix.IoctlGetInt(int(rd.Fd()), unix.TIOCINQ)
					must(t, e)
					if n == 4096 {
						full = true
						break
					}
					time.Sleep(time.Millisecond)
				}
				if kind != "deadline" {
					cancel()
				}
				if !full {
					cancel()
					<-done
					t.Fatal("blocked-output control did not fill the pipe")
				}
			}
			drained := make(chan struct{})
			if kind == "writable" {
				go func() { io.Copy(io.Discard, rd); close(drained) }()
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
