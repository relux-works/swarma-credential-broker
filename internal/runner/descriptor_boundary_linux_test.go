//go:build linux

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type descriptorObject struct {
	Device uint64
	Inode  uint64
	Kind   uint32
}
type descriptorReport struct {
	PID      int
	Entry    map[string]descriptorObject
	Opened   descriptorObject
	OpenedFD int
}

func descriptorIdentity(t *testing.T, path string) descriptorObject {
	t.Helper()
	var st syscall.Stat_t
	must(t, syscall.Stat(path, &st))
	return descriptorObject{uint64(st.Dev), st.Ino, st.Mode & syscall.S_IFMT}
}

func nativeDescriptorFixture(t *testing.T) (*fixture, *homeGuard, *process, descriptorReport) {
	t.Helper()
	f := newFixture(t, map[string]any{"DescriptorProbe": true})
	h, err := lockHome(f.home)
	must(t, err)
	must(t, h.intent())
	p, err := startProcess(f.d, f.o, h, f.a.p, []string{"app-server", "--listen", "stdio://", "-c", `cli_auth_credentials_store="ephemeral"`})
	if err != nil {
		h.close(true)
		t.Fatal(err)
	}
	cleanupDescriptorFixture(t, f, h, p)
	return f, h, p, awaitDescriptorReport(t, f, f.a.p.Executable)
}

func cleanupDescriptorFixture(t *testing.T, f *fixture, h *homeGuard, p *process) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := p.stop(ctx)
		must(t, h.close(err == nil))
		must(t, err)
		starts, err := os.ReadFile(filepath.Join(f.home, "descriptor-starts"))
		must(t, err)
		if len(bytes.Fields(starts)) != 1 {
			t.Fatal("native image did not start exactly once", string(starts))
		}
	})
}

func awaitDescriptorReport(t *testing.T, f *fixture, imagePath string) descriptorReport {
	t.Helper()

	path := filepath.Join(f.home, "descriptor-report.json")
	var report descriptorReport
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		b, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(b, &report) == nil {
			break
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if report.PID == 0 || len(report.Entry) == 0 {
		t.Fatal("native descriptor fixture did not report")
	}
	image := descriptorIdentity(t, imagePath)
	if descriptorIdentity(t, fmt.Sprintf("/proc/%d/exe", report.PID)) != image {
		t.Fatal("native image differs from pinned object")
	}
	if report.Opened != image || descriptorIdentity(t, fmt.Sprintf("/proc/%d/fd/%d", report.PID, report.OpenedFD)) != image {
		t.Fatal("fixture-created image descriptor unavailable")
	}
	return report
}

// Claim: the approved native image starts once, speaks stdio, and may open its
// own image after entry. This synthetic fixture grants no vendor qualification.
func TestSupervisorNativeLaunch(t *testing.T) {
	f, _, p, report := nativeDescriptorFixture(t)
	must(t, json.NewEncoder(p.in).Encode(map[string]any{"id": "init", "method": "initialize", "params": map[string]any{"capabilities": map[string]bool{"experimentalApi": true}}}))
	var reply struct {
		ID     string
		Result json.RawMessage
		Error  json.RawMessage
	}
	must(t, p.out.SetReadDeadline(time.Now().Add(5*time.Second)))
	must(t, json.NewDecoder(p.out).Decode(&reply))
	if reply.ID != "init" || len(reply.Result) == 0 || len(reply.Error) != 0 {
		t.Fatal("native stdio launch failed", reply)
	}
	env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", report.PID))
	must(t, err)
	if string(env) != strings.Join(cleanEnvironment(f.home), "\x00")+"\x00" {
		t.Fatal("native environment changed")
	}
	group, err := syscall.Getpgid(report.PID)
	must(t, err)
	if group != p.group {
		t.Fatal("native child escaped supervisor group")
	}
	f.noLease()
	assertAbsent(t, f.output)
}

// Claim: at audited native fixture entry, none of the supervisor's lifeline,
// home-lock or pinned-image objects is inherited, regardless of descriptor
// number. The entry snapshot precedes the child's deliberate self-image open;
// parent /proc stats verify the running image and that permitted later open.
// This is an entry snapshot, not a general restriction on future child opens.
func TestSupervisorDescriptorBoundary(t *testing.T) {
	f, h, p, report := nativeDescriptorFixture(t)
	forbidden := map[string]descriptorObject{
		"lifeline":          descriptorIdentity(t, fmt.Sprintf("/proc/self/fd/%d", p.life.Fd())),
		"home-lock":         descriptorIdentity(t, fmt.Sprintf("/proc/self/fd/%d", h.lock.Fd())),
		"pinned-executable": descriptorIdentity(t, f.a.p.Executable),
	}
	for fd, observed := range report.Entry {
		for name, identity := range forbidden {
			if observed == identity {
				if descriptorIdentity(t, fmt.Sprintf("/proc/%d/fd/%s", report.PID, fd)) != identity {
					t.Fatal("entry descriptor identity changed")
				}
				t.Errorf("inherited supervisor object: %s (fd %s, device %d inode %d)", name, fd, identity.Device, identity.Inode)
			}
		}
	}
}

// The private supervisor protocol is invoked with the same verified object and
// lifeline/lock wiring as startProcess, after the pathname is replaced/unlinked.
// This exercises its actual Go exec path without a production test hook.
func directDescriptorSupervisor(t *testing.T, f *fixture, h *homeGuard, image *os.File) *process {
	t.Helper()
	lifeR, lifeW, err := os.Pipe()
	must(t, err)
	defer lifeR.Close()
	cmd := exec.Command(supervisorPath, supervisorArg, "--", f.a.p.Executable, "app-server", "--listen", "stdio://", "-c", `cli_auth_credentials_store="ephemeral"`)
	cmd.Env = cleanEnvironment(f.home)
	cmd.Dir = f.o.Cwd
	cmd.Stderr = io.Discard
	in, err := cmd.StdinPipe()
	must(t, err)
	out, err := cmd.StdoutPipe()
	must(t, err)
	cmd.ExtraFiles = []*os.File{lifeR, h.lock, image}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		lifeW.Close()
		in.Close()
		out.Close()
		t.Fatal(err)
	}
	p := &process{cmd: cmd, in: in.(*os.File), out: out.(*os.File), life: lifeW, done: make(chan error, 1), group: cmd.Process.Pid}
	go func() { p.done <- cmd.Wait(); close(p.done) }()
	return p
}

// Claim: after verification, replacing or unlinking the selected pathname does
// not change the object executed. The live kernel exe identity must match the
// retained original; replacement has equal bytes but a distinct inode. This is
// a native pinned-object test, not authority for later child path execution.
func TestSupervisorPinnedObject(t *testing.T) {
	for _, mode := range []string{"replacement", "unlinked"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, map[string]any{"DescriptorProbe": true})
			raw, err := os.ReadFile(fakePath)
			must(t, err)
			selected := filepath.Join(f.root, "selected-native")
			must(t, os.WriteFile(selected, raw, 0700))
			f.a.p.Executable = selected
			pinned, err := openPinned(f.a.p)
			must(t, err)
			defer pinned.Close()
			retained := selected + "-retained"
			must(t, os.Rename(selected, retained))
			if mode == "replacement" {
				must(t, os.WriteFile(selected, raw, 0700))
			} else {
				must(t, os.Remove(retained))
				retained = fmt.Sprintf("/proc/self/fd/%d", pinned.Fd())
			}
			h, err := lockHome(f.home)
			must(t, err)
			must(t, h.intent())
			p := directDescriptorSupervisor(t, f, h, pinned)
			cleanupDescriptorFixture(t, f, h, p)
			awaitDescriptorReport(t, f, retained)
		})
	}
}

// Claim: pre-lease native exec/start failure acquires no lease or output; a
// post-lease pin-open failure releases exactly once and preserves old output.
// Native exec failure stays 75/fenced, guard Start failure 69/reusable, and
// post-lease failure 69/reusable. The valid native launch is above.
func TestSupervisorStartFailure(t *testing.T) {
	for _, mode := range []string{"native-exec", "supervisor-start", "post-lease-pin"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, nil)
			must(t, os.WriteFile(f.output, []byte("previous"), 0600))
			if mode == "native-exec" {
				invalid := filepath.Join(f.root, "invalid-native")
				raw := []byte("invalid native executable\n")
				must(t, os.WriteFile(invalid, raw, 0700))
				f.a.p.Executable = invalid
				f.a.p.ExecutableSHA256 = digest(raw)
			} else if mode == "supervisor-start" {
				f.d.Supervisor = filepath.Join(f.root, "missing-supervisor")
			} else {
				raw, err := os.ReadFile(fakePath)
				must(t, err)
				selected := filepath.Join(f.root, "selected-native")
				must(t, os.WriteFile(selected, raw, 0700))
				f.a.p.Executable = selected
				f.b.beforeRequest = func() { must(t, os.Chmod(selected, 0600)) }
			}
			want := 75
			if mode != "native-exec" {
				want = 69
			}
			requireStatus(t, f.run(), want, f.err.String())
			if mode == "post-lease-pin" {
				request, release := 0, 0
				for _, call := range f.b.calls {
					if call == "request" {
						request++
					}
					if call == "release" {
						release++
					}
				}
				if request != 1 || release != 1 || !strings.Contains(f.err.String(), "lease_harness_unqualified") {
					t.Fatal("post-lease failure lost release or status", f.b.calls, f.err.String())
				}
			} else {
				f.noLease()
			}
			assertAbsent(t, filepath.Join(f.home, "server-pid"))
			old, err := os.ReadFile(f.output)
			must(t, err)
			if string(old) != "previous" {
				t.Fatal("start failure replaced output")
			}
			if mode == "native-exec" {
				if !strings.Contains(f.err.String(), "teardown_unconfirmed") {
					t.Fatal("lost guard failure", f.err.String())
				}
				if guard, err := lockHome(f.home); err == nil {
					guard.close(false)
					t.Fatal("failed native exec lost home fence")
				}
			} else {
				guard, err := lockHome(f.home)
				must(t, err)
				must(t, guard.close(true))
			}
		})
	}
}
