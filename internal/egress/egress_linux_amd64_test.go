//go:build linux && amd64

package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var launcher, probe, tools string

func TestMain(m *testing.M) {
	if os.Getenv("EGRESS_TRACE_CHILD") == "1" {
		launcher = os.Getenv("EGRESS_TEST_LAUNCHER")
		if !filepath.IsAbs(launcher) {
			os.Exit(2)
		}
		os.Exit(m.Run())
	}

	goTool := os.Getenv("GO")
	if !filepath.IsAbs(goTool) {
		fmt.Fprintln(os.Stderr, "egress tests require an absolute GO executable")
		os.Exit(2)
	}
	var err error
	tools, err = os.MkdirTemp("", "egress-tools-")
	if err != nil {
		panic(err)
	}
	launcher = filepath.Join(tools, "launcher")
	probe = filepath.Join(tools, "probe")
	for _, b := range []struct{ out, pkg string }{{launcher, "./cmd/launcher"}, {probe, "./testdata/probe"}} {
		cmd := exec.Command(goTool, "build", "-p=2", "-o", b.out, b.pkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			os.RemoveAll(tools)
			os.Exit(2)
		}
	}
	code := m.Run()
	os.RemoveAll(tools)
	os.Exit(code)
}
func runProbe(t *testing.T, p Policy, mode, arg string) (Report, string, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "output-")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := Run(ctx, Config{Launcher: launcher, Executable: probe, Args: []string{mode, arg}, Env: []string{}, Policy: p, Stdout: out, Stderr: out})
	b, e := os.ReadFile(out.Name())
	if e != nil {
		t.Fatal(e)
	}
	return r, string(b), err
}
func event(t *testing.T, r Report, call, class, verdict string) {
	t.Helper()
	for _, e := range r.Events {
		if e.Syscall == call && e.Class == class && e.Verdict == verdict {
			return
		}
	}
	b, _ := json.Marshal(r)
	t.Fatalf("missing %s/%s/%s evidence: %s", call, class, verdict, b)
}
func tcp(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l, uint16(l.Addr().(*net.TCPAddr).Port)
}

// Claim: the real filter refuses documentation-address attempts (including child
// threads/exec descendants), raw/packet sockets and io_uring before any send.
// These probes do not establish hostile-memory race resistance.
func TestExternalRefusal(t *testing.T) {
	for _, row := range []struct{ mode, call, class string }{{"external", "connect", "external"}, {"sendto", "sendto", "external"}, {"sendmsg", "sendmsg", "external"}, {"sendmmsg", "sendmmsg", "external"}, {"v6", "connect", "external"}, {"mapped", "connect", "external"}, {"thread", "connect", "external"}, {"grandchild", "connect", "external"}, {"packet", "socket", "socket"}, {"raw", "socket", "socket"}, {"uring", "io_uring_setup", "other"}} {
		t.Run(row.mode, func(t *testing.T) {
			r, out, e := runProbe(t, Policy{}, row.mode, "9")
			if e != nil {
				t.Fatalf("probe failed: %v %s", e, out)
			}
			want := "errno=111"
			if row.mode == "packet" || row.mode == "raw" {
				want = "errno=97"
			}
			if row.mode == "uring" {
				want = "errno=1"
			}
			if !strings.Contains(out, want) {
				t.Fatalf("attempt was not refused: %s", out)
			}
			event(t, r, row.call, row.class, "refuse")
			if r.Incomplete {
				t.Fatal("incomplete evidence")
			}
		})
	}
}

// Claim: listening local endpoints outside the exact port set are refused,
// including a nonleader thread; allowing that exact port makes progress.
func TestLoopbackPortAndThread(t *testing.T) {
	_, port := tcp(t)
	arg := strconv.Itoa(int(port))
	for _, mode := range []string{"closed", "thread-closed"} {
		t.Run(mode, func(t *testing.T) {
			r, out, e := runProbe(t, Policy{}, mode, arg)
			if e != nil || !strings.Contains(out, "errno=111") {
				t.Fatalf("disallowed connect: %v %s", e, out)
			}
			event(t, r, "connect", "loopback", "refuse")
		})
	}
	r, out, e := runProbe(t, Policy{Ports: []uint16{port}}, "allowed", arg)
	if e != nil || !strings.Contains(out, "allowed") {
		t.Fatalf("positive connect: %v %s", e, out)
	}
	event(t, r, "connect", "loopback", "allow")
}

// Claim: UDP/sendmsg/sendmmsg addressed sends are gated; denied local packets
// never reach the fixture and permitted sends arrive. This avoids remote mutant traffic.
func TestDatagramPolicy(t *testing.T) {
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	arg := strconv.Itoa(int(port))
	r, out, e := runProbe(t, Policy{}, "udp-closed", arg)
	if e != nil || !strings.Contains(out, "errno=111") {
		t.Fatalf("disallowed send: %v %s", e, out)
	}
	event(t, r, "sendto", "loopback", "refuse")
	b := make([]byte, 20)
	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := conn.ReadFromUDP(b); err == nil {
		t.Fatal("forbidden packet reached fixture")
	}
	for _, mode := range []string{"udp-allowed", "msg-allowed", "mmsg-allowed"} {
		r, out, e = runProbe(t, Policy{Ports: []uint16{port}}, mode, arg)
		if e != nil || !strings.Contains(out, "allowed") {
			t.Fatalf("positive datagram: %v %s", e, out)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFromUDP(b)
		if err != nil || string(b[:n]) != "fixture" {
			t.Fatalf("missing permitted packet %v", err)
		}
	}
}

// Claim: exact filesystem Unix destinations are refused by default and admitted
// only on the caller's allowlist; abstract sockets are never implied by it.
func TestUnixPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.sock")
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	r, out, e := runProbe(t, Policy{}, "unix", path)
	if e != nil || !strings.Contains(out, "errno=111") {
		t.Fatalf("negative Unix %v %s", e, out)
	}
	event(t, r, "connect", "unix", "refuse")
	r, out, e = runProbe(t, Policy{UnixPaths: []string{path}}, "unix", path)
	if e != nil || !strings.Contains(out, "allowed") {
		t.Fatalf("positive Unix %v %s", e, out)
	}
	event(t, r, "connect", "unix", "allow")
}

// Claim: evidence stays bounded and overflow fails the run; a sufficient budget
// retains monotonic event timestamps and summary counts equal stored events.
func TestEvidenceBudget(t *testing.T) {
	r, _, e := runProbe(t, Policy{MaxEvents: 1}, "external", "9")
	if !errors.Is(e, ErrEvidenceLimit) || !r.Incomplete || len(r.Events) > 1 {
		t.Fatalf("overflow contract: %v %+v", e, r)
	}
	r, _, e = runProbe(t, Policy{MaxEvents: 256}, "external", "9")
	if e != nil {
		t.Fatal(e)
	}
	tot := uint64(0)
	last := int64(0)
	for _, v := range r.Summary {
		tot += v.Allowed + v.Refused
	}
	if int(tot) != len(r.Events) {
		t.Fatal("summary mismatch")
	}
	for _, v := range r.Events {
		if v.MonotonicNS < last {
			t.Fatal("nonmonotone evidence")
		}
		last = v.MonotonicNS
	}
}

// Claim: explicit environment selection excludes ambient values; inherited
// socket FDs and malformed bootstrap prefixes are rejected before launching,
// while a selected regular FD works.
func TestExplicitInputs(t *testing.T) {
	t.Setenv("EGRESS_CANARY", "ambient")
	_, out, e := runProbe(t, Policy{}, "env", "0")
	if e != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("ambient leak: %v %q", e, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e = Run(ctx, Config{Launcher: launcher, Executable: probe, Env: nil})
	if !errors.Is(e, ErrUnavailable) {
		t.Fatal("nil env accepted")
	}
	r, e := Run(ctx, Config{Launcher: launcher, LauncherArgs: []string{"bad\x00prefix"}, Executable: probe, Env: []string{}})
	if !errors.Is(e, ErrUnavailable) || len(r.Events) != 0 {
		t.Fatal("malformed bootstrap prefix accepted", e)
	}
	l, _ := tcp(t)
	f, e := l.(*net.TCPListener).File()
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e = Run(ctx, Config{Launcher: launcher, Executable: probe, Env: []string{}, ExtraFiles: []*os.File{f}})
	if !errors.Is(e, ErrUnavailable) || len(r.Events) != 0 {
		t.Fatal("inherited socket accepted", e)
	}
	input, e := os.CreateTemp(t.TempDir(), "input")
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	input.WriteString("selected")
	output, e := os.CreateTemp(t.TempDir(), "output")
	if e != nil {
		t.Fatal(e)
	}
	defer output.Close()
	r, e = Run(ctx, Config{Launcher: launcher, Executable: probe, Args: []string{"fd", "0"}, Env: []string{}, ExtraFiles: []*os.File{input}, Stdout: output})
	b, _ := os.ReadFile(output.Name())
	if e != nil || string(b) != "selected" {
		t.Fatalf("selected FD: %v %s %+v", e, b, r)
	}
}

// Claim: cancellation and bootstrap failure return an error without an
// unfiltered fallback; successful fixture controls above use the same launcher.
func TestFailureAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	r, e := Run(ctx, Config{Launcher: launcher, Executable: probe, Args: []string{"sleep", "0"}, Env: []string{}})
	if !errors.Is(e, context.DeadlineExceeded) || !r.Incomplete {
		t.Fatalf("deadline %v %+v", e, r)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	_, e = Run(ctx2, Config{Launcher: launcher, Executable: "/nonexistent-egress-fixture", Env: []string{}})
	if e == nil {
		t.Fatal("missing candidate accepted")
	}
}

// Claim: proxy variables (including lowercase client variants) are replaced,
// NO_PROXY names loopback hosts, and invalid/overlapping ports fail. Real-client
// proxy selection and independent port enforcement are tested separately.
func TestProxyEnvironment(t *testing.T) {
	for _, p := range []uint16{0, 1234} {
		if _, e := ProxyEnvironment([]string{}, p, []uint16{1234}); e == nil {
			t.Fatal("invalid proxy policy accepted")
		}
	}
	env, e := ProxyEnvironment([]string{"PATH=/usr/bin:/bin", "http_proxy=external", "NO_PROXY=*"}, 1234, []uint16{5678})
	if e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "external") || strings.Contains(joined, "*") || !strings.Contains(joined, "HTTPS_PROXY=http://127.0.0.1:1234") || !strings.Contains(joined, "NO_PROXY=127.0.0.1,localhost,::1") || !strings.Contains(joined, "no_proxy=127.0.0.1,localhost,::1") {
		t.Fatal(joined)
	}
}

// Claim: bypass-capable syscalls are rejected with EPERM by the live filter,
// not merely EBADF/EINVAL from dummy arguments. Existing network controls above
// demonstrate that this filter does not reject all calls.
func TestBypassDenials(t *testing.T) {
	for _, nr := range []int{unix.SYS_IOCTL, unix.SYS_SETSOCKOPT, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_BPF, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_PIDFD_GETFD, unix.SYS_RECVMSG, unix.SYS_RECVMMSG, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SETSID, unix.SYS_SETPGID} {
		t.Run(names[int32(nr)], func(t *testing.T) {
			r, out, e := runProbe(t, Policy{}, "syscall", strconv.Itoa(nr))
			if e != nil || !strings.Contains(out, "errno=1\n") {
				t.Fatalf("bypass denial %v %s", e, out)
			}
			event(t, r, names[int32(nr)], "other", "refuse")
		})
	}
	_, out, e := runProbe(t, Policy{}, "seal", strconv.Itoa(unix.SYS_SECCOMP))
	if e != nil || !strings.Contains(out, "errno=1\n") {
		t.Fatalf("filter tree not sealed: %v %s", e, out)
	}
}

// Claim: socket control cannot select unchecked routing/multicast operations;
// an explicitly harmless buffer-size option remains usable.
func TestSocketOptions(t *testing.T) {
	r, out, e := runProbe(t, Policy{}, "sockopt", "0")
	if e != nil || !strings.Contains(out, "errno=1\n") {
		t.Fatalf("routing sockopt: %v %s", e, out)
	}
	event(t, r, "setsockopt", "other", "refuse")
	r, out, e = runProbe(t, Policy{}, "sockopt-allowed", "0")
	if e != nil || !strings.Contains(out, "allowed") {
		t.Fatalf("buffer sockopt: %v %s", e, out)
	}
	event(t, r, "setsockopt", "socket", "allow")
}

// Claim: a caller's unrelated non-CLOEXEC descriptor does not survive candidate
// exec. TestExplicitInputs separately proves an explicitly selected FD survives.
func TestAmbientDescriptorClosed(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "ambient")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	fd, e := unix.FcntlInt(f.Fd(), unix.F_DUPFD, 512)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	_, out, e := runProbe(t, Policy{}, "check-fd", strconv.Itoa(fd))
	if e != nil || strings.TrimSpace(out) != "closed" {
		t.Fatalf("ambient FD survived %v %q", e, out)
	}
}

// Claim: both legacy and pointer-based namespace clone requests are refused by
// this notifier, with exact EPERM and evidence; ordinary threads/forks above pass.
func TestNamespaceCloneRefusal(t *testing.T) {
	for _, mode := range []string{"clone-ns", "clone3-ns"} {
		t.Run(mode, func(t *testing.T) {
			r, out, e := runProbe(t, Policy{}, mode, "0")
			if e != nil || !strings.Contains(out, "errno=1\n") {
				t.Fatalf("namespace clone %v %s", e, out)
			}
			call := "clone"
			if mode == "clone3-ns" {
				call = "clone3"
			}
			event(t, r, call, "other", "refuse")
		})
	}
}

// Claim: candidate ancillary controls are refused even for an allowed local
// destination; a plain addressed send on the same socket class reaches the fake.
// The negative control uses harmless IP_TTL, never an external route header.
func TestAncillarySendRefused(t *testing.T) {
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	arg := strconv.Itoa(int(port))
	r, out, e := runProbe(t, Policy{Ports: []uint16{port}}, "msg-control", arg)
	b := make([]byte, 20)
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, _, receiveErr := c.ReadFromUDP(b)
	if e != nil || !strings.Contains(out, "errno=1\n") || receiveErr == nil {
		t.Fatalf("ancillary control admitted: err=%v out=%s packet=%t", e, out, receiveErr == nil)
	}
	event(t, r, "sendmsg", "loopback", "refuse")
	_, out, e = runProbe(t, Policy{Ports: []uint16{port}}, "msg-allowed", arg)
	if e != nil || !strings.Contains(out, "allowed") {
		t.Fatalf("plain message %v %s", e, out)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	n, _, e := c.ReadFromUDP(b)
	if e != nil || string(b[:n]) != "fixture" {
		t.Fatalf("missing plain positive control: %v", e)
	}
}
