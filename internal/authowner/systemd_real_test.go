//go:build linux && realmanager

package authowner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func noUnit(err error) bool {
	e, ok := err.(dbus.Error)
	return ok && (e.Name == "org.freedesktop.systemd1.NoSuchUnit" || e.Name == "org.freedesktop.DBus.Error.UnknownObject")
}

// Cleanup is independent of test failure and restricted to names allocated here.
// A permission/transport failure never counts as successful unit disappearance.
func realManager(t *testing.T) (*Systemd, string, func(string)) {
	t.Helper()
	prefix := "scb-test-" + id() + "-"
	daemon := prefix + "daemon.service"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := NewSystemd(ctx, prefix, daemon)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	names := []string{daemon}
	add := func(n string) { names = append(names, n); t.Log("allocated", n) }
	t.Log("allocated", daemon)
	t.Cleanup(func() {
		cleanup, c := context.WithTimeout(context.Background(), 7*time.Second)
		defer c()
		obj := m.conn.Object(destination, managerPath)
		for i := len(names) - 1; i >= 0; i-- {
			name := names[i]
			var job dbus.ObjectPath
			err := obj.CallWithContext(cleanup, destination+".Manager.StopUnit", 0, name, "replace").Store(&job)
			if err == nil {
				if err = m.waitJob(cleanup, job); err != nil {
					t.Error("cleanup stop", name)
				}
			} else if !noUnit(err) {
				t.Error("cleanup stop", name, err)
			}
			// Reset/unref errors are admissible only if a later complete lookup confirms
			// the exact never-reused name no longer exists.
			obj.CallWithContext(cleanup, destination+".Manager.ResetFailedUnit", 0, name)
			obj.CallWithContext(cleanup, destination+".Manager.UnrefUnit", 0, name)
			gone := false
			for cleanup.Err() == nil {
				var path dbus.ObjectPath
				err = obj.CallWithContext(cleanup, destination+".Manager.GetUnit", 0, name).Store(&path)
				if noUnit(err) {
					gone = true
					break
				}
				if err != nil {
					t.Error("cleanup lookup", name, err)
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !gone {
				t.Error("own unit did not unload", name)
			} else {
				t.Log("gone", name)
			}
		}
	})
	// Readiness cannot accept a missing configured daemon; the adjacent control
	// creates only this test's daemon and then proves readiness.
	if m.Ready(ctx) == nil {
		t.Fatal("missing daemon reported ready")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	props := []property{prop("Type", "exec"), prop("AddRef", true), prop("RuntimeMaxUSec", uint64(25e6)), prop("ExecStart", []execStart{{sleep, []string{sleep, "20"}, false}})}
	var job dbus.ObjectPath
	if err = m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.StartTransientUnit", 0, daemon, "fail", props, []auxiliary{}).Store(&job); err != nil {
		t.Fatal(err)
	}
	if m.waitJob(ctx, job) != nil || m.daemonActive(ctx) != nil {
		t.Fatal("own daemon readiness control")
	}
	if m.Ready(ctx) == nil {
		t.Fatal("unqualified manager became ready")
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	cat, err = filepath.EvalSymlinks(cat)
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(cat)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(image)
	home := t.TempDir()
	if os.Chmod(home, 0700) != nil {
		t.Fatal("probe home")
	}
	probe, err := m.Probe(ctx, cat, hex.EncodeToString(hash[:]), home)
	if probe != "" {
		add(probe)
	}
	if err != nil || m.Ready(ctx) != nil {
		t.Fatal("manager capability probe", err)
	}
	if m.Owned(ctx) == nil {
		t.Fatal("unrelated test process treated as named owner")
	}
	return m, prefix, add
}
func realSpec(t *testing.T, m *Systemd, name, exe, home string, args []string, runtime time.Duration) (UnitSpec, *os.File, *os.File) {
	t.Helper()
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(image)
	input, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read, output, err := os.Pipe()
	if err != nil {
		input.Close()
		write.Close()
		t.Fatal(err)
	}
	for _, f := range []*os.File{input, write, read, output} {
		t.Cleanup(func() { f.Close() })
	}
	s := UnitSpec{Name: name, Daemon: m.daemon, Executable: exe, ExecutableSHA256: hex.EncodeToString(digest[:]), Home: home, Args: args, Environment: []string{"HOME=" + home, "CODEX_HOME=" + home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, Runtime: runtime, Input: input, Output: output}
	return s, read, write
}
func startReal(t *testing.T, m *Systemd, s UnitSpec) Observation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx, s); err != nil {
		t.Fatal("start", err)
	}
	s.Input.Close()
	s.Output.Close()
	o, err := m.Observe(ctx, s.Name)
	if err != nil || !o.Complete || o.Active != "active" || o.Cgroup == "" || o.MainPID == 0 {
		t.Fatal("running identity unavailable")
	}
	return o
}
func stopReal(t *testing.T, m *Systemd, s UnitSpec, before Observation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	o, err := m.Stop(ctx, s.Name, before)
	b := Binding{Unit: s.Name, Identity: before.Identity}
	if err != nil || !confirmed(b, before, o) {
		t.Fatal("correlated subtree absence unavailable", err)
	}
	if err = m.Unload(ctx, s.Name); err != nil {
		t.Fatal("unload", err)
	}
}

// Claim: an isolated real service applies all properties (including the 120s
// production runtime ceiling), receives private FDs and is attached at its first
// instrumented entry, before the echo. This does not observe Go runtime startup.
func TestRealFDContainment(t *testing.T) {
	home := t.TempDir()
	m, prefix, add := realManager(t)
	name := prefix + "writer.service"
	add(name)
	cat, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, read, write := realSpec(t, m, name, cat, home, []string{"entry-echo"}, 120*time.Second)
	before := startReal(t, m, s)
	cgroup, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(before.MainPID), 10) + "/cgroup")
	if err != nil || !strings.Contains(string(cgroup), before.Cgroup) {
		t.Fatal("child executed outside recorded cgroup")
	}
	read.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(read)
	entry, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(entry) != "0::"+before.Cgroup {
		t.Fatal("first instrumented child entry was outside its cgroup")
	}
	write.SetWriteDeadline(time.Now().Add(time.Second))
	read.SetReadDeadline(time.Now().Add(time.Second))
	canary := "private-pipe-canary"
	if _, err = write.Write([]byte(canary + "\n")); err != nil {
		t.Fatal(err)
	}
	echo, err := reader.ReadString('\n')
	if err != nil || echo != canary+"\n" {
		t.Fatal("private FD echo")
	}
	raw, _ := json.Marshal(properties(s))
	if strings.Contains(string(raw), canary) {
		t.Fatal("material in properties")
	}
	stopReal(t, m, s, before)
}

// Claim: SIGTERM-ignoring descendants are killed by the configured 2s stop
// timeout; RuntimeMax triggers teardown on a shorter bounded control, and daemon
// death triggers dependency stop. This does not wait 120s to measure that ceiling.
func TestRealGrandchildTimeoutAndDependencyStop(t *testing.T) {
	for _, mode := range []string{"stop-timeout", "runtime-max", "daemon-death"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "grandchild")
			m, prefix, add := realManager(t)
			name := prefix + "writer.service"
			add(name)
			runtime := 120 * time.Second
			if mode == "runtime-max" {
				runtime = 500 * time.Millisecond
			}
			s, read, write := realSpec(t, m, name, f.c.Executable, f.home, []string{"app-server"}, runtime)
			before := startReal(t, m, s)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			answer := make(chan rpcResult, 1)
			go func() { answer <- managed(ctx, read, write, nil) }()
			testutilAwait(t, func() bool { _, err := os.Stat(filepath.Join(f.home, "grandchild-pid")); return err == nil })
			pid, err := os.ReadFile(filepath.Join(f.home, "grandchild-pid"))
			if err != nil {
				t.Fatal(err)
			}
			cg, err := os.ReadFile("/proc/" + string(pid) + "/cgroup")
			if err != nil || !strings.Contains(string(cg), before.Cgroup) {
				t.Fatal("grandchild escaped cgroup")
			}
			start := time.Now()
			switch mode {
			case "runtime-max":
				testutilAwait(t, func() bool {
					o, err := m.Observe(ctx, name)
					return err == nil && o.Active == "failed" && o.Result == "timeout"
				})
			case "daemon-death":
				if err = m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.KillUnit", 0, m.daemon, "main", int32(9)).Err; err != nil {
					t.Fatal(err)
				}
				testutilAwait(t, func() bool {
					o, err := m.Observe(ctx, name)
					return err == nil && (o.Active == "inactive" || o.Active == "failed")
				})
			}
			stopReal(t, m, s, before)
			if elapsed := time.Since(start); elapsed < 1800*time.Millisecond || elapsed > 5*time.Second {
				t.Fatal("stop/runtime bound not observed", elapsed)
			}
			select {
			case <-answer:
			case <-time.After(time.Second):
				t.Fatal("RPC did not stop with subtree")
			}
		})
	}
}
func testutilAwait(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bounded real-manager condition not reached")
}

// Claim: unsupported required properties, a drifted required property, a digest
// mismatch and invalid runtime refuse readiness/admission; the FD test controls
// establish the accepted neighboring configuration.
func TestRealReadinessRefusesRequiredPropertyAndDigest(t *testing.T) {
	home := t.TempDir()
	m, prefix, add := realManager(t)
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unsupported", "drift", "digest", "runtime"} {
		name := prefix + mode + ".service"
		add(name)
		s, _, _ := realSpec(t, m, name, cat, home, nil, 120*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		switch mode {
		case "digest":
			s.ExecutableSHA256 = strings.Repeat("0", 64)
			if m.Start(ctx, s) == nil {
				t.Fatal("digest mismatch admitted")
			}
		case "runtime":
			s.Runtime = 121 * time.Second
			if m.Start(ctx, s) == nil {
				t.Fatal("runtime overflow admitted")
			}
		default:
			props := properties(s)
			if mode == "unsupported" {
				props = append(props, prop("RequiredContainmentCapabilityDoesNotExist", true))
			} else {
				for i, p := range props {
					if p.Name == "ProtectControlGroups" {
						props[i] = prop(p.Name, false)
					}
				}
			}
			var job dbus.ObjectPath
			err = m.conn.Object(destination, managerPath).CallWithContext(ctx, destination+".Manager.StartTransientUnit", 0, name, "fail", props, []auxiliary{}).Store(&job)
			if mode == "unsupported" {
				if err == nil {
					t.Fatal("unsupported property admitted")
				}
			} else {
				if err != nil || m.waitJob(ctx, job) != nil {
					t.Fatal("drift plant failed to start")
				}
				if _, err = m.Observe(ctx, name); err == nil {
					t.Fatal("required property drift accepted")
				}
			}
		}
		cancel()
	}
}

// Fixture-only cleanup polling makes no writer-absence or successful-job claim.
func (m *Systemd) waitJob(ctx context.Context, job dbus.ObjectPath) error {
	for {
		call := m.conn.Object(destination, job).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, destination+".Job")
		if call.Err != nil {
			if e, ok := call.Err.(dbus.Error); ok && (e.Name == "org.freedesktop.DBus.Error.UnknownObject" || e.Name == "org.freedesktop.systemd1.NoSuchJob") {
				return nil
			}
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-time.After(10 * time.Millisecond):
		}
	}
}
