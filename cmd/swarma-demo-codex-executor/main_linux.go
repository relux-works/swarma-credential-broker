//go:build linux

// swarma-demo-codex-executor is a fixed demo executor, not curator-run.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/brokerclient"
	"github.com/relux-works/swarma-credential-broker/internal/demo"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

func main() {
	if handled, status := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(status)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	status := run(ctx, os.Args[1:])
	cancel()
	if status != 0 {
		_, _ = os.Stderr.WriteString("fixed demo executor: refused or incomplete\n")
	}
	os.Exit(status)
}
func run(ctx context.Context, args []string) int {
	syscall.Umask(0077)
	uid, gid := os.Geteuid(), os.Getegid()
	groups, e := os.Getgroups()
	if len(args) != 0 || uid < 30000 || uid > 30019 || gid != uid || os.Getuid() != uid || os.Getgid() != gid || e != nil || len(groups) != 0 {
		return 69
	}
	// P1 passes only descriptors 0..3. Refuse inherited service sockets/handles;
	// Go runtime descriptors are CLOEXEC and never reach the app-server.
	if !inheritedDescriptorsSafe() {
		return 69
	}
	fd := os.NewFile(3, "sealed-demo-plan")
	if fd == nil {
		return 69
	}
	syscall.CloseOnExec(3)
	plan, digest, e := demo.ReadPlan(fd)
	closeErr := fd.Close()
	if e != nil || closeErr != nil {
		return 69
	}
	launch, e := demo.ReadLaunch(plan.ExecutionID)
	if e != nil || demo.MatchPlan(plan, digest, launch, uint32(uid)) != nil {
		return 69
	}
	projection, e := demo.ReadProjection()
	if e != nil {
		return 69
	}
	roster, e := demo.ReadRoster(projection.RosterPath)
	if e != nil {
		return 69
	}
	row, e := roster.Principal(uint32(uid), launch)
	if e != nil {
		return 69
	}
	// A canonical witness row never authorizes the fixed Codex executor.
	if !demo.FixedExecutorApproved(roster) {
		return 69
	}
	self, e := os.ReadFile("/proc/self/exe")
	if e != nil || demo.Hash(self) != roster.Executor.SHA256 {
		return 69
	}
	clear(self)
	if _, e = demo.ReadQualification(); e != nil {
		return 69
	}
	// No caller home/env selector. The runner gets a new 0700 HOME/CODEX_HOME and
	// refuses effective configuration or credential source conflicts.
	// A deterministic, exclusive path lets operator evidence bind the exact
	// launch configuration before execution. Existing homes always refuse;
	// reconnect/restart cannot silently create a second home for this launch.
	home := filepath.Join(row.Home, ".codex-demo-"+launch.ExecutionID)
	if e = os.Mkdir(home, 0700); e != nil {
		return 75
	}
	witness := map[string]any{"executor": "fixed demo executor, not curator-run", "execution_id": launch.ExecutionID, "uid": uid, "gid": gid, "groups": groups}
	if writeRecord(filepath.Join(home, "witness.json"), witness) != nil {
		return 75
	}
	authority := &demo.Authority{Launch: launch, UID: uint32(uid)}
	deps := runner.Dependencies{Authority: authority, Environment: os.Environ(), LaunchID: digest,
		Connect: func(call context.Context) (runner.BrokerClient, error) {
			current, e := demo.ReadProjection()
			if e != nil || !demo.SameProjection(current, projection) {
				return nil, demo.ErrRefused
			}
			// DialWorker sends no bytes; runner verifies UID 1102 before Hello.
			return brokerclient.DialWorker(call, current.SocketPath)
		}, BeforeRelease: func(call context.Context, leaseID string, success bool) error {
			if call.Err() != nil {
				return demo.ErrRefused
			}
			state := "failed_or_unknown"
			if success {
				state = "turn_completed"
			}
			return writeRecord(filepath.Join(home, "outcome.json"), map[string]any{"launch_id": digest, "lease_id": leaseID, "worker_generation": launch.Generation, "policy_generation": projection.Binding.PolicyGeneration, "state": state})
		}}
	args = []string{"--account", projection.Binding.Account, "--profile", projection.Binding.Profile, "--launch-home", home, "--prompt-stdin", "--model", plan.Model, "--reasoning-effort", plan.ReasoningEffort, "--output-last-message", filepath.Join(home, "last-message"), "--cwd", row.Workspace, "--timeout", "300"}
	return runner.Command(ctx, args, runner.IO{In: strings.NewReader(plan.Prompt), Out: io.Discard, Err: io.Discard}, deps)
}

func inheritedDescriptorsSafe() bool {
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return false
	}
	for _, entry := range entries {
		n, e := strconv.Atoi(entry.Name())
		if e != nil {
			return false
		}
		if n <= 3 {
			continue
		}
		flags, e := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
		if e == unix.EBADF {
			continue
		} // ReadDir's own descriptor is already closed.
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			return false
		}
	}
	return true
}
func writeRecord(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil || len(b)+1 > 4096 {
		return demo.ErrRefused
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return demo.ErrRefused
	}
	_, e = f.Write(append(b, '\n'))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return demo.ErrRefused
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return demo.ErrRefused
	}
	e = d.Sync()
	d.Close()
	return e
}
