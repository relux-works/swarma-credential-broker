//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the combined executable routes status to the authenticated daemon
// client, daemon configuration failures to its existing refusal, and invalid
// runner arguments, unsupported resume and unknown commands to the runner's
// existing validation. Only
// synthetic configuration and an empty home are passed to child processes.
func TestCommandDispatch(t *testing.T) {
	if os.Getenv("BROKER_TEST_ENTRYPOINT") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				return
			}
		}
		os.Exit(99)
	}
	e := testutil.New(t, lease.Options{})
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "dispatch-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	listener, err := server.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Serve(ctx, listener) }()
	defer func() { cancel(); srv.Close(); <-stopped; srv.Wait() }()
	config := filepath.Join(dir, "config.json")
	raw, err := wire.Encode(policy.Config{SocketPath: socket, StoreRoot: e.Root, Policy: e.Policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	secret := testutil.Token()
	for _, tc := range []struct {
		name       string
		args       []string
		code       int
		diagnostic string
	}{
		{"status", []string{"status", "--config", config}, 0, ""},
		{"daemon-refusal", []string{"daemon", "--config", filepath.Join(dir, "absent")}, 69, "configuration_unavailable\n"},
		{"runner-refusal", []string{"run-codex", "--unknown=" + secret}, 64, "runner: invalid_command\n"},
		{"runner-resume-refusal", []string{"run-codex", "--account", "fixture", "--profile", "fixture", "--launch-home", home, "--model", "fixture", "--reasoning-effort", "medium", "--output-last-message", filepath.Join(dir, "result"), "--prompt-stdin", "--resume", "fixture"}, 69, "runner: lease_harness_unqualified\n"},
		{"unknown-command", []string{"unknown", secret}, 64, "runner: invalid_command\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestCommandDispatch$", "--"}, tc.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = []string{"BROKER_TEST_ENTRYPOINT=1", "HOME=" + home, "CODEX_HOME=" + home}
			var out, diagnostic bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diagnostic
			err := cmd.Run()
			code := 0
			if err != nil {
				failure, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal("entrypoint unavailable")
				}
				code = failure.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit=%d, expected=%d", code, tc.code)
			}
			if tc.diagnostic != "" && diagnostic.String() != tc.diagnostic {
				t.Fatal("command routed to a different refusal")
			}
			if bytes.Contains(out.Bytes(), []byte(secret)) || bytes.Contains(diagnostic.Bytes(), []byte(secret)) {
				t.Fatal("argument reflected in output")
			}
			if code == 0 {
				var status wire.Status
				if diagnostic.Len() != 0 || wire.Decode(bytes.TrimSpace(out.Bytes()), &status) != nil || status.Generation != e.Policy.Generation || len(status.Accounts) != 1 {
					t.Fatal("authenticated status unavailable")
				}
			} else if out.Len() != 0 {
				t.Fatal("refusal emitted output")
			}
		})
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Fatal("command refusal changed the empty fixture home")
	}
	if calls, _ := e.Owner.Counts(); calls != 0 {
		t.Fatal("command dispatch started owner refresh")
	}
}
