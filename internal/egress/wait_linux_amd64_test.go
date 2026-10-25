//go:build linux && amd64

package egress

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Claim: Waited supplies exactly one actual joined status before Run returns,
// including bootstrap failure and cancellation; a launch that never happened
// supplies no wait state. A successful bounded probe is the positive control.
func TestWaitedStatus(t *testing.T) {
	for _, kind := range []string{"success", "bootstrap-exit", "missing-launcher", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			calls := 0
			var state *os.ProcessState
			config := Config{Launcher: launcher, Executable: probe, Args: []string{"env", "0"}, Env: []string{}, Waited: func(s *os.ProcessState) { calls++; state = s }}
			switch kind {
			case "bootstrap-exit":
				config.Launcher = filepath.Join(t.TempDir(), "launcher")
				if os.WriteFile(config.Launcher, []byte("#!/bin/sh\nexit 17\n"), 0700) != nil {
					t.Fatal("launcher fixture")
				}
			case "missing-launcher":
				config.Launcher = filepath.Join(t.TempDir(), "missing")
			case "cancelled":
				config.Args = []string{"sleep", "0"}
				config.Started = func(int) { cancel() }
			}
			_, e := Run(ctx, config)
			if kind == "missing-launcher" {
				if e == nil || calls != 0 || state != nil {
					t.Fatal("unlaunched helper gained wait state", e, calls, state)
				}
				return
			}
			if calls != 1 || state == nil {
				t.Fatal("joined wait state missing", e, calls, state)
			}
			want := 0
			if kind == "bootstrap-exit" {
				want = 17
			} else if kind == "cancelled" {
				want = -1
				if status, ok := state.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("cancellation signal replaced", state)
				}
			}
			if state.ExitCode() != want || (e == nil) != (kind == "success") {
				t.Fatal("actual wait status replaced", e, state)
			}
		})
	}
}
