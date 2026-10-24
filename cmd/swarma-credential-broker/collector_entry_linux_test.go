//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

// Only the owned test executable supplies this native collector fixture. The
// production binary routes the operation to it by verified descriptor.
func TestMain(m *testing.M) {
	timeconf.CollectorEntry()
	if len(os.Args) == 3 && os.Args[1] == "-c" && os.Args[2] == "tracking" {
		if !slices.Equal(os.Environ(), []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}) {
			os.Exit(9)
		}
		fmt.Println("collector_environment_minimal")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Claim: the actual production binary cannot dispatch an argv-supplied target,
// including with an injected environment; ordinary unknown commands still exit
// 64. Each rejected reserved invocation emits no target or argument output.
// A native descriptor control executes with the fixed environment, removing
// an injected value from the actual production hook before reaching the target.
func TestCollectorReservedCLIContract(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("protect fixture directory")
	}
	binary := filepath.Join(dir, "broker-fixture")
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	build := exec.Command(goTool, "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("production build failed: %v %s", err, output)
	}
	target := filepath.Join(dir, "target-fixture")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nprintf 'target_ran=true\\n'\nprintf 'fixture_environment=%s\\n' \"$TIME_ENTRY_FIXTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"ordinary-unknown", []string{"--ordinary-unknown", target, "fixture-argument"}, 64},
		{"arbitrary-target", []string{"--internal-timeconf-exec", target, "fixture-argument"}, 125},
		{"arbitrary-target-no-args", []string{"--internal-timeconf-exec", target}, 125},
		{"relative-target", []string{"--internal-timeconf-exec", "relative"}, 125},
		{"no-operation", []string{"--internal-timeconf-exec"}, 125},
		{"unknown-operation", []string{"--internal-timeconf-exec", "unknown"}, 125},
		{"extra-input", []string{"--internal-timeconf-exec", "tracking", target}, 125},
		{"missing-descriptor", []string{"--internal-timeconf-exec", "tracking"}, 125},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			cmd.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "TIME_ENTRY_FIXTURE=present"}
			var out, diagnostic bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diagnostic
			err := cmd.Run()
			code := 0
			if err != nil {
				failure, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal("binary unavailable", err)
				}
				code = failure.ExitCode()
			}
			if code != tc.code || out.Len() != 0 {
				t.Errorf("command contract: code=%d expected=%d stdout=%q", code, tc.code, out.String())
			}
			if bytes.Contains(diagnostic.Bytes(), []byte("fixture-argument")) || bytes.Contains(diagnostic.Bytes(), []byte("target_ran")) {
				t.Fatal("rejection reflected input or ran target")
			}
		})
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	native, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "native-collector-fixture")
	if err := os.WriteFile(fixture, native, 0500); err != nil {
		t.Fatal(err)
	}
	descriptor, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer descriptor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--internal-timeconf-exec", "tracking")
	cmd.ExtraFiles = []*os.File{descriptor}
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "TIME_ENTRY_FIXTURE=present"}
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "collector_environment_minimal\n" {
		t.Fatal("production entry forwarded environment or refused native control", err, string(output))
	}

}
