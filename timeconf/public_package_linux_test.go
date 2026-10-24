//go:build linux

package timeconf

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Claim: a distinct Go module builds the documented public import with ordinary
// production exports, while the same consumer cannot name the test-only parser.
// These builds do not execute the consumer or access a deployed clock/policy.
func TestExternalModuleConsumer(t *testing.T) {
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	for _, tc := range []struct {
		name string
		tags string
	}{
		{name: "public-import"},
		{name: "test-only-parser", tags: "testonlyapi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "consumer")
			args := []string{"build", "-mod=readonly", "-o", binary}
			if tc.tags != "" {
				args = append(args, "-tags="+tc.tags)
			}
			args = append(args, ".")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, goTool, args...)
			cmd.Dir = filepath.Join("..", "testdata", "timeconf-consumer")
			cmd.Env = append(os.Environ(), "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("consumer build timed out")
			}
			if tc.tags == "" {
				if err != nil {
					t.Fatalf("public import build: %v\n%s", err, out)
				}
				if info, statErr := os.Stat(binary); statErr != nil || !info.Mode().IsRegular() {
					t.Fatal("consumer executable missing")
				}
				return
			}
			failure, ok := err.(*exec.ExitError)
			if !ok || failure.ExitCode() != 1 || !bytes.Contains(out, []byte("undefined: timeconf.ParseSources")) {
				t.Fatalf("test-only export must be undefined: %v\n%s", err, out)
			}
			if _, statErr := os.Stat(binary); !os.IsNotExist(statErr) {
				t.Fatal("rejected consumer published an executable")
			}
		})
	}
}
