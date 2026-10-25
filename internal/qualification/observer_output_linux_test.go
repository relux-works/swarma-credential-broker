//go:build linux && amd64

package qualification

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Claim: the platform observer's real os/exec output path accepts a valid
// systemd line through 64 KiB, refuses excess stdout as ErrUnavailable without
// returning a version, and still refuses a bounded malformed version line.
func TestPlatformCommandOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		prefix string
		valid  bool
	}{
		{"small", 32, "systemd fixture\n", true},
		{"at-limit", 65536, "systemd fixture\n", true},
		{"over-limit", 65537, "systemd fixture\n", false},
		{"oversized", 4 << 20, "systemd fixture\n", false},
		{"malformed", 32, "unknown fixture\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPlatformOutputHelper$")
			cmd.Env = []string{
				"CANDIDATE_TRACE_CHILD=1",
				"PLATFORM_OUTPUT_BYTES=" + strconv.Itoa(tc.size),
				"PLATFORM_OUTPUT_PREFIX=" + tc.prefix,
			}
			line, err := platformSystemdVersion(cmd)
			if ctx.Err() != nil {
				t.Fatal("output fixture timed out", ctx.Err())
			}
			if tc.valid {
				if err != nil || line != "systemd fixture" {
					t.Fatal("bounded platform output refused", line, err)
				}
			} else if !errors.Is(err, ErrUnavailable) || line != "" {
				t.Fatal("invalid platform output was not refused as unavailable", len(line), err)
			}
		})
	}
}

// The child emits a valid first line even for overflow, so accepting only the
// first line cannot satisfy the output bound. It never invokes a real tool.
func TestPlatformOutputHelper(t *testing.T) {
	raw := os.Getenv("PLATFORM_OUTPUT_BYTES")
	if raw == "" {
		return
	}
	size, err := strconv.Atoi(raw)
	prefix := os.Getenv("PLATFORM_OUTPUT_PREFIX")
	if err != nil || size < len(prefix) || size > 4<<20 {
		os.Exit(2)
	}
	output := bytes.Repeat([]byte{'x'}, size)
	copy(output, prefix)
	if n, err := os.Stdout.Write(output); err != nil || n != size {
		os.Exit(3)
	}
	os.Exit(0)
}
