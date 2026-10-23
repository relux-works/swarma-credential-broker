//go:build linux

package runner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type independentContextWriter struct{ failure error }

func (w independentContextWriter) Write([]byte) (int, error) { return 0, w.failure }

// A bounded embedding writer's own cancellation/deadline is an output failure;
// it must not impersonate cancellation or expiry of the still-live execution.
// Both streamed output and the final redaction-buffer flush use the public Command.
func TestIndependentOutputErrorProvenance(t *testing.T) {
	for _, large := range []bool{false, true} {
		for _, kind := range []string{"writer-cancel", "writer-deadline", "writer-os-timeout", "writable"} {
			name := kind + "/flush"
			if large {
				name = kind + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				scenario := map[string]any{}
				if large {
					scenario["LargeOutput"] = true
				}
				f := newFixture(t, scenario)
				f.o.Timeout = 10 * time.Second
				must(t, os.WriteFile(f.output, []byte("old"), 0600))
				var writer io.Writer = io.Discard
				switch kind {
				case "writer-cancel":
					other, cancel := context.WithCancel(context.Background())
					cancel()
					writer = independentContextWriter{other.Err()}
				case "writer-deadline":
					other, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					defer cancel()
					writer = independentContextWriter{other.Err()}
				case "writer-os-timeout":
					writer = independentContextWriter{os.ErrDeadlineExceeded}
				}
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				start := time.Now()
				got := Command(parent, f.args(), IO{strings.NewReader("prompt"), writer, &f.err}, f.d)
				elapsed := time.Since(start)
				if parent.Err() != nil || elapsed >= f.o.Timeout {
					t.Fatal("execution context control failed")
				}
				pid := readPID(t, filepath.Join(f.home, "server-pid"))
				if syscall.Kill(pid, 0) != syscall.ESRCH {
					t.Fatal("child remains")
				}
				releases := 0
				for _, call := range f.b.calls {
					if call == "release" {
						releases++
					}
				}
				if releases != 1 {
					t.Fatalf("release count %d", releases)
				}
				data, e := os.ReadFile(f.output)
				must(t, e)
				want := 75
				if kind == "writable" {
					want = 0
				} else if string(data) != "old" {
					t.Fatal("failed output replaced prior file")
				}
				t.Logf("status=%d want=%d execution_context_error=%v elapsed=%s diagnostic=%s", got, want, parent.Err(), elapsed, f.err.String())
				requireStatus(t, got, want, f.err.String())
				if want == 75 && !strings.Contains(f.err.String(), "output_unavailable") {
					t.Fatal("writer failure lost output diagnostic")
				}
			})
		}
	}
}
