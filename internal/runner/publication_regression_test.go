//go:build linux

package runner

import (
	"context"
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

// Invalid options are rejected before execution, independent of a parent stop;
// valid prompt acquisition still honors the already stopped parent.
func TestProbeInputStopPrecedence(t *testing.T) {
	inputStopPrecedence(t)
}

func inputStopPrecedence(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"live", "cancel", "deadline"} {
		for _, invalid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/invalid=%t", mode, invalid), func(t *testing.T) {
				f := newFixture(t, nil)
				must(t, os.WriteFile(f.output, []byte("old"), 0600))
				ctx := context.Background()
				cancel := func() {}
				if mode == "cancel" {
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if mode == "deadline" {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				}
				defer cancel()
				args := f.args()
				if invalid {
					args = append(args, "--unknown")
				}
				input := io.Reader(strings.NewReader("prompt"))
				if mode != "live" && !invalid {
					rd, wr, e := os.Pipe()
					must(t, e)
					defer rd.Close()
					defer wr.Close()
					input = rd
				}
				got := Command(ctx, args, IO{input, io.Discard, &f.err}, f.d)
				want := 0
				if invalid {
					want = 64
				} else if mode == "cancel" {
					want = 130
				} else if mode == "deadline" {
					want = 124
				}
				if invalid || mode != "live" {
					f.noLease()
					assertAbsent(t, filepath.Join(f.home, "server-pid"))
					assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
					data, e := os.ReadFile(f.output)
					must(t, e)
					if string(data) != "old" {
						t.Fatal("pre-execution refusal replaced old output")
					}
				}
				requireStatus(t, got, want, f.err.String())
			})
		}
	}
}

// Ported public Command reproduction: cancellation 50ms after final stdout
// overlaps a real 200ms fsync. A second timing condition delays rename return
// after kernel publication. No errno is substituted. Undelayed and uninterrupted
// controls retain ordinary success; every nonzero result must preserve old output.
func TestProbePublicationTiming(t *testing.T) {
	requiredEvidenceRow(t)
	if timing := os.Getenv("RUNNER_TEST_PUBLICATION_TIMING"); timing != "" {
		publicationTiming(t, timing)
		return
	}
	for _, timing := range []string{"fsync", "rename", "undelayed"} {
		t.Run(timing, func(t *testing.T) { tracePublicationTiming(t, timing) })
	}
}

func tracePublicationTiming(t *testing.T, timing string) {
	t.Helper()
	requiredEvidenceRow(t)
	tracer, err := exec.LookPath("strace")
	if err != nil {
		if os.Getenv("RUNNER_QUALIFICATION") == "1" {
			t.Fatalf("UNVERIFIED: %s requires strace: %v", t.Name(), err)
		}
		t.Skipf("UNVERIFIED: %s requires strace: %v", t.Name(), err)
	}
	self, err := os.Executable()
	must(t, err)
	trace := filepath.Join(t.TempDir(), "publication.trace")
	args := []string{"-f", "-qq", "-yy", "-e", "signal=none", "-e", "trace=fsync,renameat", "-o", trace}
	switch timing {
	case "fsync":
		args = append(args, "-e", "inject=fsync:delay_enter=200ms")
	case "rename":
		args = append(args, "-e", "inject=renameat:delay_exit=200ms")
	case "undelayed":
	default:
		t.Fatal("unknown timing condition")
	}
	args = append(args, self, "-test.run=^TestProbePublicationTiming$", "-test.v", "-test.timeout=30s")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tracer, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "RUNNER_TEST_PUBLICATION_TIMING=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "RUNNER_TEST_PUBLICATION_TIMING="+timing)
	output, runErr := cmd.CombinedOutput()
	data, err := os.ReadFile(trace)
	must(t, err)
	// Require the intended storage control on the staging output, not merely
	// successful tracing or a delay on a helper-build/home-marker operation.
	applied := timing == "undelayed"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, ".run-codex-output-") && strings.Contains(line, "= 0 (DELAYED)") &&
			(timing == "fsync" && strings.Contains(line, "fsync(") || timing == "rename" && strings.Contains(line, "renameat(")) {
			applied = true
		}
	}
	if !applied {
		t.Fatalf("publication timing control not applied: %v\n%s\n%s", runErr, output, data)
	}
	if ctx.Err() != nil || runErr != nil {
		t.Fatalf("publication boundary failed: %v\n%s\n%s", runErr, output, data)
	}
	t.Logf("timing=%s child PID=%d; storage control applied\n%s", timing, cmd.Process.Pid, output)
}

func publicationTiming(t *testing.T, timing string) {
	t.Helper()
	for _, stopped := range []bool{false, true} {
		t.Run(fmt.Sprint(stopped), func(t *testing.T) {
			f := newFixture(t, nil)
			f.o.Timeout = 10 * time.Second
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fired := make(chan struct{})
			armed := false
			out := statusWriter(func(b []byte) (int, error) {
				if stopped && !armed {
					armed = true
					time.AfterFunc(50*time.Millisecond, func() { cancel(); close(fired) })
				}
				return len(b), nil
			})
			got := Command(ctx, f.args(), IO{strings.NewReader("prompt"), out, &f.err}, f.d)
			if stopped {
				if !armed {
					t.Fatal("final flush was not reached")
				}
				<-fired
			}
			pid := readPID(t, filepath.Join(f.home, "server-pid"))
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("child remains")
			}
			n := 0
			for _, c := range f.b.calls {
				if c == "release" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("release=%d", n)
			}
			for _, b := range f.b.transferred {
				for _, v := range b {
					if v != 0 {
						t.Fatal("material retained")
					}
				}
			}
			assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			staging, e := filepath.Glob(filepath.Join(f.root, ".run-codex-output-*"))
			must(t, e)
			if len(staging) != 0 {
				t.Fatal("staging output retained")
			}
			data, e := os.ReadFile(f.output)
			must(t, e)
			t.Logf("status=%d output=%q parent_stop=%v", got, data, ctx.Err())
			if got != 0 && string(data) != "old" {
				t.Fatalf("nonzero status %d published output %q", got, data)
			}
			if !stopped || timing == "rename" {
				requireStatus(t, got, 0, f.err.String())
				if string(data) != "answer" {
					t.Fatal("success did not publish")
				}
			} else if timing == "fsync" {
				requireStatus(t, got, 130, f.err.String())
			} else if got == 0 && string(data) != "answer" {
				t.Fatal("success did not publish")
			}
		})
	}
}
