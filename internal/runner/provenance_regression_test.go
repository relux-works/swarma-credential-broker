//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Custom As may expose an alternate typed-nil error representation without
// importing or constructing the runner's private marker type.
type alternateError struct{}

func (alternateError) Error() string { return "bounded writer failure" }
func (alternateError) As(target any) bool {
	dst := reflect.ValueOf(target).Elem()
	if dst.Kind() == reflect.Pointer && dst.Type().Elem().Name() == "executionOutputStop" {
		dst.Set(reflect.Zero(dst.Type()))
		return true
	}
	return false
}

// A normal wrapping writer and a writer with an alternate error representation
// remain output failures through Command; neither may panic or become 124/130.
func TestMarkerProvenanceRegression(t *testing.T) {
	for _, large := range []bool{false, true} {
		for _, kind := range []string{"wrapped-cancel", "wrapped-deadline", "alternate-as", "writable"} {
			t.Run(fmt.Sprintf("%s/stream=%t", kind, large), func(t *testing.T) {
				f := newFixture(t, map[string]any{"LargeOutput": large})
				f.o.Timeout = 10 * time.Second
				must(t, os.WriteFile(f.output, []byte("old"), 0600))
				var out io.Writer = io.Discard
				switch kind {
				case "wrapped-cancel":
					out = independentContextWriter{fmt.Errorf("writer: %w", context.Canceled)}
				case "wrapped-deadline":
					out = independentContextWriter{fmt.Errorf("writer: %w", context.DeadlineExceeded)}
				case "alternate-as":
					out = independentContextWriter{alternateError{}}
				}
				got := 0
				var panicValue any
				func() {
					defer func() { panicValue = recover() }()
					got = Command(context.Background(), f.args(), IO{strings.NewReader("prompt"), out, &f.err}, f.d)
				}()
				releases := 0
				for _, call := range f.b.calls {
					if call == "release" {
						releases++
					}
				}
				if releases != 1 {
					t.Fatalf("release count %d", releases)
				}
				pid := readPID(t, filepath.Join(f.home, "server-pid"))
				if syscall.Kill(pid, 0) != syscall.ESRCH {
					t.Fatal("child remains")
				}
				want := 75
				if kind == "writable" {
					want = 0
				} else {
					data, e := os.ReadFile(f.output)
					must(t, e)
					if string(data) != "old" {
						t.Fatal("replaced old output")
					}
				}
				if panicValue != nil {
					t.Fatalf("Command panicked on alternate writer error: %v; release=%d child absent", panicValue, releases)
				}
				requireStatus(t, got, want, f.err.String())
			})
		}
	}
}

// Deliberately delayed Err publication models the descriptor timer winning its
// race with context publication. This component check complements public pipe
// signal/deadline/broken-pipe controls; it does not claim a custom context is a
// production adapter or that scheduler timing is universal.
type delayedContext struct {
	context.Context
	deadline time.Time
}

func (c delayedContext) Deadline() (time.Time, bool) { return c.deadline, true }
func TestDescriptorDeadlineProvenance(t *testing.T) {
	for _, kind := range []string{"descriptor-first", "context-first", "independent-descriptor", "writable"} {
		t.Run(kind, func(t *testing.T) {
			rd, wr, e := os.Pipe()
			must(t, e)
			defer rd.Close()
			defer wr.Close()
			var ctx context.Context = context.Background()
			var cancel context.CancelFunc = func() {}
			var done chan struct{}
			switch kind {
			case "descriptor-first":
				ctx = delayedContext{context.Background(), time.Now().Add(15 * time.Millisecond)}
			case "context-first":
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			case "independent-descriptor":
				ctx = delayedContext{context.Background(), time.Now().Add(time.Hour)}
				done = make(chan struct{})
				go func() { defer close(done); time.Sleep(30 * time.Millisecond); wr.SetWriteDeadline(time.Now()) }()
			case "writable":
				done = make(chan struct{})
				go func() { defer close(done); io.Copy(io.Discard, rd) }()
			}
			defer cancel()
			_, err := (contextWriter{ctx: ctx, out: wr}).Write([]byte(strings.Repeat("x", 1<<20)))
			wr.Close()
			if done != nil {
				<-done
			}
			var mark *executionOutputStop
			marked := errors.As(err, &mark)
			switch kind {
			case "descriptor-first":
				if ctx.Err() != nil || !marked || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("err=%v marked=%t ctx=%v", err, marked, ctx.Err())
				}
			case "context-first":
				if !marked || !errors.Is(err, context.Canceled) {
					t.Fatalf("err=%v marked=%t", err, marked)
				}
			case "independent-descriptor":
				if marked || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("err=%v marked=%t", err, marked)
				}
			case "writable":
				must(t, err)
			}
		})
	}
}
