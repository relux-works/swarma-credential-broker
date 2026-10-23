//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type faultAuthority struct {
	inner Authority
	at    int
	calls int
	stop  func(context.Context) error
}

func (a *faultAuthority) Resolve(ctx context.Context, o Options) (Policy, error) {
	a.calls++
	if a.calls == a.at {
		if e := a.stop(ctx); e != nil {
			return Policy{}, e
		}
	}
	return a.inner.Resolve(ctx, o)
}

type faultStageBroker struct {
	BrokerClient
	stage     string
	stop      func(context.Context) error
	onRelease func()
}

func (b faultStageBroker) VerifyServer(ctx context.Context, u uint32) error {
	if b.stage == "verify" {
		if e := b.stop(ctx); e != nil {
			return e
		}
	}
	return b.BrokerClient.VerifyServer(ctx, u)
}
func (b faultStageBroker) Hello(ctx context.Context, r HelloRequest) (HelloResult, error) {
	if b.stage == "hello" {
		if e := b.stop(ctx); e != nil {
			return HelloResult{}, e
		}
	}
	return b.BrokerClient.Hello(ctx, r)
}
func (b faultStageBroker) Request(ctx context.Context, r LeaseRequest) (Lease, error) {
	if b.stage == "request" {
		if e := b.stop(ctx); e != nil {
			return Lease{}, e
		}
	}
	return b.BrokerClient.Request(ctx, r)
}
func (b faultStageBroker) Release(ctx context.Context, id string) error {
	if b.onRelease != nil {
		b.onRelease()
	}
	return b.BrokerClient.Release(ctx, id)
}

// Cooperative admission adapters return the execution context's stop cause.
// Their stage must not change handled cancellation 130 / execution expiry 124.
// Independent adapter errors remain 69, and valid adapters still complete.
func TestAdmissionContextRegression(t *testing.T) {
	for _, stage := range []string{"authority-first", "connect", "verify", "hello", "request", "authority-recheck"} {
		for _, mode := range []string{"signal", "deadline", "independent-cancel", "independent-deadline", "ordinary-refusal", "valid"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				f := newFixture(t, nil)
				f.o.Timeout = 500 * time.Millisecond
				must(t, os.WriteFile(f.output, []byte("old"), 0600))
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				reached := false
				var observed error
				stop := func(ctx context.Context) error {
					reached = true
					switch mode {
					case "signal":
						cancel()
						<-ctx.Done()
						observed = ctx.Err()
						return observed
					case "deadline":
						<-ctx.Done()
						observed = ctx.Err()
						return observed
					case "independent-cancel":
						return context.Canceled
					case "independent-deadline":
						return context.DeadlineExceeded
					case "ordinary-refusal":
						return errors.New("fixture admission failure")
					}
					return nil
				}
				a := &faultAuthority{inner: f.a, stop: stop}
				if stage == "authority-first" {
					a.at = 1
				} else if stage == "authority-recheck" {
					a.at = 2
				}
				f.d.Authority = a
				b := faultStageBroker{BrokerClient: f.b, stage: stage, stop: stop}
				f.d.Connect = func(ctx context.Context) (BrokerClient, error) {
					if stage == "connect" {
						if e := stop(ctx); e != nil {
							return nil, e
						}
					}
					return b, nil
				}
				got := Command(parent, f.args(), IO{strings.NewReader("prompt"), io.Discard, &f.err}, f.d)
				if !reached {
					t.Fatal("stage not reached")
				}
				want := 69
				switch mode {
				case "signal":
					want = 130
					if !errors.Is(observed, context.Canceled) {
						t.Fatalf("context control %v", observed)
					}
				case "deadline":
					want = 124
					if !errors.Is(observed, context.DeadlineExceeded) || parent.Err() != nil {
						t.Fatalf("deadline control %v parent %v", observed, parent.Err())
					}
				case "valid":
					want = 0
				}
				releases := 0
				for _, v := range f.b.calls {
					if v == "release" {
						releases++
					}
				}
				wantRelease := 0
				if mode == "valid" || stage == "authority-recheck" {
					wantRelease = 1
				}
				if releases != wantRelease {
					t.Fatalf("release count %d want %d", releases, wantRelease)
				}
				if mode != "valid" {
					assertAbsent(t, filepath.Join(f.home, "server-pid"))
					data, e := os.ReadFile(f.output)
					must(t, e)
					if string(data) != "old" {
						t.Fatal("old output replaced")
					}
				}
				assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
				t.Logf("status=%d want=%d observed_execution=%v release=%d diagnostic=%s", got, want, observed, releases, f.err.String())
				requireStatus(t, got, want, f.err.String())
			})
		}
	}
}

// Real fixture cleanup/release failures dominate each reachable terminal family.
// The cleanup plant changes only its disposable home marker after child teardown.
// Invalid input is pre-resource and separately proves no release can be attempted.
func TestStatusDominanceRegression(t *testing.T) {
	for _, kind := range []string{"completed", "failed", "init-refusal", "renew-refusal", "signal", "deadline", "output"} {
		for _, failure := range []string{"none", "release", "cleanup", "both"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				s := map[string]any{}
				want := 0
				switch kind {
				case "failed":
					s["Status"] = "failed"
					want = 1
				case "init-refusal":
					s["InitFail"] = true
					want = 69
				case "renew-refusal":
					s["RefreshCount"] = 1
					want = 75
				case "signal", "deadline":
					s["Hang"] = true
					want = 124
				case "output":
					s["LargeOutput"] = true
					want = 75
				}
				f := newFixture(t, s)
				f.o.Timeout = 500 * time.Millisecond
				if kind == "renew-refusal" {
					f.b.renewErr = errors.New("fixture renewal refusal")
				}
				if failure == "release" || failure == "both" {
					f.b.releaseErr = errors.New("fixture release refusal")
				}
				b := faultStageBroker{BrokerClient: f.b}
				if failure == "cleanup" || failure == "both" {
					b.onRelease = func() {
						p := filepath.Join(f.home, ".run-codex-unresolved")
						must(t, os.Remove(p))
						must(t, os.Mkdir(p, 0700))
						must(t, os.WriteFile(filepath.Join(p, "fixture"), []byte("not-empty"), 0600))
					}
				}
				f.d.Connect = func(context.Context) (BrokerClient, error) { return b, nil }
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				var stopDone chan struct{}
				if kind == "signal" {
					want = 130
					stopDone = make(chan struct{})
					go func() {
						defer close(stopDone)
						if waitFile(filepath.Join(f.home, "server-pid")) {
							cancel()
						}
					}()
				}
				var out io.Writer = io.Discard
				if kind == "output" {
					out = independentContextWriter{syscall.EPIPE}
				}
				must(t, os.WriteFile(f.output, []byte("old"), 0600))
				got := Command(parent, f.args(), IO{strings.NewReader("prompt"), out, &f.err}, f.d)
				if stopDone != nil {
					<-stopDone
				}
				if failure != "none" {
					want = 75
				}
				pid := readPID(t, filepath.Join(f.home, "server-pid"))
				if syscall.Kill(pid, 0) != syscall.ESRCH {
					t.Fatal("child remains")
				}
				releases := 0
				for _, c := range f.b.calls {
					if c == "release" {
						releases++
					}
				}
				if releases != 1 {
					t.Fatalf("release count %d", releases)
				}
				if want != 0 {
					data, e := os.ReadFile(f.output)
					must(t, e)
					if string(data) != "old" {
						t.Fatal("old output replaced")
					}
				}
				t.Logf("status=%d want=%d diagnostic=%s", got, want, f.err.String())
				requireStatus(t, got, want, f.err.String())
			})
		}
	}
	t.Run("invalid-before-resources", func(t *testing.T) {
		f := newFixture(t, nil)
		f.b.releaseErr = errors.New("must not reach")
		args := append(f.args(), "--unknown")
		got := Command(context.Background(), args, IO{strings.NewReader("prompt"), io.Discard, &f.err}, f.d)
		requireStatus(t, got, 64, f.err.String())
		f.noLease()
		assertAbsent(t, filepath.Join(f.home, "server-pid"))
		t.Log(fmt.Sprint(got))
	})
}
