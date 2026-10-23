//go:build linux

package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type probeCatalogAuthority struct {
	inner Authority
	calls int
	mode  string
	stop  context.CancelFunc
}

func (a *probeCatalogAuthority) Resolve(ctx context.Context, o Options) (Policy, error) {
	a.calls++
	p, e := a.inner.Resolve(ctx, o)
	if a.calls == 2 {
		if a.mode == "changed" || a.mode == "cancel" || a.mode == "deadline" || a.mode == "release-failure" {
			p.Catalog = map[string][]string{o.Model: {"unsupported"}}
		}
		if a.mode == "model-missing" {
			p.Catalog = map[string][]string{}
		}
		if a.mode == "cancel" || a.mode == "cancel-valid" {
			a.stop()
		}
		if a.mode == "deadline" {
			<-ctx.Done()
		}
		if a.mode == "generation" {
			p.PolicyGeneration++
		}
	}
	return p, e
}

// Claim: a protected policy catalog change after lease acquisition is a post-lease
// configuration refusal; an observed own stop retains precedence when cleanup succeeds.
// Non-expiry controls keep the normal fixture budget. In the expiry row, no
// app-server child starts; the pre-lease --version supervisor or helper has
// stopped before the post-lease recheck wait, which uses virtual time.
// The testing/synctest bubbles do not qualify real-clock external I/O latency.
func TestProbePostLeaseCatalog(t *testing.T) { postLeaseCatalog(t) }

// These cases also drive the normative status table's post-lease input row.
func postLeaseCatalog(t *testing.T) {
	for _, mode := range []string{"valid", "changed", "model-missing", "cancel", "deadline", "cancel-valid", "generation", "release-failure"} {
		run := func(t *testing.T) {
			f := newFixture(t, nil)
			if mode == "deadline" {
				f.o.Timeout = 100 * time.Millisecond
			}
			if mode == "release-failure" {
				f.b.releaseErr = errors.New("synthetic release failure")
			}
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &probeCatalogAuthority{inner: f.a, mode: mode, stop: cancel}
			f.d.Authority = a
			got := Command(ctx, f.args(), IO{strings.NewReader("prompt"), io.Discard, &f.err}, f.d)
			want := 69
			if mode == "valid" {
				want = 0
			}
			if mode == "cancel" || mode == "cancel-valid" {
				want = 130
			}
			if mode == "deadline" {
				want = 124
			}
			if mode == "release-failure" {
				want = 75
			}
			releases := 0
			for _, v := range f.b.calls {
				if v == "release" {
					releases++
				}
			}
			if releases != 1 {
				t.Fatalf("release count %d", releases)
			}
			for _, v := range f.b.transferred {
				for _, b := range v {
					if b != 0 {
						t.Fatal("retained material")
					}
				}
			}
			assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			if mode != "valid" {
				if mode == "cancel-valid" {
					if _, e := os.Stat(filepath.Join(f.home, "server-pid")); e == nil {
						pid := readPID(t, filepath.Join(f.home, "server-pid"))
						if syscall.Kill(pid, 0) != syscall.ESRCH {
							t.Fatal("child remains")
						}
					}
				} else {
					assertAbsent(t, filepath.Join(f.home, "server-pid"))
				}
				b, e := os.ReadFile(f.output)
				must(t, e)
				if string(b) != "old" {
					t.Fatal("output changed")
				}
			}
			t.Logf("status=%d want=%d releases=%d", got, want, releases)
			requireStatus(t, got, want, f.err.String())
		}
		t.Run(mode, func(t *testing.T) {
			if mode == "deadline" {
				synctest.Test(t, run)
			} else {
				run(t)
			}
		})
	}
}
