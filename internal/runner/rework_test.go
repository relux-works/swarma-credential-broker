//go:build linux

package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func canaryMaterials() []string {
	var values []string
	for _, token := range []string{canaryA, canaryB, canaryC} {
		hash := sha256.Sum256([]byte(token))
		values = append(values, token, fmt.Sprintf("%x", hash), fmt.Sprintf("%X", hash))
	}
	return values
}

// Claim: initial and renewed token hashes split across deltas cannot escape either
// output channel; ordinary assistant text remains byte-identical in both channels.
func TestReviewHashEcho(t *testing.T) {
	for _, tc := range []struct {
		name  string
		echo  bool
		renew int
	}{
		{"plain-control", false, 0}, {"hash-echo", true, 0}, {"renewed-hash", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, map[string]any{"HashEcho": tc.echo, "RefreshCount": tc.renew})
			requireStatus(t, f.run(), 0, f.err.String())
			data, err := os.ReadFile(f.output)
			must(t, err)
			for _, material := range canaryMaterials() {
				if strings.Contains(f.out.String()+f.err.String()+string(data), material) {
					t.Fatal("token hash escaped stdout and/or output file")
				}
			}
			want := "answer"
			if tc.echo {
				want = "safe [redacted] [redacted] tail"
			}
			if f.out.String() != want || string(data) != want {
				t.Fatal("ordinary output or redaction changed")
			}
		})
	}
}

// Claim: cancellation during a full turn/start pipe or an idle RPC read returns
// 130 within five seconds, confirms child absence, releases once and preserves output.
func TestReviewCancelBlockedRPC(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		name := "ordinary-signal"
		if blocked {
			name = "full-pipe"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, map[string]any{"StopReadAfterThread": blocked, "Hang": true})
			f.o.Timeout = 7 * time.Second
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan int, 1)
			prompt := "prompt"
			marker := "server-pid"
			if blocked {
				prompt = strings.Repeat("x", MaxPrompt)
				marker = "stopped-reading"
			}
			go func() { done <- Command(ctx, f.args(), IO{strings.NewReader(prompt), &f.out, &f.err}, f.d) }()
			if !waitFile(filepath.Join(f.home, marker), 2*time.Second) {
				cancel()
				<-done
				t.Fatal("fixture did not reach blocking path")
			}
			// With no server reads, the admitted 1 MiB frame cannot fit the pipe.
			time.Sleep(100 * time.Millisecond)
			select {
			case <-done:
				t.Fatal("command returned before cancellation")
			default:
			}
			started := time.Now()
			cancel()
			got := <-done
			elapsed := time.Since(started)
			requireStatus(t, got, 130, f.err.String())
			t.Logf("cleanup after cancellation: %s", elapsed)
			if elapsed > 5*time.Second {
				t.Fatal("handled interruption exceeded five-second teardown bound while RPC I/O remained blocked")
			}
			pid := readPID(t, filepath.Join(f.home, "server-pid"))
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("app-server survived cancellation")
			}
			count := 0
			for _, call := range f.b.calls {
				if call == "release" {
					count++
				}
			}
			if count != 1 {
				t.Fatal("release count changed")
			}
			data, err := os.ReadFile(f.output)
			must(t, err)
			if string(data) != "old" {
				t.Fatal("cancelled execution published output")
			}
		})
	}
}

type reviewOpaqueBroker struct {
	*fakeBroker
	id string
	t  *testing.T
}

func (b *reviewOpaqueBroker) Request(ctx context.Context, r LeaseRequest) (Lease, error) {
	lease, err := b.fakeBroker.Request(ctx, r)
	lease.ID = b.id
	return lease, err
}
func (b *reviewOpaqueBroker) Release(ctx context.Context, id string) error {
	if id != b.id {
		b.t.Fatal("opaque lease ID not preserved")
	}
	return b.fakeBroker.Release(ctx, "lease")
}

// Claim: profile §7 ASCII IDs, including controls and spaces, round-trip unchanged
// through admission and release; empty, overlong and non-ASCII IDs refuse before exec.
func TestReviewOpaqueLeaseID(t *testing.T) {
	for _, id := range []string{"opaque-lease", "opaque lease", " ", "\x00\t\n\x1f\x7f", strings.Repeat("x", 128), "", strings.Repeat("x", 129), "é"} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			f := newFixture(t, nil)
			broker := &reviewOpaqueBroker{f.b, id, t}
			f.d.Connect = func(context.Context) (BrokerClient, error) { return broker, nil }
			want := 0
			if id == "" || len(id) > 128 || id == "é" {
				want = 69
			}
			requireStatus(t, f.run(), want, f.err.String())
			count := 0
			for _, call := range f.b.calls {
				if call == "release" {
					count++
				}
			}
			if count != 1 {
				t.Fatal("lease not released exactly once")
			}
			if want == 69 {
				assertAbsent(t, filepath.Join(f.home, "server-pid"))
				assertAbsent(t, f.output)
			}
		})
	}
}

// Claim: both subprocess fixtures were built by the same Go version as the
// running tests, independently of any other go executable on PATH.
func TestHelperToolchain(t *testing.T) {
	for _, path := range []string{fakePath, supervisorPath} {
		info, err := buildinfo.ReadFile(path)
		must(t, err)
		if info.GoVersion != runtime.Version() {
			t.Fatalf("helper Go version %s differs from tests %s", info.GoVersion, runtime.Version())
		}
	}
}

// Claim: raw tokens remain redacted independently of digest protection, even
// when each byte arrives separately; this is the digest mutant's positive control.
func TestRawTokenRedaction(t *testing.T) {
	for _, token := range []string{canaryA, canaryB, canaryC} {
		var output bytes.Buffer
		stream := &textStream{out: &output}
		defer stream.erase()
		stream.addSecret([]byte(token))
		for _, part := range strings.Split("prefix "+token+" suffix", "") {
			must(t, stream.write(part, false))
		}
		must(t, stream.write("", true))
		if output.String() != "prefix [redacted] suffix" {
			t.Fatal("raw-token protection lost")
		}
	}
}

// Claim: cancelling the session wakes a scanner blocked on an empty owned RPC
// pipe, while the already-cancelled receiver also refuses buffered work promptly.
func TestRPCReadCancellation(t *testing.T) {
	read, write, err := os.Pipe()
	must(t, err)
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newRPC(ctx, &process{out: read})
	defer close(client.closed)
	cancel()
	deadline := time.After(time.Second)
	for {
		select {
		case _, ok := <-client.messages:
			if !ok {
				_, err := client.receive(ctx)
				if err != context.Canceled {
					t.Fatal("cancelled receiver admitted work")
				}
				return
			}
		case <-deadline:
			t.Fatal("cancelled RPC scanner stayed blocked")
		}
	}
}
