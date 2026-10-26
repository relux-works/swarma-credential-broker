//go:build linux && amd64

package qualify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

func testimonyCase(t *testing.T, image, fake, mode string, prior [32]byte) (runner.Outcome, [32]byte, error) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"home", "project"} {
		mustTestimony(t, os.Mkdir(filepath.Join(root, dir), 0700))
	}
	mustTestimony(t, os.WriteFile(filepath.Join(root, "project", ".git"), nil, 0600))
	mustTestimony(t, os.WriteFile(filepath.Join(root, "home", "scenario.json"), []byte(`{"Boundary":true}`), 0600))
	f, e := os.Open(image)
	mustTestimony(t, e)
	defer f.Close()
	b, e := os.ReadFile(image)
	mustTestimony(t, e)
	args := []string{mode, root, fake}
	if mode == "replay" {
		args[1] = hex.EncodeToString(prior[:])
	}
	o, e := egress.NewRunnerOrigin(f, fmt.Sprintf("%x", sha256.Sum256(b)), append([]string{"/proc/self/fd/3"}, args...))
	mustTestimony(t, e)
	p, e := NewRunnerTestimony(o, uint32(os.Geteuid()), root)
	mustTestimony(t, e)
	defer p.Close()
	if mode == "wrong-uid" {
		p.uid++
	}
	if mode == "no-credentials" {
		mustTestimony(t, unix.SetsockoptInt(int(p.parent.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 0))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var r egress.RunnerTraceResult
	var traceErr error
	done := make(chan struct{})
	go func() {
		r, traceErr = egress.TraceRunner(ctx, egress.RunnerTraceConfig{Origin: o, Args: args, Env: []string{"GOMAXPROCS=2"}, ExtraFiles: []*os.File{p.Child()}})
		if traceErr != nil {
			cancel()
		}
		close(done)
	}()
	if mode == "defer" || mode == "panic" {
		for testimonyLive(ctx) {
			if _, e := os.Stat(filepath.Join(root, "cleanup")); e == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		fd, e := p.connection(ctx)
		mustTestimony(t, e)
		var buf [64]byte
		if _, _, _, _, e := unix.Recvmsg(fd, buf[:], nil, unix.MSG_DONTWAIT|unix.MSG_PEEK); e != unix.EAGAIN {
			t.Error("readiness preceded deferred Command cleanup", e)
		}
		mustTestimony(t, os.WriteFile(filepath.Join(root, "continue"), nil, 0600))
	}
	exchangeCtx := ctx
	if mode == "late" {
		var stop context.CancelFunc
		exchangeCtx, stop = context.WithTimeout(ctx, 70*time.Millisecond)
		defer stop()
	}
	out, e := p.Exchange(exchangeCtx)
	<-done
	if traceErr != nil || r.State == nil || r.State.ExitCode() != 0 || !o.Facts().Verified || !o.Facts().Joined {
		t.Fatal("fixture lost real origin/wait", o.Facts(), r, traceErr)
	}
	if _, again := p.Exchange(ctx); !errors.Is(again, egress.ErrRunnerOriginUnavailable) {
		t.Error("exchange reused", again)
	}
	return out, p.nonce, e
}

// Claim: both messages require the traced PID/UID and credentials, strict
// ordering/frame bounds and the fresh nonce. Raw fault helpers prove protocol
// rejection only; actual Command outcomes are checked separately below.
func TestRunnerTestimonyProtocol(t *testing.T) {
	image, fake := rowTool(t, "./testdata/testimony"), rowTool(t, "../runner/testdata/appserver")
	out, prior, e := testimonyCase(t, image, fake, "raw", [32]byte{})
	if e != nil || out != (runner.Outcome{Status: 0, Kind: runner.OutcomeSuccess}) {
		t.Fatal("valid exchange", out, e)
	}
	for _, mode := range []string{"early", "receipt", "replay", "late", "wrong-pid", "wrong-uid", "wrong-answer", "no-credentials", "twice", "truncated", "oversized", "exit", "extra"} {
		t.Run(mode, func(t *testing.T) {
			out, nonce, e := testimonyCase(t, image, fake, mode, prior)
			if !errors.Is(e, egress.ErrRunnerOriginUnavailable) || out != (runner.Outcome{}) || mode == "replay" && nonce == prior {
				t.Fatal("invalid testimony accepted", out, e)
			}
		})
	}
}

// Claim: the measured dispatcher reports actual completed 0/69 outcomes. Error
// return and panic both block in real deferred broker cleanup before readiness;
// only the selected local conflict diagnostic gets the SourceConflict kind.
func TestRunnerTestimonyCommandReturn(t *testing.T) {
	image, fake := rowTool(t, "./testdata/testimony"), rowTool(t, "../runner/testdata/appserver")
	for mode, want := range map[string]runner.Outcome{"command": {Status: 0, Kind: runner.OutcomeSuccess}, "conflict": {Status: 69, Kind: runner.OutcomeSourceConflict}, "defer": {Status: 69, Kind: runner.OutcomeFailure}, "panic": {Status: 69, Kind: runner.OutcomeFailure}} {
		t.Run(mode, func(t *testing.T) {
			out, _, e := testimonyCase(t, image, fake, mode, [32]byte{})
			if e != nil || out != want {
				t.Fatal("actual Command outcome", out, want, e)
			}
		})
	}
}

func mustTestimony(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
