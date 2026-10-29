//go:build linux && amd64

package qualify

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
)

func closeFixture(t *testing.T, imagePath, mode string, sink func(string)) (*ownerSession, *atomic.Bool) {
	t.Helper()
	image, err := os.Open(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { image.Close() })
	pad, err := os.Open("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pad.Close() })
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{inR, inW, outR, outW} {
		t.Cleanup(func() { f.Close() })
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(mode)))
	o, err := egress.NewOwnerOrigin(image, digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var cancelled atomic.Bool
	s := &ownerSession{origin: o, ch: &ownerChannel{r: outR, w: inW}, done: make(chan struct{}), execution: newRowExecution()}
	s.cancel = func() { cancel(); cancelled.Store(true) }
	t.Cleanup(func() { s.cancel(); <-s.done })
	s.diagnosticContext = withOwnerDiagnostics(ctx, sink)
	go func() {
		defer close(s.done)
		s.report, s.err = egress.Run(ctx, egress.Config{Origin: o, Launcher: imagePath, LauncherArgs: []string{"bootstrap", mode, "0"}, Executable: "/proc/self/fd/4", Args: []string{"qualification-owner", digest}, Env: []string{"GOMAXPROCS=2", "OWNER_MODE=" + mode, "OWNER_DIGEST=" + digest}, ExtraFiles: []*os.File{image, pad, outW, pad, inR}, Started: func(pid int) { s.pid.Store(int64(pid)); s.execution.Launched = true; outW.Close(); inR.Close() }, Waited: func(state *os.ProcessState) { s.waits++; s.execution.waited(state) }})
		f := o.Facts()
		s.execution.Handshake, s.execution.Started = f.Verified, f.Entered
		if f.Verified && f.Entered && f.Joined && s.execution.Joined {
			s.execution.Completed, s.execution.attested = true, true
			s.execution.WorkerExit, s.execution.CaseExit = s.execution.HelperExit, s.execution.HelperExit
		}
	}()
	outR.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = s.receive("startup"); err != nil {
		t.Fatal(err)
	}
	return s, &cancelled
}

// Claim: the real two-second close timeout freezes pending/entered facts before
// cancellation, then cancels and joins a real owned process before delivery.
// A clean exit still succeeds; an ordinary cancellation refuses without inventing
// a timeout. This does not reproduce or explain a particular hosted CI delay.
func TestOwnerCloseTimeoutSnapshot(t *testing.T) {
	image := filepath.Join(t.TempDir(), "origin")
	cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", image, "../egress/testdata/origin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v %s", err, out)
	}
	for _, kind := range []string{"timeout", "clean", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var records []string
			var s *ownerSession
			var cancelled *atomic.Bool
			mode := "owner-close-wait"
			if kind == "clean" {
				mode = "owner-close-clean"
			}
			s, cancelled = closeFixture(t, image, mode, func(record string) {
				if !cancelled.Load() || s.waits != 1 || !s.execution.Joined {
					t.Fatal("diagnostic callback ran before cancel/join")
				}
				if _, err := s.ch.w.Write([]byte("fixture-secret-sentinel")); !errors.Is(err, os.ErrClosed) {
					t.Fatal("diagnostic callback ran before pipe cleanup", err)
				}
				records = append(records, record)
			})
			if kind == "cancelled" {
				s.cancel()
				<-s.done
			}
			start := time.Now()
			err := s.close()
			if s.waits != 1 || !s.execution.Joined {
				t.Fatal("owned child not joined exactly once", s.waits)
			}
			if kind == "clean" {
				if err != nil || len(records) != 0 || s.execution.CaseExit != 0 {
					t.Fatal("clean positive changed", err, records)
				}
				if s.origin.Diagnostic() != (egress.OriginDiagnostic{Phase: egress.OriginJoined, Exit: egress.ExitZero}) {
					t.Fatal("real zero exit observation missing", s.origin.Diagnostic())
				}
				// A controlled incomplete-ledger plant after a genuinely joined
				// zero exit cannot be repaired by that exit's diagnostic record.
				s.err = context.Canceled
				s.report.Incomplete = true
				frozen := s.closeSnapshot(false)
				ownerDiagnosticClose(s.diagnosticContext, &frozen)
				if e := s.close(); e == nil || !errors.Is(s.err, context.Canceled) || !s.report.Incomplete {
					t.Fatal("zero exit diagnostic rescued incomplete origin", e)
				}
				return
			}
			if err == nil || !s.report.Incomplete || s.execution.credit(false) {
				t.Fatal("incomplete origin acquired success", err, s.execution)
			}
			if kind == "cancelled" {
				if len(records) != 0 {
					t.Fatal("ordinary cancellation invented timeout", records)
				}
				return
			}
			want := "owner close timeout close_cancel=not_issued supervisor=pending phase=entered exit=unavailable"
			if len(records) != 1 || records[0] != want {
				t.Fatal("pre-cancel snapshot missing or changed", records)
			}
			if time.Since(start) < 2*time.Second {
				t.Fatal("actual two-second timeout not exercised")
			}
		})
	}
}

// Claim: nil/malformed observations are explicit unavailable values. The finite
// formatter never includes the existing sink's arbitrary phase or secret text,
// and observation/delivery leaves the session's credit and error state alone.
func TestOwnerCloseDiagnosticUnavailable(t *testing.T) {
	s := &ownerSession{execution: newRowExecution(), err: errors.New("fixture-secret-sentinel")}
	v := s.closeSnapshot(false)
	if v.completion != ownerCompletionUnavailable || v.origin != (egress.OriginDiagnostic{}) {
		t.Fatal("missing observation became known", v)
	}
	var records []string
	ctx := withOwnerDiagnostics(context.Background(), func(s string) { records = append(records, s) })
	ownerDiagnostics(ctx).phase = "/private/fixture-secret-sentinel"
	for _, value := range []ownerCloseSnapshot{v, {completion: 255, origin: egress.OriginDiagnostic{Phase: 255, Exit: 255}}, {origin: egress.OriginDiagnostic{Phase: egress.OriginJoined}}} {
		ownerDiagnosticClose(ctx, &value)
	}
	for _, record := range records {
		if record != "owner close timeout close_cancel=not_issued supervisor=unavailable phase=unavailable exit=unavailable" || len(record) > 160 || strings.Contains(record, "sentinel") {
			t.Fatal("unavailable/closed diagnostic widened", record)
		}
	}
	if s.execution.credit(false) || s.err.Error() != "fixture-secret-sentinel" {
		t.Fatal("diagnostic changed refusal")
	}
}

// Claim: each documented enum emits its fixed label; exit classes are visible
// only for a joined wait, and no formatter input contains free-form text.
func TestOwnerCloseDiagnosticContract(t *testing.T) {
	phases := []string{"unavailable", "starting", "supervising", "entered", "terminal", "joining", "joined"}
	exits := []string{"unavailable", "zero", "nonzero", "signaled"}
	for p, phase := range phases {
		for e, exit := range exits {
			var got string
			ctx := withOwnerDiagnostics(context.Background(), func(s string) { got = s })
			v := ownerCloseSnapshot{cancelIssued: true, completion: ownerReturned, origin: egress.OriginDiagnostic{Phase: egress.OriginPhase(p), Exit: egress.OriginExit(e)}}
			ownerDiagnosticClose(ctx, &v)
			wantPhase, wantExit := phase, "unavailable"
			if p == int(egress.OriginJoined) {
				if e == 0 {
					wantPhase = "unavailable"
				} else {
					wantExit = exit
				}
			}
			want := fmt.Sprintf("owner close timeout close_cancel=issued supervisor=returned phase=%s exit=%s", wantPhase, wantExit)
			if got != want {
				t.Fatalf("closed enum %d/%d: %q, want %q", p, e, got, want)
			}
		}
	}
}

// Claim: the production coherence check preserves a stable sample, but a phase
// change around completion sampling reports unavailable instead of a mixed join.
// The capture is also exercised by the real timeout test; this controls the
// otherwise scheduling-dependent comparison with exact scalar observations.
func TestOwnerCloseSnapshotRacing(t *testing.T) {
	entered := egress.OriginDiagnostic{Phase: egress.OriginEntered}
	joined := egress.OriginDiagnostic{Phase: egress.OriginJoined, Exit: egress.ExitZero}
	stable := ownerCloseSnapshot{cancelIssued: true, completion: ownerReturned, origin: joined}
	if got := stableCloseSnapshot(joined, stable); got != stable {
		t.Fatal("stable positive discarded", got)
	}
	for _, first := range []egress.OriginDiagnostic{entered, {}} {
		got := stableCloseSnapshot(first, stable)
		if got.completion != ownerCompletionUnavailable || got.origin != (egress.OriginDiagnostic{}) || !got.cancelIssued {
			t.Fatal("racing sample gained completion", got)
		}
	}
}
