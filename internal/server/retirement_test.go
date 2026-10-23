package server

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// retirementWriter parks the final successful payload write before returning
// to the frame writer. The client has received every byte while the manager's
// publication is still registered. Interrupt notification observes either the
// production deadline or the close used by the narrowing fault control.
type retirementWriter struct {
	*net.UnixConn
	complete        chan struct{}
	resume          <-chan struct{}
	interrupted     chan struct{}
	interruptResume <-chan struct{}
	once            sync.Once
	writes          int
}

func (w *retirementWriter) Write(p []byte) (int, error) {
	n, err := w.UnixConn.Write(p)
	w.writes++
	if w.writes == 2 && n == len(p) && err == nil {
		close(w.complete)
		<-w.resume
	}
	return n, err
}
func (w *retirementWriter) SetWriteDeadline(until time.Time) error {
	if !until.IsZero() && !until.After(time.Now()) {
		w.once.Do(func() { close(w.interrupted) })
		if w.interruptResume != nil {
			<-w.interruptResume
		}
	}
	return w.UnixConn.SetWriteDeadline(until)
}
func (w *retirementWriter) Close() error {
	err := w.UnixConn.Close()
	w.once.Do(func() { close(w.interrupted) })
	return err
}

// Claim: on a real Unix socket, a fully received frame whose writer has not
// returned can be revoked by release without losing the same-connection terminal
// receipt. Settled retirement and reconnect after deliberate receipt loss are
// positive controls. An interrupt held before setting its expired deadline must
// finish before publication retirement or the next frame. This exercises the transport primitive with the real lease
// manager; TestReviewImmediateReleaseReceipt covers the full server handshake.
func TestImmediateReleaseRetirement(t *testing.T) {
	for _, schedule := range []string{"immediate", "settled-control", "reconnect-recovery", "interrupt-inflight"} {
		t.Run(schedule, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			material := e.Issue(t)
			dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "r-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			l, err := Listen(filepath.Join(dir, "s"))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			c := dial(t, l.Addr().String())
			socket, err := l.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			resume := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(resume) }) }
			defer unblock()
			writer := &retirementWriter{UnixConn: socket, complete: make(chan struct{}), resume: resume, interrupted: make(chan struct{})}
			interruptResume := make(chan struct{})
			var interruptOnce sync.Once
			finishInterrupt := func() { interruptOnce.Do(func() { close(interruptResume) }) }
			defer finishInterrupt()
			if schedule == "interrupt-inflight" {
				writer.interruptResume = interruptResume
			}
			published := make(chan error, 1)
			go func() {
				published <- e.Manager.Publish(context.Background(), e.UID, e.Policy.Generation, material, func(ctx context.Context, until time.Time) error {
					return writeFrame(ctx, writer, map[string]any{"request_id": "issue", "result": material}, until)
				})
			}()
			awaitReview(t, writer.complete)
			frame := reply(t, c)
			var received wire.LeaseResult
			if frame.Error != nil || wire.Decode(frame.Result, &received) != nil || received.LeaseID != material.LeaseID {
				t.Fatal("complete material frame unavailable")
			}
			if schedule == "settled-control" {
				unblock()
				if err := <-published; err != nil {
					t.Fatal("settled publication failed")
				}
			}
			released := make(chan error, 1)
			go func() {
				out := e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: received.LeaseID}, time.Now())
				if out.Err != nil {
					released <- out.Err
					return
				}
				released <- writeFrame(context.Background(), socket, map[string]any{"request_id": "release", "result": out.Result}, time.Now().Add(time.Second))
			}()
			if schedule != "settled-control" {
				// Release has revoked this exact publication, after a complete frame but
				// before its final Write returns. No iteration timing is involved.
				awaitReview(t, writer.interrupted)
				if schedule == "reconnect-recovery" {
					c.Close()
				}
				unblock()
				if schedule == "interrupt-inflight" {
					// The interrupt has entered but has not set the expired
					// deadline yet. Retirement must wait before another frame.
					select {
					case <-published:
						t.Fatal("publication retired while its write interrupt remained active")
					case <-time.After(50 * time.Millisecond):
					}
					finishInterrupt()
				}
				if err := <-published; err != nil {
					t.Fatal("completed publication became a failed write")
				}
			}
			receiptErr := <-released
			if schedule == "reconnect-recovery" {
				if receiptErr == nil {
					t.Fatal("deliberately disconnected receipt unexpectedly succeeded")
				}
			} else {
				raw, readErr := wire.Read(c)
				var receipt response
				if receiptErr != nil || readErr != nil || wire.Decode(raw, &receipt) != nil || receipt.Error != nil || receipt.ID == nil || *receipt.ID != "release" {
					// Verify durable receipt recovery even when the close mutant breaks the
					// original transport, before reporting its intended assertion failure.
					retry := dial(t, start(t, e, nil))
					hello(t, retry)
					recovered := request(t, retry, "lease.release", "retry", wire.Release{LeaseID: received.LeaseID})
					t.Fatalf("completed frame lost release receipt: write_failed=%t read_failed=%t reconnect_receipt=%t", receiptErr != nil, readErr != nil, recovered.Error == nil)
				}
			}
			retry := dial(t, start(t, e, nil))
			hello(t, retry)
			if out := request(t, retry, "lease.release", "retry", wire.Release{LeaseID: received.LeaseID}); out.Error != nil {
				t.Fatal("terminal receipt recovery failed")
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("release started refresh")
			}
			if errors.Is(receiptErr, context.DeadlineExceeded) {
				t.Fatal("release exceeded its deadline")
			}
		})
	}
}

type frameResultWriter struct {
	partial bool
	writes  int
	closed  bool
}

func (w *frameResultWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.partial && w.writes == 2 {
		return 1, io.ErrShortWrite
	}
	return len(p), nil
}
func (w *frameResultWriter) Close() error                     { w.closed = true; return nil }
func (w *frameResultWriter) SetWriteDeadline(time.Time) error { return nil }

// Claim: a payload write error closes the transport before writeFrame returns
// control to the connection writer gate; a complete write keeps it open. The
// fixture injects the error; real partial-frame EOF is covered separately.
func TestFrameFailureClosesBeforeReturn(t *testing.T) {
	for _, partial := range []bool{true, false} {
		name := "complete-control"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			w := &frameResultWriter{partial: partial}
			err := writeFrame(context.Background(), w, map[string]any{"request_id": "frame", "result": "fixture"}, time.Now().Add(time.Second))
			if partial {
				if !errors.Is(err, io.ErrShortWrite) || !w.closed {
					t.Fatal("partial frame returned before transport closure")
				}
			} else if err != nil || w.closed {
				t.Fatal("completed frame lost its connection")
			}
		})
	}
}
