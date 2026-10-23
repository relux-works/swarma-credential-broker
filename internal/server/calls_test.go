package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// completionRawConn parks after the final real socket syscall callback returns
// but before RawConn.Write returns to wire.Write. No request-registry mutex is
// held by this barrier, and no production hook changes the scheduling contract.
type completionRawConn struct {
	syscall.RawConn
	complete chan struct{}
	resume   <-chan struct{}
	writes   int
}

func (c *completionRawConn) Write(fn func(uintptr) bool) error {
	err := c.RawConn.Write(fn)
	c.writes++
	if err == nil && c.writes == 2 {
		close(c.complete)
		<-c.resume
	}
	return err
}

// Claim: after a real Unix peer consumes a complete release receipt or status
// frame, the conflicting ID and the last capacity slot become reusable before
// the old handler exits. A distinct ID progresses during the parked write;
// stale cleanup cannot remove the successor. This exercises the production
// request registry and native frame writer; the sequential probes cover full serving.
func TestRequestCompletionRetirement(t *testing.T) {
	for _, shape := range []string{"release-receipt", "status"} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%t", shape, full), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				requests := newConnectionCalls()
				old, err := requests.reserve(ctx, "reuse")
				if err != nil {
					t.Fatal(err)
				}
				if full {
					for i := 0; i < 127; i++ {
						if _, err := requests.reserve(ctx, fmt.Sprintf("pending-%d", i)); err != nil {
							t.Fatal(err)
						}
					}
				}
				dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "id-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
				l, err := Listen(filepath.Join(dir, "s"))
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				peer := dial(t, l.Addr().String())
				socket, err := l.AcceptUnix()
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				resume, exit := make(chan struct{}), make(chan struct{})
				var resumeOnce, exitOnce sync.Once
				unblock := func() { resumeOnce.Do(func() { close(resume) }) }
				finish := func() { exitOnce.Do(func() { close(exit) }) }
				writer, err := newRequestFrameWriter(socket, requests, old)
				if err != nil {
					t.Fatal(err)
				}
				barrier := &completionRawConn{RawConn: writer.raw, complete: make(chan struct{}), resume: resume}
				writer.raw = barrier
				written, exited := make(chan error, 1), make(chan struct{})
				go func() {
					defer close(exited)
					defer requests.retire(old)
					var result any = wire.Status{}
					if shape == "release-receipt" {
						result = map[string]any{"lease_id": "fixture-lease", "state": "released"}
					}
					written <- requests.respond(ctx, func() error {
						return writeFrame(ctx, writer, map[string]any{"request_id": old.id, "result": result}, time.Now().Add(time.Second))
					})
					<-exit // Deliberately retain the old handler after send returns.
				}()
				defer func() { unblock(); finish(); <-exited }()
				awaitReview(t, barrier.complete)
				frame := reply(t, peer)
				if frame.ID == nil || *frame.ID != old.id || frame.Error != nil {
					t.Fatal("complete response unavailable")
				}
				if !full {
					distinct, err := requests.reserve(ctx, "distinct")
					if err != nil {
						t.Fatal("distinct ID blocked by active writer", err)
					}
					requests.retire(distinct)
				}
				nextID := old.id
				if full {
					nextID = "reclaimed-slot"
				}
				// Admission must succeed even before the completed Write returns.
				next, err := requests.reserve(ctx, nextID)
				if err != nil {
					t.Fatal("completed request remained outstanding", err)
				}
				unblock()
				if err := <-written; err != nil {
					t.Fatal("complete frame failed", err)
				}
				finish()
				<-exited
				requests.mu.Lock()
				present := requests.pending[nextID] == next
				requests.mu.Unlock()
				if !present {
					t.Fatal("old handler retired a successor")
				}
				if _, err := requests.reserve(ctx, nextID); !errors.Is(err, wire.ErrMalformed) {
					t.Fatal("outstanding duplicate was not refused", err)
				}
				requests.retire(next)
			})
		}
	}
}

// Claim: a genuinely outstanding ID and a full 128-call registry are refused;
// freeing a slot permits admission, and cancelled admission reserves nothing.
func TestRequestAdmissionBounds(t *testing.T) {
	ctx := context.Background()
	requests := newConnectionCalls()
	first, _ := requests.reserve(ctx, "first")
	if _, err := requests.reserve(ctx, "first"); !errors.Is(err, wire.ErrMalformed) {
		t.Fatal("duplicate accepted", err)
	}
	for i := 0; i < 127; i++ {
		if _, err := requests.reserve(ctx, fmt.Sprintf("id-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := requests.reserve(ctx, "overflow"); !errors.Is(err, wire.ErrMalformed) {
		t.Fatal("capacity exceeded", err)
	}
	<-requests.writer
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := requests.reserve(cancelled, "first"); !errors.Is(err, context.Canceled) {
		t.Fatal("conflict ignored cancellation", err)
	}
	requests.writer <- struct{}{}
	requests.retire(first)
	if _, err := requests.reserve(ctx, "overflow"); err != nil {
		t.Fatal("retired slot unavailable", err)
	}
}

// Claim: while a synthetic refresh is genuinely pending, a duplicate wire ID
// closes the connection without admitting a second owner refresh. Ordinary
// sequential reuse and distinct IDs have positive controls in the probes.
func TestOutstandingRequestIDRefused(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	material := e.Issue(t)
	gate := make(chan struct{})
	defer close(gate)
	entered := e.Owner.Gate(gate)
	c := dial(t, start(t, e, nil))
	hello(t, c)
	raw, _ := wire.Encode(wire.Renew{LeaseID: material.LeaseID, RejectedSHA256: lease.Digest(material.Payload.AccessToken)})
	if err := wire.Write(c, wire.Request{Method: "lease.renew", ID: "pending", Params: raw}); err != nil {
		t.Fatal(err)
	}
	<-entered // Refresh has counted this call and is held at the fixture gate.

	if err := wire.Write(c, wire.Request{Method: "status", ID: "pending", Params: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.Read(c); !errors.Is(err, io.EOF) {
		t.Fatal("outstanding duplicate did not close connection", err)
	}
	if calls, _ := e.Owner.Counts(); calls != 1 {
		t.Fatal("duplicate admitted owner work")
	}
}
