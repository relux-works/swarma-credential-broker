package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Only the contended demo gate is synthetic. Every case uses the real Unix
// listener, kernel peer credentials, lease manager and framed transport.
type acceptDeadlineGate struct {
	entered chan context.Context
	release chan struct{}
}

func (g *acceptDeadlineGate) Peer(ctx context.Context, _ uint32) error {
	g.entered <- ctx
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.release:
		return nil
	}
}
func (*acceptDeadlineGate) Check(ctx context.Context, _ uint32, _ string) error {
	return ctx.Err()
}
func (*acceptDeadlineGate) Publish(ctx context.Context, _ uint32, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func acceptDeadlineServer(t *testing.T, gate *acceptDeadlineGate) (*Server, string, context.CancelFunc) {
	t.Helper()
	e := testutil.New(t, lease.Options{DemoAdmission: gate})
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "accept-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx, l); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { testutil.StopServer(func() { cancel(); s.Close() }, done, s.Wait) })
	return s, path, cancel
}

func acceptGateContext(t *testing.T, gate *acceptDeadlineGate) context.Context {
	t.Helper()
	select {
	case ctx := <-gate.entered:
		return ctx
	case <-time.After(time.Second):
		t.Fatal("real server did not enter demo peer admission")
		return nil
	}
}

func acceptSlotsEmpty(t *testing.T, s *Server, until time.Time) {
	t.Helper()
	for {
		s.mu.Lock()
		remaining := len(s.connections)
		s.mu.Unlock()
		if remaining == 0 {
			return
		}
		if !time.Now().Before(until) {
			t.Errorf("connection slot retained past bound: %d", remaining)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Claim: neither gate contention nor a first partial header restarts the two
// seconds captured at accept. Each negative has an adjacent live hello.
func TestAcceptDeadlineThroughPeerAdmission(t *testing.T) {
	for _, early := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			name := "held-gate"
			if early {
				name = "gate-released-before-cutoff"
			}
			if partial {
				name += "/partial-frame"
			} else {
				name += "/idle"
			}
			t.Run(name, func(t *testing.T) {
				gate := &acceptDeadlineGate{entered: make(chan context.Context, 4), release: make(chan struct{})}
				s, path, _ := acceptDeadlineServer(t, gate)
				began := time.Now()
				c := dial(t, path)
				ctx := acceptGateContext(t, gate)
				cutoff, ok := ctx.Deadline()
				if !ok {
					t.Error("peer admission has no accept-time deadline")
					cutoff = began.Add(2 * time.Second)
				} else if budget := cutoff.Sub(began); budget < 1900*time.Millisecond || budget > 2100*time.Millisecond {
					t.Errorf("unexpected accept-time budget: %s", budget)
				}
				var frame bytes.Buffer
				if err := wire.Write(&frame, wire.Request{Method: "hello", ID: "late", Params: []byte(`{"profile":"codex-refresher-v0","versions":[1]}`)}); err != nil {
					t.Fatal(err)
				}
				prefix := 0
				if partial {
					prefix = 2
					if _, err := c.Write(frame.Bytes()[:prefix]); err != nil {
						t.Fatal(err)
					}
				}
				releaseAt := cutoff.Add(250 * time.Millisecond)
				if early {
					releaseAt = cutoff.Add(-1100 * time.Millisecond)
				}
				released := make(chan struct{})
				timer := time.AfterFunc(time.Until(releaseAt), func() { close(gate.release); close(released) })
				t.Cleanup(func() {
					if timer.Stop() {
						close(gate.release)
						close(released)
					}
					<-released
				})
				_ = c.SetReadDeadline(cutoff.Add(400 * time.Millisecond))
				raw, err := wire.Read(c)
				if err == nil {
					var r response
					if wire.Decode(raw, &r) != nil || r.Error == nil || r.Error.Code != "role_not_permitted" || r.Result != nil {
						t.Errorf("unexpected response to incomplete first frame: %s", raw)
					}
					_, err = wire.Read(c)
				}
				elapsed := time.Since(began)
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
					t.Errorf("first-frame connection did not close at cutoff: %v", err)
				}
				if time.Now().After(cutoff.Add(200 * time.Millisecond)) {
					t.Errorf("accept cutoff extended: elapsed=%s", elapsed)
				}
				acceptSlotsEmpty(t, s, cutoff.Add(400*time.Millisecond))
				if !early && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Errorf("held gate did not observe its deadline: %v", ctx.Err())
				}
				t.Logf("partial=%t early_release=%t cutoff_budget=%s close_elapsed=%s gate_error=%v", partial, early, cutoff.Sub(began), elapsed, ctx.Err())
				// Offering the rest of the valid frame after expiry cannot revive it.
				_, writeErr := c.Write(frame.Bytes()[prefix:])
				if writeErr == nil {
					if raw, readErr := wire.Read(c); readErr == nil {
						t.Errorf("expired connection accepted late bytes: %s", raw)
					}
				}
				<-released
				live := dial(t, path)
				hello(t, live)
				live.Close()
				acceptSlotsEmpty(t, s, time.Now().Add(200*time.Millisecond))
			})
		}
	}
}

func TestAcceptDeadlineEndsAfterHello(t *testing.T) {
	gate := &acceptDeadlineGate{entered: make(chan context.Context, 4), release: make(chan struct{})}
	_, path, _ := acceptDeadlineServer(t, gate)
	c := dial(t, path)
	ctx := acceptGateContext(t, gate)
	cutoff, ok := ctx.Deadline()
	if !ok {
		t.Fatal("missing accept deadline")
	}
	// Buffer a complete live hello while admission is held, then admit it with
	// time remaining. The accept deadline must not become a session deadline.
	b, _ := wire.Encode(wire.Hello{Versions: []int{1}, Profile: wire.Profile})
	if err := wire.Write(c, wire.Request{Method: "hello", ID: "hello", Params: b}); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if r := reply(t, c); r.Error != nil || r.ID == nil || *r.ID != "hello" {
		t.Fatal("live hello failed")
	}
	time.Sleep(time.Until(cutoff.Add(50 * time.Millisecond)))
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if r := request(t, c, "status", "after-cutoff", struct{}{}); r.Error != nil {
		t.Fatal("accept deadline canceled negotiated connection")
	}
}

func TestAcceptDeadlineShutdownCancelsAdmission(t *testing.T) {
	for _, direct := range []bool{false, true} {
		name := "parent-cancellation"
		if direct {
			name = "server-close"
		}
		t.Run(name, func(t *testing.T) {
			gate := &acceptDeadlineGate{entered: make(chan context.Context, 4), release: make(chan struct{})}
			s, path, cancel := acceptDeadlineServer(t, gate)
			c := dial(t, path)
			ctx := acceptGateContext(t, gate)
			began := time.Now()
			if direct {
				s.Close()
			} else {
				cancel()
			}
			select {
			case <-ctx.Done():
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Errorf("shutdown did not cancel admission: %v", ctx.Err())
				}
			case <-time.After(300 * time.Millisecond):
				t.Error("shutdown left peer admission blocked")
			}
			close(gate.release)
			acceptSlotsEmpty(t, s, began.Add(400*time.Millisecond))
			closed(t, c)
			t.Logf("shutdown joined admission in %s", time.Since(began))
		})
	}
}
