// Package server serves the profile subset on peer-authenticated Unix sockets.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type Server struct {
	Manager     *lease.Manager
	mu          sync.Mutex
	connections map[*net.UnixConn]bool
	listener    *net.UnixListener
	wg          sync.WaitGroup
	closed      bool
	peer        func(*net.UnixConn) (uint32, error)
	socketPath  string
	socketInfo  os.FileInfo
}

func New(m *lease.Manager) *Server {
	return &Server{Manager: m, connections: map[*net.UnixConn]bool{}, peer: PeerUID}
}

// Listen refuses an existing path. It never removes somebody else's socket.
func Listen(path string) (*net.UnixListener, error) {
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, wire.Refuse("lease_owner_unavailable")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, wire.Refuse("lease_owner_unavailable")
	}
	l.SetUnlinkOnClose(false)
	created, statErr := os.Lstat(path)
	if e = os.Chmod(path, 0600); e != nil || statErr != nil {
		l.Close()
		current, err := os.Lstat(path)
		if err == nil && created != nil && os.SameFile(created, current) {
			_ = os.Remove(path)
		}
		return nil, wire.Refuse("lease_owner_unavailable")
	}
	return l, nil
}
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	s.mu.Lock()
	s.listener = l
	s.socketPath = l.Addr().String()
	s.socketInfo, _ = os.Lstat(s.socketPath)
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				return nil
			}
			return wire.Refuse("lease_owner_unavailable")
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= 256 {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.connections[c] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { c.Close(); s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
			s.serve(ctx, c)
		}()
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	if s.listener != nil {
		s.listener.Close()
		current, err := os.Lstat(s.socketPath)
		if err == nil && s.socketInfo != nil && os.SameFile(current, s.socketInfo) {
			_ = os.Remove(s.socketPath)
		}
	}
	for c := range s.connections {
		c.Close()
	}
	s.mu.Unlock()
}
func (s *Server) Wait() { s.wg.Wait() }
func (s *Server) CloseConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.connections {
		c.Close()
	}
}
func terminal(c *net.UnixConn, code string) {
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = wire.Write(c, map[string]any{"request_id": nil, "error": wire.Refuse(code)})
}
func read(c *net.UnixConn, first bool) ([]byte, time.Time, error) {
	firstDeadline := time.Now().Add(2 * time.Second)
	if first {
		_ = c.SetReadDeadline(firstDeadline)
	} else {
		_ = c.SetReadDeadline(time.Time{})
	}
	var one [1]byte
	if _, e := io.ReadFull(c, one[:]); e != nil {
		return nil, time.Time{}, e
	}
	arrival := time.Now()
	until := arrival.Add(2 * time.Second)
	if first && firstDeadline.Before(until) {
		until = firstDeadline
	}
	_ = c.SetReadDeadline(until)
	b, e := wire.Read(io.MultiReader(&byteReader{b: one[:]}, c))
	return b, arrival, e
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
func (s *Server) serve(parent context.Context, c *net.UnixConn) {
	uid, e := s.peer(c)
	if e != nil {
		terminal(c, "peer_identity_unavailable")
		return
	}
	p := s.Manager.Policy()
	if !p.Peer(uid) {
		terminal(c, "role_not_permitted")
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	requests := newConnectionCalls()
	send := func(id any, result any, err error, g uint64, until time.Time, method string, call *connectionCall) error {
		// A request waiting behind its own connection's writer retains its
		// original arrival deadline; a non-draining connection is closed.
		wait, stopWait := context.WithDeadline(ctx, until)
		if until.IsZero() {
			stopWait()
			wait, stopWait = context.WithTimeout(ctx, 2*time.Second)
		}
		defer stopWait()
		return requests.respond(wait, func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			write := func(delivery context.Context, authDeadline time.Time) error {
				if delivery.Err() != nil {
					return delivery.Err()
				}
				writeUntil := time.Now().Add(2 * time.Second)
				if !until.IsZero() && !time.Now().Before(until) {
					result = nil
					err = wire.Refuse("request_deadline_exceeded")
					if method == "lease.renew" {
						err = wire.Refuse("renew_timeout")
					}
				}
				if err == nil {
					for _, bound := range []time.Time{until, authDeadline} {
						if !bound.IsZero() && bound.Before(writeUntil) {
							writeUntil = bound
						}
					}
				}
				response := map[string]any{"request_id": id}
				if err != nil {
					response["error"] = wire.Refuse(lease.ErrorCode(err))
				} else {
					response["result"] = result
				}
				frame, err := newRequestFrameWriter(c, requests, call)
				if err != nil {
					return err
				}
				return writeFrame(delivery, frame, response, writeUntil)
			}
			if material, ok := result.(wire.LeaseResult); ok && err == nil {
				delivery, stop := context.WithDeadline(ctx, until)
				defer stop()
				wrote := false
				e := s.Manager.Publish(delivery, uid, g, material, func(delivery context.Context, authDeadline time.Time) error {
					wrote = true
					return write(delivery, authDeadline)
				})
				if wrote {
					return e
				}
				result, err = nil, e
			}
			return s.Manager.WithGenerationContext(ctx, g, func(delivery context.Context) error { return write(delivery, time.Time{}) })
		})
	}
	hello := false
	var calls sync.WaitGroup
	defer func() { cancel(); calls.Wait() }()
	for {
		b, arrival, e := read(c, !hello)
		if e != nil {
			cancel()
			if errors.Is(e, wire.ErrTooLarge) {
				select {
				case <-requests.writer:
					terminal(c, "frame_too_large")
					requests.writer <- struct{}{}
				default:
					// Another frame is already blocked; closing interrupts it.
				}
			}
			return
		}
		var r wire.Request
		if wire.Decode(b, &r) != nil || !wire.ASCII(r.ID, 64) {
			return
		}
		if !hello {
			if r.Method != "hello" {
				return
			}
			var h wire.Hello
			if wire.Decode(r.Params, &h) != nil {
				return
			}
			if h.Profile != wire.Profile || len(h.Versions) != 1 || h.Versions[0] != 1 {
				_ = send(r.ID, nil, wire.Refuse("version_unsupported"), p.Generation, time.Time{}, "hello", nil)
				return
			}
			if send(r.ID, map[string]any{"version": 1, "profile": wire.Profile, "principal": map[string]any{"uid": uid}, "policy_generation": p.Generation}, nil, p.Generation, time.Time{}, "hello", nil) != nil {
				return
			}
			hello = true
			continue
		}
		if s.Manager.Policy().Generation != p.Generation {
			return
		}
		var params any
		switch r.Method {
		case "status":
			var empty struct{}
			if wire.Decode(r.Params, &empty) != nil {
				return
			}
		case "lease.request":
			var v wire.LeaseRequest
			if wire.Decode(r.Params, &v) != nil {
				return
			}
			params = v
		case "lease.renew":
			var v wire.Renew
			if wire.Decode(r.Params, &v) != nil || !wire.ASCII(v.LeaseID, 128) {
				return
			}
			params = v
		case "lease.release":
			var v wire.Release
			if wire.Decode(r.Params, &v) != nil || !wire.ASCII(v.LeaseID, 128) {
				return
			}
			params = v
		default:
			return
		}
		admission, stopAdmission := context.WithDeadline(ctx, s.Manager.Deadline(r.Method, arrival))
		call, err := requests.reserve(admission, r.ID)
		stopAdmission()
		if err != nil {
			return
		}
		calls.Add(1)
		go func(r wire.Request, params any, arrival time.Time, call *connectionCall) {
			defer calls.Done()
			defer requests.retire(call)
			var out lease.Outcome
			if r.Method == "status" {
				call, cancel := context.WithDeadline(ctx, arrival.Add(2*time.Second))
				defer cancel()
				result := s.Manager.Status(call, uid)
				if call.Err() != nil {
					out = lease.Outcome{Err: wire.Refuse("request_deadline_exceeded"), Generation: p.Generation}
				} else {
					out = lease.Outcome{Result: result, Generation: p.Generation}
				}
			} else {
				out = s.Manager.Call(ctx, uid, r.Method, params, arrival)
				if out.Generation == 0 {
					out.Generation = p.Generation
				}
			}
			if ctx.Err() != nil {
				return
			}
			until := s.Manager.Deadline(r.Method, arrival)
			if send(r.ID, out.Result, out.Err, out.Generation, until, r.Method, call) != nil {
				cancel()
				c.Close()
			}
		}(r, params, arrival, call)
	}
}

// Status verifies server identity before sending even the negotiation frame.
func Status(ctx context.Context, path string, expectedUID uint32) (wire.Status, error) {
	var out wire.Status
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return out, wire.Refuse("lease_owner_unavailable")
	}
	c := conn.(*net.UnixConn)
	defer c.Close()
	uid, e := PeerUID(c)
	if e != nil || uid != expectedUID {
		return out, wire.Refuse("server_identity_mismatch")
	}
	deadline := time.Now().Add(2 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	_ = c.SetDeadline(deadline)
	for i, request := range []wire.Request{{Method: "hello", Params: json.RawMessage(`{"profile":"codex-refresher-v0","versions":[1]}`), ID: "hello"}, {Method: "status", Params: json.RawMessage(`{}`), ID: "status"}} {
		if e = wire.Write(c, request); e != nil {
			return out, wire.Refuse("lease_owner_unavailable")
		}
		raw, e := wire.Read(c)
		if e != nil {
			return out, wire.Refuse("lease_owner_unavailable")
		}
		var reply struct {
			ID     string          `json:"request_id"`
			Result json.RawMessage `json:"result,omitempty"`
			Error  *wire.Error     `json:"error,omitempty"`
		}
		if wire.Decode(raw, &reply) != nil || reply.ID != request.ID {
			return out, wire.Refuse("lease_owner_unavailable")
		}
		if reply.Error != nil {
			if reply.Result != nil {
				return out, wire.Refuse("lease_owner_unavailable")
			}
			return out, wire.Refuse(reply.Error.Code)
		}
		if i == 0 {
			var h struct {
				Version   int    `json:"version"`
				Profile   string `json:"profile"`
				Principal struct {
					UID uint32 `json:"uid"`
				} `json:"principal"`
				Generation uint64 `json:"policy_generation"`
			}
			if wire.Decode(reply.Result, &h) != nil || h.Version != 1 || h.Profile != wire.Profile || h.Principal.UID != uint32(os.Geteuid()) || h.Generation == 0 {
				return out, wire.Refuse("lease_owner_unavailable")
			}
		}
		if i == 1 {
			if wire.Decode(reply.Result, &out) != nil {
				return out, wire.Refuse("lease_owner_unavailable")
			}
		}
	}
	return out, nil
}

// frameWriter lets transport interruption cover real socket writes without
// coupling successful frame completion to connection lifetime.
type frameWriter interface {
	io.Writer
	io.Closer
	SetWriteDeadline(time.Time) error
}

func writeFrame(ctx context.Context, c frameWriter, response any, until time.Time) error {
	if err := c.SetWriteDeadline(until); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Interrupt an active write; a completed frame must not close the socket
		// carrying its following release receipt. A write error closes it below.
		_ = c.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		// A stale interrupt must never expire the next frame's write deadline.
		if !stop() {
			<-interrupted
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := wire.Write(c, response)
	if err != nil {
		// Close before releasing the connection's writer gate: another response
		// must never append bytes to a partial frame.
		_ = c.Close()
	}
	return err
}
