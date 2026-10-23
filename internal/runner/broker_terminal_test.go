//go:build linux

package runner

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: a valid accept-time terminal refusal remains readable and typed when
// the server has already sent its bounded frame and closed without reading.
func TestReviewTerminalAlreadyClosed(t *testing.T) {
	for _, code := range []string{"peer_identity_unavailable", "role_not_permitted", "frame_too_large"} {
		t.Run(code, func(t *testing.T) {
			closed := make(chan struct{})
			c := clientPeer(t, func(peer *net.UnixConn) {
				if err := wire.Write(peer, map[string]any{"request_id": nil, "error": wire.Refuse(code)}); err != nil {
					t.Error("terminal fixture write failed")
				}
				peer.Close()
				close(closed)
			})
			must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
			<-closed
			_, err := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
			if r, ok := err.(*Refusal); ok {
				t.Logf("observed code=%s status=%d; expected code=%s", r.Code, r.Status, code)
			}
			refusalCode(t, err, code, 69)
		})
	}
}

// Claim: the same terminal response race occurs against the real daemon, whose
// admission refusal closes without reading a hello; the response remains queued.
func TestReviewRealDaemonTerminal(t *testing.T) {
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) {
		for i := range p.Accounts {
			p.Accounts[i].AllowedUIDs = []uint32{}
		}
	})
	root, err := os.MkdirTemp("", "dt-")
	must(t, err)
	defer os.RemoveAll(root)
	must(t, os.Chmod(root, 0755))
	path := filepath.Join(root, "s")
	l, err := server.Listen(path)
	must(t, err)
	s := server.New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	defer func() { s.Close(); cancel(); <-done; s.Wait() }()
	c, err := DialBroker(context.Background(), path)
	must(t, err)
	defer c.Close()
	must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
	must(t, c.conn.SetReadDeadline(time.Now().Add(time.Second)))
	raw, err := c.conn.SyscallConn()
	must(t, err)
	var n int
	var pe error
	var b [4]byte
	must(t, raw.Read(func(fd uintptr) bool {
		n, _, pe = syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		return pe != syscall.EAGAIN && pe != syscall.EWOULDBLOCK
	}))
	must(t, pe)
	if n != 4 {
		t.Fatal("terminal header unavailable")
	}
	s.Wait() // The admission handler itself closes; do not force daemon shutdown.
	_, err = c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
	if r, ok := err.(*Refusal); ok {
		t.Logf("observed code=%s status=%d; expected role_not_permitted", r.Code, r.Status)
	}
	e.NoLeaseRecords(t)
	if n, _ := e.Owner.Counts(); n != 0 {
		t.Fatal("denial started refresh")
	}
	refusalCode(t, err, "role_not_permitted", 69)
}

// Claim: after each write point fails against an already-closed peer, only a
// complete canonical null-ID terminal error retains its code. EOF, malformed,
// oversized, correlated and ordinary errors retain the phase's transport refusal;
// a later valid frame cannot rescue an invalid first frame.
func TestSocketClosedTerminalWritePoints(t *testing.T) {
	for _, method := range []string{"hello", "request", "renew", "release"} {
		for _, mode := range []string{"peer_identity_unavailable", "role_not_permitted", "frame_too_large", "eof", "malformed", "noncanonical", "correlated", "ordinary", "unknown", "details", "message", "missing", "extra", "null-error", "result", "partial-header", "partial-body", "oversize", "invalid-then-terminal"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				closed := make(chan struct{})
				send := make(chan struct{})
				defer close(send)
				c := clientPeer(t, func(peer *net.UnixConn) {
					defer close(closed)
					if method != "hello" {
						r := peerRequest(peer)
						if err := wire.Write(peer, map[string]any{"request_id": r.ID, "result": helloPayload()}); err != nil {
							t.Error("hello fixture write failed")
							return
						}
					}
					<-send
					id := "1"
					if method != "hello" {
						id = "2"
					}
					envelope := map[string]any{"request_id": nil, "error": wire.Refuse("role_not_permitted")}
					switch mode {
					case "peer_identity_unavailable", "role_not_permitted", "frame_too_large":
						envelope["error"] = wire.Refuse(mode)
					case "correlated":
						envelope["request_id"] = id
					case "ordinary":
						envelope["error"] = wire.Refuse("lease_owner_unavailable")
					case "unknown":
						envelope["error"] = map[string]any{"code": "unknown", "message": "request refused", "details": map[string]any{}}
					case "details":
						envelope["error"] = map[string]any{"code": "role_not_permitted", "message": "request refused", "details": map[string]any{"unexpected": true}}
					case "message":
						envelope["error"] = map[string]any{"code": "role_not_permitted", "message": "unexpected", "details": map[string]any{}}
					case "missing":
						delete(envelope, "request_id")
					case "extra":
						envelope["unexpected"] = true
					case "null-error":
						envelope["error"] = nil
					case "result":
						delete(envelope, "error")
						envelope["result"] = helloPayload()
					}
					body, err := wire.Encode(envelope)
					if err != nil {
						t.Error("terminal fixture encoding failed")
						return
					}
					switch mode {
					case "eof":
						body = nil
					case "malformed", "invalid-then-terminal":
						body = []byte(`{"error":`)
					case "noncanonical":
						body = append([]byte(" "), body...)
					}
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(body)))
					switch mode {
					case "eof":
					case "oversize":
						binary.BigEndian.PutUint32(header[:], wire.MaxPayload+1)
						_, err = peer.Write(header[:])
					case "partial-header":
						_, err = peer.Write(header[:2])
					default:
						_, err = peer.Write(header[:])
						if err == nil {
							if mode == "partial-body" {
								body = body[:len(body)/2]
							}
							_, err = peer.Write(body)
						}
						if err == nil && mode == "invalid-then-terminal" {
							err = wire.Write(peer, map[string]any{"request_id": nil, "error": wire.Refuse("role_not_permitted")})
						}
					}
					if err != nil {
						t.Error("terminal fixture write failed")
					}
					peer.Close()
				})
				if method == "hello" {
					must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
				} else {
					clientHello(t, c)
				}
				send <- struct{}{}
				<-closed
				var err error
				status, code := 69, "credential_injection_unavailable"
				switch method {
				case "hello":
					_, err = c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
				case "request":
					_, err = c.Request(context.Background(), LeaseRequest{})
				case "renew":
					_, err = c.Renew(context.Background(), RenewRequest{"lease", strings.Repeat("a", 64)})
					status, code = 75, "renew_failed"
				case "release":
					err = c.Release(context.Background(), "lease")
					status, code = 75, "lease_owner_unavailable"
				}
				switch mode {
				case "peer_identity_unavailable", "role_not_permitted", "frame_too_large":
					code = mode
				}
				refusalCode(t, err, code, status)
				p := phaseHello
				switch method {
				case "request":
					p = phaseRequest
				case "renew":
					p = phaseRefresh
				case "release":
					p = phaseRelease
				}
				state := &statusRecord{phase: p}
				state.capture(brokerFailure(err, status))
				var diagnostic strings.Builder
				requireStatus(t, classify(state, &diagnostic), status, diagnostic.String())
				if !strings.Contains(diagnostic.String(), code) {
					t.Fatal("terminal refusal lost in classification")
				}
				select {
				case <-c.closed:
				default:
					t.Fatal("uncertain stream remained open")
				}
			})
		}
	}
}

// Claim: a failed write followed by an incomplete, still-open terminal frame
// returns at or after the absolute caller deadline and within a one-second
// scheduling margin, returns no terminal code, and closes the stream. Socket
// deadline completion need not wait for the context timer to publish Err.
func TestSocketFailedWriteReadDeadline(t *testing.T) {
	ready := make(chan struct{})
	finish := make(chan struct{})
	c := clientPeer(t, func(peer *net.UnixConn) {
		raw, err := peer.SyscallConn()
		var shutdownErr error
		if err == nil {
			err = raw.Control(func(fd uintptr) { shutdownErr = syscall.Shutdown(int(fd), syscall.SHUT_RD) })
		}
		if err != nil || shutdownErr != nil {
			t.Error("fixture read shutdown failed")
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 100)
		if _, err := peer.Write(header[:]); err != nil {
			t.Error("fixture header write failed")
		}
		close(ready)
		<-finish
	})
	t.Cleanup(func() { close(finish) })
	must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
	<-ready
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_, err := c.Hello(ctx, HelloRequest{[]int{1}, ProtocolProfile})
	returned := time.Now()
	refusalCode(t, err, "credential_injection_unavailable", 69)
	if returned.Before(deadline) || returned.After(deadline.Add(time.Second)) {
		t.Fatalf("failed-write read returned %s from caller cutoff", returned.Sub(deadline))
	}
	select {
	case <-c.closed:
	default:
		t.Fatal("timed-out stream remained open")
	}
}
