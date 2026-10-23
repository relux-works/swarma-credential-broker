//go:build linux

package runner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func clientPeer(t *testing.T, serve func(*net.UnixConn)) *SocketClient {
	t.Helper()
	root, e := os.MkdirTemp("", "bc-")
	must(t, e)
	path := filepath.Join(root, "client.sock")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	must(t, e)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.AcceptUnix()
		if e == nil {
			defer c.Close()
			serve(c)
		}
	}()
	c, e := DialBroker(context.Background(), path)
	must(t, e)
	t.Cleanup(func() { c.Close(); l.Close(); <-done; os.RemoveAll(root) })
	return c
}
func peerRequest(c *net.UnixConn) wire.Request {
	b, e := wire.Read(c)
	if e != nil {
		return wire.Request{}
	}
	var r wire.Request
	if wire.Decode(b, &r) != nil {
		return wire.Request{}
	}
	return r
}
func helloPayload() any {
	return map[string]any{"version": 1, "profile": ProtocolProfile, "principal": map[string]any{"uid": uint32(os.Geteuid())}, "policy_generation": 1}
}
func clientHello(t *testing.T, c *SocketClient) {
	t.Helper()
	must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
	h, e := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
	must(t, e)
	if h.Version != 1 || h.UID != uint32(os.Geteuid()) {
		t.Fatal("hello identity mismatch")
	}
}
func refusalCode(t *testing.T, e error, code string, status int) {
	t.Helper()
	r, ok := e.(*Refusal)
	if !ok || r == nil || r.Code != code || r.Status != status {
		t.Fatalf("refusal mismatch: %T, want %s/%d", e, code, status)
	}
}

// Claim: malformed and non-profile response members fail closed as typed metadata;
// the adjacent canonical hello succeeds. No raw response reaches the diagnostic.
func TestSocketResponseValidation(t *testing.T) {
	for _, mode := range []string{"valid", "malformed", "oversize", "noncanonical", "duplicate", "null-id", "null-result", "null-error", "null-principal", "null-uid", "unknown-member", "missing-member", "both", "unknown-code", "null-code", "error-details", "error-message", "wrong-id", "version", "profile", "generation", "partial-header", "partial-body", "eof"} {
		t.Run(mode, func(t *testing.T) {
			c := clientPeer(t, func(c *net.UnixConn) {
				r := peerRequest(c)
				if r.ID == "" {
					return
				}
				result := helloPayload().(map[string]any)
				envelope := map[string]any{"request_id": r.ID, "result": result}
				switch mode {
				case "null-id":
					envelope["request_id"] = nil
				case "null-result":
					envelope["result"] = nil
				case "null-error":
					delete(envelope, "result")
					envelope["error"] = nil
				case "null-principal":
					result["principal"] = nil
				case "null-uid":
					result["principal"] = map[string]any{"uid": nil}
				case "unknown-member":
					result["unexpected"] = "response-canary"
				case "missing-member":
					delete(result, "policy_generation")
				case "both":
					envelope["error"] = wire.Refuse("lease_owner_unavailable")
				case "unknown-code", "null-code", "error-details", "error-message":
					delete(envelope, "result")
					err := map[string]any{"code": "lease_owner_unavailable", "message": "request refused", "details": map[string]any{}}
					if mode == "unknown-code" {
						err["code"] = "response-canary"
					}
					if mode == "null-code" {
						err["code"] = nil
					}
					if mode == "error-details" {
						err["details"] = map[string]any{"unexpected": "response-canary"}
					}
					if mode == "error-message" {
						err["message"] = "response-canary"
					}
					envelope["error"] = err
				case "wrong-id":
					envelope["request_id"] = "other"
				case "version":
					result["version"] = 2
				case "profile":
					result["profile"] = "other"
				case "generation":
					result["policy_generation"] = 0
				}
				b, _ := wire.Encode(envelope)
				switch mode {
				case "malformed":
					b = []byte(`{"response-canary":`)
				case "noncanonical":
					b = append([]byte(" "), b...)
				case "duplicate":
					b = []byte(fmt.Sprintf(`{"request_id":%q,"request_id":%q,"result":{}}`, r.ID, r.ID))
				case "eof":
					return
				}
				var h [4]byte
				binary.BigEndian.PutUint32(h[:], uint32(len(b)))
				if mode == "oversize" {
					binary.BigEndian.PutUint32(h[:], wire.MaxPayload+1)
					c.Write(h[:])
					return
				}
				if mode == "partial-header" {
					c.Write(h[:2])
					return
				}
				c.Write(h[:])
				if mode == "partial-body" {
					c.Write(b[:len(b)/2])
					return
				}
				c.Write(b)
			})
			must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
			_, e := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
			if mode == "valid" {
				must(t, e)
			} else {
				refusalCode(t, e, "credential_injection_unavailable", 69)
			}
		})
	}
}

// Claim: kernel UID mismatch sends no protocol bytes; the real same-UID peer is
// an adjacent positive control, including the declared interim R2 mode.
func TestSocketServerPin(t *testing.T) {
	for _, match := range []bool{false, true} {
		t.Run(fmt.Sprint(match), func(t *testing.T) {
			read := make(chan int, 1)
			c := clientPeer(t, func(c *net.UnixConn) {
				c.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				n, _ := c.Read(b[:])
				read <- n
			})
			uid := uint32(os.Geteuid())
			if !match {
				uid++
			}
			e := c.VerifyServer(context.Background(), uid)
			if match {
				must(t, e)
			} else {
				refusalCode(t, e, "server_identity_mismatch", 69)
			}
			c.Close()
			if n := <-read; n != 0 {
				t.Fatal("identity check wrote protocol bytes")
			}
		})
	}
}

// Claim: every closed profile refusal preserves its code while the operation
// selects admission (69) or renewal/release (75); unknown codes fail validation.
func TestSocketRefusalMapping(t *testing.T) {
	codes := strings.Fields("peer_identity_unavailable server_identity_mismatch role_not_permitted frame_too_large version_unsupported request_deadline_exceeded account_exists account_unknown account_duplicate account_store_keyring_refused enrol_material_invalid lease_not_authorised lease_account_unknown lease_harness_mismatch lease_account_revoked lease_reauth_required lease_owner_unavailable lease_channel_unsupported lease_harness_unqualified lease_binding_mismatch lease_network_enforcement_unavailable lease_not_owner lease_not_active renew_not_current renew_timeout renew_failed external_token_init_failed credential_source_conflict credential_injection_unavailable")
	for _, code := range codes {
		for _, method := range []string{"request", "renew", "release"} {
			t.Run(code+"/"+method, func(t *testing.T) {
				c := clientPeer(t, func(c *net.UnixConn) {
					r := peerRequest(c)
					wire.Write(c, map[string]any{"request_id": r.ID, "result": helloPayload()})
					r = peerRequest(c)
					wire.Write(c, map[string]any{"request_id": r.ID, "error": wire.Refuse(code)})
				})
				clientHello(t, c)
				var e error
				status := 75
				switch method {
				case "request":
					_, e = c.Request(context.Background(), LeaseRequest{})
					status = 69
				case "renew":
					_, e = c.Renew(context.Background(), RenewRequest{"lease", strings.Repeat("a", 64)})
				case "release":
					e = c.Release(context.Background(), "lease")
				}
				refusalCode(t, e, code, status)
				phase := phaseRequest
				if method == "renew" {
					phase = phaseRefresh
				}
				if method == "release" {
					phase = phaseRelease
				}
				state := &statusRecord{phase: phase}
				state.capture(brokerFailure(e, status))
				var diagnostic strings.Builder
				requireStatus(t, classify(state, &diagnostic), status, diagnostic.String())
				if !strings.Contains(diagnostic.String(), code) {
					t.Fatal("typed refusal lost in classification")
				}
			})
		}
	}
}

// Claim: the connection-level exception is limited to three null-ID terminal
// codes, with bounded metadata; ordinary errors cannot bypass correlation.
func TestSocketTerminalRefusal(t *testing.T) {
	for _, code := range []string{"peer_identity_unavailable", "role_not_permitted", "frame_too_large", "lease_owner_unavailable"} {
		t.Run(code, func(t *testing.T) {
			c := clientPeer(t, func(c *net.UnixConn) {
				wire.Write(c, map[string]any{"request_id": nil, "error": wire.Refuse(code)})
				io.Copy(io.Discard, c)
			})
			must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
			_, e := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
			want := code
			if code == "lease_owner_unavailable" {
				want = "credential_injection_unavailable"
			}
			refusalCode(t, e, want, 69)
		})
	}
}

// Claim: cancellation discards a late response and closes the uncertain stream;
// Close also unblocks an active call and callers queued behind it.
func TestSocketCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			reply := make(chan struct{})
			c := clientPeer(t, func(c *net.UnixConn) {
				r := peerRequest(c)
				close(entered)
				<-reply
				wire.Write(c, map[string]any{"request_id": r.ID, "result": helloPayload()})
			})
			must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, e := c.Hello(ctx, HelloRequest{[]int{1}, ProtocolProfile}); done <- e }()
			<-entered
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, e := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
				if e == nil {
					t.Error("queued call accepted")
				}
			}()
			if mode == "cancel" {
				cancel()
			} else {
				c.Close()
			}
			select {
			case e := <-done:
				refusalCode(t, e, "credential_injection_unavailable", 69)
			case <-time.After(time.Second):
				t.Fatal("call did not stop")
			}
			close(reply)
			wg.Wait()
			if _, e := c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile}); e == nil {
				t.Fatal("uncertain stream reused")
			}
		})
	}
}

func leasePayload() map[string]any {
	return map[string]any{"lease_id": "lease", "account": "account", "harness": "codex_cli", "channel": "external-token", "payload": map[string]any{"channel": "external-token", "access_token": "synthetic-material", "chatgpt_account_id": "vendor-account"}, "token_expires_at": "2030-01-01T00:00:00Z", "authorized_until": "2030-01-01T00:00:00Z", "renewable": true}
}

// Claim: every required lease member, including nested payload members, is
// present and non-null; unknown fields and invalid closed values are refused.
// Optional plan_type may be absent, but an explicit null is invalid.
func TestSocketLeaseMembers(t *testing.T) {
	fields := []string{"lease_id", "account", "harness", "channel", "payload", "token_expires_at", "authorized_until", "renewable", "payload.channel", "payload.access_token", "payload.chatgpt_account_id"}
	cases := []string{"valid", "plan", "plan-null", "unknown", "nested-unknown", "time-offset", "time-fraction", "bad-id", "wrong-harness", "wrong-channel", "wrong-payload-channel", "not-renewable", "wrong-account"}
	for _, field := range fields {
		cases = append(cases, "null/"+field, "missing/"+field)
	}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			c := clientPeer(t, func(c *net.UnixConn) {
				r := peerRequest(c)
				wire.Write(c, map[string]any{"request_id": r.ID, "result": helloPayload()})
				r = peerRequest(c)
				l := leasePayload()
				payload := l["payload"].(map[string]any)
				if op, field, ok := strings.Cut(mode, "/"); ok {
					target := l
					if name, sub, nested := strings.Cut(field, "."); nested {
						target = l[name].(map[string]any)
						field = sub
					}
					if op == "null" {
						target[field] = nil
					} else {
						delete(target, field)
					}
				}
				switch mode {
				case "plan":
					payload["plan_type"] = "fixture-plan"
				case "plan-null":
					payload["plan_type"] = nil
				case "unknown":
					l["extra"] = true
				case "nested-unknown":
					payload["extra"] = true
				case "time-offset":
					l["token_expires_at"] = "2030-01-01T00:00:00+00:00"
				case "time-fraction":
					l["authorized_until"] = "2030-01-01T00:00:00.1Z"
				case "bad-id":
					l["lease_id"] = strings.Repeat("x", 129)
				case "wrong-harness":
					l["harness"] = "other"
				case "wrong-channel":
					l["channel"] = "other"
				case "wrong-payload-channel":
					payload["channel"] = "other"
				case "not-renewable":
					l["renewable"] = false
				case "wrong-account":
					l["account"] = "other"
				}
				wire.Write(c, map[string]any{"request_id": r.ID, "result": l})
			})
			clientHello(t, c)
			l, e := c.Request(context.Background(), LeaseRequest{Account: "account"})
			if mode == "valid" || mode == "plan" {
				must(t, e)
				if string(l.Token) != "synthetic-material" {
					t.Fatal("valid material missing")
				}
			} else {
				refusalCode(t, e, "credential_injection_unavailable", 69)
				if len(l.Token) != 0 {
					t.Fatal("invalid material escaped")
				}
			}
			l.erase()
		})
	}
}

// Claim: loss, truncated responses, or the caller's earlier cutoff never return
// material or a release receipt. An adjacent full reply succeeds in each phase;
// renew and release failures have status 75 rather than admission status 69.
func TestSocketLifecycle(t *testing.T) {
	for _, method := range []string{"request", "renew", "release"} {
		for _, mode := range []string{"valid", "loss", "partial", "late", "wrong-result"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				resume := make(chan struct{})
				c := clientPeer(t, func(c *net.UnixConn) {
					r := peerRequest(c)
					wire.Write(c, map[string]any{"request_id": r.ID, "result": helloPayload()})
					r = peerRequest(c)
					if mode == "loss" {
						return
					}
					if mode == "partial" {
						c.Write([]byte{0, 0})
						return
					}
					if mode == "late" {
						<-resume
					}
					var result any = leasePayload()
					if method == "release" {
						result = wire.ReleaseResult{LeaseID: "lease", State: "released"}
					}
					if mode == "wrong-result" {
						if method == "release" {
							result = wire.ReleaseResult{LeaseID: "lease", State: "active"}
						} else {
							l := leasePayload()
							l["lease_id"] = "other"
							if method == "request" {
								l["account"] = "other"
							}
							result = l
						}
					}
					wire.Write(c, map[string]any{"request_id": r.ID, "result": result})
				})
				clientHello(t, c)
				ctx := context.Background()
				cancel := func() {}
				if mode == "late" {
					ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				}
				defer cancel()
				var l Lease
				var e error
				status := 75
				code := "lease_owner_unavailable"
				start := time.Now()
				switch method {
				case "request":
					l, e = c.Request(ctx, LeaseRequest{Account: "account"})
					status = 69
					code = "credential_injection_unavailable"
				case "renew":
					l, e = c.Renew(ctx, RenewRequest{"lease", strings.Repeat("a", 64)})
					code = "renew_failed"
				case "release":
					e = c.Release(ctx, "lease")
				}
				close(resume)
				if method == "renew" && mode == "late" {
					code = "renew_timeout"
				}
				if mode == "valid" {
					must(t, e)
				} else {
					refusalCode(t, e, code, status)
					if len(l.Token) > 0 {
						t.Fatal("material returned after failed exchange")
					}
				}
				if mode == "late" && time.Since(start) > time.Second {
					t.Fatal("earlier caller cutoff not honored")
				}
				l.erase()
			})
		}
	}
}

// Claim: the client writes no frame until peer verification and successful hello.
func TestSocketOrdering(t *testing.T) {
	for _, mode := range []string{"unverified", "unnegotiated"} {
		t.Run(mode, func(t *testing.T) {
			read := make(chan int, 1)
			c := clientPeer(t, func(c *net.UnixConn) { var b [1]byte; n, _ := c.Read(b[:]); read <- n })
			if mode == "unnegotiated" {
				must(t, c.VerifyServer(context.Background(), uint32(os.Geteuid())))
			}
			var e error
			if mode == "unverified" {
				_, e = c.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
			} else {
				_, e = c.Request(context.Background(), LeaseRequest{})
			}
			refusalCode(t, e, "credential_injection_unavailable", 69)
			if <-read != 0 {
				t.Fatal("frame sent before protocol admission")
			}
		})
	}
}

// Claim: concurrent callers are serialized with distinct request IDs and exact
// correlation; a released receipt remains reusable on the same connection.
func TestSocketConcurrentIDs(t *testing.T) {
	c := clientPeer(t, func(c *net.UnixConn) {
		seen := map[string]bool{}
		for i := 0; i < 21; i++ {
			r := peerRequest(c)
			if r.ID == "" {
				return
			}
			if seen[r.ID] {
				t.Error("request ID reused")
			}
			seen[r.ID] = true
			var result any = wire.ReleaseResult{LeaseID: "lease", State: "released"}
			if i == 0 {
				result = helloPayload()
			}
			wire.Write(c, map[string]any{"request_id": r.ID, "result": result})
		}
	})
	clientHello(t, c)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Release(context.Background(), "lease") != nil {
				t.Error("concurrent receipt failed")
			}
		}()
	}
	wg.Wait()
}

// Claim: on this real socket, an unanswered renew has the client's 8.5-second
// transport cutoff even with a later parent deadline; no material is delivered
// and the connection closes. This is a clock/transport probe, not an I/O latency
// guarantee for an arbitrarily stalled host.
func TestSocketRenewCutoff(t *testing.T) {
	c := clientPeer(t, func(c *net.UnixConn) {
		r := peerRequest(c)
		wire.Write(c, map[string]any{"request_id": r.ID, "result": helloPayload()})
		if peerRequest(c).Method != "lease.renew" {
			t.Error("renew request absent")
		}
		io.Copy(io.Discard, c)
	})
	clientHello(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	start := time.Now()
	l, e := c.Renew(ctx, RenewRequest{"lease", strings.Repeat("a", 64)})
	refusalCode(t, e, "renew_timeout", 75)
	if ctx.Err() != nil || len(l.Token) != 0 || time.Since(start) < 8*time.Second || time.Since(start) > 10*time.Second {
		t.Fatal("renew cutoff or material invariant failed")
	}
}
