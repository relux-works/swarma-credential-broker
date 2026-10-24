package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type response struct {
	ID     *string         `json:"request_id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wire.Error     `json:"error,omitempty"`
}

func start(t *testing.T, e *testutil.Env, mutate func(*Server)) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "s-")
	if err != nil {
		t.Fatal("socket directory unavailable")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(path)
	if err != nil {
		t.Fatal("listener unavailable")
	}
	s := New(e.Manager)
	if mutate != nil {
		mutate(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); stopped <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		testutil.StopServer(func() { cancel(); s.Close() }, serveDone, s.Wait)
		if <-stopped != nil {
			t.Error("serve failed")
		}
	})
	return path
}
func dial(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("connect failed")
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}
func request(t *testing.T, c *net.UnixConn, method, id string, params any) response {
	t.Helper()
	b, _ := wire.Encode(params)
	if wire.Write(c, wire.Request{Method: method, ID: id, Params: b}) != nil {
		t.Fatal("write failed")
	}
	return reply(t, c)
}
func reply(t *testing.T, c *net.UnixConn) response {
	t.Helper()
	b, err := wire.Read(c)
	if err != nil {
		t.Fatal("response unavailable")
	}
	var r response
	if wire.Decode(b, &r) != nil {
		t.Fatal("invalid response")
	}
	return r
}
func hello(t *testing.T, c *net.UnixConn) {
	t.Helper()
	if r := request(t, c, "hello", "hello", wire.Hello{Versions: []int{1}, Profile: wire.Profile}); r.Error != nil {
		t.Fatal("negotiation refused")
	}
}
func closed(t *testing.T, c *net.UnixConn) {
	t.Helper()
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)) {
		t.Fatal("connection not closed without a frame")
	}
}

// Claim: every transport vector reaches the Unix listener; faulted peer probing is a model, while valid hello uses real SO_PEERCRED.
func TestTransportVectors(t *testing.T) {
	for _, v := range testutil.Vectors(t, "transport") {
		t.Run(v.ID, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			var mutate func(*Server)
			if v.ID == "peer-identity-unavailable" {
				mutate = func(s *Server) {
					s.peer = func(*net.UnixConn) (uint32, error) { return 0, errors.New("probe unavailable") }
				}
			}
			path := start(t, e, mutate)
			c := dial(t, path)
			switch v.Setup["handshake"] {
			case "connect_only":
			case "header_only":
				var h [4]byte
				binary.BigEndian.PutUint32(h[:], uint32(v.Setup["advertised_payload_length"].(float64)))
				c.Write(h[:])
			case "partial_header":
				b, _ := hex.DecodeString(v.Setup["header_hex"].(string))
				c.Write(b)
				c.CloseWrite()
			case "raw_first_frame":
				b := []byte(v.Setup["raw_payload"].(string))
				var h [4]byte
				binary.BigEndian.PutUint32(h[:], uint32(len(b)))
				c.Write(append(h[:], b...))
			default:
				if v.Setup["handshake"] == "hello_then_request" {
					hello(t, c)
				}
				b, _ := wire.Encode(v.Request)
				if _, err := wire.Parse(b); err != nil {
					t.Fatal("bad vector")
				}
				var frame bytes.Buffer
				wire.Write(&frame, v.Request)
				c.Write(frame.Bytes())
			}
			if count, ok := v.Expect["response_frames"].(float64); ok && count == 0 {
				closed(t, c)
			} else {
				r := reply(t, c)
				if code, ok := v.Expect["error_code"].(string); ok {
					if r.Error == nil || r.Error.Code != code || r.Result != nil {
						t.Fatal("wrong transport refusal")
					}
					if _, exists := v.Expect["request_id"]; exists && r.ID != nil {
						t.Fatal("pre-request error correlated untrusted input")
					}
					if len(r.Error.Details) != 0 {
						t.Fatal("unexpected error details")
					}
					closed(t, c)
				} else {
					expected := v.Expect["result"].(map[string]any)
					if principal, ok := expected["principal"].(map[string]any); ok {
						principal["uid"] = e.UID
					}
					b, _ := wire.Encode(expected)
					if r.Error != nil || !bytes.Equal(b, r.Result) {
						t.Fatal("wrong transport result")
					}
				}
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("transport started refresh")
			}
			e.NoLeaseRecords(t)
			p, w := e.Manager.Stats(e.Account)
			if p != 0 || w != 0 {
				t.Fatal("transport retained operation")
			}
		})
	}
}

// Claim: malformed/noncanonical/unknown/prehello requests close without reflected input or owner effects; a valid same-kernel-UID lifecycle succeeds.
func TestStrictProtocol(t *testing.T) {
	cases := []struct {
		name, payload string
		negotiated    bool
	}{
		{"whitespace", `{ "method":"hello","params":{},"request_id":"a"}`, false},
		{"duplicate", `{"method":"hello","method":"hello","params":{},"request_id":"a"}`, false},
		{"prehello", `{"method":"status","params":{},"request_id":"a"}`, false},
		{"unknown", `{"method":"unknown","params":{},"request_id":"a"}`, true},
		{"unknown-field", `{"extra":0,"method":"status","params":{},"request_id":"a"}`, true},
		{"unknown-param", `{"method":"status","params":{"extra":0},"request_id":"a"}`, true},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			c := dial(t, start(t, e, nil))
			if v.negotiated {
				hello(t, c)
			}
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], uint32(len(v.payload)))
			c.Write(append(h[:], v.payload...))
			closed(t, c)
			e.NoLeaseRecords(t)
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("invalid request refreshed")
			}
		})
	}
}

// Claim: same-UID kernel admission issues independent leases; request/renew/status/release never write raw canary tokens, and status excludes hashes too; this test does not capture process logs.
func TestKernelAdmissionAndCanaryLifecycle(t *testing.T) {
	var root string
	var tokens []string
	e := testutil.NewFault(t, lease.Options{}, nil, func(string) error {
		if root == "" {
			return nil
		}
		return scanMaterialFiles(root, tokens)
	})
	root = e.Root
	nextToken := testutil.Token()
	tokens = []string{e.Owner.View().AccessToken, nextToken}
	e.Owner.Next(nextToken)
	var statusBytes bytes.Buffer
	path := start(t, e, nil)
	c := dial(t, path)
	if uid, err := PeerUID(c); err != nil || uid != e.UID {
		t.Fatal("kernel server identity mismatch")
	}
	hello(t, c)
	r := request(t, c, "lease.request", "issue", e.Request)
	var first wire.LeaseResult
	if r.Error != nil || wire.Decode(r.Result, &first) != nil {
		t.Fatal("kernel lease refused")
	}
	next := request(t, c, "lease.renew", "renew", wire.Renew{LeaseID: first.LeaseID, RejectedSHA256: lease.Digest(first.Payload.AccessToken)})
	var second wire.LeaseResult
	if next.Error != nil || wire.Decode(next.Result, &second) != nil || second.Payload.AccessToken == first.Payload.AccessToken {
		t.Fatal("kernel renew failed")
	}
	scan := func() {
		t.Helper()
		if scanMaterialFiles(e.Root, tokens) != nil {
			t.Fatal("canary file scan failed")
		}
	}
	scan()
	status := request(t, c, "status", "status", struct{}{})
	if status.Error != nil {
		t.Fatal("status refused")
	}
	statusBytes.Write(status.Result)
	if materialLeak(statusBytes.Bytes(), tokens, false) {
		t.Fatal("status leaked material")
	}
	released := request(t, c, "lease.release", "release", wire.Release{LeaseID: first.LeaseID})
	if released.Error != nil {
		t.Fatal("release refused")
	}
	denied := request(t, c, "lease.renew", "ended", wire.Renew{LeaseID: first.LeaseID, RejectedSHA256: lease.Digest(second.Payload.AccessToken)})
	if denied.Error == nil || denied.Error.Code != "lease_not_active" || denied.Result != nil {
		t.Fatal("ended lease delivered")
	}
	scan()
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("unexpected writer")
	}
}

// Claim: modeled denied UID/probe failure are refused before any client bytes; this does not substitute for the separately configured foreign-account gate.
func TestPreRequestIdentityRefusal(t *testing.T) {
	for _, v := range []struct {
		code  string
		probe func(*net.UnixConn) (uint32, error)
	}{{"role_not_permitted", func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()) + 1, nil }}, {"peer_identity_unavailable", func(*net.UnixConn) (uint32, error) { return 0, io.ErrUnexpectedEOF }}} {
		t.Run(v.code, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			c := dial(t, start(t, e, func(s *Server) { s.peer = v.probe }))
			r := reply(t, c)
			if r.ID != nil || r.Error == nil || r.Error.Code != v.code || r.Result != nil {
				t.Fatal("invalid pre-request refusal")
			}
			closed(t, c)
		})
	}
}

// Claim: a timed-out socket renew has exactly one correlated error and no late success; a later status remains usable.
func TestSocketDeadline(t *testing.T) {
	e := testutil.New(t, lease.Options{RenewTimeout: 30 * time.Millisecond})
	c := dial(t, start(t, e, nil))
	hello(t, c)
	r := e.Issue(t)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	out := request(t, c, "lease.renew", "late", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
	if out.ID == nil || *out.ID != "late" || out.Error == nil || out.Error.Code != "renew_timeout" || out.Result != nil {
		t.Fatal("late renew did not refuse")
	}
	close(gate)
	testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == 0 })
	out = request(t, c, "status", "after", struct{}{})
	if out.ID == nil || *out.ID != "after" || out.Error != nil {
		t.Fatal("extra late response or broken connection")
	}
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var b [1]byte
	_, err := c.Read(b[:])
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal("unexpected additional response")
	}
}

// Claim: status authenticates the kernel server before sending and valid same-UID status is scoped.
func TestStatusClient(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	path := start(t, e, nil)
	if _, err := Status(context.Background(), path, e.UID+1); lease.ErrorCode(err) != "server_identity_mismatch" {
		t.Fatal("wrong server accepted")
	}
	s, err := Status(context.Background(), path, e.UID)
	if err != nil || len(s.Accounts) != 1 || s.Accounts[0].Account != e.Account {
		t.Fatal("valid status unavailable")
	}
}

type slowDelivery struct {
	owner.Owner
	mu    sync.Mutex
	n     int
	block bool
}

func (o *slowDelivery) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	o.mu.Lock()
	o.n++
	block := o.block && o.n >= 3
	o.mu.Unlock()
	if block {
		<-ctx.Done()
		return owner.Snapshot{}, ctx.Err()
	}
	return o.Owner.Snapshot(ctx, label)
}

// Claim: even a slow final owner recheck shares the renew arrival budget and can only produce one timeout, followed by a usable status control.
func TestFinalDeliveryDeadline(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	e.Manager.Close()
	adapter := &slowDelivery{Owner: e.Owner, block: true}
	m, err := lease.New(e.Policy, e.Store, adapter, lease.Options{Now: func() time.Time { return e.Now }, RenewTimeout: 300 * time.Millisecond}, false)
	if err != nil {
		t.Fatal("replacement fixture failed")
	}
	e.Manager = m
	t.Cleanup(m.Close)
	r := e.Issue(t)
	c := dial(t, start(t, e, nil))
	hello(t, c)
	out := request(t, c, "lease.renew", "final", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
	if out.Error == nil || out.Error.Code != "renew_timeout" || out.Result != nil {
		t.Fatal("final gate escaped deadline")
	}
	adapter.mu.Lock()
	adapter.block = false
	adapter.mu.Unlock()
	if control := request(t, c, "status", "control", struct{}{}); control.Error != nil || control.ID == nil || *control.ID != "control" {
		t.Fatal("late extra response or status failed")
	}
}

// Claim: the canary predicate catches a bounded known leak and permits only the protected digest exception; the scanner is not an accept-all gate.
func TestCanaryScannerControl(t *testing.T) {
	token := testutil.Token()
	tokens := []string{token}
	if !materialLeak([]byte(token), tokens, true) || !materialLeak([]byte(lease.Digest(token)), tokens, false) || materialLeak([]byte(lease.Digest(token)), tokens, true) || materialLeak([]byte("metadata only"), tokens, false) {
		t.Fatal("canary control failed")
	}
}
func materialLeak(b []byte, tokens []string, metadata bool) bool {
	for _, token := range tokens {
		if bytes.Contains(b, []byte(token[:12])) || !metadata && bytes.Contains(b, []byte(lease.Digest(token)[:12])) {
			return true
		}
	}
	return false
}
func scanMaterialFiles(root string, tokens []string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		protected := strings.HasPrefix(d.Name(), "lease-") || strings.HasPrefix(d.Name(), "pending-lease-")
		if protected {
			info, err := d.Info()
			if err != nil || info.Mode() != 0600 {
				return errors.New("unprotected metadata")
			}
		}
		if materialLeak(b, tokens, protected) {
			return errors.New("material leak")
		}
		return nil
	})
}

// Claim: existing paths are never adopted and shutdown does not unlink a replacement socket-path entry.
func TestSocketPathOwnership(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "p-")
	if err != nil {
		t.Fatal("fixture path failed")
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(path)
	if err != nil {
		t.Fatal("listen failed")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("existing socket adopted")
	}
	srv := New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); stop <- srv.Serve(ctx, l) }()
	var stopOnce sync.Once
	stopServer := func() {
		stopOnce.Do(func() { testutil.StopServer(func() { cancel(); srv.Close() }, serveDone, srv.Wait); <-stop })
	}
	defer stopServer()
	c := dial(t, path)
	hello(t, c)
	if os.Rename(path, path+"-old") != nil || os.WriteFile(path, []byte("replacement"), 0600) != nil {
		t.Fatal("fixture replacement failed")
	}
	stopServer()
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatal("shutdown removed replacement")
	}
}

// Claim: a real socket disconnect removes its response waiter; resolving the accepted attempt does not start a retry and reconnect returns the current token.
func TestDisconnectedWaiter(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	r := e.Issue(t)
	path := start(t, e, nil)
	c := dial(t, path)
	hello(t, c)
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	b, _ := wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
	if wire.Write(c, wire.Request{Method: "lease.renew", ID: "disconnect", Params: b}) != nil {
		t.Fatal("renew write failed")
	}
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 1 && w == 1 })
	c.Close()
	testutil.Await(t, func() bool { _, w := e.Manager.Stats(e.Account); return w == 0 })
	close(gate)
	testutil.Await(t, func() bool { p, _ := e.Manager.Stats(e.Account); return p == 0 })
	fresh := dial(t, path)
	hello(t, fresh)
	out := request(t, fresh, "lease.renew", "retry", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
	if out.Error != nil {
		t.Fatal("reconnect failed")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("disconnect caused retry")
	}
}

// Claim: admission peer vectors drive negotiation/issuance with real same-UID SO_PEERCRED; the denied case is explicitly a model, with foreign-process qualification separate.
func TestAdmissionPeerVectors(t *testing.T) {
	for _, v := range testutil.Vectors(t, "admission") {
		if v.ID != "peer-allowed" && v.ID != "peer-denied" {
			continue
		}
		name := v.ID
		if v.ID == "peer-denied" {
			name += "-model"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			var mutate func(*Server)
			if v.ID == "peer-denied" {
				mutate = func(s *Server) { s.peer = func(*net.UnixConn) (uint32, error) { return e.UID + 1, nil } }
			}
			c := dial(t, start(t, e, mutate))
			if v.ID == "peer-denied" {
				r := reply(t, c)
				if r.ID != nil || r.Error == nil || r.Error.Code != v.Expect["error_code"] {
					t.Fatal("peer vector refusal mismatch")
				}
				closed(t, c)
			} else {
				hello(t, c)
				params := v.Request["params"].(map[string]any)
				params["credential_binding"] = e.Policy.Binding(e.UID, e.Policy.Accounts[0], e.Request.Profile)
				out := request(t, c, v.Request["method"].(string), v.Request["request_id"].(string), params)
				var result wire.LeaseResult
				if out.Error != nil || wire.Decode(out.Result, &result) != nil || result.Payload.AccessToken != e.Owner.View().AccessToken {
					t.Fatal("allowed peer vector failed")
				}
				if request(t, c, "lease.release", "release", wire.Release{LeaseID: result.LeaseID}).Error != nil {
					t.Fatal("peer fixture release failed")
				}
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("peer vector started refresh")
			}
		})
	}
}
