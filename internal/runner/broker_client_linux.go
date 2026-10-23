//go:build linux

package runner

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// SocketClient serializes exchanges on one fresh close-on-exec Unix connection.
// A failed exchange closes the stream: partial or late replies cannot be reused.
// The gate and each socket operation share the caller's bounded call context.
// No token material is retained between calls.
type SocketClient struct {
	conn            *net.UnixConn
	gate            chan struct{}
	closed          chan struct{}
	once            sync.Once
	verified, hello bool   // protected by gate
	next            uint64 // monotonic IDs, protected by gate
}

func DialBroker(ctx context.Context, path string) (*SocketClient, error) {
	d := net.Dialer{}
	c, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return nil, refuse("lease_owner_unavailable", 69)
	}
	return &SocketClient{conn: c.(*net.UnixConn), gate: make(chan struct{}, 1), closed: make(chan struct{})}, nil
}
func (c *SocketClient) Close() error {
	c.once.Do(func() { close(c.closed); _ = c.conn.Close() })
	return nil
}
func (c *SocketClient) acquire(ctx context.Context) bool {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return false
	case <-c.closed:
		return false
	}
	select {
	case <-c.closed:
		<-c.gate
		return false
	default:
	}
	if ctx.Err() != nil {
		<-c.gate
		return false
	}
	return true
}
func (c *SocketClient) VerifyServer(ctx context.Context, expected uint32) error {
	if !c.acquire(ctx) {
		return refuse("server_identity_mismatch", 69)
	}
	defer func() { <-c.gate }()
	raw, e := c.conn.SyscallConn()
	var uid uint32
	var observed error
	if e == nil {
		e = raw.Control(func(fd uintptr) {
			var cred *syscall.Ucred
			cred, observed = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if observed == nil {
				uid = cred.Uid
			}
		})
	}
	if e != nil || observed != nil || uid != expected || ctx.Err() != nil {
		c.Close()
		return refuse("server_identity_mismatch", 69)
	}
	c.verified = true
	return nil
}

func profileCode(code string) bool {
	switch code {
	case "peer_identity_unavailable", "server_identity_mismatch", "role_not_permitted", "frame_too_large", "version_unsupported", "request_deadline_exceeded", "account_exists", "account_unknown", "account_duplicate", "account_store_keyring_refused", "enrol_material_invalid", "lease_not_authorised", "lease_account_unknown", "lease_harness_mismatch", "lease_account_revoked", "lease_reauth_required", "lease_owner_unavailable", "lease_channel_unsupported", "lease_harness_unqualified", "lease_binding_mismatch", "lease_network_enforcement_unavailable", "lease_not_owner", "lease_not_active", "renew_not_current", "renew_timeout", "renew_failed", "external_token_init_failed", "credential_source_conflict", "credential_injection_unavailable":
		return true
	}
	return false
}

type brokerReply struct {
	ID     json.RawMessage `json:"request_id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// exchange keeps the gate through typed result validation, and joins the
// cancellation callback before permitting any following exchange.
func (c *SocketClient) exchange(parent context.Context, method string, params any, limit time.Duration, status int, decode func([]byte) bool) error {
	failure := "credential_injection_unavailable"
	if method == "lease.renew" {
		failure = "renew_failed"
	}
	if method == "lease.release" {
		failure = "lease_owner_unavailable"
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	failureCode := func() string {
		until, _ := ctx.Deadline()
		if method == "lease.renew" && (ctx.Err() == context.DeadlineExceeded || !time.Now().Before(until)) {
			return "renew_timeout"
		}
		return failure
	}
	bad := func() error { c.Close(); return refuse(failureCode(), status) }
	if !c.acquire(ctx) {
		return refuse(failureCode(), status)
	}
	defer func() { <-c.gate }()
	if !c.verified || method != "hello" && !c.hello || method == "hello" && c.hello {
		return bad()
	}
	until, _ := ctx.Deadline()
	if c.conn.SetDeadline(until) != nil {
		return bad()
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	if ctx.Err() != nil {
		return bad()
	}
	c.next++
	if c.next == 0 {
		return bad()
	}
	id := strconv.FormatUint(c.next, 10)
	b, e := wire.Encode(params)
	if e != nil {
		return bad()
	}
	// A peer may queue an accept-time terminal refusal and close before our
	// write. Read exactly one frame even after a failed/short write, using the
	// same deadline and wire size bound. Only the terminal exception may then
	// be retained; the stream is always closed and no request is retried.
	writeFailed := wire.Write(c.conn, wire.Request{Method: method, Params: b, ID: id}) != nil
	if writeFailed {
		defer c.Close()
	}
	raw, e := wire.Read(c.conn)
	defer clear(raw)
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return bad()
	}
	var reply brokerReply
	if wire.Decode(raw, &reply) != nil {
		return bad()
	}
	fields, e := wire.Parse(raw)
	if e != nil || len(fields) != 2 {
		return bad()
	}
	_, resultPresent := fields["result"]
	_, errorPresent := fields["error"]
	if resultPresent == errorPresent {
		return bad()
	}
	var replyID string
	nullID := string(reply.ID) == "null"
	if !nullID && (writeFailed || json.Unmarshal(reply.ID, &replyID) != nil || replyID != id) {
		return bad()
	}
	if errorPresent {
		var r wire.Error
		if wire.Decode(reply.Error, &r) != nil || !profileCode(r.Code) || r.Message != "request refused" || len(r.Details) != 0 {
			return bad()
		}
		if nullID {
			if len(raw) > 512 || r.Code != "peer_identity_unavailable" && r.Code != "role_not_permitted" && r.Code != "frame_too_large" {
				return bad()
			}
			c.Close()
		}
		return refuse(r.Code, status)
	}
	if nullID || !decode(reply.Result) || ctx.Err() != nil || !time.Now().Before(until) {
		return bad()
	}
	return nil
}

func (c *SocketClient) Hello(ctx context.Context, r HelloRequest) (HelloResult, error) {
	var out HelloResult
	e := c.exchange(ctx, "hello", wire.Hello{Versions: r.Versions, Profile: r.Profile}, 2*time.Second, 69, func(b []byte) bool {
		var h struct {
			Version   int    `json:"version"`
			Profile   string `json:"profile"`
			Principal struct {
				UID uint32 `json:"uid"`
			} `json:"principal"`
			Generation uint64 `json:"policy_generation"`
		}
		if wire.Decode(b, &h) != nil || h.Version != 1 || h.Profile != ProtocolProfile || h.Principal.UID != uint32(os.Geteuid()) || h.Generation == 0 {
			return false
		}
		out = HelloResult{h.Version, h.Profile, h.Principal.UID, h.Generation}
		c.hello = true
		return true
	})
	return out, e
}
func (c *SocketClient) Request(ctx context.Context, r LeaseRequest) (Lease, error) {
	b := r.CredentialBinding
	request := wire.LeaseRequest{Harness: r.Harness, Profile: r.Profile, Account: r.Account, Channel: r.Channel, LaunchID: r.LaunchID, Network: json.RawMessage("null"), Binding: wire.Binding{Digest: b.Digest, Harness: b.Harness, Profile: b.Profile, Account: b.Account, Channel: b.Channel, Endpoint: b.Endpoint, ExecutableSHA256: b.ExecutableSHA256, PolicyGeneration: b.PolicyGeneration}, Executor: wire.Executor{Capabilities: r.Executor.Capabilities, Version: r.Executor.Version}}
	if r.Network != nil {
		return Lease{}, refuse("lease_network_enforcement_unavailable", 69)
	}
	return c.material(ctx, "lease.request", request, 30*time.Second, 69, func(l Lease) bool { return l.Account == r.Account })
}
func (c *SocketClient) Renew(ctx context.Context, r RenewRequest) (Lease, error) {
	if !wire.ASCII(r.LeaseID, 128) || !isSHA256(r.RejectedSHA256) {
		return Lease{}, refuse("renew_failed", 75)
	}
	// The runner's callback cutoff is 8.5 seconds, including transport. The
	// daemon retains its independent eight-second budget from request arrival.
	return c.material(ctx, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: r.RejectedSHA256}, 8500*time.Millisecond, 75, func(l Lease) bool { return l.ID == r.LeaseID })
}
func wireTime(value string) (time.Time, bool) {
	t, e := time.Parse("2006-01-02T15:04:05Z", value)
	return t, e == nil && t.Format("2006-01-02T15:04:05Z") == value
}
func (c *SocketClient) material(ctx context.Context, method string, params any, limit time.Duration, status int, match func(Lease) bool) (Lease, error) {
	var out Lease
	e := c.exchange(ctx, method, params, limit, status, func(b []byte) bool {
		var l wire.LeaseResult
		if wire.Decode(b, &l) != nil {
			return false
		}
		expiry, ok := wireTime(l.TokenExpiresAt)
		if !ok {
			return false
		}
		until, ok := wireTime(l.AuthorizedUntil)
		if !ok {
			return false
		}
		if !wire.ASCII(l.LeaseID, 128) || l.Account == "" || l.Harness != "codex_cli" || l.Channel != "external-token" || l.Payload.Channel != "external-token" || l.Payload.AccessToken == "" || l.Payload.AccountID == "" || !l.Renewable {
			return false
		}
		out = Lease{ID: l.LeaseID, Account: l.Account, Harness: l.Harness, Channel: l.Channel, ChatGPTAccountID: l.Payload.AccountID, PlanType: l.Payload.PlanType, Token: []byte(l.Payload.AccessToken), TokenExpiresAt: expiry, AuthorizedUntil: until, Renewable: l.Renewable}
		return match(out)
	})
	if e != nil {
		out.erase()
		return Lease{}, e
	}
	return out, nil
}
func (c *SocketClient) Release(ctx context.Context, id string) error {
	if !wire.ASCII(id, 128) {
		return refuse("lease_owner_unavailable", 75)
	}
	return c.exchange(ctx, "lease.release", wire.Release{LeaseID: id}, 2*time.Second, 75, func(b []byte) bool {
		var r wire.ReleaseResult
		return wire.Decode(b, &r) == nil && r.LeaseID == id && r.State == "released"
	})
}
