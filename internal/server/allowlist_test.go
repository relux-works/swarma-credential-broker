package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/brokerclient"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func observerFixture(t *testing.T, options lease.Options) (*testutil.Env, uint32) {
	t.Helper()
	observer := uint32(os.Geteuid()) + 1
	e := testutil.NewPolicy(t, options, func(p *policy.Policy) { p.ObserverUIDs = []uint32{observer} })
	return e, observer
}
func observation(e *testutil.Env) wire.AllowlistRequest {
	return wire.AllowlistRequest{TargetUID: e.UID, Account: e.Account, Profile: e.Request.Profile, Harness: e.Request.Harness, Channel: e.Request.Channel, Binding: e.Request.Binding, ExpectedGeneration: e.Policy.Generation}
}
func observerPath(t *testing.T, e *testutil.Env, uid uint32) string {
	t.Helper()
	// Model the caller UID only; the public client still verifies the real server
	// SO_PEERCRED. No host account switch or cross-UID qualification is claimed.
	return start(t, e, func(s *Server) { s.peer = func(*net.UnixConn) (uint32, error) { return uid, nil } })
}

// The model caller UID differs from this test process's UID. Use the real wire
// server entry, rather than weakening the public client's hello-principal check.
// Public client decoding/identity/cancellation is tested independently.
type observerRPC struct {
	t *testing.T
	c *net.UnixConn
}

func dialObserverRPC(t *testing.T, path string, _ uint32) (*observerRPC, error) {
	c := dial(t, path)
	b, _ := wire.Encode(wire.Hello{Versions: []int{1}, Profile: wire.Profile})
	_ = wire.Write(c, wire.Request{Method: "hello", ID: "hello", Params: b})
	raw, err := wire.Read(c)
	var r response
	if err != nil || wire.Decode(raw, &r) != nil {
		return nil, &brokerclient.Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	if r.Error != nil {
		return nil, &brokerclient.Refusal{Code: r.Error.Code, Status: 69}
	}
	return &observerRPC{t, c}, nil
}
func (c *observerRPC) Close() error { return c.c.Close() }
func (c *observerRPC) Check(_ context.Context, r wire.AllowlistRequest) (wire.AllowlistResult, error) {
	b, _ := wire.Encode(r)
	if wire.Write(c.c, wire.Request{Method: "allowlist.check", ID: "check", Params: b}) != nil {
		return wire.AllowlistResult{}, &brokerclient.Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	raw, err := wire.Read(c.c)
	if err != nil {
		return wire.AllowlistResult{}, &brokerclient.Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	var reply response
	if wire.Decode(raw, &reply) != nil {
		return wire.AllowlistResult{}, &brokerclient.Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	if reply.Error != nil {
		return wire.AllowlistResult{}, &brokerclient.Refusal{Code: reply.Error.Code, Status: 69}
	}
	var result wire.AllowlistResult
	if wire.Decode(reply.Result, &result) != nil {
		return wire.AllowlistResult{}, &brokerclient.Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	return result, nil
}
func refusedObservation(t *testing.T, result brokerclient.AllowlistResult, err error, code string) {
	t.Helper()
	var refusal *brokerclient.Refusal
	if !errors.As(err, &refusal) || refusal.Code != code || result != (brokerclient.AllowlistResult{}) {
		t.Fatalf("not a closed refusal: %T, want %s", err, code)
	}
}

// Claim: the real socket/client entry returns exact static metadata only, while
// an unchanged synthetic worker can still acquire/renew/release its own lease.
func TestAllowlistExactAndWorkerControl(t *testing.T) {
	e, observer := observerFixture(t, lease.Options{})
	path := observerPath(t, e, observer)
	c, err := dialObserverRPC(t, path, e.UID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := observation(e)
	got, err := c.Check(context.Background(), r)
	if err != nil || got.Tuple != r || got.Generation != e.Policy.Generation || got.Decision != "allow" {
		t.Fatal("exact observation missing")
	}
	e.NoLeaseRecords(t)
	if calls, _ := e.Owner.Counts(); calls != 0 {
		t.Fatal("observation refreshed")
	}
	raw, _ := wire.Encode(got)
	if bytes.Contains(raw, []byte(e.Owner.View().AccessToken)) || bytes.Contains(raw, []byte("access_token")) || bytes.Contains(raw, []byte("lease_id")) {
		t.Fatal("observer material disclosure")
	}
	worker, err := brokerclient.DialWorker(context.Background(), start(t, e, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if err = worker.VerifyServer(context.Background(), e.UID); err != nil {
		t.Fatal(err)
	}
	if _, err = worker.Hello(context.Background(), brokerclient.HelloRequest{Versions: []int{1}, Profile: brokerclient.ProtocolProfile}); err != nil {
		t.Fatal(err)
	}
	l, err := worker.Request(context.Background(), brokerclient.LeaseRequest{Harness: r.Harness, Profile: r.Profile, Account: r.Account, Channel: r.Channel, CredentialBinding: r.Binding, LaunchID: "synthetic-launch", Executor: brokerclient.Executor{Capabilities: []string{"credential-injection/1"}, Version: "synthetic"}})
	if err != nil || len(l.Token) == 0 {
		t.Fatal("worker lease control failed")
	}
	renewed, err := worker.Renew(context.Background(), brokerclient.RenewRequest{LeaseID: l.ID, RejectedSHA256: lease.Digest(string(l.Token))})
	if err != nil || renewed.ID != l.ID {
		t.Fatal("worker renew control failed")
	}
	renewed.Erase()
	retained := l.Token
	l.Erase()
	if len(l.Token) != 0 || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("caller erase failed")
	}
	if err = worker.Release(context.Background(), l.ID); err != nil {
		t.Fatal("worker release failed")
	}
}

// Claim: every supplied tuple member, including every binding member, is checked;
// all denials leave no lease/refresh effect. Adjacent exact observation is valid.
func TestAllowlistTupleRefusals(t *testing.T) {
	e, observer := observerFixture(t, lease.Options{})
	c, err := dialObserverRPC(t, observerPath(t, e, observer), e.UID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, field := range []string{"TargetUID", "Account", "Profile", "Harness", "Channel", "ExpectedGeneration", "Binding.Digest", "Binding.Harness", "Binding.Profile", "Binding.Account", "Binding.Channel", "Binding.Endpoint", "Binding.ExecutableSHA256", "Binding.PolicyGeneration"} {
		t.Run(field, func(t *testing.T) {
			r := observation(e)
			v := reflect.ValueOf(&r).Elem()
			name := field
			if len(field) > 8 && field[:8] == "Binding." {
				v = v.FieldByName("Binding")
				name = field[8:]
			}
			f := v.FieldByName(name)
			switch f.Kind() {
			case reflect.String:
				f.SetString(f.String() + "x")
			default:
				f.SetUint(f.Uint() + 1)
			}
			got, err := c.Check(context.Background(), r)
			code := "allowlist_tuple_mismatch"
			if field == "ExpectedGeneration" {
				code = "allowlist_generation_mismatch"
			}
			refusedObservation(t, got, err, code)
			e.NoLeaseRecords(t)
		})
	}
	if _, err := c.Check(context.Background(), observation(e)); err != nil {
		t.Fatal("positive neighbor refused")
	}
	if calls, _ := e.Owner.Counts(); calls != 0 {
		t.Fatal("refusal refreshed")
	}
}

// Claim: lease request/renew/release reject an observer before lease lookup or
// owner work, even for a known valid worker ID; existing records remain exact.
func TestAllowlistObserverLeaseExclusion(t *testing.T) {
	e, observer := observerFixture(t, lease.Options{})
	l := e.Issue(t)
	disk, err := e.Store.Account(e.Account, false)
	if err != nil {
		t.Fatal(err)
	}
	before, err := disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	path := observerPath(t, e, observer)
	for _, tc := range []struct {
		method string
		params any
	}{{"lease.request", e.Request}, {"lease.renew", wire.Renew{LeaseID: l.LeaseID, RejectedSHA256: lease.Digest(l.Payload.AccessToken)}}, {"lease.release", wire.Release{LeaseID: l.LeaseID}}} {
		t.Run(tc.method, func(t *testing.T) {
			c := dial(t, path)
			hello(t, c)
			r := request(t, c, tc.method, "forbidden", tc.params)
			if r.Error == nil || r.Error.Code != "role_not_permitted" || r.Result != nil {
				t.Fatal("observer lease operation admitted")
			}
			raw, _ := wire.Encode(r)
			if bytes.Contains(raw, []byte(l.Payload.AccessToken)) {
				t.Fatal("refusal leaked material")
			}
		})
		out := e.Manager.Call(context.Background(), observer, tc.method, tc.params, time.Now())
		if lease.ErrorCode(out.Err) != "role_not_permitted" || out.Result != nil {
			t.Fatal("manager observer exclusion missing")
		}
	}
	after, err := disk.Records()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("observer changed lease state")
	}
	if calls, _ := e.Owner.Counts(); calls != 0 {
		t.Fatal("observer refreshed")
	}
}

// Claim: a real worker kernel UID is not observer authority, unknown peers are
// refused before hello, and retired/not-ready protected policy cannot allow.
func TestAllowlistRoleAndReadiness(t *testing.T) {
	for _, mode := range []string{"worker", "unknown", "disabled", "unqualified", "network", "unreadable", "replaced-after-hello", "closed-manager"} {
		t.Run(mode, func(t *testing.T) {
			options := lease.Options{}
			if mode == "unreadable" {
				options.ObservePolicy = func(context.Context, policy.Policy) error { return errors.New("synthetic-private-sentinel") }
			}
			e, observer := observerFixture(t, options)
			if mode == "closed-manager" {
				e.Manager.Close()
			}
			if mode == "disabled" || mode == "unqualified" || mode == "network" {
				p := e.Policy.Clone()
				p.Generation++
				if mode == "disabled" {
					p.Accounts[0].Enabled = false
				}
				if mode == "unqualified" {
					p.Accounts[0].QualificationID = ""
				}
				if mode == "network" {
					p.Accounts[0].NetworkRequired = true
				}
				if e.Manager.Replace(p) != nil {
					t.Fatal("replace failed")
				}
				e.Policy = p
				e.Request.Binding = p.Binding(e.UID, p.Accounts[0], e.Request.Profile)
			}
			path := observerPath(t, e, observer)
			if mode == "worker" {
				path = start(t, e, nil)
			}
			if mode == "unknown" {
				path = observerPath(t, e, observer+1)
			}
			c, err := dialObserverRPC(t, path, e.UID)
			if err != nil {
				if mode != "unknown" && mode != "closed-manager" {
					t.Fatal(err)
				}
				return
			}
			defer c.Close()
			if mode == "replaced-after-hello" {
				p := e.Policy.Clone()
				p.Generation++
				if e.Manager.Replace(p) != nil {
					t.Fatal("replace failed")
				}
			}
			got, err := c.Check(context.Background(), observation(e))
			if err == nil || got != (brokerclient.AllowlistResult{}) {
				t.Fatal("role/readiness admitted")
			}
			if bytes.Contains([]byte(err.Error()), []byte("synthetic-private-sentinel")) {
				t.Fatal("raw error leaked")
			}
			e.NoLeaseRecords(t)
		})
	}
}

// Claim: closed decoding rejects unknown/null request members and malformed
// framing without creating material; valid unknown peers never gain authority.
func TestAllowlistClosedRequest(t *testing.T) {
	e, observer := observerFixture(t, lease.Options{})
	path := observerPath(t, e, observer)
	for _, mode := range []string{"unknown", "binding-unknown", "null", "oversize", "partial"} {
		t.Run(mode, func(t *testing.T) {
			c := dial(t, path)
			hello(t, c)
			r := observation(e)
			b, _ := wire.Encode(r)
			var m map[string]any
			json.Unmarshal(b, &m)
			switch mode {
			case "unknown":
				m["extra"] = "sentinel"
			case "binding-unknown":
				m["credential_binding"].(map[string]any)["extra"] = "sentinel"
			case "null":
				m["target_uid"] = nil
			}
			if mode == "oversize" {
				var h [4]byte
				binary.BigEndian.PutUint32(h[:], wire.MaxPayload+1)
				c.Write(h[:])
				r := reply(t, c)
				if r.Error == nil || r.Error.Code != "frame_too_large" {
					t.Fatal("oversize accepted")
				}
				return
			}
			if mode == "partial" {
				c.Write([]byte{0, 0})
				c.CloseWrite()
				closed(t, c)
				return
			}
			b, _ = wire.Encode(m)
			if wire.Write(c, wire.Request{Method: "allowlist.check", ID: "closed", Params: b}) != nil {
				t.Fatal("fixture write")
			}
			closed(t, c)
		})
	}
	e.NoLeaseRecords(t)
}
