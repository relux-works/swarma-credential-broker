//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/claude"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const gatewayFixtureToken = "FAKE_CLAUDE_TOKEN_NOT_A_CREDENTIAL_a1"

type socketServiceAuthority struct {
	mu               sync.RWMutex
	uid              uint32
	role, generation string
	binding          wire.ServiceBinding
	caller           wire.ServiceCaller
	callerOK         bool
}

func (a *socketServiceAuthority) WithCurrent(ctx context.Context, fn func(service.View) error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fn(a)
}
func (a *socketServiceAuthority) Principal(uid uint32) (service.Principal, error) {
	if uid == a.uid {
		p := service.Principal{UID: uid, Role: a.role, Generation: a.generation}
		if a.role == "service" {
			p.Service = service.Gateway
		}
		return p, nil
	}
	if uid == a.uid+1 {
		return service.Principal{UID: uid, Role: "operator", Generation: "operator-generation"}, nil
	}
	return service.Principal{}, errors.New("unknown fixture identity")
}
func (a *socketServiceAuthority) Service(b wire.ServiceBinding) (time.Time, error) {
	if b != a.binding || a.role != "service" || a.generation != b.Generation {
		return time.Time{}, errors.New("fixture service denied")
	}
	return time.Now().Add(time.Hour), nil
}
func (a *socketServiceAuthority) Caller(b wire.ServiceBinding, c wire.ServiceCaller) (time.Time, error) {
	if !a.callerOK || b != a.binding || c != a.caller {
		return time.Time{}, errors.New("fixture caller denied")
	}
	return time.Now().Add(time.Hour), nil
}
func (a *socketServiceAuthority) Owner(uint32, string) bool { return false }

func newSocketService(t *testing.T) (*service.Broker, *socketServiceAuthority) {
	t.Helper()
	uid := uint32(os.Geteuid())
	s, err := store.Open(filepath.Join(t.TempDir(), "store"), "socket-service-fixture", uid, true, nil)
	if err != nil {
		t.Fatal("service fixture store unavailable")
	}
	t.Cleanup(func() { s.Close() })
	const account = "owner/claude/socket"
	r, err := s.Account(account, true)
	if err != nil {
		t.Fatal("service fixture account unavailable")
	}
	a, err := claude.NewAccount(r, "socket-service-fixture", account)
	if err != nil || a.Enroll([]byte(gatewayFixtureToken), nil) != nil {
		t.Fatal("service fixture custody unavailable")
	}
	binding := wire.ServiceBinding{Service: service.Gateway, UID: uid, Generation: "socket-service-generation", Account: account, Kind: service.Kind, PolicyDigest: strings.Repeat("a", 64)}
	view := &socketServiceAuthority{uid: uid, role: "service", generation: binding.Generation, binding: binding, caller: wire.ServiceCaller{Account: account, UID: uid + 2, Generation: "socket-agent-generation", LaunchID: "socket-launch"}, callerOK: true}
	broker, err := service.New(view, map[string]service.Account{account: a}, nil)
	if err != nil {
		t.Fatal("service fixture broker unavailable")
	}
	p, err := broker.Open(context.Background(), uid+1)
	if err != nil {
		t.Fatal("fixture operator unavailable")
	}
	raw, _ := wire.Encode(binding)
	if broker.Call(context.Background(), p, "service.bind", raw, func(any) error { return nil }) != nil {
		t.Fatal("fixture operator bind failed")
	}
	return broker, view
}
func assertGatewayAbsent(t *testing.T, raw []byte) {
	t.Helper()
	for _, v := range []string{gatewayFixtureToken, base64.StdEncoding.EncodeToString([]byte(gatewayFixtureToken))} {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("gateway fixture material escaped response boundary")
		}
	}
}
func serviceHello(t *testing.T, c *net.UnixConn) response {
	t.Helper()
	return request(t, c, "hello", "hello-service", wire.Hello{Versions: []int{1}, Profile: wire.ServiceProfile})
}
func serviceRequest(a *socketServiceAuthority) wire.ServiceRequest {
	return wire.ServiceRequest{Caller: a.caller, Kind: service.Kind, PolicyDigest: a.binding.PolicyDigest}
}

// A real SO_PEERCRED connection negotiates broker/1 on the same listener as
// legacy framing, gets a fixed service role, and receives material only for its
// current gateway lease. Metadata and refusal frames contain no fixture token.
func TestServiceSocketMaterialAndPoll(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	broker, a := newSocketService(t)
	path := start(t, e, func(s *Server) { s.Services = broker })
	c := dial(t, path)
	h := serviceHello(t, c)
	if h.Error != nil {
		t.Fatal("service hello refused")
	}
	var hello struct {
		Version   int               `json:"version"`
		Profile   string            `json:"profile"`
		Principal service.Principal `json:"principal"`
	}
	if wire.Decode(h.Result, &hello) != nil || hello.Principal.UID != uint32(os.Geteuid()) || hello.Principal.Role != "service" || hello.Profile != wire.ServiceProfile {
		t.Fatal("kernel service role mismatch")
	}
	assertGatewayAbsent(t, h.Result)
	r := request(t, c, "service.lease.request", "lease-service", serviceRequest(a))
	var l wire.ServiceLease
	if r.Error != nil || wire.Decode(r.Result, &l) != nil || l.Token != gatewayFixtureToken || l.Kind != service.Kind {
		t.Fatal("gateway wire material control failed")
	}
	until, err := time.Parse(time.RFC3339Nano, l.AuthorizedUntil)
	if err != nil || until.After(time.Now().Add(service.V0LeaseCeiling)) {
		t.Fatal("wire deadline exceeds ceiling")
	}
	r = request(t, c, "service.revocation.check", "poll-live", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if r.Error != nil || !bytes.Contains(r.Result, []byte("not_revoked")) {
		t.Fatal("live poll control failed")
	}
	assertGatewayAbsent(t, r.Result)
	a.mu.Lock()
	a.callerOK = false
	a.mu.Unlock()
	r = request(t, c, "service.lease.renew", "renew-denied", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if r.Error == nil || r.Error.Code != "lease_not_authorised" || r.Result != nil {
		t.Fatal("revoked caller received material")
	}
	assertGatewayAbsent(t, encodeResponse(t, r))
	r = request(t, c, "service.revocation.check", "poll-revoked", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if r.Error != nil || !bytes.Contains(r.Result, []byte("unavailable")) {
		t.Fatal("revoked poll widened")
	}
	assertGatewayAbsent(t, r.Result)
	// Parent/non-gateway process never receives material via argv or environment.
	assertGatewayAbsent(t, []byte(strings.Join(os.Args, "\n")))
	assertGatewayAbsent(t, []byte(strings.Join(os.Environ(), "\n")))
}
func encodeResponse(t *testing.T, r response) []byte {
	t.Helper()
	b, err := wire.Encode(r)
	if err != nil {
		t.Fatal("response encoding failed")
	}
	return b
}

// Kernel UID still resolves current role/generation after hello. Workers and
// orchestrators cannot request service material or change the fixed role, and
// a retired connection cannot inherit a replacement generation.
func TestServiceSocketRoleAndGenerationRefusals(t *testing.T) {
	for _, change := range []string{"worker", "orchestrator", "generation"} {
		t.Run(change, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			broker, a := newSocketService(t)
			path := start(t, e, func(s *Server) { s.Services = broker })
			c := dial(t, path)
			if serviceHello(t, c).Error != nil {
				t.Fatal("service hello control failed")
			}
			if r := request(t, c, "service.lease.request", "control", serviceRequest(a)); r.Error != nil {
				t.Fatal("service control failed")
			}
			a.mu.Lock()
			if change == "generation" {
				a.generation = "replacement-generation"
			} else {
				a.role = change
			}
			a.mu.Unlock()
			r := request(t, c, "service.lease.request", "refusal", serviceRequest(a))
			if r.Error == nil || r.Error.Code != "role_not_permitted" || r.Result != nil {
				t.Fatal("fixed principal changed authority")
			}
			assertGatewayAbsent(t, encodeResponse(t, r))
			// Fresh wrong-role connections also refuse; a new service generation
			// remains unbound, despite recycling the same real kernel UID.
			fresh := dial(t, path)
			if serviceHello(t, fresh).Error != nil {
				t.Fatal("current principal hello failed")
			}
			r = request(t, fresh, "service.lease.request", "fresh-refusal", serviceRequest(a))
			if r.Error == nil || r.Result != nil {
				t.Fatal("replacement principal inherited lease")
			}
			assertGatewayAbsent(t, encodeResponse(t, r))
		})
	}
}

// No role or placeholder field is accepted during hello or material requests;
// the exact valid shape on a separate connection remains accepted.
func TestServiceSocketRejectsRoleAndPlaceholderFields(t *testing.T) {
	for _, field := range []string{"role", "placeholder"} {
		t.Run(field, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			broker, a := newSocketService(t)
			path := start(t, e, func(s *Server) { s.Services = broker })
			c := dial(t, path)
			if serviceHello(t, c).Error != nil {
				t.Fatal("hello control failed")
			}
			good, _ := wire.Encode(serviceRequest(a))
			var params map[string]any
			if json.Unmarshal(good, &params) != nil {
				t.Fatal("fixture shape failed")
			}
			params[field] = "service"
			r := request(t, c, "service.lease.request", "bad-shape", params)
			if r.Error == nil || r.Error.Code != "lease_not_authorised" || r.Result != nil {
				t.Fatal("caller role/placeholder accepted")
			}
			assertGatewayAbsent(t, encodeResponse(t, r))
			if r := request(t, c, "service.lease.request", "good-shape", serviceRequest(a)); r.Error != nil {
				t.Fatal("valid shape control failed")
			}
			badHello := dial(t, path)
			bad := map[string]any{"versions": []int{1}, "profile": wire.ServiceProfile, field: "service"}
			raw, _ := wire.Encode(bad)
			if wire.Write(badHello, wire.Request{Method: "hello", ID: "bad-hello", Params: raw}) != nil {
				t.Fatal("hello write failed")
			}
			closed(t, badHello)
		})
	}
}
