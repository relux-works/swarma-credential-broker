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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/claude"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
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
	counter          atomic.Uint64
	custody          *socketServiceAccount
}

type socketServiceAccount struct {
	*claude.Account
	publications atomic.Uint64
}

func (a *socketServiceAccount) Publish(ctx context.Context, until time.Time, now func() time.Time, fn func([]byte) error) error {
	a.publications.Add(1)
	return a.Account.Publish(ctx, until, now, fn)
}

func (a *socketServiceAuthority) WithIdentity(ctx context.Context, fn func(service.View) error) error {
	return a.WithCurrent(ctx, fn)
}
func (a *socketServiceAuthority) OperatorAct(service.Principal, string, json.RawMessage) bool {
	return true
}

// This is a fixture codec; production must reuse its baseline event codec.
func (a *socketServiceAuthority) Event(raw json.RawMessage) bool {
	var event struct {
		Kind  string `json:"kind"`
		Class string `json:"class"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || len(members) != 2 || event.Kind != "credential_error" {
		return false
	}
	return event.Class == "auth" || event.Class == "permission" || event.Class == "quota" || event.Class == "unknown"
}
func (a *socketServiceAuthority) Sequence() json.RawMessage { return json.RawMessage(`1`) }
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
func (a *socketServiceAuthority) Service(b wire.ServiceBinding) error {
	if b != a.binding || a.role != "service" || a.generation != b.Generation {
		return wire.Refuse("service_binding_mismatch")
	}
	return nil
}
func (a *socketServiceAuthority) Caller(b wire.ServiceBinding, c wire.ServiceCaller) (time.Time, string, error) {
	if !a.callerOK || b != a.binding || c != a.caller {
		return time.Time{}, "", wire.Refuse("lease_caller_revoked")
	}
	return time.Now().Add(time.Hour), "socket-binding-1", nil
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
	view.custody = &socketServiceAccount{Account: a}
	broker, err := service.New(view, map[string]service.Account{account: view.custody}, nil)
	if err != nil {
		t.Fatal("service fixture broker unavailable")
	}
	p, err := broker.Open(context.Background(), uid+1)
	if err != nil {
		t.Fatal("fixture operator unavailable")
	}
	raw, _ := wire.Encode(wire.ServiceBind{OperationID: "bind-1", ServiceBinding: binding})
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
	return wire.ServiceRequest{OperationID: strconv.FormatUint(a.counter.Add(1), 10), ServiceCaller: a.caller}
}

// A real SO_PEERCRED connection negotiates broker/1 on the same listener as
// legacy framing, gets a fixed service role, and receives material only for its
// current gateway lease. Metadata and refusal frames contain no fixture token.
func TestServiceSocketMaterialAndPoll(t *testing.T) {
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) {
		for i := range p.Accounts {
			p.Accounts[i].AllowedUIDs = nil
		}
	})
	if e.Manager.Peer(context.Background(), uint32(os.Geteuid())) {
		t.Fatal("service fixture retained legacy peer authority")
	}
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
	if wire.Decode(h.Result, &hello) != nil || hello.Principal.UID != uint32(os.Geteuid()) || hello.Principal.Service != service.Gateway || hello.Profile != wire.ServiceProfile {
		t.Fatal("kernel service role mismatch")
	}
	assertGatewayAbsent(t, h.Result)
	// The same kernel service UID cannot fall back to the exposed profile.
	legacy := dial(t, path)
	denied := request(t, legacy, "hello", "legacy-denied", wire.Hello{Versions: []int{1}, Profile: wire.Profile})
	if denied.Error == nil || denied.Error.Code != "role_not_permitted" || denied.Result != nil {
		t.Fatal("service identity inherited exposed-lane authority")
	}
	assertGatewayAbsent(t, encodeResponse(t, denied))
	r := request(t, c, "service.lease.request", "lease-service", serviceRequest(a))
	var l wire.ServiceLease
	if r.Error != nil || wire.Decode(r.Result, &l) != nil || l.Payload.Value != gatewayFixtureToken || l.Kind != service.Kind {
		t.Fatal("gateway wire material control failed")
	}
	until, err := time.Parse(time.RFC3339Nano, l.AuthorizedUntil)
	if err != nil || until.After(time.Now().Add(service.V0LeaseCeiling)) {
		t.Fatal("wire deadline exceeds ceiling")
	}
	r = request(t, c, "service.revocation.check", "poll-live", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	var verdict struct {
		Verdict  string          `json:"verdict"`
		Sequence json.RawMessage `json:"revocation_sequence"`
	}
	if r.Error != nil || wire.Decode(r.Result, &verdict) != nil || verdict.Verdict != "not_revoked" {
		t.Fatal("live poll control failed")
	}
	assertGatewayAbsent(t, r.Result)
	a.mu.Lock()
	a.callerOK = false
	a.mu.Unlock()
	r = request(t, c, "service.lease.renew", "renew-denied", wire.ServiceRenew{OperationID: "renew-1", ServiceLeaseID: wire.ServiceLeaseID{LeaseID: l.LeaseID}})
	if r.Error == nil || r.Error.Code != "lease_caller_revoked" || r.Result != nil {
		t.Fatal("revoked caller received material")
	}
	assertGatewayAbsent(t, encodeResponse(t, r))
	r = request(t, c, "service.revocation.check", "poll-revoked", wire.ServiceLeaseID{LeaseID: l.LeaseID})
	if r.Error != nil || wire.Decode(r.Result, &verdict) != nil || verdict.Verdict != "revoked" {
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

// The current baseline has no exposed Claude lane: an admitted agent naming
// the enrolled Claude account gets no material, record or custody publication.
// The same listener/controller issues a service lease for that account. Peer
// identities use the existing test seam; this is not foreign-UID qualification
// or a test of the future section 1 exposed-lane policy interlock.
func TestAgentClaudeLeaseRefusalBesideServiceControl(t *testing.T) {
	broker, a := newSocketService(t)
	agentUID := a.caller.UID
	account := a.binding.Account
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) {
		p.Accounts[0].Label = account
		p.Accounts[0].AllowedUIDs = []uint32{agentUID}
	})
	var peers atomic.Uint64
	path := start(t, e, func(s *Server) {
		s.Services = broker
		s.peer = func(*net.UnixConn) (uint32, error) {
			if peers.Add(1) == 1 {
				return agentUID, nil
			}
			return a.uid, nil
		}
	})
	agent := dial(t, path)
	hello(t, agent)
	info, err := a.custody.ServiceAccount()
	if err != nil || info.Kind != service.Kind {
		t.Fatal("enrolled Claude account control failed")
	}
	before, err := a.custody.LoadServiceState()
	if err != nil || len(before.Leases) != 0 {
		t.Fatal("initial service journal control failed")
	}
	entries := a.custody.publications.Load()
	raw := e.Request
	raw.Account, raw.Harness, raw.Channel = account, "claude_code", "env"
	raw.Binding = e.Policy.Binding(agentUID, e.Policy.Accounts[0], raw.Profile)
	r := request(t, agent, "lease.request", "agent-claude-refused", raw)
	if r.Error == nil || r.Error.Code != "lease_harness_mismatch" || r.Result != nil {
		t.Fatal("agent received an exposed Claude lease")
	}
	assertGatewayAbsent(t, encodeResponse(t, r))
	after, err := a.custody.LoadServiceState()
	if err != nil || !reflect.DeepEqual(before, after) || a.custody.publications.Load() != entries {
		t.Fatal("agent refusal changed the service journal or entered custody")
	}
	records, err := e.Store.Account(account, false)
	if err != nil {
		t.Fatal("legacy account control failed")
	}
	if names, err := records.Records(); err != nil || len(names) != 0 {
		t.Fatal("agent refusal created a legacy lease record")
	}
	gateway := dial(t, path)
	if serviceHello(t, gateway).Error != nil {
		t.Fatal("service hello control failed")
	}
	r = request(t, gateway, "service.lease.request", "service-claude-control", serviceRequest(a))
	var l wire.ServiceLease
	if r.Error != nil || wire.Decode(r.Result, &l) != nil || l.Account != account || l.Kind != service.Kind || l.Payload.Value != gatewayFixtureToken || a.custody.publications.Load() <= entries {
		t.Fatal("same-account service lease control failed")
	}
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
			before, err := a.custody.LoadServiceState()
			if err != nil {
				t.Fatal("service journal control failed")
			}
			entries := a.custody.publications.Load()
			r := request(t, c, "service.lease.request", "refusal", serviceRequest(a))
			code := "role_not_permitted"
			if change == "generation" {
				code = "principal_ledger_mismatch"
			}
			if r.Error == nil || r.Error.Code != code || r.Result != nil {
				t.Fatal("fixed principal changed authority")
			}
			assertGatewayAbsent(t, encodeResponse(t, r))
			after, err := a.custody.LoadServiceState()
			if err != nil || !reflect.DeepEqual(before, after) || a.custody.publications.Load() != entries {
				t.Fatal("retired principal changed state or entered custody")
			}
			// Fresh wrong-role connections also refuse; a new service generation
			// remains unbound, despite recycling the same real kernel UID.
			fresh := dial(t, path)
			if h := serviceHello(t, fresh); h.Error != nil {
				if change == "generation" {
					if h.Error.Code != "role_not_permitted" || h.Result != nil {
						t.Fatal("unbound new generation got the wrong hello refusal")
					}
					return
				}
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
			if r.Error == nil || r.Error.Code != "request_malformed" || r.Result != nil {
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

// A real service socket is usable while bound and closes after the durable
// operator unbind; the disconnected generation cannot negotiate another role.
func TestServiceSocketUnbindCloses(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	broker, a := newSocketService(t)
	path := start(t, e, func(s *Server) { s.Services = broker })
	c := dial(t, path)
	if serviceHello(t, c).Error != nil {
		t.Fatal("hello control")
	}
	if r := request(t, c, "service.lease.request", "before-unbind", serviceRequest(a)); r.Error != nil {
		t.Fatal("lease control")
	}
	p, err := broker.Open(context.Background(), a.uid+1)
	if err != nil {
		t.Fatal(err)
	}
	var bindingID string
	// The equal bind retry returns the current binding identity without replacing it.
	raw, _ := wire.Encode(wire.ServiceBind{OperationID: "bind-1", ServiceBinding: a.binding})
	if err = broker.Call(context.Background(), p, "service.bind", raw, func(v any) error { bindingID = v.(map[string]any)["service_binding_id"].(string); return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ = wire.Encode(wire.ServiceUnbind{OperationID: "unbind-socket", BindingID: bindingID})
	if err = broker.Call(context.Background(), p, "service.unbind", raw, func(any) error { return nil }); err != nil {
		t.Fatal(err)
	}
	closed(t, c)
}

// The unchanged broker/1 hello is versions-only. It returns the service triple
// without a new profile member, while unknown members still close before any
// method or material publication. Legacy static-profile parsing stays separate.
func TestServiceSocketStandardHello(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	broker, a := newSocketService(t)
	path := start(t, e, func(s *Server) { s.Services = broker })
	c := dial(t, path)
	params, _ := wire.Encode(map[string]any{"versions": []int{1}})
	if wire.Write(c, wire.Request{Method: "hello", ID: "standard", Params: params}) != nil {
		t.Fatal("standard hello write failed")
	}
	raw, err := wire.Read(c)
	var h response
	if err != nil || wire.Decode(raw, &h) != nil || h.ID == nil || *h.ID != "standard" {
		t.Fatal("standard broker hello refused")
	}
	if h.Error != nil || h.Result == nil {
		t.Fatal("standard broker hello refused")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(h.Result, &result) != nil || len(result) != 2 || result["principal"] == nil || result["version"] == nil {
		t.Fatal("standard hello response invented members")
	}
	var principal map[string]json.RawMessage
	if json.Unmarshal(result["principal"], &principal) != nil || len(principal) != 3 || principal["service_name"] == nil || principal["uid"] == nil || principal["service_generation"] == nil {
		t.Fatal("standard hello lost service triple")
	}
	if r := request(t, c, "service.lease.request", "standard-lease", serviceRequest(a)); r.Error != nil {
		t.Fatal("standard hello could not request its lease")
	}
	for _, key := range []string{"role", "placeholder"} {
		bad := dial(t, path)
		raw, _ := wire.Encode(map[string]any{"versions": []int{1}, key: "inert"})
		if wire.Write(bad, wire.Request{Method: "hello", ID: "bad-standard", Params: raw}) != nil {
			t.Fatal("bad hello write")
		}
		closed(t, bad)
	}
}
