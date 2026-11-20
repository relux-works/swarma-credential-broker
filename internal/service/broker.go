// Package service implements the inactive secret-free service dialect v0.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const Gateway = "credential-gateway"
const Kind = "claude-oauth-token"
const V0LeaseCeiling = 900 * time.Second

// Principal is local protected managed-record evidence, never request input.
// Operator is also the owner role; an act still requires OperatorAct below.
type Principal struct {
	UID        uint32 `json:"uid"`
	Role       string `json:"-"`
	Generation string `json:"service_generation"`
	Service    string `json:"service_name"`
}

// View methods read settled local evidence only; they perform no synchronous
// platform-service calls. Caller returns the originating binding identity as
// well as its exclusive authority deadline. Providers enforce both admission
// classes, local placement, account policy, chains, revocations and time fences.
type View interface {
	Principal(uint32) (Principal, error)
	Service(wire.ServiceBinding) error
	Caller(wire.ServiceBinding, wire.ServiceCaller) (time.Time, string, error)
	Owner(uint32, string) bool
	OperatorAct(Principal, string, json.RawMessage) bool
	// Event validates exactly the existing baseline typed event form.
	Event(json.RawMessage) bool
	// Sequence preserves the baseline representation, including unavailable.
	// Its unavailable encoding is still broker-owned (dialect section 10).
	Sequence() json.RawMessage
}

type identityWindow interface {
	identityContext() context.Context
	materialReleased()
}

// WithIdentity settles only protected principal/operator evidence and remains
// available when caller grants or use-authority readers are unavailable.
// WithCurrent acquires current use facts before the broker state lock, holding
// them stable through fn and its bounded material write. ManagedAuthority reads
// production service identity; installed use facts and trusted time remain gates.
type Authority interface {
	WithIdentity(context.Context, func(View) error) error
	WithCurrent(context.Context, func(View) error) error
}
type Account interface {
	ExpiresAt() (*time.Time, error)
	ServiceAccount() (wire.ServiceAccount, error)
	Publish(context.Context, time.Time, func() time.Time, func([]byte) error) error
	LoadServiceState() (wire.ServiceState, error)
	StoreServiceState(wire.ServiceState) error
}
type Broker struct {
	gate                chan struct{}
	authority           Authority
	accounts            map[string]Account
	states              map[string]*wire.ServiceState
	bindings            map[string]*wire.ServiceBindingRecord
	leases              map[string]*wire.ServiceLeaseRecord
	holds               map[string]*wire.AccountHoldRecord
	now                 func() time.Time
	watermark           time.Time
	lifetime            time.Duration
	credentialKind      string
	terminalContainment bool
	strictReplay        bool
	failed              bool
	connections         map[uint64]serviceConnection
	nextConnection      uint64
	pendingHold         *pendingHold
	realClock           bool
	anchorWall          time.Time
	anchorMono          time.Time
}

type pendingHold struct {
	principal string
	account   string
	arguments json.RawMessage
}

// recoverHold reconciles only an identical authenticated retry of the uncertain
// narrowing transaction. It reloads and re-confirms protected durable state,
// discarding the unacknowledged in-memory candidate before replay/admission.
func (b *Broker) recoverHold(p Principal, raw json.RawMessage) error {
	pending := b.pendingHold
	if pending == nil || pending.principal != principalRef(p) || !bytes.Equal(pending.arguments, raw) {
		return refuse("lease_owner_unavailable")
	}
	account := pending.account
	state, e := b.accounts[account].LoadServiceState()
	if e != nil || !validStateForKind(state, account, b.credentialKind) || state.Revision == 0 || state.Revision >= 9007199254740990 {
		return refuse("account_hold_unknown")
	}
	state.Revision++
	if b.accounts[account].StoreServiceState(state) != nil {
		return refuse("account_hold_unknown")
	}
	for id, s := range b.bindings {
		if s.Account == account {
			delete(b.bindings, id)
		}
	}
	for id, l := range b.leases {
		if l.Account == account {
			delete(b.leases, id)
		}
	}
	for id, h := range b.holds {
		if h.Account == account {
			delete(b.holds, id)
		}
	}
	for _, s := range state.Bindings {
		s := s
		b.bindings[s.ID] = &s
	}
	for _, l := range state.Leases {
		l := l
		b.leases[l.ID] = &l
	}
	for _, h := range state.Holds {
		h := h
		b.holds[h.ID] = &h
	}
	b.states[account] = &state
	if state.Watermark.After(b.watermark) {
		b.watermark = state.Watermark
	}
	b.failed = false
	b.pendingHold = nil
	return nil
}

type serviceConnection struct {
	principal Principal
	close     func()
}

// RegisterConnection lets the transport close the exact bound uid/generation
// on unbind. The returned cleanup removes only that connection registration.
func (b *Broker) RegisterConnection(ctx context.Context, p Principal, close func()) (func(), error) {
	if close == nil {
		return nil, refuse("role_not_permitted")
	}
	select {
	case <-ctx.Done():
		return nil, refuse("request_deadline_exceeded")
	case <-b.gate:
	}
	defer func() { b.gate <- struct{}{} }()
	if p.Role == "service" && !b.serviceBound(p) {
		return nil, refuse("role_not_permitted")
	}
	if b.connections == nil {
		b.connections = map[uint64]serviceConnection{}
	}
	b.nextConnection++
	id := b.nextConnection
	b.connections[id] = serviceConnection{p, close}
	return func() { <-b.gate; delete(b.connections, id); b.gate <- struct{}{} }, nil
}
func (b *Broker) serviceBound(p Principal) bool {
	for _, s := range b.bindings {
		if s.State == "active" && s.UID == p.UID && s.Generation == p.Generation && s.Service == p.Service {
			return true
		}
	}
	return false
}
func (b *Broker) closeConnections(uid uint32, generation string) {
	for _, c := range b.connections {
		if c.principal.UID == uid && c.principal.Generation == generation {
			c.close()
		}
	}
}
func refuse(code string) error { return wire.Refuse(code) }

// A stale connection must close after its refusal is written. Keep that
// transport decision separate from an ordinary current lessee's refusal code.
type staleConnectionError struct{ refusal *wire.Error }

func (e *staleConnectionError) Error() string { return e.refusal.Error() }
func (e *staleConnectionError) Unwrap() error { return e.refusal }

// IsStaleConnection reports whether Call rejected a retired fixed principal.
func IsStaleConnection(err error) bool {
	var stale *staleConnectionError
	return errors.As(err, &stale)
}

func New(a Authority, accounts map[string]Account, now func() time.Time) (*Broker, error) {
	return NewWithLifetime(a, accounts, now, V0LeaseCeiling)
}

// NewWithLifetime refuses invalid configuration instead of silently clamping.
func NewWithLifetime(a Authority, accounts map[string]Account, now func() time.Time, lifetime time.Duration) (*Broker, error) {
	return newWithKind(a, accounts, now, lifetime, Kind, false)
}

func newWithKind(a Authority, accounts map[string]Account, now func() time.Time, lifetime time.Duration, credentialKind string, terminalContainment bool) (*Broker, error) {
	if a == nil || len(accounts) == 0 || lifetime <= 0 || lifetime > V0LeaseCeiling || lifetime%time.Second != 0 {
		return nil, refuse("lease_owner_unavailable")
	}
	realClock := now == nil
	if now == nil {
		now = time.Now
	}
	b := &Broker{gate: make(chan struct{}, 1), authority: a, accounts: map[string]Account{}, states: map[string]*wire.ServiceState{}, bindings: map[string]*wire.ServiceBindingRecord{}, leases: map[string]*wire.ServiceLeaseRecord{}, holds: map[string]*wire.AccountHoldRecord{}, now: now, lifetime: lifetime}
	b.credentialKind, b.terminalContainment = credentialKind, terminalContainment
	b.gate <- struct{}{}
	for label, account := range accounts {
		if account == nil || !wire.ASCII(label, 128) {
			return nil, refuse("lease_owner_unavailable")
		}
		s, err := account.LoadServiceState()
		if err != nil || !validStateForKind(s, label, credentialKind) {
			return nil, refuse("lease_owner_unavailable")
		}
		// Recovery re-confirms file and directory durability before replay can
		// acknowledge a record observed after an interrupted directory sync.
		if s.Revision > 0 {
			s.Revision++
			if account.StoreServiceState(s) != nil {
				return nil, refuse("lease_owner_unavailable")
			}
		}
		b.accounts[label], b.states[label] = account, &s
		if s.Watermark.After(b.watermark) {
			b.watermark = s.Watermark
		}
		for _, r := range s.Bindings {
			r := r
			if b.bindings[r.ID] != nil {
				return nil, refuse("lease_owner_unavailable")
			}
			b.bindings[r.ID] = &r
		}
		for _, r := range s.Leases {
			r := r
			if b.leases[r.ID] != nil {
				return nil, refuse("lease_owner_unavailable")
			}
			b.leases[r.ID] = &r
		}
		for _, r := range s.Holds {
			r := r
			if b.holds[r.ID] != nil {
				return nil, refuse("lease_owner_unavailable")
			}
			b.holds[r.ID] = &r
		}
	}
	for _, l := range b.leases {
		s := b.bindings[l.BindingID]
		if s == nil || s.Account != l.Account || s.Service != l.Service || s.UID != l.UID || s.Generation != l.Generation {
			return nil, refuse("lease_owner_unavailable")
		}
	}
	b.realClock = realClock
	b.anchorWall = b.now().UTC()
	if b.watermark.After(b.anchorWall) {
		b.anchorWall = b.watermark
	}
	b.anchorMono = time.Now()
	return b, nil
}
func validState(s wire.ServiceState, account string) bool {
	return validStateForKind(s, account, Kind)
}

func validStateForKind(s wire.ServiceState, account, credentialKind string) bool {
	if s.Revision == 0 {
		return s.Kind == "" && len(s.Bindings)+len(s.Leases)+len(s.Holds)+len(s.Operations) == 0
	}
	if s.Revision > 9007199254740990 || s.Watermark.IsZero() {
		return false
	}
	active := map[wire.ServiceBinding]bool{}
	for _, r := range s.Bindings {
		if !wire.ASCII(r.ID, 128) || r.Account != account || !validBindingForKind(r.Binding(), credentialKind) || r.CreatedAt.IsZero() || !wire.ASCII(r.CreatedBy, 512) || !wire.ASCII(r.OperationID, 128) || (r.State != "active" && r.State != "removed") {
			return false
		}
		if r.State == "active" {
			if active[r.Binding()] || r.RemovedAt != nil || r.RemovedOperationID != nil {
				return false
			}
			active[r.Binding()] = true
		} else if r.RemovedAt == nil || r.RemovedOperationID == nil {
			return false
		}
	}
	for _, r := range s.Leases {
		if !wire.ASCII(r.ID, 128) || r.Account != account || r.Kind != credentialKind || r.Harness != "claude_code" || !validCaller(r.Caller()) || !wire.ASCII(r.AgentBindingID, 128) || r.Until.IsZero() || (r.State != "active" && r.State != "released" && r.State != "expired" && r.State != "revoked") {
			return false
		}
	}
	n := 0
	for _, h := range s.Holds {
		if !wire.ASCII(h.ID, 128) || h.Account != account || h.Reason != "leak_match" || h.PlacedAt.IsZero() || (h.State != "active" && h.State != "lifted") {
			return false
		}
		if h.State == "active" {
			n++
		}
	}
	if n > 1 {
		return false
	}
	seen := map[string]bool{}
	for _, o := range s.Operations {
		k := o.Principal + "/" + o.Method + "/" + o.ID
		if seen[k] || !wire.ASCII(o.ID, 128) || o.At.IsZero() || !json.Valid(o.Arguments) || !json.Valid(o.Result) {
			return false
		}
		seen[k] = true
	}
	return true
}
func validBinding(v wire.ServiceBinding) bool {
	return validBindingForKind(v, Kind)
}

func validBindingForKind(v wire.ServiceBinding, credentialKind string) bool {
	return v.Service == Gateway && v.Kind == credentialKind && wire.ASCII(v.Generation, 128) && wire.ASCII(v.Account, 128) && wire.ASCII(v.PolicyDigest, 128)
}
func validCaller(c wire.ServiceCaller) bool {
	return wire.ASCII(c.Account, 128) && wire.ASCII(c.Generation, 128) && wire.ASCII(c.LaunchID, 128)
}
func validPrincipal(p Principal, uid uint32) bool {
	if p.UID != uid || !wire.ASCII(p.Generation, 128) {
		return false
	}
	switch p.Role {
	case "service":
		return p.Service == Gateway
	case "operator", "owner", "worker", "orchestrator", "observer":
		return p.Service == ""
	}
	return false
}
func principalRef(p Principal) string {
	return fmt.Sprintf("%d:%s:%s:%s", p.UID, p.Generation, p.Role, p.Service)
}

func (b *Broker) acquire(ctx context.Context, view View) error {
	window := ctx
	if identity, ok := view.(identityWindow); ok {
		window = identity.identityContext()
	}
	select {
	case <-ctx.Done():
		return refuse("request_deadline_exceeded")
	case <-window.Done():
		if ctx.Err() != nil {
			return refuse("request_deadline_exceeded")
		}
		return refuse("principal_ledger_mismatch")
	case <-b.gate:
	}
	if ctx.Err() != nil {
		b.gate <- struct{}{}
		return refuse("request_deadline_exceeded")
	}
	if window.Err() != nil {
		b.gate <- struct{}{}
		return refuse("principal_ledger_mismatch")
	}
	return nil
}

func (b *Broker) Open(ctx context.Context, uid uint32) (Principal, error) {
	var p Principal
	if b == nil {
		return p, refuse("role_not_permitted")
	}
	err := b.authority.WithIdentity(ctx, func(v View) error {
		var e error
		p, e = v.Principal(uid)
		if e != nil {
			return known(e, "role_not_permitted")
		}
		if !validPrincipal(p, uid) {
			return refuse("role_not_permitted")
		}
		if err := b.acquire(ctx, v); err != nil {
			return err
		}
		defer func() { b.gate <- struct{}{} }()
		if p.Role == "service" && !b.serviceBound(p) {
			return refuse("role_not_permitted")
		}
		return ctx.Err()
	})
	if err != nil {
		var refusal *wire.Error
		if errors.As(err, &refusal) && refusal.Code == "principal_ledger_mismatch" {
			return Principal{}, refuse("principal_ledger_mismatch")
		}
		return Principal{}, refuse("role_not_permitted")
	}
	return p, nil
}

// A supplied clock owns qualified monotonic progression. The default projects
// consumed wall time along Go's monotonic clock, so a backward wall step cannot
// extend the 900-second cap or the containment window inside this process.
func (b *Broker) evaluation() time.Time {
	n := b.now().UTC()
	if b.realClock {
		floor := b.anchorWall.Add(time.Since(b.anchorMono))
		if n.Before(floor) {
			n = floor
		} else {
			b.anchorWall = n
			b.anchorMono = time.Now()
		}
	}
	if n.After(b.watermark) {
		b.watermark = n
	}
	return b.watermark.UTC()
}
func (b *Broker) activeBinding(p Principal, account string) *wire.ServiceBindingRecord {
	for _, s := range b.bindings {
		if s.State == "active" && s.UID == p.UID && s.Generation == p.Generation && s.Service == p.Service && s.Account == account {
			return s
		}
	}
	return nil
}
func (b *Broker) held(account string) *wire.AccountHoldRecord {
	for _, h := range b.holds {
		if h.Account == account && h.State == "active" {
			return h
		}
	}
	return nil
}
func (b *Broker) own(p Principal, id string) (*wire.ServiceLeaseRecord, error) {
	l := b.leases[id]
	if l == nil || p.Role != "service" || l.UID != p.UID || l.Generation != p.Generation || l.Service != p.Service {
		return nil, refuse("lease_not_owner")
	}
	return l, nil
}
func (b *Broker) Call(ctx context.Context, p Principal, method string, raw json.RawMessage, publish func(any) error) error {
	if b == nil || publish == nil {
		return refuse("lease_owner_unavailable")
	}
	// A recorded bind outcome grants no new authority. Resolve it using only
	// current identity/operator admission before fetching use-authority evidence.
	if method == "service.bind" {
		resolved := false
		err := b.authority.WithIdentity(ctx, func(v View) error {
			current, e := v.Principal(p.UID)
			if e != nil || !validPrincipal(current, p.UID) {
				return refuse("principal_ledger_mismatch")
			}
			if current != p || p.Role != "operator" || !v.OperatorAct(p, method, raw) {
				return refuse("role_not_permitted")
			}
			var r wire.ServiceBind
			if decode(raw, &r, "operation_id", "service_name", "uid", "service_generation", "account", "kind", "installation_policy_digest") != nil {
				return refuse("request_malformed")
			}
			if err := b.acquire(ctx, v); err != nil {
				return err
			}
			defer func() { b.gate <- struct{}{} }()
			if b.failed {
				return refuse("lease_owner_unavailable")
			}
			o, e := b.replay(p, method, r.OperationID, raw)
			if e != nil {
				return e
			}
			if o == nil {
				return nil
			}
			resolved = true
			return b.call(ctx, v, p, method, raw, publish)
		})
		if err != nil {
			if ctx.Err() != nil {
				return refuse("request_deadline_exceeded")
			}
			return known(err, "principal_ledger_mismatch")
		}
		if resolved {
			return nil
		}
	}
	// Acquire external evidence before the state lock (R-LOCK). A hold needs no
	// current caller/grant/vendor evidence; only its own protected identity.
	ran := false
	run := func(v View) error {
		ran = true
		if err := b.acquire(ctx, v); err != nil {
			return err
		}
		defer func() { b.gate <- struct{}{} }()
		if ctx.Err() != nil {
			return refuse("request_deadline_exceeded")
		}
		current, err := v.Principal(p.UID)
		if err != nil || !validPrincipal(current, p.UID) {
			return refuse("principal_ledger_mismatch")
		}
		if current != p {
			if p.Role == "service" && current.Role == "service" {
				switch method {
				case "service.lease.request":
					return refuse("principal_ledger_mismatch")
				case "service.lease.renew", "service.lease.release", "event.report", "service.revocation.check", "account.hold":
					return &staleConnectionError{wire.Refuse("lease_not_owner")}
				}
			}
			return refuse("role_not_permitted")
		}
		if b.failed {
			if method == "service.revocation.check" {
				var r wire.ServiceLeaseID
				if decode(raw, &r, "service_lease_id") != nil {
					return refuse("request_malformed")
				}
				if _, e := b.own(p, r.LeaseID); e != nil {
					return e
				}
				return poll(publish, "unavailable", v.Sequence())
			}
			if method != "account.hold" || p.Role != "service" {
				return refuse("lease_owner_unavailable")
			}
			if e := b.recoverHold(p, raw); e != nil {
				return e
			}
		}
		return b.call(ctx, v, p, method, raw, publish)
	}
	var err error
	if method == "service.lease.request" || method == "service.lease.renew" || method == "service.bind" || method == "service.revocation.check" {
		err = b.authority.WithCurrent(ctx, run)
	} else {
		err = b.authority.WithIdentity(ctx, run)
	}
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return refuse("request_deadline_exceeded")
	}
	if ran {
		return known(err, "lease_owner_unavailable")
	}
	// An unavailable revocation read is published only using the provider's own
	// baseline unavailable-sequence representation, never a locally invented one.
	if method == "service.revocation.check" {
		fallbackErr := b.authority.WithIdentity(ctx, func(v View) error {
			if err := b.acquire(ctx, v); err != nil {
				return err
			}
			defer func() { b.gate <- struct{}{} }()
			current, e := v.Principal(p.UID)
			if e != nil || current != p {
				return &staleConnectionError{wire.Refuse("lease_not_owner")}
			}
			var r wire.ServiceLeaseID
			if decode(raw, &r, "service_lease_id") != nil {
				return refuse("request_malformed")
			}
			if _, e = b.own(p, r.LeaseID); e != nil {
				return e
			}
			return poll(publish, "unavailable", v.Sequence())
		})
		if fallbackErr != nil {
			return known(fallbackErr, "lease_owner_unavailable")
		}
		return nil
	}
	// Identity was settled before a fresh bind's current-policy read. Its
	// unreadable policy is section 5.1 step 5, not a caller revocation failure.
	if method == "service.bind" {
		return known(err, "service_binding_mismatch")
	}
	if method == "service.lease.request" || method == "service.lease.renew" {
		return known(err, "revocation_state_unavailable")
	}
	// Identity-only methods have no caller/use-authority read (section 2.2).
	return known(err, "principal_ledger_mismatch")
}

// decode requires every closed member, including uid zero, and rejects nulls.
func decode(raw json.RawMessage, out any, keys ...string) error {
	m, err := wire.Parse(raw)
	if err != nil || len(m) != len(keys) {
		return refuse("request_malformed")
	}
	for _, k := range keys {
		if v, ok := m[k]; !ok || v == nil {
			return refuse("request_malformed")
		}
	}
	if json.Unmarshal(raw, out) != nil {
		return refuse("request_malformed")
	}
	return nil
}
func (b *Broker) replay(p Principal, method, id string, raw json.RawMessage) (*wire.ServiceOperation, error) {
	if !wire.ASCII(id, 128) {
		return nil, refuse("request_malformed")
	}
	for _, s := range b.states {
		for i := range s.Operations {
			o := &s.Operations[i]
			if o.Principal == principalRef(p) && o.Method == method && o.ID == id {
				if !bytes.Equal(o.Arguments, raw) {
					return nil, refuse("service_operation_conflict")
				}
				return o, nil
			}
		}
	}
	return nil, nil
}
func randomID() (string, error) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return "", refuse("lease_owner_unavailable")
	}
	return hex.EncodeToString(id[:]), nil
}
func (b *Broker) save(account string, p Principal, method, id string, raw json.RawMessage, result any) error {
	s := *b.states[account]
	if s.Revision >= 9007199254740990 {
		return refuse("lease_owner_unavailable")
	}
	s.Revision++
	s.Watermark = b.evaluation()
	s.Bindings = []wire.ServiceBindingRecord{}
	s.Leases = []wire.ServiceLeaseRecord{}
	s.Holds = []wire.AccountHoldRecord{}
	for _, r := range b.bindings {
		if r.Account == account {
			s.Bindings = append(s.Bindings, *r)
		}
	}
	for _, r := range b.leases {
		if r.Account == account {
			s.Leases = append(s.Leases, *r)
		}
	}
	for _, r := range b.holds {
		if r.Account == account {
			s.Holds = append(s.Holds, *r)
		}
	}
	sort.Slice(s.Bindings, func(i, j int) bool { return s.Bindings[i].ID < s.Bindings[j].ID })
	sort.Slice(s.Leases, func(i, j int) bool { return s.Leases[i].ID < s.Leases[j].ID })
	sort.Slice(s.Holds, func(i, j int) bool { return s.Holds[i].ID < s.Holds[j].ID })
	if method != "" {
		r, err := wire.Encode(result)
		if err != nil {
			return refuse("lease_owner_unavailable")
		}
		s.Operations = append(append([]wire.ServiceOperation(nil), s.Operations...), wire.ServiceOperation{Principal: principalRef(p), Method: method, ID: id, Arguments: append(json.RawMessage(nil), raw...), Result: r, At: s.Watermark})
	}
	if b.accounts[account].StoreServiceState(s) != nil {
		b.failed = true
		return refuse("lease_owner_unavailable")
	}
	b.states[account] = &s
	b.watermark = s.Watermark
	return nil
}
func decodedResult(o *wire.ServiceOperation) any {
	var out any
	_ = json.Unmarshal(o.Result, &out)
	return out
}
func bindingResult(s *wire.ServiceBindingRecord) any {
	return map[string]any{"service_binding_id": s.ID, "service_name": s.Service, "uid": s.UID, "service_generation": s.Generation, "account": s.Account, "kind": s.Kind, "installation_policy_digest": s.PolicyDigest, "state": s.State}
}
func (b *Broker) call(ctx context.Context, v View, p Principal, method string, raw json.RawMessage, publish func(any) error) error {
	switch method {
	case "service.bind":
		var r wire.ServiceBind
		if decode(raw, &r, "operation_id", "service_name", "uid", "service_generation", "account", "kind", "installation_policy_digest") != nil {
			return refuse("request_malformed")
		}
		if p.Role != "operator" || !v.OperatorAct(p, method, raw) {
			return refuse("role_not_permitted")
		}
		o, err := b.replay(p, method, r.OperationID, raw)
		if err != nil {
			return err
		}
		if o != nil {
			var x struct {
				ID string `json:"service_binding_id"`
			}
			_ = json.Unmarshal(o.Result, &x)
			if b.bindings[x.ID] == nil {
				return refuse("lease_owner_unavailable")
			}
			return publish(bindingResult(b.bindings[x.ID]))
		}
		if r.Service != Gateway || r.Kind != b.credentialKind {
			return refuse("bind_target_invalid")
		}
		target, e := v.Principal(r.UID)
		if e != nil || !validPrincipal(target, r.UID) || target.Role != "service" || target.Generation != r.Generation {
			return refuse("principal_ledger_mismatch")
		}
		if b.accounts[r.Account] == nil {
			return refuse("account_unknown")
		}
		info, infoErr := b.accounts[r.Account].ServiceAccount()
		if infoErr != nil {
			return refuse("lease_owner_unavailable")
		}
		if info.Kind != r.Kind {
			return refuse("service_binding_mismatch")
		}
		if !validBindingForKind(r.ServiceBinding, b.credentialKind) {
			return refuse("service_binding_mismatch")
		}
		e = v.Service(r.ServiceBinding)
		if e != nil {
			return refuse("service_binding_mismatch")
		}
		for _, s := range b.bindings {
			if s.State == "active" && s.Service == r.Service && s.UID == r.UID && s.Generation == r.Generation && s.Account == r.Account && s.Kind == r.Kind {
				return refuse("service_binding_mismatch")
			}
		}
		id, e := randomID()
		if e != nil {
			return e
		}
		if b.bindings[id] != nil {
			return refuse("lease_owner_unavailable")
		}
		s := &wire.ServiceBindingRecord{ID: id, Service: r.Service, UID: r.UID, Generation: r.Generation, Account: r.Account, Kind: r.Kind, PolicyDigest: r.PolicyDigest, CreatedBy: principalRef(p), OperationID: r.OperationID, CreatedAt: b.evaluation(), State: "active"}
		b.bindings[id] = s
		out := bindingResult(s)
		if e = b.save(r.Account, p, method, r.OperationID, raw, out); e != nil {
			return e
		}
		return publish(out)
	case "service.unbind":
		var r wire.ServiceUnbind
		if decode(raw, &r, "operation_id", "service_binding_id") != nil {
			return refuse("request_malformed")
		}
		if p.Role != "operator" || !v.OperatorAct(p, method, raw) {
			return refuse("role_not_permitted")
		}
		o, e := b.replay(p, method, r.OperationID, raw)
		if e != nil {
			return e
		}
		if o != nil {
			return publish(decodedResult(o))
		}
		s := b.bindings[r.BindingID]
		if s == nil {
			return refuse("service_binding_unknown")
		}
		if s.State != "active" {
			return refuse("service_binding_unknown")
		}
		now := b.evaluation()
		s.State = "removed"
		s.RemovedAt = &now
		s.RemovedOperationID = &r.OperationID
		if b.terminalContainment {
			for _, lease := range b.leases {
				if lease.BindingID == s.ID && lease.State == "active" {
					lease.State = "revoked"
				}
			}
		}
		out := map[string]any{"service_binding_id": s.ID, "state": "removed"}
		if e = b.save(s.Account, p, method, r.OperationID, raw, out); e != nil {
			return e
		}
		b.closeConnections(s.UID, s.Generation)
		return publish(out)
	case "account.hold.lift":
		var r wire.ServiceLift
		if decode(raw, &r, "operation_id", "hold_id", "account") != nil {
			return refuse("request_malformed")
		}
		if (p.Role != "operator" && p.Role != "owner") || !v.Owner(p.UID, r.Account) || !v.OperatorAct(p, method, raw) {
			return refuse("role_not_permitted")
		}
		o, e := b.replay(p, method, r.OperationID, raw)
		if e != nil {
			return e
		}
		if o != nil {
			return publish(decodedResult(o))
		}
		h := b.held(r.Account)
		if h == nil || h.ID != r.HoldID {
			return refuse("account_hold_not_found")
		}
		now, owner := b.evaluation(), principalRef(p)
		h.State = "lifted"
		h.LiftedAt = &now
		h.LiftedBy = &owner
		h.LiftOperationID = &r.OperationID
		out := map[string]any{"hold_id": h.ID, "account": h.Account, "state": "lifted", "lifted_at": now}
		if e = b.save(h.Account, p, method, r.OperationID, raw, out); e != nil {
			return e
		}
		return publish(out)
	case "status", "account.describe":
		var r struct {
			Account string `json:"account"`
		}
		if method == "status" {
			if decode(raw, &struct{}{}) != nil {
				return refuse("request_malformed")
			}
		} else if decode(raw, &r, "account") != nil {
			return refuse("request_malformed")
		}
		if p.Role != "operator" && p.Role != "owner" && !(p.Role == "observer" && method == "status") {
			return refuse("role_not_permitted")
		}
		holds := []any{}
		for _, h := range b.holds {
			if h.State == "active" && (r.Account == "" || h.Account == r.Account) && (p.Role == "operator" && method == "status" || p.Role == "observer" || v.Owner(p.UID, h.Account)) {
				holds = append(holds, h.Metadata())
			}
		}
		if method == "account.describe" && !v.Owner(p.UID, r.Account) {
			return refuse("role_not_permitted")
		}
		return publish(map[string]any{"holds": holds})
	}
	if p.Role != "service" {
		if method == "service.lease.renew" || method == "service.lease.release" || method == "service.revocation.check" || method == "event.report" {
			return refuse("lease_not_owner")
		}
		return refuse("role_not_permitted")
	}
	switch method {
	case "service.lease.request":
		var r wire.ServiceRequest
		if decode(raw, &r, "operation_id", "account", "agent_uid", "agent_generation", "launch_id") != nil || !validCaller(r.ServiceCaller) {
			return refuse("request_malformed")
		}
		o, e := b.replay(p, method, r.OperationID, raw)
		if e != nil {
			return e
		}
		if o != nil {
			return b.replayMaterial(ctx, v, p, o, publish)
		}
		s := b.activeBinding(p, r.Account)
		if s == nil {
			return refuse("service_binding_unknown")
		}
		id, e := randomID()
		if e != nil {
			return e
		}
		if b.leases[id] != nil {
			return refuse("lease_owner_unavailable")
		}
		l := &wire.ServiceLeaseRecord{ID: id, BindingID: s.ID, Service: s.Service, UID: s.UID, Generation: s.Generation, Account: r.Account, Harness: "claude_code", Kind: b.credentialKind, AgentUID: r.UID, AgentGeneration: r.Generation, LaunchID: r.LaunchID, OperationID: r.OperationID, State: "active"}
		return b.issue(ctx, v, p, l, method, r.OperationID, raw, publish)
	case "service.lease.renew":
		var r wire.ServiceRenew
		if decode(raw, &r, "operation_id", "service_lease_id") != nil {
			return refuse("request_malformed")
		}
		o, e := b.replay(p, method, r.OperationID, raw)
		if e != nil {
			return e
		}
		if o != nil {
			return b.replayMaterial(ctx, v, p, o, publish)
		}
		l, e := b.own(p, r.LeaseID)
		if e != nil {
			return e
		}
		if s := b.activeBinding(p, l.Account); s == nil {
			return refuse("lease_not_owner")
		} else if s.ID != l.BindingID {
			return refuse("service_binding_unknown")
		}
		if l.State != "active" || !b.evaluation().Before(l.Until) {
			return refuse("lease_not_active")
		}
		return b.issue(ctx, v, p, l, method, r.OperationID, raw, publish)
	case "service.lease.release", "service.revocation.check", "event.report":
		var r struct {
			LeaseID string          `json:"service_lease_id"`
			Event   json.RawMessage `json:"event,omitempty"`
		}
		keys := []string{"service_lease_id"}
		if method == "event.report" {
			keys = append(keys, "event")
		}
		if decode(raw, &r, keys...) != nil || !wire.ASCII(r.LeaseID, 128) {
			return refuse("request_malformed")
		}
		l, e := b.own(p, r.LeaseID)
		if e != nil {
			return e
		}
		if method == "service.revocation.check" {
			return b.poll(ctx, v, l, publish)
		}
		if method == "service.lease.release" {
			if l.State == "released" {
				return publish(map[string]any{"service_lease_id": l.ID, "state": "released"})
			}
			if l.State != "active" || !b.evaluation().Before(l.Until) {
				return refuse("lease_not_active")
			}
			l.State = "released"
		} else {
			if !v.Event(r.Event) {
				return refuse("request_malformed")
			}
			if l.State != "active" || !b.evaluation().Before(l.Until) {
				return refuse("lease_not_active")
			}
		}
		out := map[string]any{"service_lease_id": l.ID, "state": l.State}
		// No replay id is assigned to these methods. Their typed event/end-time
		// evidence is retained under a fresh internal journal identity.
		id, e := randomID()
		if e != nil {
			return e
		}
		if e = b.save(l.Account, p, method, id, raw, out); e != nil {
			return e
		}
		return publish(out)
	case "account.hold":
		var r wire.ServiceHold
		if decode(raw, &r, "operation_id", "service_lease_id", "account", "reason_code") != nil {
			return refuse("request_malformed")
		}
		o, e := b.replay(p, method, r.OperationID, raw)
		if e != nil {
			return e
		}
		if o != nil {
			var recorded struct {
				ID string `json:"hold_id"`
			}
			if json.Unmarshal(o.Result, &recorded) != nil || b.holds[recorded.ID] == nil {
				return refuse("lease_owner_unavailable")
			}
			return publish(b.holds[recorded.ID].Metadata())
		}
		l, e := b.own(p, r.LeaseID)
		if e != nil {
			return e
		}
		if !b.holdEligible(l) {
			return refuse("lease_not_active")
		}
		s := b.bindings[l.BindingID]
		if s == nil || r.Account != l.Account || s.Account != l.Account {
			return refuse("service_binding_mismatch")
		}
		if r.Reason != "leak_match" {
			return refuse("hold_reason_unknown")
		}
		h := b.held(l.Account)
		if h == nil {
			id, e := randomID()
			if e != nil {
				return e
			}
			if b.holds[id] != nil {
				return refuse("lease_owner_unavailable")
			}
			h = &wire.AccountHoldRecord{ID: id, Account: l.Account, Reason: r.Reason, Service: l.Service, UID: l.UID, Generation: l.Generation, BindingID: l.BindingID, LeaseID: l.ID, OperationID: r.OperationID, PlacedAt: b.evaluation(), State: "active"}
			b.holds[id] = h
		}
		// Even when returning an existing hold, retain this operation's correlation
		// in the journal without creating or changing the hold record.
		b.pendingHold = &pendingHold{principal: principalRef(p), account: l.Account, arguments: append(json.RawMessage(nil), raw...)}
		if b.terminalContainment {
			for _, lease := range b.leases {
				if lease.Account == l.Account && lease.State == "active" {
					lease.State = "revoked"
				}
			}
		}
		if e = b.save(l.Account, p, method, r.OperationID, raw, h.Metadata()); e != nil {
			return refuse("account_hold_unknown")
		}
		b.pendingHold = nil
		// Holds neither require caller/use authority nor rewrite any lease record.
		return publish(h.Metadata())
	}
	return refuse("role_not_permitted")
}
func (b *Broker) holdEligible(l *wire.ServiceLeaseRecord) bool {
	now := b.evaluation()
	if l.State == "active" && now.Before(l.Until) {
		return true
	}
	end := l.Until
	if l.State == "released" || l.State == "revoked" {
		end = time.Time{}
		for _, o := range b.states[l.Account].Operations {
			if o.Method == "service.lease.release" {
				var r wire.ServiceLeaseID
				if json.Unmarshal(o.Arguments, &r) == nil && r.LeaseID == l.ID {
					end = o.At
				}
			}
		}
		if end.IsZero() {
			return false
		}
	} else if l.State != "active" && l.State != "expired" {
		return false
	}
	return !now.Before(end) && now.Sub(end) <= b.lifetime
}
func (b *Broker) authorities(ctx context.Context, v View, l *wire.ServiceLeaseRecord) (time.Time, error) {
	s := b.bindings[l.BindingID]
	if s == nil || s.State != "active" {
		return time.Time{}, refuse("service_binding_unknown")
	}
	e := v.Service(s.Binding())
	if e != nil {
		return time.Time{}, known(e, "service_binding_mismatch")
	}
	callerUntil, bindingID, e := v.Caller(s.Binding(), l.Caller())
	if e != nil {
		return time.Time{}, known(e, "lease_not_authorised")
	}
	if !wire.ASCII(bindingID, 128) {
		return time.Time{}, refuse("lease_unbound")
	}
	if l.AgentBindingID != "" && l.AgentBindingID != bindingID {
		return time.Time{}, refuse("lease_unbound")
	}
	if ctx.Err() != nil {
		return time.Time{}, refuse("request_deadline_exceeded")
	}
	now := b.evaluation()
	until := now.Add(b.lifetime)
	for _, t := range []time.Time{callerUntil} {
		if t.Before(until) {
			until = t
		}
	}
	if !now.Before(until) {
		return time.Time{}, refuse("lease_not_active")
	}
	if l.AgentBindingID == "" {
		l.AgentBindingID = bindingID
	}
	return until, nil
}
func known(e error, fallback string) error {
	var stale *staleConnectionError
	if errors.As(e, &stale) {
		return &staleConnectionError{wire.Refuse(stale.refusal.Code)}
	}
	if r, ok := e.(*wire.Error); ok {
		return refuse(r.Code)
	}
	return refuse(fallback)
}
func (b *Broker) issue(ctx context.Context, v View, p Principal, l *wire.ServiceLeaseRecord, method, op string, raw json.RawMessage, publish func(any) error) error {
	until, e := b.authorities(ctx, v, l)
	if e != nil {
		return e
	}
	a := b.accounts[l.Account]
	info, e := a.ServiceAccount()
	if e != nil {
		return refuse("lease_owner_unavailable")
	}
	if info.Account != l.Account || info.Kind != b.credentialKind || info.Harness != "claude_code" {
		return refuse("lease_harness_mismatch")
	}
	switch info.State {
	case "active":
	case "revoked":
		return refuse("lease_account_revoked")
	case "reauth_required":
		return refuse("lease_reauth_required")
	default:
		return refuse("lease_owner_unavailable")
	}
	if info.ExpiresAt != nil && !b.evaluation().Before(*info.ExpiresAt) {
		return refuse("lease_reauth_required")
	}
	if b.held(l.Account) != nil {
		return refuse("account_hold_active")
	}
	expiry := info.ExpiresAt
	if expiry != nil && expiry.Before(until) {
		until = *expiry
	}
	if !b.evaluation().Before(until) {
		return refuse("lease_reauth_required")
	}
	l.Until = until
	if method == "service.lease.renew" {
		l.LastRenewalOperationID = &op
	}
	b.leases[l.ID] = l
	result := map[string]any{"service_lease_id": l.ID, "authorized_until": until}
	if e = b.save(l.Account, p, method, op, raw, result); e != nil {
		return e
	}
	return b.material(ctx, v, l, until, expiry, publish)
}
func (b *Broker) replayMaterial(ctx context.Context, v View, p Principal, o *wire.ServiceOperation, publish func(any) error) error {
	var r struct {
		ID    string    `json:"service_lease_id"`
		Until time.Time `json:"authorized_until"`
	}
	if json.Unmarshal(o.Result, &r) != nil {
		return refuse("lease_owner_unavailable")
	}
	l, e := b.own(p, r.ID)
	if e != nil {
		return e
	}
	if l.State != "active" || !b.evaluation().Before(r.Until) || !b.evaluation().Before(l.Until) {
		return refuse("lease_not_active")
	}
	currentUntil, e := b.authorities(ctx, v, l)
	if e != nil {
		return e
	}
	if b.strictReplay && r.Until.After(currentUntil) {
		return refuse("lease_not_authorised")
	}
	info, e := b.accounts[l.Account].ServiceAccount()
	if e != nil {
		return refuse("lease_owner_unavailable")
	}
	if info.Kind != l.Kind || info.Harness != l.Harness {
		return refuse("lease_harness_mismatch")
	}
	switch info.State {
	case "active":
	case "revoked":
		return refuse("lease_account_revoked")
	case "reauth_required":
		return refuse("lease_reauth_required")
	default:
		return refuse("lease_owner_unavailable")
	}
	if info.ExpiresAt != nil && !b.evaluation().Before(*info.ExpiresAt) {
		return refuse("lease_reauth_required")
	}
	if b.held(l.Account) != nil {
		return refuse("account_hold_active")
	}
	expiry := info.ExpiresAt
	return b.material(ctx, v, l, r.Until, expiry, publish)
}
func (b *Broker) material(ctx context.Context, v View, l *wire.ServiceLeaseRecord, until time.Time, expiry *time.Time, publish func(any) error) error {
	var identityErr error
	err := b.accounts[l.Account].Publish(ctx, until, b.evaluation, func(token []byte) error {
		if ctx.Err() != nil || !b.evaluation().Before(until) {
			return refuse("lease_not_active")
		}
		current, err := v.Principal(l.UID)
		if err != nil || current != (Principal{UID: l.UID, Generation: l.Generation, Service: l.Service, Role: "service"}) {
			identityErr = refuse("principal_ledger_mismatch")
			return identityErr
		}
		err = publish(wire.ServiceLease{LeaseID: l.ID, Account: l.Account, Harness: l.Harness, Kind: l.Kind, Payload: wire.ServicePayload{Kind: l.Kind, Value: string(token)}, TokenExpiresAt: expiry, AuthorizedUntil: until.UTC().Format(time.RFC3339Nano), Renewable: true})
		if err == nil {
			if identity, ok := v.(identityWindow); ok {
				identity.materialReleased()
			}
		}
		return err
	})
	if identityErr != nil {
		return identityErr
	}
	// A lost/partial reply leaves a durable outcome; replay repeats final checks.
	// It never revokes or extends the record merely to compensate for transport.
	if err != nil {
		return refuse("lease_owner_unavailable")
	}
	return nil
}
func poll(publish func(any) error, verdict string, seq json.RawMessage) error {
	if len(seq) == 0 || !json.Valid(seq) {
		return refuse("revocation_state_unavailable")
	}
	return publish(map[string]any{"verdict": verdict, "revocation_sequence": seq})
}
func (b *Broker) poll(ctx context.Context, v View, l *wire.ServiceLeaseRecord, publish func(any) error) error {
	verdict := "not_revoked"
	s := b.bindings[l.BindingID]
	if l.State != "active" || !b.evaluation().Before(l.Until) || s == nil || s.State != "active" || b.held(l.Account) != nil {
		verdict = "revoked"
	} else if _, e := b.authorities(ctx, v, l); e != nil {
		verdict = "unavailable"
		if r, ok := e.(*wire.Error); ok {
			switch r.Code {
			case "lease_unbound", "lease_grant_revoked", "lease_caller_revoked", "lease_account_revoked", "service_binding_unknown":
				verdict = "revoked"
			}
		}
	}
	if verdict == "not_revoked" {
		info, e := b.accounts[l.Account].ServiceAccount()
		if e != nil {
			verdict = "unavailable"
		} else if info.State == "revoked" {
			verdict = "revoked"
		}
	}
	return poll(publish, verdict, v.Sequence())
}
