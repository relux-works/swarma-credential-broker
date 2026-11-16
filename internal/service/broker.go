// Package service implements Core's secret-free service decisions, inactive
// until a protected current authority provider is installed by the embedder.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const Gateway = "credential-gateway"
const Kind = "claude-oauth-token"

// V0LeaseCeiling is the named v0 ceiling selected by Core for this delivery.
const V0LeaseCeiling = 900 * time.Second

// Principal is obtained from a protected current user-manager record indexed
// by the kernel-observed UID, never from hello or request fields.
// SPEC-PENDING: generation encoding and operator/owner record integration.
type Principal struct {
	UID        uint32 `json:"uid"`
	Role       string `json:"role"`
	Generation string `json:"generation"`
	Service    string `json:"service,omitempty"`
}

// View supplies independently checked service and originating-caller authority.
// Each result is an exclusive deadline; errors/missing evidence always refuse.
// Service verifies the active local managed service generation, kind, account
// and policy digest. Caller verifies the active local agent generation, launch,
// selected secret-free lane and current narrowing authority for that account.
// Neither request fields nor a service grant can stand in for caller authority.
type View interface {
	Principal(uint32) (Principal, error)
	Service(wire.ServiceBinding) (time.Time, error)
	Caller(wire.ServiceBinding, wire.ServiceCaller) (time.Time, error)
	Owner(uint32, string) bool
}

// Authority must hold current-generation, revocation, selected-policy and time
// evidence stable through fn, including the final material write. Replacing or
// revoking that evidence must exclude or interrupt active writes before return.
// SPEC-PENDING: protected user-manager/authority reader and settlement contract;
// there is no default accepting provider or standalone daemon activation.
type Authority interface {
	WithCurrent(context.Context, func(View) error) error
}

type Account interface {
	ExpiresAt() (*time.Time, error)
	Publish(context.Context, time.Time, func() time.Time, func([]byte) error) error
	Hold() error
	LiftHold() error
	LoadServiceBinding() (wire.ServiceBindingState, error)
	StoreServiceBinding(wire.ServiceBindingState) error
}

type lease struct {
	id       string
	binding  wire.ServiceBinding
	revision uint64
	caller   wire.ServiceCaller
	until    time.Time
	revoked  bool
}

type Broker struct {
	gate      chan struct{}
	authority Authority
	accounts  map[string]Account
	bindings  map[string]wire.ServiceBindingState
	leases    map[string]*lease
	now       func() time.Time
	failed    bool
}

// New loads only protected binding metadata. Leases deliberately do not survive
// process replacement: SPEC-PENDING restart/recovery and lease-record schema.
// The authority and custody objects are trusted, exclusively owned dependencies.
func New(authority Authority, accounts map[string]Account, now func() time.Time) (*Broker, error) {
	if authority == nil || len(accounts) == 0 {
		return nil, refuse("lease_owner_unavailable")
	}
	if now == nil {
		now = time.Now
	}
	b := &Broker{gate: make(chan struct{}, 1), authority: authority, accounts: map[string]Account{}, bindings: map[string]wire.ServiceBindingState{}, leases: map[string]*lease{}, now: now}
	b.gate <- struct{}{}
	for label, a := range accounts {
		if a == nil || !wire.ASCII(label, 128) {
			return nil, refuse("lease_owner_unavailable")
		}
		s, err := a.LoadServiceBinding()
		if err != nil || s.Revision > 9007199254740990 || s.Revision != 0 && (!validBinding(s.Binding) || s.Binding.Account != label) || s.Bound && s.Revision == 0 {
			return nil, refuse("lease_owner_unavailable")
		}
		b.accounts[label], b.bindings[label] = a, s
	}
	return b, nil
}

// SPEC-PENDING: reuse existing fixed broker refusal codes, without diagnostics.
func refuse(code string) error { return wire.Refuse(code) }
func validBinding(v wire.ServiceBinding) bool {
	return v.Service == Gateway && v.Kind == Kind && wire.ASCII(v.Generation, 128) && wire.ASCII(v.Account, 128) && hash(v.PolicyDigest)
}
func hash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
	case "operator", "owner", "worker", "orchestrator":
		return p.Service == ""
	}
	return false
}

func (b *Broker) Open(ctx context.Context, uid uint32) (Principal, error) {
	var p Principal
	if b == nil {
		return p, refuse("role_not_permitted")
	}
	err := b.authority.WithCurrent(ctx, func(v View) error {
		var err error
		p, err = v.Principal(uid)
		if err != nil || !validPrincipal(p, uid) {
			return refuse("role_not_permitted")
		}
		return ctx.Err()
	})
	if err != nil {
		return Principal{}, refuse("role_not_permitted")
	}
	return p, nil
}

// Call never returns material. The only material-bearing result goes to publish
// inside the final authority/custody gates. The transport must bound its write.
func (b *Broker) Call(ctx context.Context, principal Principal, method string, raw json.RawMessage, publish func(any) error) error {
	if b == nil || publish == nil {
		return refuse("lease_owner_unavailable")
	}
	select {
	case <-ctx.Done():
		return refuse("request_deadline_exceeded")
	case <-b.gate:
	}
	defer func() { b.gate <- struct{}{} }()
	if b.failed {
		return refuse("lease_owner_unavailable")
	}
	err := b.authority.WithCurrent(ctx, func(v View) error {
		p, err := v.Principal(principal.UID)
		if err != nil || !validPrincipal(p, principal.UID) || p != principal {
			return refuse("role_not_permitted")
		}
		if ctx.Err() != nil {
			return refuse("request_deadline_exceeded")
		}
		switch method {
		case "service.bind", "service.unbind":
			if p.Role != "operator" {
				return refuse("role_not_permitted")
			}
			var r wire.ServiceBinding
			if wire.Decode(raw, &r) != nil || !validBinding(r) {
				return refuse("lease_not_authorised")
			}
			return b.bind(ctx, v, method == "service.bind", r, publish)
		case "account.hold.lift":
			var r wire.ServiceLift
			if p.Role != "owner" {
				return refuse("role_not_permitted")
			}
			if wire.Decode(raw, &r) != nil || !v.Owner(p.UID, r.Account) {
				return refuse("lease_not_authorised")
			}
			a := b.accounts[r.Account]
			if a == nil {
				return refuse("lease_account_unknown")
			}
			b.revoke(r.Account)
			if a.LiftHold() != nil {
				return refuse("lease_owner_unavailable")
			}
			return publish(map[string]any{"state": "enrolled"})
		default:
			if p.Role != "service" {
				return refuse("role_not_permitted")
			}
		}
		switch method {
		case "service.lease.request":
			var r wire.ServiceRequest
			if wire.Decode(raw, &r) != nil || !validCaller(r.Caller) || r.Kind != Kind || !hash(r.PolicyDigest) {
				return refuse("lease_not_authorised")
			}
			s := b.bindings[r.Caller.Account]
			if !s.Bound || s.Binding.UID != p.UID || s.Binding.Generation != p.Generation || s.Binding.Kind != r.Kind || s.Binding.PolicyDigest != r.PolicyDigest {
				return refuse("lease_not_authorised")
			}
			// SPEC-PENDING: bounded in-memory lease capacity, random 128-bit IDs;
			// exhausted capacity refuses rather than evicting a live lease.
			// Ended IDs remain tombstones until process replacement.
			if len(b.leases) >= 256 {
				return refuse("lease_owner_unavailable")
			}
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return refuse("lease_owner_unavailable")
			}
			l := &lease{id: hex.EncodeToString(id[:]), binding: s.Binding, revision: s.Revision, caller: r.Caller}
			if b.leases[l.id] != nil {
				return refuse("lease_owner_unavailable")
			}
			return b.issue(ctx, v, l, publish)
		case "service.lease.renew", "service.revocation.check", "service.lease.release":
			var r wire.ServiceLeaseID
			if wire.Decode(raw, &r) != nil || !wire.ASCII(r.LeaseID, 128) {
				return refuse("lease_not_authorised")
			}
			l := b.leases[r.LeaseID]
			if l == nil || l.binding.UID != p.UID || l.binding.Generation != p.Generation {
				return refuse("lease_not_owner")
			}
			if method == "service.revocation.check" {
				state := "not_revoked"
				if l.revoked || !b.now().Before(l.until) {
					state = "revoked"
				} else if _, err := b.current(ctx, v, l); err != nil {
					state = "unavailable"
				}
				// SPEC-PENDING: poll result vocabulary; all unavailable evidence
				// is conservatively closed, never reported not_revoked.
				return publish(map[string]any{"lease_id": l.id, "state": state})
			}
			if _, err := b.current(ctx, v, l); err != nil {
				return err
			}
			if method == "service.lease.release" {
				l.revoked = true
				return publish(map[string]any{"lease_id": l.id, "state": "released"})
			}
			return b.issue(ctx, v, l, publish)
		case "account.hold":
			var r wire.ServiceHold
			if wire.Decode(raw, &r) != nil || r.Reason != "leak_match" {
				return refuse("lease_not_authorised")
			}
			l := b.leases[r.LeaseID]
			if l == nil || l.binding.UID != p.UID || l.binding.Generation != p.Generation {
				return refuse("lease_not_owner")
			}
			if _, err := b.current(ctx, v, l); err != nil {
				return err
			}
			b.revoke(l.binding.Account)
			if b.accounts[l.binding.Account].Hold() != nil {
				return refuse("lease_owner_unavailable")
			}
			// The hold is durable before even constructing its acknowledgment.
			return publish(map[string]any{"account": l.binding.Account, "state": "held"})
		default:
			return refuse("role_not_permitted")
		}
	})
	if err == nil {
		return nil
	}
	if e, ok := err.(*wire.Error); ok {
		return wire.Refuse(e.Code)
	}
	return refuse("lease_owner_unavailable")
}

func (b *Broker) bind(ctx context.Context, v View, bound bool, r wire.ServiceBinding, publish func(any) error) error {
	a := b.accounts[r.Account]
	if a == nil {
		return refuse("lease_account_unknown")
	}
	prior := b.bindings[r.Account]
	if !bound && (!prior.Bound || prior.Binding != r) {
		return refuse("lease_binding_mismatch")
	}
	if bound {
		p, err := v.Principal(r.UID)
		if err != nil || !validPrincipal(p, r.UID) || p.Role != "service" || p.Generation != r.Generation {
			return refuse("lease_not_authorised")
		}
		until, err := v.Service(r)
		if err != nil || !b.now().Before(until) {
			return refuse("lease_not_authorised")
		}
	}
	if ctx.Err() != nil || prior.Revision >= 9007199254740990 {
		return refuse("lease_owner_unavailable")
	}
	b.revoke(r.Account)
	// SPEC-PENDING: every accepted bind creates a successor, including an
	// identical rebind. Tombstones persist; no replacement inherits leases.
	next := wire.ServiceBindingState{Revision: prior.Revision + 1, Bound: bound, Binding: r}
	if a.StoreServiceBinding(next) != nil {
		b.failed = true
		return refuse("lease_owner_unavailable")
	}
	b.bindings[r.Account] = next
	return publish(map[string]any{"bound": bound, "revision": next.Revision})
}

func (b *Broker) revoke(account string) {
	for _, l := range b.leases {
		if l.binding.Account == account {
			l.revoked = true
		}
	}
}

func (b *Broker) authorities(ctx context.Context, v View, l *lease) (time.Time, error) {
	s := b.bindings[l.binding.Account]
	if !s.Bound || s.Binding != l.binding || s.Revision != l.revision || l.revoked || l.caller.Account != l.binding.Account {
		return time.Time{}, refuse("lease_not_active")
	}
	p, err := v.Principal(l.binding.UID)
	if err != nil || p.Role != "service" || !validPrincipal(p, l.binding.UID) || p.Generation != l.binding.Generation {
		return time.Time{}, refuse("lease_not_authorised")
	}
	serviceUntil, serviceErr := v.Service(l.binding)
	callerUntil, callerErr := v.Caller(l.binding, l.caller)
	if serviceErr != nil || callerErr != nil || ctx.Err() != nil {
		return time.Time{}, refuse("lease_not_authorised")
	}
	until := b.now().Add(V0LeaseCeiling)
	for _, t := range []time.Time{serviceUntil, callerUntil} {
		if t.Before(until) {
			until = t
		}
	}
	if !b.now().Before(until) {
		return time.Time{}, refuse("lease_not_active")
	}
	return until, nil
}

func (b *Broker) current(ctx context.Context, v View, l *lease) (time.Time, error) {
	if l.revoked || !b.now().Before(l.until) {
		return time.Time{}, refuse("lease_not_active")
	}
	until, err := b.authorities(ctx, v, l)
	if err != nil {
		return time.Time{}, err
	}
	expiry, err := b.accounts[l.binding.Account].ExpiresAt()
	if err != nil || expiry != nil && !b.now().Before(*expiry) {
		return time.Time{}, refuse("lease_not_active")
	}
	return until, nil
}

func (b *Broker) issue(ctx context.Context, v View, l *lease, publish func(any) error) error {
	until, err := b.authorities(ctx, v, l)
	if err != nil {
		return err
	}
	a := b.accounts[l.binding.Account]
	expiry, err := a.ExpiresAt()
	if err != nil {
		return refuse("lease_not_active")
	}
	if expiry != nil && expiry.Before(until) {
		until = *expiry
	}
	if !b.now().Before(until) {
		return refuse("lease_not_active")
	}
	// Reserve the ID before publication: a partial/lost reply cannot make that
	// ID renewable with unknown delivery. SPEC-PENDING uncertain-write recovery.
	l.until = until
	b.leases[l.id] = l
	err = a.Publish(ctx, until, b.now, func(token []byte) error {
		if ctx.Err() != nil || !b.now().Before(until) {
			return refuse("lease_not_active")
		}
		return publish(wire.ServiceLease{LeaseID: l.id, Account: l.binding.Account, Kind: Kind, AuthorizedUntil: until.UTC().Format(time.RFC3339Nano), Token: string(token)})
	})
	if err != nil {
		l.revoked = true
		return refuse("lease_owner_unavailable")
	}
	return nil
}
