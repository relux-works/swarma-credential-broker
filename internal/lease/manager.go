// Package lease serializes account demand without holding state locks over owner I/O.
package lease

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Kind    string
	LeaseID string
	Arrival time.Time
	At      time.Time
}
type Options struct {
	Observe        func(Event)
	Now            func() time.Time
	RenewTimeout   time.Duration
	RequestTimeout time.Duration
	MaxActive      int
	MaxPending     int
	MaxWaiters     int
}

func (o Options) defaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RenewTimeout == 0 {
		o.RenewTimeout = 8 * time.Second
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = 30 * time.Second
	}
	if o.MaxActive == 0 {
		o.MaxActive = 256
	}
	if o.MaxPending == 0 {
		o.MaxPending = 64
	}
	if o.MaxWaiters == 0 {
		o.MaxWaiters = 2
	}
	return o
}

type Record struct {
	Kind               string       `json:"kind"`
	LeaseID            string       `json:"lease_id"`
	Installation       string       `json:"installation_id"`
	DaemonInstance     string       `json:"daemon_instance_id"`
	Revision           uint64       `json:"revision"`
	UID                uint32       `json:"peer_uid"`
	Account            string       `json:"account"`
	Profile            string       `json:"profile"`
	PolicyGeneration   uint64       `json:"policy_generation"`
	Binding            wire.Binding `json:"credential_binding"`
	LaunchID           string       `json:"launch_id"`
	AuthorizedUntil    time.Time    `json:"authorized_until"`
	OfferedDigest      string       `json:"last_offered_digest"`
	ObservedDigest     string       `json:"client_observed_digest"`
	OfferedGeneration  uint64       `json:"last_offered_generation"`
	ObservedGeneration uint64       `json:"client_observed_generation"`
	State              string       `json:"state"`
}
type Outcome struct {
	Result     any
	Generation uint64
	Err        error
}
type waiter struct {
	id     uint64
	ctx    context.Context
	answer chan Outcome
}
type operation struct {
	arrival    time.Time
	key        string
	method     string
	uid        uint32
	generation uint64
	request    wire.LeaseRequest
	id         string
	rejected   string
	waiters    map[uint64]*waiter
	running    bool
}
type account struct {
	failed  bool
	mu      sync.Mutex
	store   *store.Account
	records map[string]Record
	queue   []*operation
	pending map[string]*operation
	waiters int
	next    uint64
	wake    chan struct{}
}
type Manager struct {
	policyMu     sync.RWMutex
	policy       policy.Policy
	policyFailed bool
	owner        owner.Owner
	store        *store.Store
	accounts     map[string]*account
	options      Options
	instance     string
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func RandomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}
func Digest(token string) string { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func New(p policy.Policy, s *store.Store, o owner.Owner, options Options, initialize bool) (*Manager, error) {
	options = options.defaults()
	if options.MaxActive < 1 || options.MaxActive > 256 || options.MaxPending < 1 || options.MaxPending > 64 || options.MaxWaiters < 1 || options.MaxWaiters > 2 || options.RenewTimeout <= 0 || options.RenewTimeout > 8*time.Second || options.RequestTimeout <= 0 || options.RequestTimeout > 30*time.Second {
		return nil, wire.Refuse("lease_not_authorised")
	}
	if e := p.Validate(p.BrokerUID); e != nil {
		return nil, e
	}
	if err := s.PolicyGeneration(p.Generation, initialize); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{policy: p.Clone(), owner: o, store: s, accounts: map[string]*account{}, options: options, instance: RandomID(), ctx: ctx, cancel: cancel}
	for _, entry := range p.Accounts {
		disk, e := s.Account(entry.Label, initialize)
		if e != nil {
			cancel()
			return nil, e
		}
		raw, e := disk.Records()
		if e != nil {
			cancel()
			return nil, e
		}
		a := &account{store: disk, records: map[string]Record{}, pending: map[string]*operation{}, wake: make(chan struct{}, 1)}
		for name, b := range raw {
			// The owner validates its own protected records; leases never decode them.
			if strings.HasPrefix(name, "owner-") {
				continue
			}
			var rec Record
			if wire.Decode(b, &rec) != nil || rec.Kind != "lease-record/1" || rec.Installation != p.Installation || rec.Account != entry.Label || rec.Revision == 0 || rec.PolicyGeneration > p.Generation || !validID(rec.LeaseID) || name != store.LeaseName(rec.LeaseID) || !policy.Hash(rec.OfferedDigest) || !policy.Hash(rec.ObservedDigest) || (rec.State != "active" && rec.State != "released" && rec.State != "expired") {
				cancel()
				return nil, store.ErrUnavailable
			}
			if rec.State == "active" && !options.Now().Before(rec.AuthorizedUntil) {
				rec.State = "expired"
				prior := rec.Revision
				rec.Revision++
				rec.DaemonInstance = m.instance
				if e = disk.Put(name, prior, rec); e != nil {
					cancel()
					return nil, e
				}
			}
			a.records[rec.LeaseID] = rec
		}
		m.accounts[entry.Label] = a
	}
	for label, a := range m.accounts {
		m.wg.Add(1)
		go m.worker(label, a)
	}
	return m, nil
}
func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func (m *Manager) Close() { m.cancel(); m.wg.Wait() }
func (m *Manager) Policy() policy.Policy {
	m.policyMu.RLock()
	defer m.policyMu.RUnlock()
	return m.policy.Clone()
}

// WithGeneration fences final socket publication against concurrent policy replacement.
func (m *Manager) WithGeneration(g uint64, fn func() error) error {
	m.policyMu.RLock()
	defer m.policyMu.RUnlock()
	if m.policyFailed || g != m.policy.Generation {
		return wire.Refuse("lease_not_authorised")
	}
	return fn()
}
func (m *Manager) Replace(p policy.Policy) error {
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	if e := p.Validate(m.policy.BrokerUID); e != nil {
		return e
	}
	if p.Installation != m.policy.Installation || p.Generation <= m.policy.Generation {
		return wire.Refuse("lease_not_authorised")
	}
	if err := m.store.PolicyGeneration(p.Generation, false); err != nil {
		m.policyFailed = true
		return wire.Refuse("lease_owner_unavailable")
	}
	m.policy = p.Clone()
	return nil
}
func (m *Manager) Call(ctx context.Context, uid uint32, method string, params any, arrival time.Time) Outcome {
	m.policyMu.RLock()
	failed := m.policyFailed
	p := m.policy.Clone()
	m.policyMu.RUnlock()
	if failed {
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
	op := &operation{arrival: arrival, method: method, uid: uid, generation: p.Generation, waiters: map[uint64]*waiter{}}
	defer func() {
		if m.options.Observe != nil {
			m.options.Observe(Event{Kind: "response", LeaseID: op.id, Arrival: arrival, At: time.Now()})
		}
	}()
	var label string
	switch r := params.(type) {
	case proactiveRequest:
		if method != "proactive" {
			return Outcome{Err: wire.ErrMalformed}
		}
		label = r.label
		op.id = RandomID()
		op.key = op.id
	case wire.LeaseRequest:
		if method != "lease.request" {
			return Outcome{Err: wire.ErrMalformed}
		}
		if _, e := p.Check(uid, r); e != nil {
			return Outcome{Err: e}
		}
		op.request = r
		label = r.Account
		op.id = RandomID()
		op.key = op.id
	case wire.Renew:
		op.id = r.LeaseID
		op.rejected = r.RejectedSHA256
		op.key = r.LeaseID
		label = m.label(r.LeaseID)
	case wire.Release:
		op.id = r.LeaseID
		op.key = r.LeaseID
		label = m.label(r.LeaseID)
	default:
		return Outcome{Err: wire.ErrMalformed}
	}
	if m.options.Observe != nil {
		m.options.Observe(Event{Kind: "arrival", LeaseID: op.id, Arrival: arrival, At: time.Now()})
	}
	a := m.accounts[label]
	if a == nil {
		code := "lease_not_owner"
		if method == "lease.request" {
			code = "lease_owner_unavailable"
		}
		return Outcome{Err: wire.Refuse(code)}
	}
	timeout := m.options.RequestTimeout
	if method == "lease.renew" {
		timeout = m.options.RenewTimeout
	} else if method == "lease.release" {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithDeadline(ctx, arrival.Add(timeout))
	defer cancel()
	if ctx.Err() != nil {
		return Outcome{Err: deadline(method)}
	}
	a.mu.Lock()
	if method == "proactive" && len(a.pending) != 0 {
		a.mu.Unlock()
		return Outcome{}
	}
	if method != "lease.request" && method != "proactive" {
		r, ok := a.records[op.id]
		if !ok || r.UID != uid || r.PolicyGeneration != p.Generation {
			a.mu.Unlock()
			return Outcome{Err: wire.Refuse("lease_not_owner")}
		}
	}
	existing := a.pending[op.key]
	if existing != nil && existing.method != method {
		a.mu.Unlock()
		return Outcome{Err: wire.Refuse("renew_timeout")}
	}
	if existing != nil && method == "lease.renew" && (existing.uid != uid || existing.rejected != op.rejected) {
		a.mu.Unlock()
		return Outcome{Err: wire.Refuse("renew_not_current")}
	}
	if existing != nil && len(existing.waiters) >= m.options.MaxWaiters || a.waiters >= 128 || existing == nil && len(a.pending) >= m.options.MaxPending {
		a.mu.Unlock()
		return Outcome{Err: wire.Refuse("renew_timeout")}
	}
	if existing != nil {
		op = existing
	} else {
		a.pending[op.key] = op
		a.queue = append(a.queue, op)
	}
	a.next++
	w := &waiter{id: a.next, ctx: ctx, answer: make(chan Outcome, 1)}
	op.waiters[w.id] = w
	a.waiters++
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	select {
	case out := <-w.answer:
		if ctx.Err() != nil {
			return Outcome{Err: deadline(method)}
		}
		return out
	case <-ctx.Done():
		a.mu.Lock()
		if _, ok := op.waiters[w.id]; ok {
			delete(op.waiters, w.id)
			a.waiters--
		}
		if len(op.waiters) == 0 && !op.running {
			delete(a.pending, op.key)
		}
		a.mu.Unlock()
		return Outcome{Err: deadline(method)}
	case <-m.ctx.Done():
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
}

// Deadline keeps transport publication within the same arrival budget as admission.
func (m *Manager) Deadline(method string, arrival time.Time) time.Time {
	timeout := m.options.RequestTimeout
	if method == "lease.renew" {
		timeout = m.options.RenewTimeout
	}
	if method == "lease.release" || method == "status" {
		timeout = 2 * time.Second
	}
	return arrival.Add(timeout)
}

type proactiveRequest struct{ label string }

// Proactive coalesces with admitted demand by doing nothing while it is pending.
// The owner scheduler decides when work is due; this is the common FIFO gate.
func (m *Manager) Proactive(ctx context.Context, label string) error {
	return m.Call(ctx, m.Policy().BrokerUID, "proactive", proactiveRequest{label}, time.Now()).Err
}
func deadline(method string) error {
	if method == "lease.renew" {
		return wire.Refuse("renew_timeout")
	}
	return wire.Refuse("request_deadline_exceeded")
}
func (m *Manager) label(id string) string {
	for label, a := range m.accounts {
		a.mu.Lock()
		_, ok := a.records[id]
		a.mu.Unlock()
		if ok {
			return label
		}
	}
	return ""
}
func (m *Manager) worker(label string, a *account) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-a.wake:
		}
		for {
			a.mu.Lock()
			if len(a.queue) == 0 {
				a.mu.Unlock()
				break
			}
			op := a.queue[0]
			a.queue = a.queue[1:]
			if len(op.waiters) == 0 {
				a.mu.Unlock()
				continue
			}
			op.running = true
			a.mu.Unlock()
			if m.options.Observe != nil {
				m.options.Observe(Event{Kind: "dequeue", LeaseID: op.id, Arrival: op.arrival, At: time.Now()})
			}
			out := Outcome{Err: deadline(op.method)}
			if m.live(a, op) {
				out = m.execute(label, a, op)
			}
			a.mu.Lock()
			if a.pending[op.key] == op {
				delete(a.pending, op.key)
			}
			for id, w := range op.waiters {
				if w.ctx.Err() == nil {
					w.answer <- out
				}
				delete(op.waiters, id)
				a.waiters--
			}
			a.mu.Unlock()
		}
	}
}
func (m *Manager) record(a *account, op *operation) (Record, error) {
	a.mu.Lock()
	r, ok := a.records[op.id]
	a.mu.Unlock()
	p := m.Policy()
	if !ok || r.UID != op.uid || r.Installation != p.Installation || r.PolicyGeneration != p.Generation {
		return r, wire.Refuse("lease_not_owner")
	}
	if _, e := p.Admit(op.uid, r.Account, r.Profile); e != nil {
		return r, e
	}
	if r.State != "active" || !m.options.Now().Before(r.AuthorizedUntil) {
		if op.method == "lease.release" && r.State == "released" && m.options.Now().Before(r.AuthorizedUntil) {
			return r, nil
		}
		return r, wire.Refuse("lease_not_active")
	}
	return r, nil
}
func (m *Manager) persist(a *account, r Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	prior := r.Revision
	r.Revision++
	r.DaemonInstance = m.instance
	if e := a.store.Put(store.LeaseName(r.LeaseID), prior, r); e != nil {
		a.failed = true
		return wire.Refuse("lease_owner_unavailable")
	}
	a.records[r.LeaseID] = r
	return nil
}
func (m *Manager) execute(label string, a *account, op *operation) Outcome {
	a.mu.Lock()
	failed := a.failed
	a.mu.Unlock()
	if failed {
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
	p := m.Policy()
	if p.Generation != op.generation {
		return Outcome{Err: wire.Refuse("lease_not_authorised")}
	}
	if e := a.store.Healthy(); e != nil {
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
	var rec Record
	var err error
	if op.method != "lease.request" && op.method != "proactive" {
		rec, err = m.record(a, op)
		if err != nil {
			return Outcome{Err: err}
		}
		if op.method == "lease.release" {
			if rec.State != "released" {
				rec.State = "released"
				if e := m.persist(a, rec); e != nil {
					return Outcome{Err: e}
				}
			}
			return Outcome{Result: wire.ReleaseResult{LeaseID: rec.LeaseID, State: "released"}, Generation: p.Generation}
		}
		if !policy.Hash(op.rejected) || (op.rejected != rec.OfferedDigest && op.rejected != rec.ObservedDigest) {
			return Outcome{Err: wire.Refuse("renew_not_current")}
		}
	}
	snapshot, err := m.owner.Snapshot(m.ctx, label)
	if err != nil {
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
	if err = m.usable(snapshot, label); err != nil {
		return Outcome{Err: err}
	}
	if op.method == "proactive" || op.method == "lease.renew" && op.rejected == Digest(snapshot.AccessToken) {
		// Admission of new owner work requires remaining live demand. Once
		// admitted, the contained attempt may resolve under the manager lifetime.
		if !m.live(a, op) {
			return Outcome{Err: deadline(op.method)}
		}
		snapshot, err = m.owner.Refresh(m.ctx, label, snapshot.Generation)
		if err != nil {
			return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
		}
		if m.Policy().Generation != op.generation {
			return Outcome{Err: wire.Refuse("lease_not_authorised")}
		}
		if err = m.usable(snapshot, label); err != nil {
			return Outcome{Err: err}
		}
		if op.rejected == Digest(snapshot.AccessToken) {
			return Outcome{Err: wire.Refuse("renew_failed")}
		}
	}
	// Re-read authority and lifecycle evidence after I/O; no state lock crossed it.
	p = m.Policy()
	if p.Generation != op.generation {
		return Outcome{Err: wire.Refuse("lease_not_authorised")}
	}
	if op.method == "proactive" {
		return Outcome{Generation: p.Generation}
	}
	request := op.request
	if op.method != "lease.request" {
		request = wire.LeaseRequest{Harness: "codex_cli", Profile: rec.Profile, Account: rec.Account, Channel: "external-token", Binding: rec.Binding, Network: json.RawMessage("null"), LaunchID: rec.LaunchID, Executor: wire.Executor{Capabilities: []string{"credential-injection/1"}, Version: "record"}}
	}
	if _, err = p.Check(op.uid, request); err != nil {
		return Outcome{Err: err}
	}
	if err = a.store.Healthy(); err != nil {
		return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
	}
	if err = m.usable(snapshot, label); err != nil {
		return Outcome{Err: err}
	}
	if !m.live(a, op) {
		return Outcome{Err: deadline(op.method)}
	}
	if op.method == "lease.request" {
		a.mu.Lock()
		active := 0
		for _, r := range a.records {
			if r.State == "active" && r.PolicyGeneration == p.Generation && m.options.Now().Before(r.AuthorizedUntil) {
				active++
			}
		}
		a.mu.Unlock()
		if active >= m.options.MaxActive {
			return Outcome{Err: wire.Refuse("lease_not_authorised")}
		}
		until := m.options.Now().Add(time.Duration(p.MaxLeaseSeconds) * time.Second)
		for _, bound := range []time.Time{snapshot.ExpiresAt, snapshot.AuthorityUntil} {
			if !bound.IsZero() && bound.Before(until) {
				until = bound
			}
		}
		until = until.UTC().Truncate(time.Second)
		if !m.options.Now().Before(until) {
			return Outcome{Err: wire.Refuse("lease_owner_unavailable")}
		}
		rec = Record{Kind: "lease-record/1", LeaseID: op.id, Installation: p.Installation, UID: op.uid, Account: label, Profile: request.Profile, PolicyGeneration: p.Generation, Binding: request.Binding, LaunchID: request.LaunchID, AuthorizedUntil: until, OfferedDigest: Digest(snapshot.AccessToken), ObservedDigest: Digest(snapshot.AccessToken), OfferedGeneration: snapshot.Generation, ObservedGeneration: snapshot.Generation, State: "active"}
	} else {
		if !m.options.Now().Before(rec.AuthorizedUntil) {
			return Outcome{Err: wire.Refuse("lease_not_active")}
		}
		if op.rejected == rec.OfferedDigest {
			rec.ObservedDigest = rec.OfferedDigest
			rec.ObservedGeneration = rec.OfferedGeneration
		}
		rec.OfferedDigest = Digest(snapshot.AccessToken)
		rec.OfferedGeneration = snapshot.Generation
	}
	if e := m.persist(a, rec); e != nil {
		return Outcome{Err: e}
	}
	if !m.live(a, op) {
		return Outcome{Err: deadline(op.method)}
	}
	if m.Policy().Generation != op.generation {
		return Outcome{Err: wire.Refuse("lease_not_authorised")}
	}
	return Outcome{Generation: p.Generation, Result: wire.LeaseResult{LeaseID: rec.LeaseID, Account: label, Harness: "codex_cli", Channel: "external-token", Payload: wire.Payload{Channel: "external-token", AccessToken: snapshot.AccessToken, AccountID: snapshot.AccountID, PlanType: snapshot.PlanType}, TokenExpiresAt: snapshot.ExpiresAt.UTC().Format(time.RFC3339), AuthorizedUntil: rec.AuthorizedUntil.UTC().Format(time.RFC3339), Renewable: true}}
}
func (m *Manager) live(a *account, op *operation) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, w := range op.waiters {
		if w.ctx.Err() == nil {
			return true
		}
	}
	return false
}
func (m *Manager) usable(s owner.Snapshot, label string) error {
	return usable(m.Policy(), m.options.Now(), s, label)
}
func usable(p policy.Policy, now time.Time, s owner.Snapshot, label string) error {
	switch s.State {
	case owner.Reauth:
		return wire.Refuse("lease_reauth_required")
	case owner.Active, owner.Transient:
	default:
		return wire.Refuse("lease_owner_unavailable")
	}
	a := mustAccount(p, label)
	if !s.Qualified || s.PolicyGeneration != p.Generation || s.ExecutableSHA256 != p.ExecutableSHA256 || s.QualificationID != a.QualificationID {
		return wire.Refuse("lease_harness_unqualified")
	}
	if !s.Trusted || !s.Fresh || s.AccessToken == "" || s.Generation == 0 || !now.Before(s.ExpiresAt.Truncate(time.Second)) || (!s.AuthorityUntil.IsZero() && !now.Before(s.AuthorityUntil.Truncate(time.Second))) {
		return wire.Refuse("lease_owner_unavailable")
	}
	for _, a := range p.Accounts {
		if a.Label == label && a.VendorID == s.AccountID {
			return nil
		}
	}
	return wire.Refuse("lease_owner_unavailable")
}
func (m *Manager) Status(ctx context.Context, uid uint32) wire.Status {
	p := m.Policy()
	status := wire.Status{Generation: p.Generation, Accounts: []wire.AccountStatus{}}
	for _, a := range p.Visible(uid) {
		s, e := m.owner.Snapshot(ctx, a.Label)
		if e != nil {
			s.State = owner.Unavailable
		}
		state := s.State
		disk := m.accounts[a.Label]
		unhealthy := disk == nil
		if disk != nil {
			disk.mu.Lock()
			unhealthy = disk.failed
			disk.mu.Unlock()
			unhealthy = unhealthy || disk.store.Healthy() != nil
		}
		if unhealthy {
			state = owner.Unavailable
		}
		switch state {
		case owner.Active, owner.Transient, owner.Reauth, owner.Unavailable:
		default:
			state = owner.Unavailable
		}
		var expiry *string
		if !s.ExpiresAt.IsZero() {
			v := s.ExpiresAt.UTC().Format(time.RFC3339)
			expiry = &v
		}
		status.Accounts = append(status.Accounts, wire.AccountStatus{Account: a.Label, State: state, SingleOwner: true, TokenExpiresAt: expiry})
	}
	return status
}
func ErrorCode(e error) string {
	var refusal *wire.Error
	if errors.As(e, &refusal) {
		return refusal.Code
	}
	return "lease_owner_unavailable"
}

// Stats exposes queue counts only; it never returns material or token digests.
func (m *Manager) Stats(label string) (pending, waiters int) {
	a := m.accounts[label]
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending), a.waiters
}

// Publish performs owner I/O without state locks, then fences the complete
// bounded socket write against lease mutation and policy replacement. The callback
// must use the supplied authorization deadline and must not reenter the manager.
func (m *Manager) Publish(ctx context.Context, uid uint32, generation uint64, result wire.LeaseResult, write func(time.Time) error) error {
	label := m.label(result.LeaseID)
	a := m.accounts[label]
	if a == nil {
		return wire.Refuse("lease_not_owner")
	}
	snapshot, err := m.owner.Snapshot(ctx, label)
	if err != nil {
		return wire.Refuse("lease_owner_unavailable")
	}
	m.policyMu.RLock()
	defer m.policyMu.RUnlock()
	if m.policyFailed {
		return wire.Refuse("lease_owner_unavailable")
	}
	p := m.policy
	if p.Generation != generation {
		return wire.Refuse("lease_not_authorised")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.records[result.LeaseID]
	if !ok || r.UID != uid || r.PolicyGeneration != p.Generation || r.Installation != p.Installation {
		return wire.Refuse("lease_not_owner")
	}
	now := m.options.Now()
	if r.State != "active" || !now.Before(r.AuthorizedUntil) {
		return wire.Refuse("lease_not_active")
	}
	if _, err = p.Admit(uid, label, r.Profile); err != nil {
		return err
	}
	if r.Binding != p.Binding(uid, mustAccount(p, label), r.Profile) {
		return wire.Refuse("lease_binding_mismatch")
	}
	if a.failed || a.store.Healthy() != nil {
		return wire.Refuse("lease_owner_unavailable")
	}
	if err = usable(p, m.options.Now(), snapshot, label); err != nil {
		return err
	}
	if Digest(snapshot.AccessToken) != Digest(result.Payload.AccessToken) {
		return wire.Refuse("lease_owner_unavailable")
	}
	// Check time again after local store I/O, and bound the write itself by all
	// authorization/material limits, using a monotonic transport deadline.
	now = m.options.Now()
	limit := r.AuthorizedUntil
	for _, bound := range []time.Time{snapshot.ExpiresAt.Truncate(time.Second), snapshot.AuthorityUntil.Truncate(time.Second)} {
		if !bound.IsZero() && bound.Before(limit) {
			limit = bound
		}
	}
	if !now.Before(limit) {
		return wire.Refuse("lease_not_active")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return write(time.Now().Add(limit.Sub(now)))
}
func mustAccount(p policy.Policy, label string) policy.Account {
	for _, a := range p.Accounts {
		if a.Label == label {
			return a
		}
	}
	return policy.Account{}
}
