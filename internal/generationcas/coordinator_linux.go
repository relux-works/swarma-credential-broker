//go:build linux

package generationcas

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/freshstore"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"sort"
	"sync"
)

const (
	queued uint8 = iota + 1
	published
	terminal
)
const (
	reasonPublished uint8 = iota + 1
	reasonStale
	reasonCancelled
)

type job struct {
	slots         [4][]byte // R/G/O/F: each has permanently reserved RecordBytes capacity.
	attempt, ph   [32]byte
	root          Token
	observer      uint32
	state, reason uint8
	outcome       Outcome
	selected      bool
}
type mailbox struct {
	open      bool
	delivered uint32
}

// Coordinator owns all serialization and effect state. Variable metadata lives
// only in charged canonical slots; decoded units are transient per operation.
type Coordinator struct {
	mu                 sync.Mutex
	account            *store.Account
	fixture            *freshstore.Fixture
	limits             Limits
	initial            []byte
	initialToken, root Token
	fingerprint        [32]byte
	jobs               []job
	observers          []mailbox
	used, opened       uint32
	fence              uint32 // zero or one-based admission ordinal
}
type Observer struct {
	owner *Coordinator
	slot  uint32
}

func mapped(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, freshstore.ErrLimit) || errors.Is(e, store.ErrImmutableLimit) || errors.Is(e, store.ErrTooLarge) {
		return ErrCapacity
	}
	if errors.Is(e, freshstore.ErrInvalid) || errors.Is(e, freshstore.ErrConflict) || errors.Is(e, store.ErrImmutableInvalid) {
		return ErrInvalid
	}
	return ErrUnavailable
}
func census(a *store.Account, l Limits) (store.ImmutableSnapshot, [32]byte, error) {
	s, _, e := a.ReadImmutableBounded(nil, store.ImmutableLimits{RecordBytes: l.RecordBytes, TotalBytes: l.RetainedBytes, TotalRecords: l.RetainedObjects, ReadBytes: l.ReadBytes})
	if e != nil {
		return s, [32]byte{}, mapped(e)
	}
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].Name < s.Entries[j].Name })
	h := sha256.New()
	h.Write([]byte(s.Installation))
	var n [8]byte
	for _, v := range s.Entries {
		h.Write([]byte{0})
		h.Write([]byte(v.Name))
		binary.BigEndian.PutUint64(n[:], v.Size)
		h.Write(n[:])
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return s, d, nil
}

// NewFixture requires a complete explicit canonical seed and existing retained
// content. It never initializes missing history or recovers a lost Coordinator.
func NewFixture(a *store.Account, l Limits, initial []byte) (*Coordinator, error) {
	if a == nil {
		return nil, ErrInvalid
	}
	if _, _, e := l.costs(); e != nil {
		return nil, e
	}
	s, e := parseSeed(initial, l)
	if e != nil {
		return nil, e
	}
	snap, fp, e := census(a, l)
	if e != nil {
		return nil, e
	}
	if snap.Installation != s.installation {
		return nil, ErrInvalid
	}
	if _, _, _, e = l.charge(snap.Bytes, snap.Records, 0); e != nil {
		return nil, e
	}
	f, e := freshstore.NewFixture(a, l.content())
	if e != nil {
		return nil, mapped(e)
	}
	// Exactly one NewFixture and at most Units sequential ReadExact calls. No raw
	// return or decoded unit is retained across the next underlying boundary.
	for _, u := range s.units {
		if e = readUnit(f, u, l, snap, uint64(len(initial))); e != nil {
			return nil, e
		}
	}
	c := &Coordinator{account: a, fixture: f, limits: l, fingerprint: fp, jobs: make([]job, int(l.Attempts)), observers: make([]mailbox, int(l.Handles))}
	c.initial = make([]byte, len(initial), int(l.RecordBytes))
	copy(c.initial, initial)
	c.initialToken = Token{c, 1, domain("freshcas-initial/1", c.initial)}
	c.root = c.initialToken
	return c, nil
}
func readUnit(f *freshstore.Fixture, u freshstore.Expected, l Limits, s store.ImmutableSnapshot, coordBytes uint64) error {
	q, ok := add(512, coordBytes)
	if !ok {
		return ErrCapacity
	}
	unit := uint64(0)
	// Inventory is already bounded and validated before names or payload copies.
	names := make([]string, 0, len(u.Inventory)+2)
	names = append(names, "owner-fresh-manifest-"+u.ManifestDigest+".json")
	for _, r := range u.Inventory {
		names = append(names, "owner-fresh-object-"+r.Digest+".json")
	}
	unitNames := len(names)
	if u.Previous[:2] == "m:" {
		names = append(names, "owner-fresh-manifest-"+u.Previous[2:]+".json")
	}
	for i, name := range names {
		found := false
		for _, v := range s.Entries {
			if v.Name == name {
				found = true
				q, ok = add(q, v.Size)
				if !ok {
					return ErrCapacity
				}
				if i < unitNames {
					unit, ok = add(unit, v.Size)
					if !ok {
						return ErrCapacity
					}
				}
				break
			}
		}
		if !found {
			return ErrUnavailable
		}
	}
	if q > l.ReadBytes || unit > l.UnitBytes {
		return ErrCapacity
	}
	_, e := f.ReadExact(u)
	return mapped(e)
}
func (c *Coordinator) seed() (seed, error) {
	if c.usedBytes()+512 > c.limits.ReadBytes {
		return seed{}, ErrCapacity
	}
	return parseSeed(c.initial, c.limits)
}
func (c *Coordinator) usedBytes() uint64 {
	n := uint64(len(c.initial))
	for i := uint32(0); i < c.used; i++ {
		for _, b := range c.jobs[i].slots {
			n += uint64(len(b))
		}
	}
	return n
}
func (c *Coordinator) registry() (store.ImmutableSnapshot, error) {
	s, d, e := census(c.account, c.limits)
	if e != nil {
		return s, e
	}
	if d != c.fingerprint {
		return s, ErrRegistryChanged
	}
	return s, nil
}
func (c *Coordinator) token(t Token) error {
	if t.owner == nil || t.number == 0 || t.number > 1<<40 || t.record == ([32]byte{}) {
		return ErrInvalid
	}
	if t.owner != c {
		return ErrForeign
	}
	if t.number == c.initialToken.number && t.record == c.initialToken.record {
		return nil
	}
	for i := uint32(0); i < c.used; i++ {
		j := &c.jobs[i]
		if j.selected && j.root.number == t.number && j.root.record == t.record {
			return nil
		}
	}
	return ErrInvalid
}
func (c *Coordinator) selection(t Token) (Selection, error) {
	if e := c.token(t); e != nil {
		return Selection{}, e
	}
	if t == c.initialToken {
		s, e := c.seed()
		if e != nil {
			return Selection{}, ErrState
		}
		for _, u := range s.units {
			if u.ManifestDigest == s.manifest {
				return Selection{t, u}, nil
			}
		}
		return Selection{}, ErrState
	}
	for i := uint32(0); i < c.used; i++ {
		j := &c.jobs[i]
		if j.selected && j.root == t {
			g, u, a, p, e := parseGeneration(j.slots[1], c.limits, c)
			if e != nil || g != t || a != j.attempt || p != j.ph {
				return Selection{}, ErrState
			}
			return Selection{g, u}, nil
		}
	}
	return Selection{}, ErrState
}
func (c *Coordinator) OpenObserver() (*Observer, error) {
	if c == nil {
		return nil, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if uint64(c.opened) >= c.limits.Handles {
		return nil, ErrCapacity
	}
	n := c.opened
	c.opened++
	c.observers[n].open = true
	return &Observer{c, n}, nil
}
func (o *Observer) check() error {
	if o == nil || o.owner == nil || o.slot >= o.owner.opened {
		return ErrInvalid
	}
	if !o.owner.observers[o.slot].open {
		return ErrDisconnected
	}
	return nil
}
func (o *Observer) Current() (Selection, error) {
	if o == nil || o.owner == nil {
		return Selection{}, ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := o.check(); e != nil {
		return Selection{}, e
	}
	snap, e := c.registry()
	if e != nil {
		return Selection{}, e
	}
	s, e := c.selection(c.root)
	if e != nil {
		return Selection{}, e
	}
	if e = readUnit(c.fixture, s.Unit, c.limits, snap, c.usedBytes()); e != nil {
		return Selection{}, e
	}
	return s, nil
}
func (c *Coordinator) request(r Request) (seed, [32]byte, error) {
	var z [32]byte
	if e := c.token(r.Expected); e != nil {
		return seed{}, z, e
	}
	n, ok := add(r.Expected.number, 1)
	if !ok || r.CandidateGeneration != n || n > 1<<40 {
		return seed{}, z, ErrInvalid
	}
	if n > c.limits.MaxGeneration {
		return seed{}, z, ErrCapacity
	}
	s, e := c.seed()
	if e != nil {
		if e == ErrCapacity {
			return seed{}, z, e
		}
		return seed{}, z, ErrState
	}
	found := false
	for _, u := range s.units {
		if equalUnit(u, r.Candidate) {
			found = true
			break
		}
	}
	if !found {
		return seed{}, z, ErrInvalid
	}
	if e := validateUnit(r.Candidate, c.limits); e != nil {
		return seed{}, z, e
	}
	w := newWriter(c.limits)
	payload(w, s, r)
	if w.err != nil {
		return seed{}, z, w.err
	}
	return s, domain("freshcas-payload/1", w.b), nil
}
func (o *Observer) Bind(nonce [16]byte, expected Token, next uint64, unit freshstore.Expected) (Request, error) {
	if o == nil || o.owner == nil {
		return Request{}, ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := o.check(); e != nil {
		return Request{}, e
	}
	r := Request{Nonce: nonce, Expected: expected, CandidateGeneration: next, Candidate: unit}
	_, ph, e := c.request(r)
	if e != nil {
		return Request{}, e
	}
	r.Attempt = attempt(nonce, ph)
	r.Candidate = copyUnit(unit)
	return r, nil
}
func (c *Coordinator) same(r Request, s seed, ph [32]byte) (*job, uint32, error) {
	for i := uint32(0); i < c.used; i++ {
		j := &c.jobs[i]
		if j.attempt == r.Attempt {
			w := newWriter(c.limits)
			reservation(w, s, r, ph)
			if w.err != nil {
				return nil, 0, w.err
			}
			if ph != j.ph || !bytes.Equal(w.b, j.slots[0]) {
				return nil, 0, ErrInvalid
			}
			return j, i, nil
		}
	}
	return nil, 0, nil
}
func (o *Observer) Submit(r Request) (Ticket, error) {
	if o == nil || o.owner == nil {
		return Ticket{}, ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := o.check(); e != nil {
		return Ticket{}, e
	}
	s, ph, e := c.request(r)
	if e != nil {
		return Ticket{}, e
	}
	if attempt(r.Nonce, ph) != r.Attempt {
		return Ticket{}, ErrInvalid
	}
	j, n, e := c.same(r, s, ph)
	if e != nil {
		return Ticket{}, e
	}
	if j != nil {
		return Ticket{c, n + 1}, nil
	}
	if c.fence != 0 {
		return Ticket{}, ErrFenced
	}
	snap, e := c.registry()
	if e != nil {
		return Ticket{}, e
	}
	if _, _, _, e = c.limits.charge(snap.Bytes, snap.Records, uint64(c.used)+1); e != nil {
		return Ticket{}, e
	}
	rw, gw := newWriter(c.limits), newWriter(c.limits)
	reservation(rw, s, r, ph)
	generation(gw, r, ph)
	if rw.err != nil {
		return Ticket{}, rw.err
	}
	if gw.err != nil {
		return Ticket{}, gw.err
	}
	if e = readUnit(c.fixture, r.Candidate, c.limits, snap, c.usedBytes()+uint64(len(rw.b)+len(gw.b))); e != nil {
		return Ticket{}, e
	}
	// Prove worst numeric root and longest terminal record fit the reserved O/F
	// before admission. Empty used-length does not refund their full capacity.
	jnew := job{slots: [4][]byte{rw.b, gw.b, nil, nil}, attempt: r.Attempt, ph: ph, observer: o.slot, state: queued}
	ow, fw := newWriter(c.limits), newWriter(c.limits)
	root := Token{c, c.limits.MaxGeneration, c.root.record}
	outcomeBytes(ow, &jnew, c.used+1, Committed, reasonPublished, root)
	fenceBytes(fw, &jnew, c.used+1, domain("freshcas-outcome/1", ow.b))
	if ow.err != nil {
		return Ticket{}, ow.err
	}
	if fw.err != nil {
		return Ticket{}, fw.err
	}
	jnew.slots[2] = ow.b[:0]
	jnew.slots[3] = fw.b[:0]
	n = c.used
	c.jobs[n] = jnew
	c.used++
	c.fence = n + 1
	return Ticket{c, n + 1}, nil
}
func (c *Coordinator) ticket(t Ticket) (*job, error) {
	if t.owner == nil || t.slot == 0 {
		return nil, ErrInvalid
	}
	if t.owner != c {
		return nil, ErrForeign
	}
	if t.slot > c.used {
		return nil, ErrInvalid
	}
	return &c.jobs[t.slot-1], nil
}
func outcomeBytes(w *writer, j *job, n uint32, o Outcome, reason uint8, root Token) {
	w.put(`{"attempt":`)
	w.str(hx(j.attempt))
	w.put(`,"job":`)
	w.num(uint64(n))
	w.put(`,"kind":"freshcas-outcome/1","outcome":`)
	if o == Committed {
		w.str("committed")
	} else {
		w.str("no_commit")
	}
	w.put(`,"payload_hash":`)
	w.str(hx(j.ph))
	w.put(`,"reason":`)
	r := "published"
	if reason == reasonStale {
		r = "stale"
	}
	if reason == reasonCancelled {
		r = "cancelled"
	}
	w.str(r)
	w.put(`,"root":`)
	w.token(root)
	w.put(`}`)
}
func fenceBytes(w *writer, j *job, n uint32, oh [32]byte) {
	w.put(`{"attempt":`)
	w.str(hx(j.attempt))
	w.put(`,"job":`)
	w.num(uint64(n))
	w.put(`,"kind":"freshcas-fence/1","outcome_record":`)
	w.str(hx(oh))
	w.put(`,"payload_hash":`)
	w.str(hx(j.ph))
	w.put(`}`)
}
func (c *Coordinator) outcome(j *job, n uint32, o Outcome, reason uint8, root Token) error {
	w := &writer{b: j.slots[2][:0]}
	outcomeBytes(w, j, n, o, reason, root)
	if w.err != nil {
		return w.err
	}
	j.slots[2] = w.b
	j.outcome = o
	j.reason = reason
	j.root = root
	return nil
}
func (c *Coordinator) finish(j *job, n uint32) error {
	w := &writer{b: j.slots[3][:0]}
	fenceBytes(w, j, n, domain("freshcas-outcome/1", j.slots[2]))
	if w.err != nil {
		return w.err
	}
	j.slots[3] = w.b
	j.state = terminal
	if c.fence == n {
		c.fence = 0
	}
	return nil
}

// verifyJob binds BOTH canonical records to the fixed admitted identity. It
// reconstructs only bounded transient data; prepared G alone is not evidence.
func (c *Coordinator) verifyJob(j *job) (Token, freshstore.Expected, Token, error) {
	g, u, a, ph, e := parseGeneration(j.slots[1], c.limits, c)
	if e != nil || a != j.attempt || ph != j.ph {
		return Token{}, freshstore.Expected{}, Token{}, ErrState
	}
	gp := parser{b: j.slots[1], l: c.limits}
	gp.want(`{"attempt":`)
	gp.s(64)
	gp.want(`,"generation":`)
	gp.num()
	gp.want(`,"kind":"freshcas-generation/1","payload_hash":`)
	gp.s(64)
	gp.want(`,"previous":`)
	previous := gp.token(c)
	rp := parser{b: j.slots[0], l: c.limits}
	rp.want(`{"attempt":`)
	rp.s(64)
	rp.want(`,"kind":"freshcas-reservation/1","nonce":`)
	nonce := rp.s(32)
	raw, e := hex.DecodeString(nonce)
	if gp.err || rp.err || e != nil || len(raw) != 16 || hex.EncodeToString(raw) != nonce {
		return Token{}, freshstore.Expected{}, Token{}, ErrState
	}
	r := Request{Attempt: j.attempt, Expected: previous, CandidateGeneration: g.number, Candidate: u}
	copy(r.Nonce[:], raw)
	seed, p, e := c.request(r)
	if e != nil || p != j.ph || attempt(r.Nonce, p) != j.attempt {
		return Token{}, freshstore.Expected{}, Token{}, ErrState
	}
	rw := newWriter(c.limits)
	reservation(rw, seed, r, p)
	gw := newWriter(c.limits)
	generation(gw, r, p)
	if rw.err != nil || gw.err != nil || !bytes.Equal(rw.b, j.slots[0]) || !bytes.Equal(gw.b, j.slots[1]) {
		return Token{}, freshstore.Expected{}, Token{}, ErrState
	}
	return g, u, previous, nil
}
func (c *Coordinator) ComparePublish(t Ticket) error {
	if c == nil {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j, e := c.ticket(t)
	if e != nil {
		return e
	}
	if j.state == terminal {
		return ErrTerminal
	}
	if j.state != queued {
		return ErrState
	}
	g, u, expected, e := c.verifyJob(j)
	if e != nil {
		return ErrState
	}
	snap, e := c.registry()
	if e != nil {
		return e
	}
	if e = readUnit(c.fixture, u, c.limits, snap, c.usedBytes()); e != nil {
		return e
	}
	if expected != c.root {
		if e = c.outcome(j, t.slot, ConfirmedNoCommit, reasonStale, c.root); e != nil {
			return e
		}
		if e = c.finish(j, t.slot); e != nil {
			return e
		}
		return ErrTerminal
	}
	// The actual selection linearizes here under the ONE shared owner lock.
	c.root = g
	j.root = g
	j.selected = true
	j.state = published
	return nil
}
func (c *Coordinator) RecordOutcome(t Ticket) error {
	if c == nil {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j, e := c.ticket(t)
	if e != nil {
		return e
	}
	return c.record(j, t.slot)
}
func (c *Coordinator) record(j *job, n uint32) error {
	if j.state == terminal {
		return nil
	}
	if j.state != published || !j.selected {
		return ErrPending
	}
	g, _, _, e := c.verifyJob(j)
	if e != nil || g != j.root {
		return ErrState
	}
	return c.outcome(j, n, Committed, reasonPublished, g)
}
func (c *Coordinator) Deliver(t Ticket) error {
	if c == nil {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j, e := c.ticket(t)
	if e != nil {
		return e
	}
	if j.state == terminal {
		return nil
	}
	if j.state != published || j.outcome != Committed {
		return ErrPending
	}
	m := &c.observers[j.observer]
	if !m.open {
		return ErrDisconnected
	}
	if m.delivered != 0 && m.delivered != t.slot {
		return ErrCapacity
	}
	if e = c.finish(j, t.slot); e != nil {
		return e
	}
	m.delivered = t.slot
	return nil
}
func (c *Coordinator) result(j *job, n uint32) (Result, error) {
	r := Result{Outcome: Unknown, Attempt: j.attempt, PayloadHash: j.ph}
	if j.state != terminal {
		return r, nil
	}
	ow, fw := newWriter(c.limits), newWriter(c.limits)
	outcomeBytes(ow, j, n, j.outcome, j.reason, j.root)
	fenceBytes(fw, j, n, domain("freshcas-outcome/1", ow.b))
	if ow.err != nil || fw.err != nil || !bytes.Equal(ow.b, j.slots[2]) || !bytes.Equal(fw.b, j.slots[3]) {
		return Result{}, ErrState
	}
	s, e := c.selection(j.root)
	if e != nil {
		return Result{}, e
	}
	r.Outcome = j.outcome
	r.Selection = s
	r.TerminalProof = domain("freshcas-fence/1", j.slots[3])
	return r, nil
}
func (c *Coordinator) CancelQueued(t Ticket) (Result, error) {
	if c == nil {
		return Result{}, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j, e := c.ticket(t)
	if e != nil {
		return Result{}, e
	}
	if j.state == terminal {
		return c.result(j, t.slot)
	}
	if j.state == published {
		r, _ := c.result(j, t.slot)
		return r, ErrPending
	}
	if j.state != queued {
		return Result{}, ErrState
	}
	if e = c.outcome(j, t.slot, ConfirmedNoCommit, reasonCancelled, c.root); e != nil {
		return Result{}, e
	}
	if e = c.finish(j, t.slot); e != nil {
		return Result{}, e
	}
	return c.result(j, t.slot)
}
func (o *Observer) Receive(t Ticket) (Result, error) {
	if o == nil || o.owner == nil {
		return Result{}, ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := o.check(); e != nil {
		return Result{}, e
	}
	j, e := c.ticket(t)
	if e != nil {
		return Result{}, e
	}
	if j.observer != o.slot {
		return Result{}, ErrForeign
	}
	if j.state == terminal {
		if c.observers[o.slot].delivered == t.slot {
			c.observers[o.slot].delivered = 0
		}
		return c.result(j, t.slot)
	}
	return Result{Outcome: Unknown, Attempt: j.attempt, PayloadHash: j.ph}, nil
}
func (o *Observer) Reconcile(r Request) (Result, error) {
	if o == nil || o.owner == nil {
		return Result{}, ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := o.check(); e != nil {
		return Result{}, e
	}
	s, ph, e := c.request(r)
	if e != nil {
		return Result{}, e
	}
	if attempt(r.Nonce, ph) != r.Attempt {
		return Result{}, ErrInvalid
	}
	j, n, e := c.same(r, s, ph)
	if e != nil {
		return Result{}, e
	}
	if j == nil {
		return Result{}, ErrInvalid
	}
	if j.state == published {
		if e = c.record(j, n+1); e != nil {
			return Result{}, e
		}
		if e = c.finish(j, n+1); e != nil {
			return Result{}, e
		}
	}
	return c.result(j, n+1)
}
func (o *Observer) Close() error {
	if o == nil || o.owner == nil {
		return ErrInvalid
	}
	c := o.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if o.slot >= c.opened {
		return ErrInvalid
	}
	c.observers[o.slot].open = false
	return nil
}
