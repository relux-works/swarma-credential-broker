//go:build linux

// Package generationcas is an inactive, RAM-local generation selection fixture.
// Its tokens and outcomes confer no production or durable recovery authority.
package generationcas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/freshstore"
	"strconv"
)

const Schema = "freshcas/1"

var (
	ErrInvalid         = errors.New("invalid generation fixture input")
	ErrForeign         = errors.New("foreign generation fixture owner")
	ErrCapacity        = errors.New("generation fixture capacity")
	ErrFenced          = errors.New("generation fixture fenced")
	ErrRegistryChanged = errors.New("generation fixture registry changed")
	ErrUnavailable     = errors.New("generation fixture unavailable")
	ErrDisconnected    = errors.New("generation fixture observer disconnected")
	ErrPending         = errors.New("generation fixture pending")
	ErrTerminal        = errors.New("generation fixture terminal")
	ErrState           = errors.New("generation fixture state")
)

type Token struct {
	owner  *Coordinator
	number uint64
	record [32]byte
}

func (t Token) Number() uint64         { return t.number }
func (t Token) RecordDigest() [32]byte { return t.record }

type Ticket struct {
	owner *Coordinator
	slot  uint32
}
type Selection struct {
	Generation Token
	Unit       freshstore.Expected
}
type Request struct {
	Attempt             [32]byte
	Nonce               [16]byte
	Expected            Token
	CandidateGeneration uint64
	Candidate           freshstore.Expected
}
type Outcome uint8

const (
	Unknown Outcome = iota + 1
	Committed
	ConfirmedNoCommit
)

type Result struct {
	Outcome              Outcome
	Attempt, PayloadHash [32]byte
	Selection            Selection
	TerminalProof        [32]byte
}

type seed struct {
	epoch, installation, pin, scope, manifest string
	units                                     []freshstore.Expected
}

func hx(h [32]byte) string { return hex.EncodeToString(h[:]) }
func hash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func id(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '-')) {
			return false
		}
	}
	return true
}
func domain(kind string, b []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(kind + "\n"))
	h.Write(b)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}
func attempt(n [16]byte, p [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("freshcas-attempt/1\n"))
	h.Write(n[:])
	h.Write(p[:])
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// No generic JSON object tree: fields/order are consumed literally; strings
// borrow bounded source while scanning and are copied only after length checks.
type parser struct {
	b        []byte
	at       int
	err      bool
	capacity bool
	l        Limits
}

func (p *parser) want(s string) {
	if p.err {
		return
	}
	if !bytes.HasPrefix(p.b[p.at:], []byte(s)) {
		p.err = true
		return
	}
	p.at += len(s)
}
func (p *parser) s(max int) string {
	p.want(`"`)
	if p.err {
		return ""
	}
	n := bytes.IndexByte(p.b[p.at:], '"')
	if n < 0 || n > max {
		p.err = true
		return ""
	}
	x := p.b[p.at : p.at+n]
	for _, c := range x {
		if c < 32 || c > 126 || c == '\\' {
			p.err = true
			return ""
		}
	}
	p.at += n + 1
	return string(x)
}
func (p *parser) num() uint64 {
	if p.err {
		return 0
	}
	st := p.at
	for p.at < len(p.b) && p.b[p.at] >= '0' && p.b[p.at] <= '9' {
		p.at++
		if p.at-st > 20 {
			p.err = true
			return 0
		}
	}
	x := p.b[st:p.at]
	if len(x) == 0 || len(x) > 1 && x[0] == '0' {
		p.err = true
		return 0
	}
	n, e := strconv.ParseUint(string(x), 10, 64)
	if e != nil || n == 0 || n > 1<<40 {
		p.err = true
	}
	return n
}
func (p *parser) token(owner *Coordinator) Token {
	p.want(`{"number":`)
	n := p.num()
	p.want(`,"record":`)
	s := p.s(64)
	p.want(`}`)
	var d [32]byte
	if !hash(s) {
		p.err = true
	} else {
		v, _ := hex.DecodeString(s)
		copy(d[:], v)
	}
	return Token{owner, n, d}
}
func (p *parser) unit() freshstore.Expected {
	var u freshstore.Expected
	p.want(`{"binding":{"installation":`)
	u.Installation = p.s(64)
	p.want(`,"pin":`)
	u.Pin = p.s(64)
	p.want(`,"previous":`)
	u.Previous = p.s(66)
	p.want(`,"scope":`)
	u.Scope = p.s(64)
	p.want(`},"inventory":[`)
	for !p.err && p.at < len(p.b) && p.b[p.at] != ']' {
		if uint64(len(u.Inventory)) >= p.l.Dependencies {
			p.err = true
			p.capacity = true
			break
		}
		var r freshstore.Ref
		p.want(`{"digest":`)
		r.Digest = p.s(64)
		p.want(`,"encoded":`)
		r.Encoded = p.num()
		p.want(`,"kind":`)
		r.Kind = p.s(64)
		p.want(`,"name":`)
		r.Name = p.s(64)
		p.want(`,"raw":`)
		r.Raw = p.num()
		p.want(`,"raw_digest":`)
		r.RawDigest = p.s(64)
		p.want(`}`)
		u.Inventory = append(u.Inventory, r)
		if p.at < len(p.b) && p.b[p.at] == ',' {
			p.at++
			if p.at == len(p.b) || p.b[p.at] == ']' {
				p.err = true
			}
			continue
		}
		break
	}
	p.want(`],"manifest":`)
	u.ManifestDigest = p.s(64)
	p.want(`,"schema":`)
	u.Schema = p.s(64)
	p.want(`}`)
	if e := validateUnit(u, p.l); e != nil {
		p.err = true
		p.capacity = p.capacity || e == ErrCapacity
	}
	return u
}
func validateUnit(u freshstore.Expected, l Limits) error {
	if !id(u.Installation) || !id(u.Scope) || !hash(u.Pin) || len(u.Previous) != 66 || !(u.Previous[:2] == "g:" || u.Previous[:2] == "m:") || !hash(u.Previous[2:]) || u.Schema != freshstore.Schema || !hash(u.ManifestDigest) || len(u.Inventory) == 0 {
		return ErrInvalid
	}
	if uint64(len(u.Inventory)) > l.Dependencies {
		return ErrCapacity
	}
	var total uint64
	for i, r := range u.Inventory {
		if !id(r.Name) || !id(r.Kind) || !hash(r.Digest) || !hash(r.RawDigest) || r.Raw == 0 || r.Encoded == 0 || r.Raw > 1<<40 || r.Encoded > 1<<40 || i > 0 && u.Inventory[i-1].Name >= r.Name {
			return ErrInvalid
		}
		if r.Raw > l.RawObjectBytes || r.Encoded > l.RecordBytes {
			return ErrCapacity
		}
		var ok bool
		total, ok = add(total, r.Encoded)
		if !ok {
			return ErrCapacity
		}
	}
	if total > l.UnitBytes {
		return ErrCapacity
	}
	return nil
}
func parseSeed(b []byte, l Limits) (seed, error) {
	var s seed
	if uint64(len(b)) > l.RecordBytes {
		return s, ErrCapacity
	}
	p := parser{b: b, l: l}
	p.want(`{"epoch":`)
	s.epoch = p.s(64)
	p.want(`,"generation":1,"initial_manifest":`)
	s.manifest = p.s(64)
	p.want(`,"installation":`)
	s.installation = p.s(64)
	p.want(`,"kind":"freshcas-initial/1","pin":`)
	s.pin = p.s(64)
	p.want(`,"schema":"freshcas/1","scope":`)
	s.scope = p.s(64)
	p.want(`,"units":[`)
	for !p.err && p.at < len(b) && b[p.at] != ']' {
		if uint64(len(s.units)) >= l.Units {
			return seed{}, ErrCapacity
		}
		u := p.unit()
		if len(s.units) > 0 && s.units[len(s.units)-1].ManifestDigest >= u.ManifestDigest {
			p.err = true
		}
		if u.Installation != s.installation || u.Scope != s.scope || u.Pin != s.pin {
			p.err = true
		}
		s.units = append(s.units, u)
		if p.at < len(b) && b[p.at] == ',' {
			p.at++
			if p.at == len(b) || b[p.at] == ']' {
				p.err = true
			}
			continue
		}
		break
	}
	p.want(`]}`)
	if p.capacity {
		return seed{}, ErrCapacity
	}
	found := false
	for _, u := range s.units {
		found = found || u.ManifestDigest == s.manifest
	}
	if p.err || p.at != len(b) || !hash(s.epoch) || !hash(s.manifest) || !hash(s.pin) || !id(s.scope) || !id(s.installation) || !found {
		return seed{}, ErrInvalid
	}
	return s, nil
}

// Every writer has one pre-admitted RecordBytes buffer. No append grows it.
type writer struct {
	b   []byte
	err error
}

func newWriter(l Limits) *writer { return &writer{b: make([]byte, 0, int(l.RecordBytes))} }
func (w *writer) put(s string) {
	if w.err != nil {
		return
	}
	if len(s) > cap(w.b)-len(w.b) {
		w.err = ErrCapacity
		return
	}
	w.b = append(w.b, s...)
}
func (w *writer) str(s string) { w.put(`"`); w.put(s); w.put(`"`) }
func (w *writer) num(n uint64) { w.put(strconv.FormatUint(n, 10)) }
func (w *writer) token(t Token) {
	w.put(`{"number":`)
	w.num(t.number)
	w.put(`,"record":`)
	w.str(hx(t.record))
	w.put(`}`)
}
func (w *writer) unit(u freshstore.Expected) {
	w.put(`{"binding":{"installation":`)
	w.str(u.Installation)
	w.put(`,"pin":`)
	w.str(u.Pin)
	w.put(`,"previous":`)
	w.str(u.Previous)
	w.put(`,"scope":`)
	w.str(u.Scope)
	w.put(`},"inventory":[`)
	for i, r := range u.Inventory {
		if i > 0 {
			w.put(`,`)
		}
		w.put(`{"digest":`)
		w.str(r.Digest)
		w.put(`,"encoded":`)
		w.num(r.Encoded)
		w.put(`,"kind":`)
		w.str(r.Kind)
		w.put(`,"name":`)
		w.str(r.Name)
		w.put(`,"raw":`)
		w.num(r.Raw)
		w.put(`,"raw_digest":`)
		w.str(r.RawDigest)
		w.put(`}`)
	}
	w.put(`],"manifest":`)
	w.str(u.ManifestDigest)
	w.put(`,"schema":`)
	w.str(u.Schema)
	w.put(`}`)
}
func payload(w *writer, s seed, r Request) {
	w.put(`{"candidate_generation":`)
	w.num(r.CandidateGeneration)
	w.put(`,"epoch":`)
	w.str(s.epoch)
	w.put(`,"expected":`)
	w.token(r.Expected)
	w.put(`,"installation":`)
	w.str(s.installation)
	w.put(`,"kind":"freshcas-payload/1","pin":`)
	w.str(s.pin)
	w.put(`,"schema":"freshcas/1","scope":`)
	w.str(s.scope)
	w.put(`,"unit":`)
	w.unit(r.Candidate)
	w.put(`}`)
}
func reservation(w *writer, s seed, r Request, ph [32]byte) {
	w.put(`{"attempt":`)
	w.str(hx(r.Attempt))
	w.put(`,"kind":"freshcas-reservation/1","nonce":`)
	w.str(hex.EncodeToString(r.Nonce[:]))
	w.put(`,"payload":`)
	payload(w, s, r)
	w.put(`,"payload_hash":`)
	w.str(hx(ph))
	w.put(`}`)
}
func generation(w *writer, r Request, ph [32]byte) {
	w.put(`{"attempt":`)
	w.str(hx(r.Attempt))
	w.put(`,"generation":`)
	w.num(r.CandidateGeneration)
	w.put(`,"kind":"freshcas-generation/1","payload_hash":`)
	w.str(hx(ph))
	w.put(`,"previous":`)
	w.token(r.Expected)
	w.put(`,"unit":`)
	w.unit(r.Candidate)
	w.put(`}`)
}

func parseGeneration(b []byte, l Limits, c *Coordinator) (Token, freshstore.Expected, [32]byte, [32]byte, error) {
	if uint64(len(b)) > l.RecordBytes {
		return Token{}, freshstore.Expected{}, [32]byte{}, [32]byte{}, ErrCapacity
	}
	p := parser{b: b, l: l}
	p.want(`{"attempt":`)
	a := p.s(64)
	p.want(`,"generation":`)
	n := p.num()
	p.want(`,"kind":"freshcas-generation/1","payload_hash":`)
	ph := p.s(64)
	p.want(`,"previous":`)
	p.token(c)
	p.want(`,"unit":`)
	u := p.unit()
	p.want(`}`)
	var ad, pd [32]byte
	if p.err || p.at != len(b) || !hash(a) || !hash(ph) || uint64(len(b)) > l.RecordBytes {
		return Token{}, freshstore.Expected{}, ad, pd, ErrState
	}
	ab, _ := hex.DecodeString(a)
	pb, _ := hex.DecodeString(ph)
	copy(ad[:], ab)
	copy(pd[:], pb)
	return Token{c, n, domain("freshcas-generation/1", b)}, u, ad, pd, nil
}
func equalUnit(a, b freshstore.Expected) bool {
	if a.Binding != b.Binding || a.Schema != b.Schema || a.ManifestDigest != b.ManifestDigest || len(a.Inventory) != len(b.Inventory) {
		return false
	}
	for i := range a.Inventory {
		if a.Inventory[i] != b.Inventory[i] {
			return false
		}
	}
	return true
}
func copyUnit(u freshstore.Expected) freshstore.Expected {
	u.Inventory = append([]freshstore.Ref(nil), u.Inventory...)
	return u
}
