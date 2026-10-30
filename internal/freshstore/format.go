//go:build linux

// Package freshstore implements an inactive, bounded immutable content fixture.
// Its caller-supplied limits and hashes establish no production authority.
package freshstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
)

const Schema = "freshstore/1"

var ErrInvalid = errors.New("invalid immutable fixture input")
var ErrLimit = errors.New("immutable fixture limit")
var ErrConflict = errors.New("immutable fixture conflict")
var ErrUnavailable = errors.New("immutable fixture unavailable")

type Binding struct{ Installation, Scope, Pin, Previous string }
type Input struct {
	Name, Kind string
	Raw        []byte
}
type Ref struct {
	Digest     string
	Encoded    uint64
	Kind, Name string
	Raw        uint64
	RawDigest  string
}
type Expected struct {
	Binding
	Schema, ManifestDigest string
	Inventory              []Ref
}
type Stored struct {
	ManifestDigest string
	Inventory      []Ref
}
type object struct {
	Binding
	Name, Kind string
	data       []byte
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
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
func (b Binding) valid() bool {
	return id(b.Installation) && id(b.Scope) && hash(b.Pin) && len(b.Previous) == 66 && (b.Previous[:2] == "g:" || b.Previous[:2] == "m:") && hash(b.Previous[2:])
}
func objectName(d string) string   { return "owner-fresh-object-" + d + ".json" }
func manifestName(d string) string { return "owner-fresh-manifest-" + d + ".json" }
func str(dst []byte, s string) []byte {
	dst = append(dst, '"')
	dst = append(dst, s...)
	return append(dst, '"')
}
func field(dst []byte, key, s string) []byte { dst = append(dst, key...); return str(dst, s) }
func objectBytes(b Binding, n, k, data string) []byte {
	x := field(nil, `{"data":`, data)
	x = field(x, `,"installation_id":`, b.Installation)
	x = field(x, `,"kind":`, "freshstore-object/1")
	x = field(x, `,"name":`, n)
	x = field(x, `,"object_kind":`, k)
	x = field(x, `,"pin":`, b.Pin)
	x = field(x, `,"previous":`, b.Previous)
	x = append(x, `,"revision":1,"schema":"freshstore/1"`...)
	x = field(x, `,"scope":`, b.Scope)
	return append(x, '}')
}
func refBytes(x []byte, r Ref) []byte {
	x = field(x, `{"digest":`, r.Digest)
	x = append(x, `,"encoded":`...)
	x = strconv.AppendUint(x, r.Encoded, 10)
	x = field(x, `,"kind":`, r.Kind)
	x = field(x, `,"name":`, r.Name)
	x = append(x, `,"raw":`...)
	x = strconv.AppendUint(x, r.Raw, 10)
	x = field(x, `,"raw_digest":`, r.RawDigest)
	return append(x, '}')
}
func manifestBytes(b Binding, refs []Ref) []byte {
	x := []byte(`{"dependencies":[`)
	for i, r := range refs {
		if i > 0 {
			x = append(x, ',')
		}
		x = refBytes(x, r)
	}
	x = append(x, ']')
	x = field(x, `,"installation_id":`, b.Installation)
	x = field(x, `,"kind":`, "freshstore-manifest/1")
	x = field(x, `,"pin":`, b.Pin)
	x = field(x, `,"previous":`, b.Previous)
	x = append(x, `,"revision":1,"schema":"freshstore/1"`...)
	x = field(x, `,"scope":`, b.Scope)
	return append(x, '}')
}

// The closed parser borrows bounded input slices and refuses before growing an
// inventory past its limit. It never builds an arbitrary JSON object tree.
type parser struct {
	b   []byte
	at  int
	err bool
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
func (p *parser) quoted(max int) []byte {
	if p.err {
		return nil
	}
	p.want(`"`)
	if p.err {
		return nil
	}
	n := bytes.IndexByte(p.b[p.at:], '"')
	if n < 0 || n > max {
		p.err = true
		return nil
	}
	v := p.b[p.at : p.at+n]
	for _, c := range v {
		if c < 32 || c > 126 || c == '\\' {
			p.err = true
			return nil
		}
	}
	p.at += n + 1
	return v
}
func (p *parser) s(max int) string { return string(p.quoted(max)) }
func (p *parser) num() uint64 {
	if p.err {
		return 0
	}
	start := p.at
	for p.at < len(p.b) && p.b[p.at] >= '0' && p.b[p.at] <= '9' {
		p.at++
		if p.at-start > 20 {
			p.err = true
			return 0
		}
	}
	v := p.b[start:p.at]
	if len(v) == 0 || len(v) > 1 && v[0] == '0' {
		p.err = true
		return 0
	}
	n, e := strconv.ParseUint(string(v), 10, 64)
	if e != nil || n == 0 {
		p.err = true
	}
	return n
}
func (p *parser) bindingTail(b *Binding) {
	p.want(`,"pin":`)
	b.Pin = p.s(64)
	p.want(`,"previous":`)
	b.Previous = p.s(66)
	p.want(`,"revision":1,"schema":"freshstore/1","scope":`)
	b.Scope = p.s(64)
	p.want(`}`)
}
func parseObject(raw []byte, recordLimit uint64) (object, error) {
	var o object
	if uint64(len(raw)) > recordLimit {
		return o, ErrLimit
	}
	p := parser{b: raw}
	p.want(`{"data":`)
	o.data = p.quoted(int(recordLimit))
	p.want(`,"installation_id":`)
	o.Installation = p.s(64)
	p.want(`,"kind":"freshstore-object/1","name":`)
	o.Name = p.s(64)
	p.want(`,"object_kind":`)
	o.Kind = p.s(64)
	p.bindingTail(&o.Binding)
	if p.err || p.at != len(raw) || !o.Binding.valid() || !id(o.Name) || !id(o.Kind) {
		return object{}, ErrInvalid
	}
	return o, nil
}
func parseManifest(raw []byte, recordLimit, maxRefs uint64) (Binding, []Ref, error) {
	var b Binding
	if uint64(len(raw)) > recordLimit {
		return b, nil, ErrLimit
	}
	p := parser{b: raw}
	p.want(`{"dependencies":[`)
	var refs []Ref
	for !p.err {
		if p.at >= len(raw) || raw[p.at] == ']' {
			break
		}
		if uint64(len(refs)) >= maxRefs {
			return b, nil, ErrLimit
		}
		var r Ref
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
		if p.err || !hash(r.Digest) || !hash(r.RawDigest) || !id(r.Name) || !id(r.Kind) {
			return b, nil, ErrInvalid
		}
		if len(refs) > 0 && refs[len(refs)-1].Name >= r.Name {
			return b, nil, ErrInvalid
		}
		refs = append(refs, r)
		if p.at < len(raw) && raw[p.at] == ',' {
			p.at++
			if p.at >= len(raw) || raw[p.at] == ']' {
				return b, nil, ErrInvalid
			}
			continue
		}
		break
	}
	p.want(`],"installation_id":`)
	b.Installation = p.s(64)
	p.want(`,"kind":"freshstore-manifest/1"`)
	p.bindingTail(&b)
	if p.err || p.at != len(raw) || !b.valid() || len(refs) == 0 {
		return Binding{}, nil, ErrInvalid
	}
	return b, refs, nil
}
func decodeData(b []byte, want uint64) ([]byte, error) {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil, ErrInvalid
	}
	padding := 0
	if b[len(b)-1] == '=' {
		padding++
	}
	if len(b) > 1 && b[len(b)-2] == '=' {
		padding++
	}
	for i, c := range b {
		if c == '=' && i >= len(b)-padding {
			continue
		}
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return nil, ErrInvalid
		}
	}
	n := uint64(len(b)/4*3 - padding)
	if n != want {
		return nil, ErrInvalid
	}
	raw := make([]byte, int(n))
	got, e := base64.StdEncoding.Strict().Decode(raw, b)
	if e != nil || got != len(raw) {
		return nil, ErrInvalid
	}
	return raw, nil
}
