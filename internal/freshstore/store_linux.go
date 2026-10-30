//go:build linux

package freshstore

import (
	"encoding/base64"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"strings"
)

type Fixture struct {
	account      *store.Account
	limits       Limits
	installation string
}

func mapped(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, store.ErrImmutableLimit) || errors.Is(e, store.ErrTooLarge) {
		return ErrLimit
	}
	if errors.Is(e, store.ErrImmutableInvalid) {
		return ErrInvalid
	}
	if errors.Is(e, store.ErrConflict) {
		return ErrConflict
	}
	return ErrUnavailable
}

// NewFixture never initializes history or grants an installed-policy capability.
func NewFixture(a *store.Account, l Limits) (*Fixture, error) {
	if a == nil || !l.valid() {
		return nil, ErrInvalid
	}
	if e := l.cost(0, 512, 0, 0); e != nil {
		return nil, e
	}
	s, _, e := a.ReadImmutableBounded(nil, l.store())
	if e != nil {
		return nil, mapped(e)
	}
	return &Fixture{a, l, s.Installation}, nil
}

// selectedRead measures only bounded metadata before admitting payload buffers.
// The subsequent locked read is capped to that admission, including on size changes.
func (f *Fixture) selectedRead(names []string, u, v, k uint64) ([][]byte, error) {
	l := f.limits
	if e := l.cost(u, 512, v, k); e != nil {
		return nil, e
	}
	snap, _, e := f.account.ReadImmutableBounded(nil, l.store())
	if e != nil {
		return nil, mapped(e)
	}
	q := uint64(512)
	for _, name := range names {
		found := false
		for _, entry := range snap.Entries {
			if entry.Name == name {
				if entry.Size > l.RecordBytes {
					return nil, ErrLimit
				}
				var ok bool
				q, ok = add(q, entry.Size)
				if !ok {
					return nil, ErrLimit
				}
				found = true
				break
			}
		}
		if !found {
			return nil, ErrUnavailable
		}
	}
	if e = l.cost(u, q, v, k); e != nil {
		return nil, e
	}
	bounded := l.store()
	bounded.ReadBytes = q
	_, raw, e := f.account.ReadImmutableBounded(names, bounded)
	return raw, mapped(e)
}
func (f *Fixture) checkPredecessor(b Binding, raw []byte) error {
	if digest(raw) != b.Previous[2:] {
		return ErrInvalid
	}
	p, _, e := parseManifest(raw, f.limits.RecordBytes, f.limits.Dependencies)
	if e != nil {
		return e
	}
	if p.Installation != b.Installation || p.Scope != b.Scope || p.Pin != b.Pin {
		return ErrInvalid
	}
	return nil
}
func (f *Fixture) binding(b Binding) error {
	if f == nil || !b.valid() || b.Installation != f.installation {
		return ErrInvalid
	}
	return nil
}
func (f *Fixture) Retain(b Binding, objects []Input) (Stored, error) {
	zero := Stored{}
	if e := f.binding(b); e != nil {
		return zero, e
	}
	l := f.limits
	k := uint64(len(objects))
	if k == 0 {
		return zero, ErrInvalid
	}
	if k > l.Dependencies {
		return zero, ErrLimit
	}
	// Size all data and the complete manifest before allocating encoded content.
	if e := l.cost(0, 512, 0, k); e != nil {
		return zero, e
	}
	var u, v, refSize uint64
	for i, o := range objects {
		if !id(o.Name) || !id(o.Kind) || len(o.Raw) == 0 || i > 0 && objects[i-1].Name >= o.Name {
			return zero, ErrInvalid
		}
		n := uint64(len(o.Raw))
		if n > l.RawObjectBytes {
			return zero, ErrLimit
		}
		expanded, ok := add(n, 2)
		if !ok {
			return zero, ErrLimit
		}
		expanded, ok = mul(expanded/3, 4)
		if !ok {
			return zero, ErrLimit
		}
		size, ok := add(uint64(len(objectBytes(b, o.Name, o.Kind, ""))), expanded)
		if !ok || size > l.RecordBytes {
			return zero, ErrLimit
		}
		u, ok = add(u, size)
		if !ok {
			return zero, ErrLimit
		}
		v, ok = add(v, n)
		if !ok {
			return zero, ErrLimit
		}
		rs := uint64(len(refBytes(nil, Ref{strings.Repeat("0", 64), size, o.Kind, o.Name, n, strings.Repeat("0", 64)})))
		refSize, ok = add(refSize, rs)
		if !ok {
			return zero, ErrLimit
		}
	}
	size, ok := add(uint64(len(manifestBytes(b, nil))), refSize)
	if !ok {
		return zero, ErrLimit
	}
	size, ok = add(size, k-1)
	if !ok {
		return zero, ErrLimit
	}
	u, ok = add(u, size)
	if !ok || size > l.RecordBytes {
		return zero, ErrLimit
	}
	if strings.HasPrefix(b.Previous, "m:") {
		raw, e := f.selectedRead([]string{manifestName(b.Previous[2:])}, u, v, k)
		if e != nil {
			return zero, e
		}
		if e = f.checkPredecessor(b, raw[0]); e != nil {
			return zero, e
		}
	} else if e := l.cost(u, 512, v, k); e != nil {
		return zero, e
	}
	refs := make([]Ref, 0, len(objects))
	batch := make([]store.EncodedImmutable, 0, len(objects)+1)
	for _, o := range objects {
		raw := objectBytes(b, o.Name, o.Kind, base64.StdEncoding.EncodeToString(o.Raw))
		refs = append(refs, Ref{digest(raw), uint64(len(raw)), o.Kind, o.Name, uint64(len(o.Raw)), digest(o.Raw)})
		batch = append(batch, store.EncodedImmutable{Name: objectName(refs[len(refs)-1].Digest), Bytes: raw})
	}
	raw := manifestBytes(b, refs)
	d := digest(raw)
	batch = append(batch, store.EncodedImmutable{Name: manifestName(d), Bytes: raw})
	if e := f.account.AppendImmutableBounded(batch, l.store()); e != nil {
		return zero, mapped(e)
	}
	return Stored{d, refs}, nil
}
func (f *Fixture) ReadExact(want Expected) ([][]byte, error) {
	if e := f.binding(want.Binding); e != nil {
		return nil, e
	}
	if want.Schema != Schema || !hash(want.ManifestDigest) || len(want.Inventory) == 0 {
		return nil, ErrInvalid
	}
	l := f.limits
	k := uint64(len(want.Inventory))
	if k > l.Dependencies {
		return nil, ErrLimit
	}
	var v uint64
	for i, r := range want.Inventory {
		if !id(r.Name) || !id(r.Kind) || !hash(r.Digest) || !hash(r.RawDigest) || r.Encoded == 0 || r.Raw == 0 || i > 0 && want.Inventory[i-1].Name >= r.Name {
			return nil, ErrInvalid
		}
		if r.Encoded > l.RecordBytes || r.Raw > l.RawObjectBytes {
			return nil, ErrLimit
		}
		var ok bool
		v, ok = add(v, r.Raw)
		if !ok {
			return nil, ErrLimit
		}
	}
	if e := l.cost(0, 512, v, k); e != nil {
		return nil, e
	}
	// Snapshot names are bounded only after the conservative preallocation gate.
	names := make([]string, 0, len(want.Inventory)+1)
	names = append(names, manifestName(want.ManifestDigest))
	for _, r := range want.Inventory {
		names = append(names, objectName(r.Digest))
	}
	if strings.HasPrefix(want.Previous, "m:") {
		names = append(names, manifestName(want.Previous[2:]))
	}
	raw, e := f.selectedRead(names, 0, v, k)
	if e != nil {
		return nil, e
	}
	if digest(raw[0]) != want.ManifestDigest {
		return nil, ErrInvalid
	}
	b, refs, e := parseManifest(raw[0], l.RecordBytes, l.Dependencies)
	if e != nil {
		return nil, e
	}
	if b != want.Binding || len(refs) != len(want.Inventory) {
		return nil, ErrInvalid
	}
	for i, r := range refs {
		if r != want.Inventory[i] {
			return nil, ErrInvalid
		}
	}
	if strings.HasPrefix(b.Previous, "m:") {
		if e := f.checkPredecessor(b, raw[len(raw)-1]); e != nil {
			return nil, e
		}
	}
	out := make([][]byte, 0, len(refs))
	for i, r := range refs {
		encoded := raw[i+1]
		if uint64(len(encoded)) != r.Encoded || digest(encoded) != r.Digest {
			return nil, ErrInvalid
		}
		o, e := parseObject(encoded, l.RecordBytes)
		if e != nil {
			return nil, e
		}
		if o.Binding != b || o.Name != r.Name || o.Kind != r.Kind {
			return nil, ErrInvalid
		}
		decoded, e := decodeData(o.data, r.Raw)
		if e != nil {
			return nil, e
		}
		if digest(decoded) != r.RawDigest {
			return nil, ErrInvalid
		}
		out = append(out, decoded)
	}
	return out, nil
}
