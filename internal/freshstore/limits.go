//go:build linux

package freshstore

import "github.com/relux-works/swarma-credential-broker/internal/store"

type Limits struct{ RecordBytes, RetainedBytes, RetainedRecords, UnitBytes, Dependencies, RawObjectBytes, ReadBytes, MemoryBytes, WorkBytes uint64 }

func (l Limits) valid() bool {
	for _, n := range []uint64{l.RecordBytes, l.RetainedBytes, l.RetainedRecords, l.UnitBytes, l.Dependencies, l.RawObjectBytes, l.ReadBytes, l.MemoryBytes, l.WorkBytes} {
		if n == 0 || n > 1<<40 || n > uint64(int(^uint(0)>>1)) {
			return false
		}
	}
	return l.RecordBytes <= store.MaxRecordBytes && l.RetainedRecords <= 4096 && l.Dependencies <= 256 && l.Dependencies <= l.RetainedRecords && l.UnitBytes <= l.RetainedBytes
}
func add(a, b uint64) (uint64, bool) {
	if b > ^uint64(0)-a {
		return 0, false
	}
	return a + b, true
}
func mul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}
func (l Limits) cost(u, q, v, k uint64) error {
	if !l.valid() {
		return ErrInvalid
	}
	if k > l.Dependencies || u > l.UnitBytes || q > l.ReadBytes {
		return ErrLimit
	}
	// Conservative ceilings, not a racy previously observed account census.
	nodes, ok := add(l.RetainedRecords, k)
	if !ok {
		return ErrLimit
	}
	nodes, ok = add(nodes, 4)
	if !ok {
		return ErrLimit
	}
	m, ok := add(u, q)
	if !ok {
		return ErrLimit
	}
	m, ok = mul(m, 4)
	if !ok {
		return ErrLimit
	}
	raw, ok := mul(v, 4)
	if !ok {
		return ErrLimit
	}
	m, ok = add(m, raw)
	if !ok {
		return ErrLimit
	}
	meta, ok := mul(nodes, 512)
	if !ok {
		return ErrLimit
	}
	m, ok = add(m, meta)
	if !ok {
		return ErrLimit
	}
	m, ok = add(m, 4096)
	if !ok || m > l.MemoryBytes {
		return ErrLimit
	}
	w, ok := add(l.RetainedBytes, u)
	if !ok {
		return ErrLimit
	}
	w, ok = add(w, q)
	if !ok {
		return ErrLimit
	}
	w, ok = add(w, v)
	if !ok {
		return ErrLimit
	}
	w, ok = mul(w, 8)
	if !ok {
		return ErrLimit
	}
	meta, ok = mul(nodes, 1024)
	if !ok {
		return ErrLimit
	}
	w, ok = add(w, meta)
	if !ok || w > l.WorkBytes {
		return ErrLimit
	}
	return nil
}
func (l Limits) store() store.ImmutableLimits {
	return store.ImmutableLimits{RecordBytes: l.RecordBytes, TotalBytes: l.RetainedBytes, TotalRecords: l.RetainedRecords, ReadBytes: l.ReadBytes}
}
