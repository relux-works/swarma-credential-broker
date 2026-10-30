//go:build linux

package generationcas

import "github.com/relux-works/swarma-credential-broker/internal/freshstore"

// Limits are mandatory logical fixture bounds, not measured process RSS.
type Limits struct {
	RecordBytes, RetainedBytes, RetainedObjects, Units, Attempts, Handles uint64
	CoordinationRecords, UnitBytes, Dependencies, RawObjectBytes          uint64
	ReadBytes, MemoryBytes, WorkBytes, MaxGeneration                      uint64
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
func (l Limits) valid() bool {
	for _, n := range []uint64{l.RecordBytes, l.RetainedBytes, l.RetainedObjects, l.Units, l.Attempts, l.Handles, l.CoordinationRecords, l.UnitBytes, l.Dependencies, l.RawObjectBytes, l.ReadBytes, l.MemoryBytes, l.WorkBytes, l.MaxGeneration} {
		if n == 0 || n > 1<<40 || n > uint64(int(^uint(0)>>1)) {
			return false
		}
	}
	return l.RecordBytes <= 1<<20 && l.RetainedObjects <= 4096 && l.Units <= 64 && l.Attempts <= 64 && l.Handles <= 16 && l.CoordinationRecords <= 257 && l.Dependencies <= 256 && l.Dependencies <= l.RetainedObjects && l.UnitBytes <= l.RetainedBytes
}

// Formula operations are checked independently even though valid ceilings also
// imply that their largest intermediate fits uint64.
type arithmetic struct{ ok bool }

func (a *arithmetic) sum(xs ...uint64) uint64 {
	var n uint64
	for _, x := range xs {
		v, ok := add(n, x)
		a.ok = a.ok && ok
		n = v
	}
	return n
}
func (a *arithmetic) product(x, y uint64) uint64 { n, ok := mul(x, y); a.ok = a.ok && ok; return n }
func (l Limits) costs() (uint64, uint64, error) {
	if !l.valid() {
		return 0, 0, ErrInvalid
	}
	a := arithmetic{ok: true}
	c := a.product(l.RecordBytes, l.CoordinationRecords)
	v := a.product(l.RawObjectBytes, l.Dependencies)
	n := a.sum(l.RetainedObjects, l.Attempts, l.Handles, 16)
	m := a.sum(a.product(8, a.sum(c, l.ReadBytes, l.UnitBytes, v)), a.product(2048, n), 8192)
	w0 := a.sum(a.product(16, a.sum(l.RetainedBytes, c, l.ReadBytes, l.UnitBytes, v)), a.product(2048, n))
	ws := a.sum(a.product(8, a.sum(l.RetainedBytes, l.ReadBytes, v)), a.product(1024, a.sum(l.RetainedObjects, l.Dependencies, 4)))
	w := a.sum(w0, a.product(a.sum(l.Units, 1), ws))
	if !a.ok || m > l.MemoryBytes || w > l.WorkBytes {
		return m, w, ErrCapacity
	}
	return m, w, nil
}
func (l Limits) content() freshstore.Limits {
	return freshstore.Limits{RecordBytes: l.RecordBytes, RetainedBytes: l.RetainedBytes, RetainedRecords: l.RetainedObjects, UnitBytes: l.UnitBytes, Dependencies: l.Dependencies, RawObjectBytes: l.RawObjectBytes, ReadBytes: l.ReadBytes, MemoryBytes: l.MemoryBytes, WorkBytes: l.WorkBytes}
}
func (l Limits) runtime() (uint64, uint64) {
	return 4096 + 1024*(l.Attempts+l.Handles), 1 + l.Attempts + l.Handles
}
func (l Limits) charge(contentBytes, contentObjects, attempts uint64) (uint64, uint64, uint64, error) {
	if attempts > l.Attempts {
		return 0, 0, 0, ErrCapacity
	}
	d, n := l.runtime()
	slots := 1 + 4*attempts
	b, ok := mul(slots, l.RecordBytes)
	if !ok {
		return 0, 0, 0, ErrCapacity
	}
	b, ok = add(b, contentBytes)
	if !ok {
		return 0, 0, 0, ErrCapacity
	}
	b, ok = add(b, d)
	if !ok {
		return 0, 0, 0, ErrCapacity
	}
	o, ok := add(contentObjects, slots+n)
	if !ok || b > l.RetainedBytes || o > l.RetainedObjects || slots > l.CoordinationRecords || attempts > l.Attempts {
		return 0, 0, 0, ErrCapacity
	}
	return b, o, slots, nil
}
