//go:build linux

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// ImmutableLimits bounds a dedicated inactive content account, including controls
// and abandoned files. These parameters do not establish installed policy.
type ImmutableLimits struct{ RecordBytes, TotalBytes, TotalRecords, ReadBytes uint64 }
type EncodedImmutable struct {
	Name  string
	Bytes []byte
}
type ImmutableMeta struct {
	Name string
	Size uint64
}
type ImmutableSnapshot struct {
	Installation   string
	Bytes, Records uint64
	Entries        []ImmutableMeta
}

var ErrImmutableLimit = errors.New("immutable content limit")
var ErrImmutableInvalid = errors.New("invalid immutable content request")

func (l ImmutableLimits) valid() bool {
	return l.RecordBytes > 0 && l.RecordBytes <= MaxRecordBytes && l.TotalBytes > 0 && l.TotalBytes <= 1<<40 && l.TotalRecords > 0 && l.TotalRecords <= 4096 && l.ReadBytes >= 512 && l.ReadBytes <= 1<<40
}
func immutableName(n string, pending bool) bool {
	if len(n) > 128 {
		return false
	}
	if pending {
		n = strings.TrimPrefix(n, "pending-")
	}
	var d string
	if strings.HasPrefix(n, "owner-fresh-object-") {
		d = strings.TrimPrefix(n, "owner-fresh-object-")
	} else if strings.HasPrefix(n, "owner-fresh-manifest-") {
		d = strings.TrimPrefix(n, "owner-fresh-manifest-")
	} else {
		return false
	}
	if !strings.HasSuffix(d, ".json") {
		return false
	}
	d = strings.TrimSuffix(d, ".json")
	if len(d) != 64 {
		return false
	}
	for _, c := range []byte(d) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func immutableHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func immutableID(s string) bool {
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
func immutableControl(r *os.Root, uid uint32, installation, kind string) error {
	f, e := openFile(r, "identity.json", os.O_RDONLY, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	if immutableFileProtected(f, uid) != nil {
		return ErrUnavailable
	}
	st, e := f.Stat()
	if e != nil || st.Size() < 0 || st.Size() > 256 {
		return ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil || len(b) > 256 {
		return ErrUnavailable
	}
	// All identifiers were bounded before this small, fixed-shape comparison.
	want := `{"installation_id":"` + installation + `","kind":"` + kind + `","revision":1}`
	if string(b) != want {
		return ErrUnavailable
	}
	return nil
}
func (a *Account) immutableControls() error {
	if a == nil || a.parent == nil || !immutableID(a.installation) {
		return ErrUnavailable
	}
	original, e := a.parent.root.Stat(".")
	current, ce := os.Lstat(a.parent.path)
	if e != nil || ce != nil || !os.SameFile(original, current) {
		return ErrUnavailable
	}
	account, e := a.root.Stat(".")
	entry, ee := a.parent.root.Lstat(a.name)
	if e != nil || ee != nil || !os.SameFile(account, entry) {
		return ErrUnavailable
	}
	for _, r := range []*os.Root{a.parent.root, a.root} {
		d, e := r.Open(".")
		if e != nil {
			return ErrUnavailable
		}
		e = protected(d, a.uid, os.ModeDir|0700)
		d.Close()
		if e != nil {
			return ErrUnavailable
		}
	}
	if immutableControl(a.parent.root, a.uid, a.installation, "store-identity/1") != nil || immutableControl(a.root, a.uid, a.installation, "account-store/1") != nil {
		return ErrUnavailable
	}
	f, e := openFile(a.root, "owner.lock", os.O_RDONLY, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	s, e := f.Stat()
	held, he := a.lock.Stat()
	if e != nil || he != nil || s.Size() != 0 || !os.SameFile(s, held) || protected(f, a.uid, 0600) != nil {
		return ErrUnavailable
	}
	return nil
}
func (a *Account) immutableCensus(l ImmutableLimits) (ImmutableSnapshot, error) {
	s := ImmutableSnapshot{Installation: a.installation}
	if a.immutableControls() != nil {
		return s, ErrUnavailable
	}
	d, e := a.root.Open(".")
	if e != nil {
		return s, ErrUnavailable
	}
	defer d.Close()
	for {
		n := int(l.TotalRecords - s.Records + 1)
		if n > 16 {
			n = 16
		}
		entries, e := d.Readdirnames(n)
		if e != nil && e != io.EOF {
			return s, ErrUnavailable
		}
		for _, name := range entries {
			if s.Records >= l.TotalRecords {
				return s, ErrImmutableLimit
			}
			if name != "identity.json" && name != "owner.lock" && !immutableName(name, true) {
				return s, ErrUnavailable
			}
			f, er := openFile(a.root, name, os.O_RDONLY, 0)
			if er != nil {
				return s, immutableIO(er)
			}
			er = immutableFileProtected(f, a.uid)
			st, se := f.Stat()
			f.Close()
			if er != nil || se != nil || st.Size() < 0 {
				return s, ErrUnavailable
			}
			size := uint64(st.Size())
			if size > l.TotalBytes-s.Bytes {
				return s, ErrImmutableLimit
			}
			s.Bytes += size
			s.Records++
			s.Entries = append(s.Entries, ImmutableMeta{name, size})
		}
		if e == io.EOF {
			break
		}
	}
	return s, nil
}

// ReadImmutableBounded checks controls and the complete bounded census before
// allocating selected payloads. It does not decode arbitrary retained records.
func (a *Account) ReadImmutableBounded(names []string, l ImmutableLimits) (ImmutableSnapshot, [][]byte, error) {
	if a == nil || !l.valid() {
		return ImmutableSnapshot{}, nil, ErrImmutableInvalid
	}
	if uint64(len(names)) > l.TotalRecords {
		return ImmutableSnapshot{}, nil, ErrImmutableLimit
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !immutableName(n, false) || seen[n] {
			return ImmutableSnapshot{}, nil, ErrImmutableInvalid
		}
		seen[n] = true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, e := a.immutableCensus(l)
	if e != nil {
		return s, nil, e
	}
	sizes := make(map[string]uint64, len(s.Entries))
	for _, v := range s.Entries {
		sizes[v.Name] = v.Size
	}
	q := uint64(512)
	for _, n := range names {
		size, ok := sizes[n]
		if !ok {
			return s, nil, ErrUnavailable
		}
		if size > l.RecordBytes || size > l.ReadBytes-q {
			return s, nil, ErrImmutableLimit
		}
		q += size
	}
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		f, e := openFile(a.root, n, os.O_RDONLY, 0)
		if e != nil {
			return s, nil, ErrUnavailable
		}
		if immutableFileProtected(f, a.uid) != nil {
			f.Close()
			return s, nil, ErrUnavailable
		}
		size := sizes[n]
		st, e := f.Stat()
		if e != nil || st.Size() != int64(size) {
			f.Close()
			return s, nil, ErrUnavailable
		}
		b := make([]byte, int(size))
		_, e = io.ReadFull(f, b)
		var extra [1]byte
		more, tail := f.Read(extra[:])
		f.Close()
		if e != nil || more != 0 || tail != io.EOF {
			return s, nil, ErrUnavailable
		}
		out = append(out, b)
	}
	return s, out, nil
}

// AppendImmutableBounded admits the entire unit under the account exclusion.
// Failed writes remain charged; no current pointer or authority is selected.
func (a *Account) AppendImmutableBounded(batch []EncodedImmutable, l ImmutableLimits) error {
	if a == nil || !l.valid() {
		return ErrImmutableInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(batch) < 2 || uint64(len(batch)) > l.TotalRecords {
		return ErrImmutableLimit
	}
	total := uint64(0)
	seen := make(map[string]bool, len(batch))
	for i, v := range batch {
		if !immutableName(v.Name, false) || seen[v.Name] {
			return ErrImmutableInvalid
		}
		seen[v.Name] = true
		manifest := strings.HasPrefix(v.Name, "owner-fresh-manifest-")
		if manifest != (i == len(batch)-1) {
			return ErrImmutableInvalid
		}
		size := uint64(len(v.Bytes))
		if size == 0 || size > l.RecordBytes || size > l.TotalBytes-total {
			return ErrImmutableLimit
		}
		total += size
		if !strings.HasSuffix(v.Name, immutableHash(v.Bytes)+".json") {
			return ErrImmutableInvalid
		}
	}
	s, e := a.immutableCensus(l)
	if e != nil {
		return e
	}
	if uint64(len(batch)) > l.TotalRecords-s.Records || total > l.TotalBytes-s.Bytes {
		return ErrImmutableLimit
	}
	for _, existing := range s.Entries {
		if seen[existing.Name] {
			return ErrConflict
		}
	}
	for _, v := range batch {
		f, e := openFile(a.root, v.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			if os.IsExist(e) {
				return ErrConflict
			}
			return ErrUnavailable
		}
		if notify(a.hook, "immutable-create") != nil {
			f.Close()
			return ErrUnavailable
		}
		n, e := f.Write(v.Bytes)
		if e == nil && n != len(v.Bytes) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = notify(a.hook, "immutable-write")
		}
		if e == nil {
			e = f.Sync()
		}
		if e == nil {
			e = notify(a.hook, "immutable-file-sync")
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return ErrUnavailable
		}
		d, e := a.root.Open(".")
		if e != nil {
			return ErrUnavailable
		}
		e = d.Sync()
		ce = d.Close()
		if e != nil || ce != nil || notify(a.hook, "immutable-directory-sync") != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// Keep syscall errors inside the structured public error surface.
func immutableIO(e error) error                           { return ErrUnavailable }
func immutableFileProtected(f *os.File, uid uint32) error { return protected(f, uid, 0600) }
