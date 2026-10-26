//go:build linux

// Package store owns protected metadata, atomic replacement and stable locks.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var ErrUnavailable = errors.New("protected store unavailable")
var ErrConflict = errors.New("record revision conflict")

// MaxRecordBytes is the inclusive ceiling for encoded protected records.
const MaxRecordBytes = 1 << 20

// ErrTooLarge identifies a write refused before filesystem mutation. It also
// matches ErrUnavailable through errors.Is for existing fail-closed callers.
var ErrTooLarge = fmt.Errorf("%w: encoded record too large", ErrUnavailable)

// Durability receives completed stages; returning an error injects an I/O fault in tests.
type Durability func(stage string) error
type Store struct {
	mu           sync.Mutex
	root         *os.Root
	path         string
	lock         *os.File
	uid          uint32
	installation string
	hook         Durability
	accounts     map[string]*Account
}
type Account struct {
	parent       *Store
	name         string
	mu           sync.Mutex
	root         *os.Root
	lock         *os.File
	uid          uint32
	installation string
	hook         Durability
}
type identity struct {
	Kind         string `json:"kind"`
	Installation string `json:"installation_id"`
	Revision     uint64 `json:"revision"`
}

func protected(f *os.File, uid uint32, mode os.FileMode) error {
	s, e := f.Stat()
	if e != nil {
		return ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || s.Mode() != mode || (!s.IsDir() && st.Nlink != 1) {
		return ErrUnavailable
	}
	return nil
}
func ReadProtected(path string, uid uint32) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	if e = protected(f, uid, 0600); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	if e != nil || len(b) > MaxRecordBytes {
		return nil, ErrUnavailable
	}
	return b, nil
}
func openDir(path string, uid uint32) (*os.Root, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	if e = protected(f, uid, os.ModeDir|0700); e != nil {
		f.Close()
		return nil, e
	}
	defer f.Close()
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrUnavailable
	}
	opened, err := r.Stat(".")
	original, oldErr := f.Stat()
	if err != nil || oldErr != nil || !os.SameFile(opened, original) {
		r.Close()
		return nil, ErrUnavailable
	}
	return r, nil
}

// os.Root follows in-root symlinks even with O_NOFOLLOW. All record names
// are single components, so openat against its directory descriptor fails closed.
func openFile(r *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrUnavailable
	}
	d, err := r.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer d.Close()
	fd, err := syscall.Openat(int(d.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func lock(r *os.Root, uid uint32) (*os.File, error) {
	f, e := openFile(r, "owner.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrUnavailable
	}
	if e = protected(f, uid, 0600); e == nil {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if e != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func Open(path, installation string, uid uint32, initialize bool, hook Durability) (*Store, error) {
	if installation == "" {
		return nil, ErrUnavailable
	}
	var initial []byte
	if initialize {
		var e error
		initial, e = encodeRecord(identity{"store-identity/1", installation, 1})
		if e != nil {
			return nil, e
		}
		if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
		parent, e := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, ErrUnavailable
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	r, e := openDir(path, uid)
	if e != nil {
		return nil, e
	}
	l, e := lock(r, uid)
	if e != nil {
		r.Close()
		return nil, e
	}
	s := &Store{root: r, path: path, lock: l, uid: uid, installation: installation, hook: hook, accounts: map[string]*Account{}}
	fail := func() (*Store, error) { s.Close(); return nil, ErrUnavailable }
	b, e := read(r, "identity.json", uid)
	if os.IsNotExist(e) && initialize {
		// An existing nonempty store cannot be adopted as a new installation.
		entries, er := os.ReadDir(path)
		if er != nil || len(entries) != 1 || entries[0].Name() != "owner.lock" {
			return fail()
		}
		if e = replaceEncoded(r, "identity.json", initial, hook); e != nil {
			return fail()
		}
	} else if e != nil {
		return fail()
	} else {
		var id identity
		if wire.Decode(b, &id) != nil || id.Kind != "store-identity/1" || id.Installation != installation || id.Revision != 1 {
			return fail()
		}
	}
	return s, nil
}
func read(r *os.Root, name string, uid uint32) ([]byte, error) {
	f, e := openFile(r, name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = protected(f, uid, 0600); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	if e != nil || len(b) > MaxRecordBytes {
		return nil, ErrUnavailable
	}
	if _, e = wire.Parse(b); e != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}
func notify(h Durability, s string) error {
	if h != nil {
		return h(s)
	}
	return nil
}
func checkRecordSize(b []byte) error {
	if len(b) > MaxRecordBytes {
		return ErrTooLarge
	}
	return nil
}

func encodeRecord(v any) ([]byte, error) {
	b, e := wire.Encode(v)
	if e != nil {
		return nil, ErrUnavailable
	}
	if e = checkRecordSize(b); e != nil {
		return nil, e
	}
	return b, nil
}

func replace(r *os.Root, name string, v any, h Durability) error {
	b, e := encodeRecord(v)
	if e != nil {
		return e
	}
	return replaceEncoded(r, name, b, h)
}

// All record writers converge here with the exact canonical bytes they checked.
func replaceEncoded(r *os.Root, name string, b []byte, h Durability) error {
	if e := checkRecordSize(b); e != nil {
		return e
	}
	f, e := openFile(r, "pending-"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrUnavailable
	}
	defer r.Remove("pending-" + name)
	if _, e = f.Write(b); e == nil {
		e = notify(h, "write")
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = notify(h, "file-sync")
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return ErrUnavailable
	}
	if e = r.Rename("pending-"+name, name); e != nil {
		return ErrUnavailable
	}
	if e = notify(h, "rename"); e != nil {
		return ErrUnavailable
	}
	dir, e := r.Open(".")
	if e != nil {
		return ErrUnavailable
	}
	e = dir.Sync()
	ce = dir.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = notify(h, "directory-sync")
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Account(label string, initialize bool) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[label]; a != nil {
		return a, nil
	}
	sum := sha256.Sum256([]byte(label))
	name := "account-" + hex.EncodeToString(sum[:])
	var initial []byte
	if initialize {
		var e error
		initial, e = encodeRecord(identity{"account-store/1", s.installation, 1})
		if e != nil {
			return nil, e
		}
		if e := s.root.Mkdir(name, 0700); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
		parent, e := s.root.Open(".")
		if e != nil {
			return nil, ErrUnavailable
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	// OpenRoot confines descendants; the entry itself is checked without following links.
	info, e := s.root.Lstat(name)
	if e != nil || !info.IsDir() || info.Mode() != os.ModeDir|0700 {
		return nil, ErrUnavailable
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != s.uid {
		return nil, ErrUnavailable
	}
	r, e := s.root.OpenRoot(name)
	if e != nil {
		return nil, ErrUnavailable
	}
	opened, er := r.Stat(".")
	if er != nil || !os.SameFile(info, opened) {
		r.Close()
		return nil, ErrUnavailable
	}
	l, e := lock(r, s.uid)
	if e != nil {
		r.Close()
		return nil, e
	}
	a := &Account{parent: s, name: name, root: r, lock: l, uid: s.uid, installation: s.installation, hook: s.hook}
	b, e := read(r, "identity.json", s.uid)
	if os.IsNotExist(e) && initialize {
		d, er := r.Open(".")
		if er == nil {
			var names []string
			names, er = d.Readdirnames(-1)
			d.Close()
			if er == nil && (len(names) != 1 || names[0] != "owner.lock") {
				er = ErrUnavailable
			}
		}
		if er != nil {
			l.Close()
			r.Close()
			return nil, ErrUnavailable
		}
		e = replaceEncoded(r, "identity.json", initial, s.hook)
	} else if e == nil {
		var id identity
		e = wire.Decode(b, &id)
		if id.Kind != "account-store/1" || id.Installation != s.installation || id.Revision != 1 {
			e = ErrUnavailable
		}
	}
	if e != nil {
		l.Close()
		r.Close()
		return nil, ErrUnavailable
	}
	s.accounts[label] = a
	return a, nil
}
func validName(n string) bool {
	if !strings.HasSuffix(n, ".json") || strings.HasPrefix(n, "pending-") {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return n != "identity.json"
}
func (a *Account) Put(name string, prior uint64, v any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !validName(name) {
		return ErrUnavailable
	}
	b, e := read(a.root, name, a.uid)
	var revision uint64
	if e == nil {
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil || json.Unmarshal(m["revision"], &revision) != nil {
			return ErrUnavailable
		}
	} else if !os.IsNotExist(e) {
		return ErrUnavailable
	}
	if revision != prior {
		return ErrConflict
	}
	b, e = wire.Encode(v)
	if e != nil {
		return ErrUnavailable
	}
	var m map[string]json.RawMessage
	var id string
	var next uint64
	if json.Unmarshal(b, &m) != nil || json.Unmarshal(m["installation_id"], &id) != nil || id != a.installation || json.Unmarshal(m["revision"], &next) != nil || next != prior+1 {
		return ErrConflict
	}
	return replaceEncoded(a.root, name, b, a.hook)
}
func (a *Account) Records() (map[string][]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, e := a.root.Open(".")
	if e != nil {
		return nil, ErrUnavailable
	}
	names, e := d.Readdirnames(-1)
	d.Close()
	if e != nil {
		return nil, ErrUnavailable
	}
	out := map[string][]byte{}
	for _, n := range names {
		if n == "identity.json" || n == "owner.lock" {
			continue
		}
		if !validName(n) {
			return nil, ErrUnavailable
		}
		b, e := read(a.root, n, a.uid)
		if e != nil {
			return nil, ErrUnavailable
		}
		out[n] = b
	}
	return out, nil
}
func (a *Account) Healthy() error {
	if a.parent.Healthy() != nil {
		return ErrUnavailable
	}
	opened, e := a.root.Stat(".")
	current, er := a.parent.root.Lstat(a.name)
	if e != nil || er != nil || !os.SameFile(opened, current) {
		return ErrUnavailable
	}
	d, e := a.root.Open(".")
	if e != nil {
		return ErrUnavailable
	}
	e = protected(d, a.uid, os.ModeDir|0700)
	d.Close()
	if e != nil {
		return e
	}
	b, e := read(a.root, "identity.json", a.uid)
	if e != nil {
		return ErrUnavailable
	}
	var id identity
	if wire.Decode(b, &id) != nil || id.Kind != "account-store/1" || id.Installation != a.installation || id.Revision != 1 {
		return ErrUnavailable
	}
	return nil
}

// Healthy refuses replaced/missing roots as well as a lost installation marker.
func (s *Store) Healthy() error {
	current, err := os.Lstat(s.path)
	opened, other := s.root.Stat(".")
	if err != nil || other != nil || !os.SameFile(current, opened) || current.Mode() != os.ModeDir|0700 {
		return ErrUnavailable
	}
	b, err := read(s.root, "identity.json", s.uid)
	var id identity
	if err != nil || wire.Decode(b, &id) != nil || id.Kind != "store-identity/1" || id.Installation != s.installation || id.Revision != 1 {
		return ErrUnavailable
	}
	return nil
}

// PolicyGeneration durably raises the installation-wide policy floor before
// authority is published. Missing evidence is only created during initialization.
// The store's stable exclusive lock serializes this across daemon replacement.
func (s *Store) PolicyGeneration(g uint64, initialize bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Healthy() != nil || g == 0 {
		return ErrUnavailable
	}
	var mark struct {
		Kind         string `json:"kind"`
		Installation string `json:"installation_id"`
		Revision     uint64 `json:"revision"`
		Generation   uint64 `json:"policy_generation"`
	}
	b, err := read(s.root, "policy-watermark.json", s.uid)
	if os.IsNotExist(err) && initialize {
		d, e := s.root.Open(".")
		if e != nil {
			return ErrUnavailable
		}
		names, e := d.Readdirnames(-1)
		d.Close()
		if e != nil {
			return ErrUnavailable
		}
		for _, name := range names {
			if name != "identity.json" && name != "owner.lock" {
				return ErrUnavailable
			}
		}
		mark.Kind = "policy-watermark/1"
		mark.Installation = s.installation
	} else if err != nil || wire.Decode(b, &mark) != nil || mark.Kind != "policy-watermark/1" || mark.Installation != s.installation || mark.Revision == 0 || mark.Generation == 0 {
		return ErrUnavailable
	}
	if g < mark.Generation {
		return ErrUnavailable
	}
	if g == mark.Generation {
		return nil
	}
	mark.Generation = g
	mark.Revision++
	return replace(s.root, "policy-watermark.json", mark, s.hook)
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		a.lock.Close()
		a.root.Close()
	}
	if s.lock != nil {
		s.lock.Close()
	}
	if s.root != nil {
		return s.root.Close()
	}
	return nil
}
func LeaseName(id string) string  { return fmt.Sprintf("lease-%s.json", id) }
func IsAbsolute(path string) bool { return filepath.IsAbs(path) }

// Append retains an immutable owner evidence record with its attempt-wide
// revision. The owner validates sequential revisions across these distinct names.
// Exclusive lifetime locks and this account fence serialize cooperating writers.
func (a *Account) Append(name string, v any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !validName(name) || !strings.HasPrefix(name, "owner-") {
		return ErrUnavailable
	}
	if _, err := read(a.root, name, a.uid); !os.IsNotExist(err) {
		return ErrConflict
	}
	b, err := wire.Encode(v)
	var header struct {
		Installation string `json:"installation_id"`
		Revision     uint64 `json:"revision"`
	}
	if err != nil || json.Unmarshal(b, &header) != nil || header.Installation != a.installation || header.Revision == 0 {
		return ErrConflict
	}
	return replaceEncoded(a.root, name, b, a.hook)
}
