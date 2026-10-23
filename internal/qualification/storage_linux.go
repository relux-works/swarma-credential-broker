//go:build linux

package qualification

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Fault is a durability-stage observer. It carries no publication authority.
type Fault func(string) error
type Repository struct {
	Path     string
	UID      uint32
	Observer IdentityObserver
	Fault    Fault
}
type List struct {
	Kind    string  `json:"kind"`
	Entries []Entry `json:"entries"`
}
type Entry struct {
	Identity Identity `json:"identity"`
	Evidence string   `json:"evidence_sha256"`
}

// Artifact is intentionally closed metadata, never stdout, raw RPC or arbitrary
// strings. Its digest is verified from this protected typed file on every read.
type Artifact struct {
	Kind     string   `json:"kind"`
	Identity Identity `json:"identity"`
	CaseID   string   `json:"case_id"`
	Side     string   `json:"side"`
	Result   Control  `json:"result"`
}
type Approval struct {
	Kind         string   `json:"kind"`
	Identity     Identity `json:"identity"`
	AccountCheck string   `json:"account_identity_check"`
	Accepted     bool     `json:"operator_accepted"`
}

func Directory(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "qualification")
}
func (r Repository) root(create bool) (*os.File, error) {
	if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return nil, ErrUnavailable
	}
	if create {
		if e := os.Mkdir(r.Path, 0700); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
	}
	fd, e := unix.Open(r.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "qualification-directory")
	if !protected(f, r.UID, os.ModeDir|0700) {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func protected(f *os.File, uid uint32, mode os.FileMode) bool {
	s, e := f.Stat()
	if e != nil {
		return false
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && s.Mode() == mode && (s.IsDir() || st.Nlink == 1)
}
func openAt(root *os.File, name string, flags int) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrUnavailable
	}
	fd, e := unix.Openat(int(root.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), nil
}
func readAt(root *os.File, name string, uid uint32) ([]byte, error) {
	f, e := openAt(root, name, unix.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if !protected(f, uid, 0600) {
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		clear(b)
		return nil, ErrUnavailable
	}
	return b, nil
}
func lock(root *os.File, uid uint32, how int) (*os.File, error) {
	f, e := openAt(root, "lock", unix.O_RDWR|unix.O_CREAT)
	if e != nil {
		return nil, e
	}
	if !protected(f, uid, 0600) || unix.Flock(int(f.Fd()), how|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func exists(root *os.File, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}
func (r Repository) stage(name string) error {
	if r.Fault != nil {
		return r.Fault(name)
	}
	return nil
}
func (r Repository) write(root *os.File, name string, b []byte) error {
	f, e := openAt(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if e != nil {
		return e
	}
	if !protected(f, r.UID, 0600) {
		f.Close()
		return ErrUnavailable
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}

// PutArtifact stores only a validated metadata artifact. Caller code cannot use
// this writer to stash private diagnostics or arbitrary material in evidence.
func (r Repository) PutArtifact(a Artifact) (string, error) {
	if validArtifact(a) != nil {
		return "", ErrInvalid
	}
	b, e := wire.Encode(a)
	if e != nil {
		return "", ErrInvalid
	}
	return r.putContent("artifact-", b)
}
func validArtifact(a Artifact) error {
	if a.Kind != "qualification-case/1" || a.Identity.Validate() != nil || a.Side != "positive" && a.Side != "negative" || len(a.Result.Artifacts) != 0 {
		return ErrInvalid
	}
	rec := Pending(a.Identity)
	found := false
	for n, c := range rec.Cases {
		if c.ID == a.CaseID {
			found = true
			if a.Side == "positive" {
				rec.Cases[n].Positive = a.Result
			} else {
				rec.Cases[n].Negative = a.Result
			}
		}
	}
	if !found {
		return ErrInvalid
	}
	// Validate the control through the same closed schema with a placeholder
	// reference; the artifact's own reference is not recursively self-hashed.
	for n := range rec.Cases {
		if rec.Cases[n].ID == a.CaseID {
			if a.Side == "positive" {
				rec.Cases[n].Positive.Artifacts = []string{Hash(nil)}
			} else {
				rec.Cases[n].Negative.Artifacts = []string{Hash(nil)}
			}
		}
	}
	return rec.Validate()
}
func (r Repository) PutApproval(a Approval) (string, error) {
	if a.Kind != "qualification-approval/1" || a.Identity.Validate() != nil || !a.Accepted || a.AccountCheck != "matched" {
		return "", ErrInvalid
	}
	b, e := wire.Encode(a)
	if e != nil {
		return "", ErrInvalid
	}
	return r.putContent("approval-", b)
}
func (r Repository) putContent(prefix string, b []byte) (string, error) {
	root, e := r.root(true)
	if e != nil {
		return "", e
	}
	defer root.Close()
	l, e := lock(root, r.UID, unix.LOCK_EX)
	if e != nil {
		return "", e
	}
	defer l.Close()
	name := prefix + Hash(b) + ".json"
	if exists(root, name) {
		old, e := readAt(root, name, r.UID)
		if e != nil || !reflect.DeepEqual(old, b) {
			return "", ErrUnavailable
		}
	} else if e = r.write(root, name, b); e != nil {
		return "", e
	}
	if root.Sync() != nil {
		return "", ErrUnavailable
	}
	return Hash(b), nil
}
func (r Repository) verifySources(root *os.File, rec Record) error {
	b, e := readAt(root, "approval-"+rec.Approval+".json", r.UID)
	if e != nil || Hash(b) != rec.Approval {
		return ErrInvalid
	}
	var approval Approval
	if wire.Decode(b, &approval) != nil || approval.Kind != "qualification-approval/1" || approval.Identity != rec.Identity || approval.AccountCheck != "matched" || !approval.Accepted {
		return ErrInvalid
	}
	for _, c := range rec.Cases {
		for side, result := range map[string]Control{"positive": c.Positive, "negative": c.Negative} {
			if len(result.Artifacts) != 1 {
				return ErrInvalid
			}
			ref := result.Artifacts[0]
			b, e := readAt(root, "artifact-"+ref+".json", r.UID)
			if e != nil || Hash(b) != ref {
				return ErrInvalid
			}
			var a Artifact
			if wire.Decode(b, &a) != nil || validArtifact(a) != nil || a.Identity != rec.Identity || a.CaseID != c.ID || a.Side != side {
				return ErrInvalid
			}
			result.Artifacts = []string{}
			if !reflect.DeepEqual(result, a.Result) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Publish leaves the durable fence on every uncertain path, including failures
// after rename. Only a fully flushed, reread publication may remove that fence.
func (r Repository) Publish(ctx context.Context, rec Record) error {
	if rec.Publishable() != nil || r.Observer == nil {
		return ErrInvalid
	}
	root, e := r.root(true)
	if e != nil {
		return e
	}
	defer root.Close()
	l, e := lock(root, r.UID, unix.LOCK_EX)
	if e != nil {
		return e
	}
	defer l.Close()
	if exists(root, "in-progress") {
		return ErrUnavailable
	}
	if e = r.write(root, "in-progress", []byte("qualification-publication/1\n")); e != nil || root.Sync() != nil {
		return ErrUnavailable
	}
	current, _, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || !sameIdentity(current, rec.Identity) || current.Validate() != nil || r.verifySources(root, rec) != nil {
		return ErrUnavailable
	}
	raw, e := wire.Encode(rec)
	if e != nil {
		return ErrInvalid
	}
	if r.stage("before-evidence-flush") != nil {
		return ErrUnavailable
	}
	ref := Hash(raw)
	if exists(root, "record-"+ref+".json") {
		saved, e := readAt(root, "record-"+ref+".json", r.UID)
		if e != nil || string(saved) != string(raw) {
			return ErrUnavailable
		}
	} else if e = r.write(root, "record-"+ref+".json", raw); e != nil {
		return e
	}
	if root.Sync() != nil {
		return ErrUnavailable
	}
	if r.stage("after-evidence-flush") != nil {
		return ErrUnavailable
	}
	// Replacing the whole list preserves other exact entries, never a wildcard.
	list := List{Kind: "qualified-list/1", Entries: []Entry{}}
	if exists(root, "qualified.json") {
		b, e := readAt(root, "qualified.json", r.UID)
		if e != nil || wire.Decode(b, &list) != nil || validateList(list) != nil {
			return ErrUnavailable
		}
	}
	entries := []Entry{}
	for _, entry := range list.Entries {
		if entry.Identity != rec.Identity {
			entries = append(entries, entry)
		}
	}
	list.Entries = append(entries, Entry{rec.Identity, ref})
	if validateList(list) != nil {
		return ErrInvalid
	}
	b, e := wire.Encode(list)
	if e != nil {
		return ErrInvalid
	}
	if e = r.write(root, "pending-list", b); e != nil {
		return e
	}
	if unix.Renameat(int(root.Fd()), "pending-list", int(root.Fd()), "qualified.json") != nil {
		return ErrUnavailable
	}
	if r.stage("after-list-replace") != nil {
		return ErrUnavailable
	}
	if root.Sync() != nil || r.stage("after-list-directory-flush") != nil {
		return ErrUnavailable
	}
	savedList, e := readAt(root, "qualified.json", r.UID)
	if e != nil || string(savedList) != string(b) {
		return ErrUnavailable
	}
	again, _, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || !sameIdentity(again, current) {
		return ErrUnavailable
	}
	saved, e := readAt(root, "record-"+ref+".json", r.UID)
	verified, e2 := DecodeRecord(saved)
	if e != nil || e2 != nil || Hash(saved) != ref || !sameIdentity(verified.Identity, current) || verified.Publishable() != nil || r.verifySources(root, verified) != nil {
		return ErrUnavailable
	}
	if unix.Unlinkat(int(root.Fd()), "in-progress", 0) != nil || root.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
func (r Repository) Read(ctx context.Context) (Record, Catalog, error) {
	if r.Observer == nil {
		return Record{}, Catalog{}, ErrUnavailable
	}
	root, e := r.root(false)
	if e != nil {
		return Record{}, Catalog{}, e
	}
	defer root.Close()
	l, e := lock(root, r.UID, unix.LOCK_SH)
	if e != nil {
		return Record{}, Catalog{}, e
	}
	defer l.Close()
	if exists(root, "in-progress") {
		return Record{}, Catalog{}, ErrUnavailable
	}
	current, catalog, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || current.Validate() != nil {
		return Record{}, Catalog{}, ErrUnavailable
	}
	b, e := readAt(root, "qualified.json", r.UID)
	var list List
	if e != nil || wire.Decode(b, &list) != nil || validateList(list) != nil {
		return Record{}, Catalog{}, ErrUnavailable
	}
	for _, entry := range list.Entries {
		if !sameIdentity(entry.Identity, current) {
			continue
		}
		b, e := readAt(root, "record-"+entry.Evidence+".json", r.UID)
		if e != nil || Hash(b) != entry.Evidence {
			return Record{}, Catalog{}, ErrUnavailable
		}
		rec, e := DecodeRecord(b)
		if e != nil || !sameIdentity(rec.Identity, current) || rec.Publishable() != nil || r.verifySources(root, rec) != nil {
			return Record{}, Catalog{}, ErrUnavailable
		}
		again, againCatalog, missing := Observe(ctx, r.Observer)
		if len(missing) > 0 || !sameIdentity(again, current) || !reflect.DeepEqual(catalog, againCatalog) {
			return Record{}, Catalog{}, ErrUnavailable
		}
		return rec, catalog, nil
	}
	return Record{}, Catalog{}, ErrUnavailable
}

// WhileClosed holds an exclusive admission fence for a qualification run. A
// pending or failed run preserves the fence; recovery is an operator procedure.
func (r Repository) WhileClosed(ctx context.Context, run func() error) error {
	root, e := r.root(true)
	if e != nil {
		return e
	}
	defer root.Close()
	l, e := lock(root, r.UID, unix.LOCK_EX)
	if e != nil {
		return e
	}
	defer l.Close()
	if exists(root, "in-progress") {
		return ErrUnavailable
	}
	if r.write(root, "in-progress", []byte("qualification-run/1\n")) != nil || root.Sync() != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return run()
}

func sameIdentity(a, b Identity) bool { return a == b }

func validateList(list List) error {
	if list.Kind != "qualified-list/1" || list.Entries == nil || len(list.Entries) > 128 {
		return ErrInvalid
	}
	seen := map[Identity]bool{}
	for _, e := range list.Entries {
		if e.Identity.Validate() != nil || !validHash(e.Evidence) || seen[e.Identity] {
			return ErrInvalid
		}
		seen[e.Identity] = true
	}
	return nil
}
