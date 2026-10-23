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
	ops      storageSyscalls
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

// storageSyscalls is private. Only test-compiled constructors provide a shim;
// production uses the real operation directly and has no selector or setter.
type storageSyscalls interface {
	run(string, func() error) error
}

func (r Repository) syscall(name string, call func() error) error {
	if r.ops != nil {
		return r.ops.run(name, call)
	}
	return call()
}
func fileKind(name string) string {
	for _, prefix := range []string{"record-", "artifact-", "approval-"} {
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			return prefix[:len(prefix)-1]
		}
	}
	return name
}
func (r Repository) sync(f *os.File, stage string) error {
	return r.syscall("fsync:"+stage, f.Sync)
}
func (r Repository) root(create bool) (*os.File, error) {
	if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return nil, ErrUnavailable
	}
	if create {
		if e := r.syscall("mkdir:root", func() error { return os.Mkdir(r.Path, 0700) }); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
	}
	var fd int
	e := r.syscall("open:root", func() (err error) {
		fd, err = unix.Open(r.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		return
	})
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "qualification-directory")
	if !r.protected(f, os.ModeDir|0700) {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func (r Repository) protected(f *os.File, mode os.FileMode) bool {
	var s os.FileInfo
	e := r.syscall("fstat:"+fileKind(f.Name()), func() (err error) { s, err = f.Stat(); return })
	if e != nil {
		return false
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	return ok && st.Uid == r.UID && s.Mode() == mode && (s.IsDir() || st.Nlink == 1)
}
func (r Repository) openAt(root *os.File, name string, flags int) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrUnavailable
	}
	var fd int
	operation := "open:" + fileKind(name)
	if flags&unix.O_CREAT != 0 {
		operation = "open-create:" + fileKind(name)
	}
	e := r.syscall(operation, func() (err error) {
		fd, err = unix.Openat(int(root.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
		return
	})
	if e != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), nil
}
func (r Repository) readAt(root *os.File, name string) ([]byte, error) {
	f, e := r.openAt(root, name, unix.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if !r.protected(f, 0600) {
		return nil, ErrUnavailable
	}
	var b []byte
	e = r.syscall("read:"+fileKind(name), func() (err error) { b, err = io.ReadAll(io.LimitReader(f, 1<<20+1)); return })
	if e != nil || len(b) > 1<<20 {
		clear(b)
		return nil, ErrUnavailable
	}
	return b, nil
}
func (r Repository) lock(root *os.File, how int) (*os.File, error) {
	f, e := r.openAt(root, "lock", unix.O_RDWR|unix.O_CREAT)
	if e != nil {
		return nil, e
	}
	if !r.protected(f, 0600) || r.syscall("flock:lock", func() error { return unix.Flock(int(f.Fd()), how|unix.LOCK_NB) }) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

// Only a confirmed ENOENT proves absence. Unavailable metadata is never clean.
func (r Repository) exists(root *os.File, name string) (bool, error) {
	var st unix.Stat_t
	e := r.syscall("lookup:"+fileKind(name), func() error { return unix.Fstatat(int(root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) })
	if e == unix.ENOENT {
		return false, nil
	}
	if e != nil {
		return false, ErrUnavailable
	}
	return true, nil
}
func (r Repository) unlink(root *os.File, name string) error {
	return r.syscall("unlink:"+name, func() error { return unix.Unlinkat(int(root.Fd()), name, 0) })
}
func (r Repository) rename(root *os.File, from, to string) error {
	return r.syscall("rename:"+from, func() error { return unix.Renameat(int(root.Fd()), from, int(root.Fd()), to) })
}
func (r Repository) stage(name string) error {
	if r.Fault != nil {
		return r.Fault(name)
	}
	return nil
}
func (r Repository) write(root *os.File, name string, b []byte) error {
	f, e := r.openAt(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if e != nil {
		return e
	}
	if !r.protected(f, 0600) {
		f.Close()
		return ErrUnavailable
	}
	n := 0
	e = r.syscall("write:"+fileKind(name), func() (err error) { n, err = f.Write(b); return })
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = r.sync(f, "file:"+fileKind(name))
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
	l, e := r.lock(root, unix.LOCK_EX)
	if e != nil {
		return "", e
	}
	defer l.Close()
	name := prefix + Hash(b) + ".json"
	if present, lookupErr := r.exists(root, name); lookupErr != nil {
		return "", lookupErr
	} else if present {
		old, e := r.readAt(root, name)
		if e != nil || !reflect.DeepEqual(old, b) {
			return "", ErrUnavailable
		}
	} else if e = r.write(root, name, b); e != nil {
		return "", e
	}
	if r.sync(root, "directory") != nil {
		return "", ErrUnavailable
	}
	return Hash(b), nil
}
func (r Repository) verifySources(root *os.File, rec Record) error {
	b, e := r.readAt(root, "approval-"+rec.Approval+".json")
	if e != nil || Hash(b) != rec.Approval {
		return ErrInvalid
	}
	var approval Approval
	if wire.Decode(b, &approval) != nil || approval.Kind != "qualification-approval/1" || approval.Identity != rec.Identity || approval.AccountCheck != "matched" || !approval.Accepted {
		return ErrInvalid
	}
	for _, c := range rec.Cases {
		for _, control := range []struct {
			side   string
			result Control
		}{{"positive", c.Positive}, {"negative", c.Negative}} {
			side, result := control.side, control.result
			if len(result.Artifacts) != 1 {
				return ErrInvalid
			}
			ref := result.Artifacts[0]
			b, e := r.readAt(root, "artifact-"+ref+".json")
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

type activation struct {
	Kind       string `json:"kind"`
	ListSHA256 string `json:"list_sha256"`
}

func (r Repository) readEntry(root *os.File, entry Entry) (Record, error) {
	b, e := r.readAt(root, "record-"+entry.Evidence+".json")
	if e != nil || Hash(b) != entry.Evidence {
		return Record{}, ErrUnavailable
	}
	rec, e := DecodeRecord(b)
	if e != nil || rec.Identity != entry.Identity || rec.Publishable() != nil || r.verifySources(root, rec) != nil {
		return Record{}, ErrUnavailable
	}
	return rec, nil
}

// Publication prepares durable evidence and activation bytes before removing
// the fence. Activation's final rename happens only after the removal fsync.
// Losing that last namespace change after a crash conservatively closes Read;
// no durability operation follows activation and can return a late failure.
func (r Repository) Publish(ctx context.Context, rec Record) error {
	if rec.Publishable() != nil || r.Observer == nil {
		return ErrInvalid
	}
	root, e := r.root(true)
	if e != nil {
		return e
	}
	defer root.Close()
	l, e := r.lock(root, unix.LOCK_EX)
	if e != nil {
		return e
	}
	defer l.Close()
	if present, e := r.exists(root, "in-progress"); e != nil || present {
		return ErrUnavailable
	}
	if r.write(root, "in-progress", []byte("qualification-publication/1\n")) != nil || r.sync(root, "fence-directory") != nil {
		return ErrUnavailable
	}
	// An earlier activation can never commit this attempt, even for equal bytes.
	if present, e := r.exists(root, "activation.json"); e != nil {
		return e
	} else if present {
		if r.unlink(root, "activation.json") != nil {
			return ErrUnavailable
		}
	}
	if r.sync(root, "invalidation-directory") != nil {
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
	if present, e := r.exists(root, "record-"+ref+".json"); e != nil {
		return e
	} else if present {
		saved, e := r.readAt(root, "record-"+ref+".json")
		if e != nil || string(saved) != string(raw) {
			return ErrUnavailable
		}
	} else if r.write(root, "record-"+ref+".json", raw) != nil {
		return ErrUnavailable
	}
	if r.sync(root, "evidence-directory") != nil || r.stage("after-evidence-flush") != nil {
		return ErrUnavailable
	}
	list := List{Kind: "qualified-list/1", Entries: []Entry{}}
	if present, e := r.exists(root, "qualified.json"); e != nil {
		return e
	} else if present {
		b, e := r.readAt(root, "qualified.json")
		if e != nil || wire.Decode(b, &list) != nil || validateList(list) != nil {
			return ErrUnavailable
		}
		for _, entry := range list.Entries {
			if _, e := r.readEntry(root, entry); e != nil {
				return e
			}
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
	if r.write(root, "pending-list", b) != nil || r.rename(root, "pending-list", "qualified.json") != nil {
		return ErrUnavailable
	}
	if r.stage("after-list-replace") != nil || r.sync(root, "list-directory") != nil || r.stage("after-list-directory-flush") != nil {
		return ErrUnavailable
	}
	savedList, e := r.readAt(root, "qualified.json")
	if e != nil || string(savedList) != string(b) {
		return ErrUnavailable
	}
	for _, entry := range list.Entries {
		if _, e := r.readEntry(root, entry); e != nil {
			return e
		}
	}
	again, _, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || !sameIdentity(again, current) {
		return ErrUnavailable
	}
	ready, e := wire.Encode(activation{Kind: "qualification-activation/1", ListSHA256: Hash(b)})
	if e != nil {
		return ErrInvalid
	}
	if r.write(root, "pending-activation", ready) != nil || r.sync(root, "activation-preparation-directory") != nil {
		return ErrUnavailable
	}
	if r.unlink(root, "in-progress") != nil {
		return ErrUnavailable
	}
	if r.sync(root, "fence-removal-directory") != nil || r.stage("after-fence-removal-flush") != nil {
		return ErrUnavailable
	}
	// This is the last fallible operation, not followed by an unsafe late fsync.
	// Its prepared inode and all authority data are already flushed. A crash can
	// lose the activation name, but cannot activate unflushed list/evidence data.
	if r.rename(root, "pending-activation", "activation.json") != nil {
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
	l, e := r.lock(root, unix.LOCK_SH)
	if e != nil {
		return Record{}, Catalog{}, e
	}
	defer l.Close()
	for _, name := range []string{"in-progress", "pending-activation"} {
		if present, e := r.exists(root, name); e != nil || present {
			return Record{}, Catalog{}, ErrUnavailable
		}
	}
	current, catalog, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || current.Validate() != nil {
		return Record{}, Catalog{}, ErrUnavailable
	}
	b, e := r.readAt(root, "qualified.json")
	var list List
	if e != nil || wire.Decode(b, &list) != nil || validateList(list) != nil {
		return Record{}, Catalog{}, ErrUnavailable
	}
	ready, e := r.readAt(root, "activation.json")
	var active activation
	if e != nil || wire.Decode(ready, &active) != nil || active.Kind != "qualification-activation/1" || active.ListSHA256 != Hash(b) {
		return Record{}, Catalog{}, ErrUnavailable
	}
	var selected Record
	found := false
	// The list is one authority: verify all protected records and sources before
	// selecting any entry, including unrelated entries before and after a match.
	for _, entry := range list.Entries {
		rec, e := r.readEntry(root, entry)
		if e != nil {
			return Record{}, Catalog{}, ErrUnavailable
		}
		if sameIdentity(entry.Identity, current) {
			selected = rec
			found = true
		}
	}
	if !found {
		return Record{}, Catalog{}, ErrUnavailable
	}
	again, againCatalog, missing := Observe(ctx, r.Observer)
	if len(missing) > 0 || !sameIdentity(again, current) || !reflect.DeepEqual(catalog, againCatalog) {
		return Record{}, Catalog{}, ErrUnavailable
	}
	return selected, catalog, nil
}

// WhileClosed holds an exclusive admission fence for a qualification run. A
// pending or failed run preserves the fence; recovery is an operator procedure.
func (r Repository) WhileClosed(ctx context.Context, run func() error) error {
	root, e := r.root(true)
	if e != nil {
		return e
	}
	defer root.Close()
	l, e := r.lock(root, unix.LOCK_EX)
	if e != nil {
		return e
	}
	defer l.Close()
	if present, lookupErr := r.exists(root, "in-progress"); lookupErr != nil || present {
		return ErrUnavailable
	}
	if r.write(root, "in-progress", []byte("qualification-run/1\n")) != nil || r.sync(root, "directory") != nil || ctx.Err() != nil {
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
