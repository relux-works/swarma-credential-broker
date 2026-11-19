//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

const managedIdentityLimit = 8 * 1024 * 1024

type managedAccount struct {
	UID        uint32 `json:"uid"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Class      string `json:"class"`
	Placement  string `json:"placement"`
	Generation string `json:"generation"`
	State      string `json:"state"`
}

type managedDocument struct {
	Format      string           `json:"format"`
	JournalHead string           `json:"journal_head"`
	Accounts    []managedAccount `json:"accounts"`
}

type managedPolicy struct {
	anchor string
	uid    uint32
	gid    uint32
}

type ManagedAuthority struct {
	root   string
	facts  Authority
	policy managedPolicy
	mu     sync.Mutex
	kinds  map[uint32]string
}

func NewManagedAuthority(root string, facts Authority) (*ManagedAuthority, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, refuse("principal_ledger_mismatch")
	}
	return &ManagedAuthority{root: root, facts: facts, policy: managedPolicy{anchor: "/"}, kinds: make(map[uint32]string)}, nil
}

func (a *ManagedAuthority) WithIdentity(ctx context.Context, fn func(View) error) error {
	return a.withManaged(ctx, false, fn)
}

func (a *ManagedAuthority) WithCurrent(ctx context.Context, fn func(View) error) error {
	return a.withManaged(ctx, true, fn)
}

func managedRefusal() error { return refuse("principal_ledger_mismatch") }

func (a *ManagedAuthority) withManaged(ctx context.Context, current bool, fn func(View) error) error {
	return a.withManagedAtBoundary(ctx, current, nil, fn)
}

func (a *ManagedAuthority) withManagedAtBoundary(ctx context.Context, current bool, boundary func(string), fn func(View) error) error {
	if a == nil || ctx == nil || fn == nil || ctx.Err() != nil {
		return managedRefusal()
	}
	parent, err := a.openDirectory(filepath.Join(a.root, "lib/user-manager"))
	if err != nil {
		return managedRefusal()
	}
	defer parent.Close()
	directory, err := a.openAt(parent, "generations", true)
	if err != nil {
		return managedRefusal()
	}
	defer directory.Close()
	if managedPending(directory) {
		return managedRefusal()
	}
	if boundary != nil {
		boundary("after-first-pending")
	}
	gate, err := a.openAt(directory, "gate.lock", false)
	if err != nil {
		return managedRefusal()
	}
	defer gate.Close()
	data, err := a.openAt(directory, "data.lock", false)
	if err != nil {
		return managedRefusal()
	}
	defer data.Close()
	for _, lock := range []*os.File{gate, data} {
		info, statErr := lock.Stat()
		if statErr != nil || info.Size() != 0 {
			return managedRefusal()
		}
	}
	if unix.Flock(int(gate.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return managedRefusal()
	}
	if managedPending(directory) {
		_ = unix.Flock(int(gate.Fd()), unix.LOCK_UN)
		return managedRefusal()
	}
	if boundary != nil {
		boundary("before-data-lock")
	}
	if unix.Flock(int(data.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		_ = unix.Flock(int(gate.Fd()), unix.LOCK_UN)
		return managedRefusal()
	}
	deadline := time.Now().Add(genjournal.ReaderHold)
	if boundary != nil {
		boundary("data-locked")
	}
	_ = unix.Flock(int(gate.Fd()), unix.LOCK_UN)
	defer unix.Flock(int(data.Fd()), unix.LOCK_UN)
	window, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	projection, err := a.readAt(parent, "identities.json", managedIdentityLimit)
	if err != nil {
		return managedRefusal()
	}
	if boundary != nil {
		boundary("projection-read")
	}
	journal, err := a.readAt(directory, "journal", genjournal.MaxFile)
	if err != nil {
		return managedRefusal()
	}
	verified, err := genjournal.Verify(bytes.NewReader(journal), genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil || verified.Capacity() != nil {
		return managedRefusal()
	}
	accounts, err := decodeManaged(projection, verified.Tail.Hash)
	if err != nil || window.Err() != nil {
		return managedRefusal()
	}
	if !a.rememberKinds(accounts) {
		return managedRefusal()
	}
	run := func(facts View) error {
		view := &managedView{accounts: accounts, journal: verified, facts: facts, ctx: window}
		view.active.Store(true)
		defer view.active.Store(false)
		if !view.live() {
			return managedRefusal()
		}
		if err := fn(view); err != nil {
			return err
		}
		if !view.released.Load() && !view.live() {
			return managedRefusal()
		}
		return nil
	}
	if a.facts == nil {
		if current {
			return refuse("revocation_state_unavailable")
		}
		return run(nil)
	}
	if current {
		return a.facts.WithCurrent(window, run)
	}
	return a.facts.WithIdentity(window, run)
}

func (a *ManagedAuthority) rememberKinds(accounts map[uint32]managedAccount) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for uid, account := range accounts {
		if previous, exists := a.kinds[uid]; exists && previous != account.Kind {
			return false
		}
	}
	for uid, account := range accounts {
		a.kinds[uid] = account.Kind
	}
	return true
}

func managedHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func decodeManaged(raw []byte, head string) (map[uint32]managedAccount, error) {
	var document managedDocument
	if len(raw) > managedIdentityLimit {
		return nil, managedRefusal()
	}
	if _, err := wire.Parse(raw); err != nil || wire.Decode(raw, &document) != nil || document.Format != "swarma-managed-identities/1" || !managedHex(document.JournalHead, 64) || document.JournalHead != head {
		return nil, managedRefusal()
	}
	accounts := make(map[uint32]managedAccount, len(document.Accounts))
	services := make(map[string]bool)
	for _, account := range document.Accounts {
		if _, exists := accounts[account.UID]; exists {
			return nil, managedRefusal()
		}
		if account.UID == 0 || !managedHex(account.Generation, 32) || account.Generation == "00000000000000000000000000000000" || account.Name == "" || strings.ContainsRune(account.Name, '\x00') || account.Placement != "local" || (account.Class != "trusted" && account.Class != "untrusted") || (account.State != "active" && account.State != "retired") {
			return nil, managedRefusal()
		}
		switch account.Kind {
		case "service":
			if account.Name != Gateway || account.State == "active" && services[account.Name] {
				return nil, managedRefusal()
			}
			if account.State == "active" {
				services[account.Name] = true
			}
		case "agent", "workplace":
		default:
			return nil, managedRefusal()
		}
		accounts[account.UID] = account
	}
	return accounts, nil
}

func (a *ManagedAuthority) check(file *os.File, directory bool, exact bool) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Uid != a.policy.uid || stat.Gid != a.policy.gid || stat.Mode&0022 != 0 {
		return managedRefusal()
	}
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || exact && stat.Mode&07777 != 0755 {
			return managedRefusal()
		}
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0644 || stat.Nlink != 1 {
		return managedRefusal()
	}
	return nil
}

func (a *ManagedAuthority) openDirectory(path string) (*os.File, error) {
	anchor := a.policy.anchor
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path != anchor && !strings.HasPrefix(path, strings.TrimSuffix(anchor, "/")+"/") {
		return nil, managedRefusal()
	}
	descriptor, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, managedRefusal()
	}
	directory := os.NewFile(uintptr(descriptor), "managed-directory")
	if a.check(directory, true, false) != nil {
		directory.Close()
		return nil, managedRefusal()
	}
	relative, err := filepath.Rel(anchor, path)
	if err != nil {
		directory.Close()
		return nil, managedRefusal()
	}
	if relative != "." {
		for _, component := range strings.Split(relative, "/") {
			descriptor, err = unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			directory.Close()
			if err != nil {
				return nil, managedRefusal()
			}
			directory = os.NewFile(uintptr(descriptor), "managed-directory")
			if a.check(directory, true, false) != nil {
				directory.Close()
				return nil, managedRefusal()
			}
		}
	}
	return directory, nil
}

func (a *ManagedAuthority) openAt(directory *os.File, name string, isDirectory bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if isDirectory {
		flags |= unix.O_DIRECTORY
	}
	descriptor, err := unix.Openat(int(directory.Fd()), name, flags, 0)
	if err != nil {
		return nil, managedRefusal()
	}
	file := os.NewFile(uintptr(descriptor), "managed-record")
	if a.check(file, isDirectory, true) != nil {
		file.Close()
		return nil, managedRefusal()
	}
	return file, nil
}

func (a *ManagedAuthority) readAt(directory *os.File, name string, limit int) ([]byte, error) {
	return a.readAtBoundary(directory, name, limit, nil)
}

func (a *ManagedAuthority) readAtBoundary(directory *os.File, name string, limit int, afterRead func()) ([]byte, error) {
	file, err := a.openAt(directory, name, false)
	if err != nil {
		return nil, managedRefusal()
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Size > int64(limit) {
		return nil, managedRefusal()
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if afterRead != nil {
		afterRead()
	}
	if err != nil || len(raw) > limit || unix.Fstat(int(file.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || a.check(file, false, true) != nil {
		return nil, managedRefusal()
	}
	return raw, nil
}

func managedPending(directory *os.File) bool {
	var stat unix.Stat_t
	return !errors.Is(unix.Fstatat(int(directory.Fd()), "writer.pending", &stat, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT)
}

type managedView struct {
	accounts map[uint32]managedAccount
	journal  genjournal.View
	facts    View
	ctx      context.Context
	active   atomic.Bool
	released atomic.Bool
}

func (v *managedView) identityContext() context.Context { return v.ctx }

func (v *managedView) materialReleased() { v.released.Store(true) }

func (v *managedView) live() bool {
	deadline, bounded := v.ctx.Deadline()
	return v.active.Load() && v.ctx.Err() == nil && (!bounded || time.Now().Before(deadline))
}

func (v *managedView) Principal(uid uint32) (Principal, error) {
	account, exists := v.accounts[uid]
	if !v.live() || !exists || account.Kind != "service" || account.State != "active" || account.Class != "trusted" || account.Placement != "local" || v.journal.Active(int64(uid), account.Generation) != nil {
		return Principal{}, managedRefusal()
	}
	return Principal{UID: uid, Generation: account.Generation, Service: account.Name, Role: "service"}, nil
}

func (v *managedView) Service(binding wire.ServiceBinding) error {
	if !v.live() || v.facts == nil {
		return refuse("service_binding_mismatch")
	}
	return v.facts.Service(binding)
}

func (v *managedView) Caller(binding wire.ServiceBinding, caller wire.ServiceCaller) (time.Time, string, error) {
	if !v.live() || v.facts == nil {
		return time.Time{}, "", refuse("revocation_state_unavailable")
	}
	return v.facts.Caller(binding, caller)
}

func (v *managedView) Owner(uid uint32, account string) bool {
	return v.live() && v.facts != nil && v.facts.Owner(uid, account)
}

func (v *managedView) OperatorAct(principal Principal, method string, arguments json.RawMessage) bool {
	return v.live() && v.facts != nil && v.facts.OperatorAct(principal, method, arguments)
}

func (v *managedView) Event(event json.RawMessage) bool {
	return v.live() && v.facts != nil && v.facts.Event(event)
}

func (v *managedView) Sequence() json.RawMessage {
	if !v.live() || v.facts == nil {
		return nil
	}
	return bytes.Clone(v.facts.Sequence())
}
