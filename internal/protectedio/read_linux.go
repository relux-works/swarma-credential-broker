package protectedio

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"golang.org/x/sys/unix"
)

type FilePolicy = assemblyv0.ProtectedFilePolicy
type Identity = assemblyv0.FileIdentity
type ConfigGate = assemblyv0.ConfigGate

const MaxBytes int64 = 1 << 20

var ErrProtection = errors.New("protected_file_unavailable")

type Reader struct{}

type descriptor struct {
	file   *os.File
	parent int
	name   string
	stat   unix.Stat_t
}

type opened struct {
	parts []descriptor
}

func sameNode(first, second unix.Stat_t) bool {
	left, right := identity(first), identity(second)
	if first.Mode&unix.S_IFMT == unix.S_IFDIR && second.Mode&unix.S_IFMT == unix.S_IFDIR {
		left.Links, right.Links, left.Size, right.Size = 0, 0, 0, 0
	}
	return first.Mode&unix.S_IFMT == second.Mode&unix.S_IFMT && left == right
}

var _ assemblyv0.ProtectedRead = Reader{}

func identity(stat unix.Stat_t) Identity {
	mode := fs.FileMode(stat.Mode & 0777)
	if stat.Mode&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if stat.Mode&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if stat.Mode&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		mode |= fs.ModeDir
	}
	return Identity{Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: mode, Links: uint64(stat.Nlink), Size: stat.Size}
}

func (opened *opened) close() {
	for _, part := range opened.parts {
		part.file.Close()
	}
}

func (opened *opened) current(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, part := range opened.parts {
		var current unix.Stat_t
		if unix.Fstat(int(part.file.Fd()), &current) != nil || !sameNode(current, part.stat) {
			return ErrProtection
		}
		if current.Mode&unix.S_IFMT != unix.S_IFDIR && (current.Mtim != part.stat.Mtim || current.Ctim != part.stat.Ctim) {
			return ErrProtection
		}
		if part.parent >= 0 {
			var named unix.Stat_t
			if unix.Fstatat(part.parent, part.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNode(named, current) {
				return ErrProtection
			}
		}
	}
	return nil
}

func open(ctx context.Context, path string, owner uint32, directory bool) (*opened, error) {
	if ctx == nil || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, ErrProtection
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrProtection
	}
	result := &opened{}
	rootFile := os.NewFile(uintptr(root), "/")
	var rootStat unix.Stat_t
	if unix.Fstat(root, &rootStat) != nil || rootStat.Uid != 0 || rootStat.Mode&07022 != 0 {
		rootFile.Close()
		return nil, ErrProtection
	}
	result.parts = append(result.parts, descriptor{file: rootFile, parent: -1, stat: rootStat})
	names := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent := root
	for index, name := range names {
		last := index == len(names)-1
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if !last || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := unix.Openat(parent, name, flags, 0)
		if openErr != nil {
			currentErr := result.current(ctx)
			result.close()
			if currentErr != nil {
				return nil, currentErr
			}
			if last && errors.Is(openErr, unix.ENOENT) {
				return nil, fs.ErrNotExist
			}
			return nil, ErrProtection
		}
		file := os.NewFile(uintptr(fd), name)
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			file.Close()
			result.close()
			return nil, ErrProtection
		}
		result.parts = append(result.parts, descriptor{file: file, parent: parent, name: name, stat: stat})
		if !last && (stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07022 != 0 || stat.Uid != 0 && stat.Uid != owner) {
			result.close()
			return nil, ErrProtection
		}
		parent = fd
	}
	if err := result.current(ctx); err != nil {
		result.close()
		return nil, err
	}
	return result, nil
}

func openFile(ctx context.Context, path string, policy FilePolicy) (*opened, error) {
	if policy.Mode&^fs.FileMode(0777) != 0 || policy.Links != 1 || policy.MaxBytes < 0 || policy.MaxBytes > MaxBytes {
		return nil, ErrProtection
	}
	result, err := open(ctx, path, policy.UID, false)
	if err != nil {
		return nil, err
	}
	stat := result.parts[len(result.parts)-1].stat
	metadata := identity(stat)
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || metadata.UID != policy.UID || metadata.GID != policy.GID || metadata.Mode != policy.Mode || metadata.Links != policy.Links || metadata.Size < 0 || metadata.Size > policy.MaxBytes {
		result.close()
		return nil, ErrProtection
	}
	return result, nil
}

func (Reader) Read(ctx context.Context, path string, policy FilePolicy) (Identity, []byte, error) {
	result, err := openFile(ctx, path, policy)
	if err != nil {
		return Identity{}, nil, err
	}
	defer result.close()
	leaf := result.parts[len(result.parts)-1]
	contents, err := io.ReadAll(io.LimitReader(leaf.file, policy.MaxBytes+1))
	if err != nil || int64(len(contents)) != leaf.stat.Size {
		return Identity{}, nil, ErrProtection
	}
	if err := result.current(ctx); err != nil {
		return Identity{}, nil, err
	}
	return identity(leaf.stat), contents, nil
}

func (Reader) CheckDirectory(ctx context.Context, path string, policy FilePolicy, ancestorUID uint32) error {
	result, err := open(ctx, path, ancestorUID, true)
	if err != nil {
		return err
	}
	defer result.close()
	metadata := identity(result.parts[len(result.parts)-1].stat)
	if metadata.UID != policy.UID || metadata.GID != policy.GID || metadata.Mode != fs.ModeDir|policy.Mode {
		return ErrProtection
	}
	return result.current(ctx)
}

type configGate struct {
	path   string
	policy FilePolicy
	pin    Identity
}

func NewConfigGate(ctx context.Context, path string, policy FilePolicy) (ConfigGate, error) {
	if policy.Mode != 0640 || policy.MaxBytes != 0 {
		return nil, ErrProtection
	}
	if err := (Reader{}).CheckDirectory(ctx, filepath.Dir(path), FilePolicy{UID: policy.UID, GID: policy.GID, Mode: 0750}, policy.UID); err != nil {
		return nil, err
	}
	metadata, contents, err := (Reader{}).Read(ctx, path, policy)
	if err != nil || len(contents) != 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrProtection
	}
	return &configGate{path: path, policy: policy, pin: metadata}, nil
}

func (gate *configGate) WithRead(ctx context.Context, callback func(context.Context) error) error {
	if ctx == nil || callback == nil || ctx.Value(gate) != nil {
		return ErrProtection
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := (Reader{}).CheckDirectory(ctx, filepath.Dir(gate.path), FilePolicy{UID: gate.policy.UID, GID: gate.policy.GID, Mode: 0750}, gate.policy.UID); err != nil {
		return err
	}
	result, err := openFile(ctx, gate.path, gate.policy)
	if err != nil {
		return err
	}
	defer result.close()
	leaf := result.parts[len(result.parts)-1]
	if identity(leaf.stat) != gate.pin || unix.Flock(int(leaf.file.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return ErrProtection
	}
	defer unix.Flock(int(leaf.file.Fd()), unix.LOCK_UN)
	if err := result.current(ctx); err != nil {
		return err
	}
	if err := callback(context.WithValue(ctx, gate, true)); err != nil {
		return err
	}
	return result.current(ctx)
}
