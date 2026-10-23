//go:build linux

package qualify

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"golang.org/x/sys/unix"
)

// commandSyscalls has no production constructor or selector. Tests supply a
// private implementation to fail an operation before its kernel call.
type commandSyscalls interface {
	run(string, func() error) error
}

func (d driver) syscall(name string, call func() error) error {
	if d.ops != nil {
		return d.ops.run(name, call)
	}
	return call()
}

const socketName = "qualification.sock"

// privateSocket reserves a future row endpoint inside a fresh private directory.
// Its pathname inode differs from the listener's sockfs inode on Linux.
type privateSocket struct {
	listener                    *net.UnixListener
	parent, directory, entry    *os.File
	path, directoryName         string
	directoryInfo, socketInfo   unix.Stat_t
	directoryVerified, bound    bool
	socketVerified              bool
	stop                        func() bool
	listenerOnce, cleanupOnce   sync.Once
	listenerError, cleanupError error
	candidateDigest             string
	ops                         commandSyscalls
}

func descriptorPath(f *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}
func sameObject(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func privateDirectoryStat(st unix.Stat_t) bool {
	return st.Mode == unix.S_IFDIR|0700 && st.Uid == uint32(os.Geteuid())
}

func reserve(ctx context.Context, dir, digest string) (*privateSocket, error) {
	return (driver{}).reserve(ctx, dir, digest)
}
func (d driver) reserve(ctx context.Context, dir, digest string) (socket *privateSocket, err error) {
	if ctx.Err() != nil || !policy.Hash(digest) {
		return nil, qualification.ErrUnavailable
	}
	s := &privateSocket{candidateDigest: digest, ops: d.ops}
	defer func() {
		if err != nil {
			err = errors.Join(qualification.ErrUnavailable, err, s.close())
			socket = nil
		}
	}()
	var fd int
	if err = d.syscall("open:evidence", func() (e error) {
		fd, e = unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		return
	}); err != nil {
		return nil, err
	}
	s.parent = os.NewFile(uintptr(fd), "evidence-directory")
	var parentInfo unix.Stat_t
	if err = d.syscall("fstat:evidence", func() error { return unix.Fstat(fd, &parentInfo) }); err != nil {
		return nil, err
	}
	if !privateDirectoryStat(parentInfo) {
		return nil, qualification.ErrUnavailable
	}
	var created string
	if err = d.syscall("mkdir:socket-directory", func() (e error) {
		created, e = os.MkdirTemp(descriptorPath(s.parent), ".qualification-")
		return
	}); err != nil {
		return nil, err
	}
	s.directoryName = filepath.Base(created)
	if err = d.syscall("open:socket-directory", func() (e error) {
		fd, e = unix.Openat(int(s.parent.Fd()), s.directoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		return
	}); err != nil {
		return nil, err
	}
	s.directory = os.NewFile(uintptr(fd), "socket-directory")
	if err = d.syscall("fstat:socket-directory", func() error { return unix.Fstat(fd, &s.directoryInfo) }); err != nil {
		return nil, err
	}
	if !privateDirectoryStat(s.directoryInfo) {
		return nil, qualification.ErrUnavailable
	}
	s.directoryVerified = true
	s.path = filepath.Join(dir, s.directoryName, socketName)
	// Binding through the held descriptor avoids re-resolving the evidence path
	// and keeps the sockaddr independent of the caller's directory path length.
	if err = d.syscall("bind:socket", func() (e error) {
		s.listener, e = net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(descriptorPath(s.directory), socketName), Net: "unix"})
		return
	}); err != nil {
		return nil, err
	}
	s.bound = true
	s.listener.SetUnlinkOnClose(false)
	if err = d.syscall("open:socket-entry", func() (e error) {
		fd, e = unix.Openat(int(s.directory.Fd()), socketName, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		return
	}); err != nil {
		return nil, err
	}
	s.entry = os.NewFile(uintptr(fd), "socket-entry")
	if err = d.syscall("fstat:socket-entry", func() error { return unix.Fstat(fd, &s.socketInfo) }); err != nil {
		return nil, err
	}
	if s.socketInfo.Mode&unix.S_IFMT != unix.S_IFSOCK || s.socketInfo.Uid != uint32(os.Geteuid()) || s.socketInfo.Nlink != 1 {
		return nil, qualification.ErrUnavailable
	}
	s.socketVerified = true
	if err = d.syscall("chmod:socket", func() error { return unix.Fchmodat(int(s.directory.Fd()), socketName, 0600, 0) }); err != nil {
		return nil, err
	}
	s.stop = context.AfterFunc(ctx, func() { s.closeListener() })
	return s, nil
}

func (s *privateSocket) syscall(name string, call func() error) error {
	return (driver{ops: s.ops}).syscall(name, call)
}
func (s *privateSocket) closeListener() error {
	s.listenerOnce.Do(func() {
		if s.listener != nil {
			s.listenerError = s.listener.Close()
		}
	})
	return s.listenerError
}
func (s *privateSocket) close() error {
	s.cleanupOnce.Do(func() {
		if s.stop != nil {
			s.stop()
		}
		s.cleanupError = s.cleanup()
	})
	return s.cleanupError
}
func (s *privateSocket) cleanup() (err error) {
	// Each descriptor closes even when a lookup/unlink refuses. Cleanup errors
	// cannot turn a failed reservation or report into success.
	defer func() {
		if s.entry != nil {
			err = errors.Join(err, s.entry.Close())
		}
		if s.directory != nil {
			err = errors.Join(err, s.directory.Close())
		}
		if s.parent != nil {
			err = errors.Join(err, s.parent.Close())
		}
		if err != nil {
			err = errors.Join(qualification.ErrUnavailable, err)
		}
	}()
	err = s.closeListener()
	if s.bound {
		if s.socketVerified {
			var current unix.Stat_t
			if e := s.syscall("lookup:socket-teardown", func() error {
				return unix.Fstatat(int(s.directory.Fd()), socketName, &current, unix.AT_SYMLINK_NOFOLLOW)
			}); e != nil {
				return errors.Join(err, e)
			}
			if !sameObject(current, s.socketInfo) {
				return errors.Join(err, unix.ESTALE)
			}
		}
		// Before metadata verification, this known name was created by our bind
		// in our fresh private directory; no other principal can add an entry.
		if e := s.syscall("unlink:socket", func() error { return unix.Unlinkat(int(s.directory.Fd()), socketName, 0) }); e != nil {
			return errors.Join(err, e)
		}
	}
	if s.directoryVerified {
		var current unix.Stat_t
		if e := s.syscall("lookup:directory-teardown", func() error {
			return unix.Fstatat(int(s.parent.Fd()), s.directoryName, &current, unix.AT_SYMLINK_NOFOLLOW)
		}); e != nil {
			return errors.Join(err, e)
		}
		if !sameObject(current, s.directoryInfo) {
			return errors.Join(err, unix.ESTALE)
		}
		// AT_REMOVEDIR refuses a nonempty directory; never recurse or remove a
		// replacement. The held parent anchors this operation to the evidence.
		err = errors.Join(err, s.syscall("unlink:socket-directory", func() error {
			return unix.Unlinkat(int(s.parent.Fd()), s.directoryName, unix.AT_REMOVEDIR)
		}))
	}
	return err
}
