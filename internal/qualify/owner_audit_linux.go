//go:build linux

package qualify

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type ownerFile struct {
	Mode os.FileMode
	Ino  uint64
	Size int64
	Hash string
}
type ownerAudit struct {
	fd                        int
	watches                   map[int]string
	retiring                  map[int]bool
	events                    int
	before, after, tombstones map[string]ownerFile
}

func ownerInventory(root string) (map[string]ownerFile, error) {
	out := map[string]ownerFile{}
	metadata := 0
	e := filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if len(out) >= 32 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("audit inventory limit/type")
		}
		if info.Mode().IsRegular() && strings.HasPrefix(path, filepath.Join(root, "metadata")+string(os.PathSeparator)) {
			metadata++
			if metadata > 16 {
				return errors.New("audit metadata budget")
			}
		}
		v := ownerFile{Mode: info.Mode(), Ino: info.Sys().(*syscall.Stat_t).Ino, Size: info.Size()}
		if info.Mode().IsRegular() && info.Mode().Perm() == 0600 {
			b, e := os.ReadFile(path)
			if e != nil || len(b) > 16384 {
				return errors.New("audit inventory unreadable")
			}
			v.Hash = qualificationHash(b)
		}
		out[path] = v
		return nil
	})
	return out, e
}
func newOwnerAudit(root string) (*ownerAudit, error) {
	inv, e := ownerInventory(root)
	if e != nil {
		return nil, e
	}
	fd, e := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if e != nil {
		return nil, e
	}
	a := &ownerAudit{before: inv, tombstones: map[string]ownerFile{}, fd: fd, watches: map[int]string{}, retiring: map[int]bool{}}
	for path := range inv {
		wd, e := unix.InotifyAddWatch(fd, path, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MOVED_FROM|unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_DELETE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF)
		if e != nil {
			unix.Close(fd)
			return nil, e
		}
		a.watches[wd] = path
	}
	return a, nil
}
func (a *ownerAudit) parse(b []byte, fault bool) error {
	for len(b) > 0 {
		if len(b) < 16 {
			return errors.New("audit truncated")
		}
		wd := int(int32(binary.NativeEndian.Uint32(b)))
		mask := binary.NativeEndian.Uint32(b[4:])
		n := int(binary.NativeEndian.Uint32(b[12:]))
		if n > len(b)-16 {
			return errors.New("audit truncated")
		}
		b = b[16+n:]
		a.events++
		if a.events > 1024 || mask&unix.IN_Q_OVERFLOW != 0 {
			return errors.New("audit overflow")
		}
		path, ok := a.watches[wd]
		if !ok {
			return errors.New("audit lost watch")
		}
		if a.retiring[wd] && mask & ^uint32(unix.IN_DELETE_SELF|unix.IN_IGNORED) == 0 {
			if mask&unix.IN_IGNORED != 0 {
				delete(a.watches, wd)
				delete(a.retiring, wd)
			}
			continue
		}
		if mask&unix.IN_IGNORED != 0 {
			_, e := os.Lstat(path)
			if !fault || !os.IsNotExist(e) {
				return errors.New("audit lost watch")
			}
			delete(a.watches, wd)
			continue
		}
		if !fault {
			return errors.New("audit mutation")
		}
	}
	return nil
}
func (a *ownerAudit) drain(fault bool) error {
	for {
		var b [16384]byte
		n, e := unix.Read(a.fd, b[:])
		if e == unix.EAGAIN {
			return nil
		}
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return errors.New("audit source lost")
		}
		if e = a.parse(b[:n], fault); e != nil {
			return e
		}
	}
}
func (a *ownerAudit) seal(root string, before map[string]ownerFile) error {
	if e := a.drain(false); e != nil {
		return e
	}
	after, e := ownerInventory(root)
	a.after = after
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("audit inventory changed")
	}
	return nil
}

// Removed files can retain a watch until O1 closes its last open descriptor.
// Only exact self-delete/ignored retirement is allowed after the parent fault.
func (a *ownerAudit) retireMissing() {
	for path, v := range a.before {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			a.tombstones[path] = v
		}
	}
	for wd, path := range a.watches {
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			a.retiring[wd] = true
		}
	}
}
