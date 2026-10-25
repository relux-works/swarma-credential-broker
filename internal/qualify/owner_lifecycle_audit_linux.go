//go:build linux

package qualify

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Directory watches retain replacement/temp events without losing watches when
// atomic record replacements retire old inodes. Stable identities remain pinned.
// This audits cooperating measured roles; it is not hostile same-UID byte capture.
type lifecycleAudit struct {
	fd, events int
	root       string
	watches    map[int]string
	stable     map[string]ownerFile
	native     bool
	revisions  map[string]uint64
}

func newLifecycleAudit(root string) (*lifecycleAudit, error) {
	fd, e := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if e != nil {
		return nil, e
	}
	a := &lifecycleAudit{fd: fd, root: root, watches: map[int]string{}, stable: map[string]ownerFile{}, revisions: map[string]uint64{}}
	for _, dir := range []string{root, filepath.Join(root, "home"), filepath.Join(root, "metadata"), ownerAccountPath(root)} {
		wd, e := unix.InotifyAddWatch(fd, dir, unix.IN_CREATE|unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF)
		if e != nil {
			unix.Close(fd)
			return nil, e
		}
		a.watches[wd] = dir
	}
	if e = a.inventory(); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return a, nil
}
func (a *lifecycleAudit) inventory() error {
	objects, records := 0, 0
	return filepath.Walk(a.root, func(path string, st os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		objects++
		if objects > 64 || !st.IsDir() && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 16384) {
			return errors.New("lifecycle inventory bounds")
		}
		if st.IsDir() {
			if st.Mode().Perm() != 0700 {
				return errors.New("lifecycle directory mode")
			}
			return nil
		}
		name := filepath.Base(path)
		if name == "identity.json" || name == "owner.lock" || name == ".home-owner.lock" {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			v := ownerFile{Mode: st.Mode(), Ino: st.Sys().(*syscall.Stat_t).Ino, Size: st.Size(), Hash: qualificationHash(b)}
			if old, ok := a.stable[path]; ok && old != v {
				return errors.New("lifecycle stable identity changed")
			}
			a.stable[path] = v
		}
		if strings.HasSuffix(name, ".json") && strings.HasPrefix(path, filepath.Join(a.root, "metadata")+string(os.PathSeparator)) {
			records++
			if records > 32 {
				return errors.New("lifecycle metadata bounds")
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			var record struct {
				Revision uint64 `json:"revision"`
			}
			// Full typed canonical validation is done by the owner/lease record readers.
			if jsonRevision(b, &record.Revision) != nil || record.Revision < a.revisions[path] {
				return errors.New("lifecycle revision rollback")
			}
			a.revisions[path] = record.Revision
		}
		return nil
	})
}
func jsonRevision(b []byte, v *uint64) error {
	if _, e := wire.Parse(b); e != nil {
		return e
	}
	var record struct {
		Revision uint64 `json:"revision"`
	}
	if json.Unmarshal(b, &record) != nil || record.Revision == 0 {
		return errors.New("lifecycle revision missing")
	}
	*v = record.Revision
	return nil
}

func (a *lifecycleAudit) parse(b []byte, phase string) error {
	for len(b) > 0 {
		if len(b) < 16 {
			return errors.New("lifecycle truncated event")
		}
		wd := int(int32(binary.NativeEndian.Uint32(b)))
		mask := binary.NativeEndian.Uint32(b[4:])
		n := int(binary.NativeEndian.Uint32(b[12:]))
		if n > len(b)-16 {
			return errors.New("lifecycle truncated event")
		}
		name := strings.TrimRight(string(b[16:16+n]), "\x00")
		b = b[16+n:]
		a.events++
		if a.events > 2048 || mask&unix.IN_Q_OVERFLOW != 0 {
			return errors.New("lifecycle event overflow")
		}
		dir, ok := a.watches[wd]
		if !ok || mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
			return errors.New("lifecycle lost watch")
		}
		allowed := false
		switch dir {
		case a.root:
			allowed = name == ".home-owner.lock" && phase != "closed"
		case filepath.Join(a.root, "home"):
			allowed = a.native && (name == "auth.json" || name == "native.pending")
		case ownerAccountPath(a.root):
			base := strings.TrimPrefix(name, "pending-")
			allowed = phase != "closed" && (base == "owner-checkpoint.json" || strings.HasPrefix(base, "owner-attempt-") && strings.HasSuffix(base, ".json") || strings.HasPrefix(base, "lease-") && strings.HasSuffix(base, ".json"))
		}
		if !allowed {
			return errors.New("lifecycle phase write not admitted")
		}
	}
	return nil
}
func (a *lifecycleAudit) drain(phase string) error {
	for {
		var b [16384]byte
		n, e := unix.Read(a.fd, b[:])
		if e == unix.EAGAIN {
			return a.inventory()
		}
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return errors.New("lifecycle observer lost")
		}
		if e = a.parse(b[:n], phase); e != nil {
			return e
		}
	}
}
