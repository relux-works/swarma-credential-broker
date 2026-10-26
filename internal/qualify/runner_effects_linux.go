//go:build linux

package qualify

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"golang.org/x/sys/unix"
)

const runnerChanges = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO

// Installed after parent setup and before exec, covering fixture files and
// transient changes. Directory loss, overflow, malformed events and unknown
// watches cannot establish absence. Native-path contents are never read.
func (f *runnerRowFixture) startWatch() error {
	f.close()
	fd, e := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if e != nil {
		f.watch = -1
		return e
	}
	f.watch, f.watches = fd, map[int]string{}
	for _, name := range []string{".", "home", "project"} {
		wd, e := unix.InotifyAddWatch(fd, filepath.Join(f.root, name), unix.IN_OPEN|runnerChanges|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_UNMOUNT)
		if e != nil {
			return e
		}
		f.watches[wd] = name
	}
	return nil
}
func (f *runnerRowFixture) watchComplete(side string) bool {
	if len(f.watches) != 3 {
		return false
	}
	var b [8192]byte
	for total := 0; total < 65536; {
		n, e := unix.Read(f.watch, b[:])
		if e == unix.EAGAIN {
			return true
		}
		if e != nil || n == 0 {
			return false
		}
		total += n
		for at := 0; at < n; {
			if n-at < unix.SizeofInotifyEvent {
				return false
			}
			wd := int(int32(binary.NativeEndian.Uint32(b[at : at+4])))
			mask := binary.NativeEndian.Uint32(b[at+4 : at+8])
			length := int(binary.NativeEndian.Uint32(b[at+12 : at+16]))
			if length > n-at-16 {
				return false
			}
			dir, ok := f.watches[wd]
			if !ok || mask & ^uint32(unix.IN_OPEN|runnerChanges|unix.IN_ISDIR) != 0 {
				return false
			}
			name := strings.TrimRight(string(b[at+16:at+16+length]), "\x00")
			if dir == "home" && name == "auth.json" {
				return false
			}
			if mask&runnerChanges != 0 {
				if side != "positive" || mask&unix.IN_ISDIR != 0 {
					return false
				}
				allowed := dir == "." && (name == "answer.txt" || len(name) == 50 && strings.HasPrefix(name, ".run-codex-output-") && strings.Trim(name[18:], "0123456789abcdef") == "") || dir == "home" && (name == "events.jsonl" || name == "version-probe" || name == "server-pid" || name == "boundary.jsonl" || name == ".run-codex.lock" || name == ".run-codex-unresolved")
				if !allowed {
					return false
				}
			}
			at += 16 + length
		}
	}
	return false
}

// runnerReadFile bounds protected fixture diagnostics; never native credentials.
func runnerReadFile(path string) ([]byte, error) {
	if _, e := os.Lstat(path); e != nil {
		return nil, e
	}
	b, e := store.ReadProtected(path, uint32(os.Geteuid()))
	if e != nil || len(b) > 65536 {
		return nil, qualification.ErrUnavailable
	}
	return b, nil
}
