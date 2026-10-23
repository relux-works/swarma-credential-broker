//go:build linux

package server

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// checkSocketDirectory validates the existing path without changing its modes.
// R2 trusts daemon-owned ancestors as well as root, and root-owned sticky
// ancestors protect their already-existing owned children from other UIDs.
// It does not establish dedicated service-user isolation from the daemon UID.
func checkSocketDirectory(dir string) error {
	refused := wire.Refuse("lease_owner_unavailable")
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return refused
	}
	uid := uint32(os.Geteuid())
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return refused
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return refused
		}
		if current == dir {
			if st.Uid != uid || info.Mode() != os.ModeDir|0755 {
				return refused
			}
		} else {
			if st.Uid != 0 && st.Uid != uid {
				return refused
			}
			if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
				return refused
			}
		}
		if current == string(filepath.Separator) {
			return nil
		}
	}
}

func socketPermissions(info os.FileInfo) bool {
	if info == nil || info.Mode() != os.ModeSocket|0666 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
