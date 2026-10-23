//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
)

func socketDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Claim: an existing daemon-owned 0755 directory yields an owned 0666 socket;
// existing entries and invalid directory modes are refused without changing them.
func TestSocketDirectoryModes(t *testing.T) {
	for _, mode := range []os.FileMode{0755, 0700, 0775, 0757, os.ModeSticky | 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := socketDirectory(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "s")
			l, err := Listen(path)
			if mode == 0755 {
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				info, err := os.Lstat(path)
				if err != nil || info.Mode() != os.ModeSocket|0666 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
					t.Fatal("socket type, ownership or mode mismatch")
				}
				if duplicate, err := Listen(path); err == nil {
					duplicate.Close()
					t.Fatal("existing socket adopted")
				}
			} else {
				if err == nil {
					l.Close()
					t.Fatal("invalid directory accepted")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("refusal created a socket")
				}
			}
			info, err := os.Lstat(dir)
			if err != nil || info.Mode() != os.ModeDir|mode {
				t.Fatal("listener changed directory permissions")
			}
		})
	}
}

// Claim: existing regular entries, socket-directory links, missing directories
// and untrusted writable ancestors are refused without replacing their entries.
func TestSocketDirectoryPaths(t *testing.T) {
	for _, shape := range []string{"existing-file", "linked-directory", "missing-directory", "writable-ancestor", "group-writable-ancestor", "daemon-sticky-ancestor", "linked-ancestor", "relative-path"} {
		t.Run(shape, func(t *testing.T) {
			dir := socketDirectory(t)
			path := filepath.Join(dir, "s")
			switch shape {
			case "existing-file":
				if err := os.WriteFile(path, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "linked-directory":
				link := filepath.Join(socketDirectory(t), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "s")
			case "missing-directory":
				path = filepath.Join(dir, "missing", "s")
			case "relative-path":
				path = "relative-socket"
			case "linked-ancestor":
				child := filepath.Join(dir, "child")
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(child, 0755); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(socketDirectory(t), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "child", "s")
			case "writable-ancestor", "group-writable-ancestor", "daemon-sticky-ancestor":
				child := filepath.Join(dir, "child")
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(child, 0755); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0777)
				if shape == "group-writable-ancestor" {
					mode = 0775
				}
				if shape == "daemon-sticky-ancestor" {
					mode |= os.ModeSticky
				}
				if err := os.Chmod(dir, mode); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(child, "s")
			}
			if l, err := Listen(path); err == nil {
				l.Close()
				t.Fatal("unsafe socket path accepted")
			}
			if shape == "existing-file" {
				if b, err := os.ReadFile(path); err != nil || string(b) != "retained" {
					t.Fatal("existing file changed")
				}
			} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("refusal created a socket")
			}
		})
	}
}

// Claim: a real directory owned by a different UID cannot be the socket parent.
// This non-root fixture uses the filesystem root and never writes to it.
func TestSocketDirectoryForeignOwnerRefused(t *testing.T) {
	info, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid()) {
		t.Skip("requires a non-root test process to exercise different directory ownership")
	}
	if err := checkSocketDirectory(string(filepath.Separator)); err == nil {
		t.Fatal("foreign-owned socket directory accepted")
	}
}

// Claim: a socket whose mode changes after Listen is refused before Serve
// accepts clients, and its owned listener/path are closed and removed.
func TestSocketModeChangedBeforeServe(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	path := filepath.Join(socketDirectory(t), "s")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	s := New(e.Manager)
	if err := s.Serve(context.Background(), l); err == nil {
		t.Fatal("changed socket permissions accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refused listener path remains")
	}
}
