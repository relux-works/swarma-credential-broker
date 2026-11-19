package protectedfixture

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func ancestryError(path string, owner uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("protected_fixture_temp_ancestry: noncanonical root %q", path)
	}
	for ancestor := path; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil {
			return fmt.Errorf("protected_fixture_temp_ancestry: %q: %w", ancestor, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky|0022) != 0 || stat.Uid != 0 && (ancestor == "/" || stat.Uid != owner) {
			return fmt.Errorf("protected_fixture_temp_ancestry: unsafe ancestor %q", ancestor)
		}
		if ancestor == "/" {
			return nil
		}
	}
}

func TempDir(test *testing.T, check func(string) error) string {
	test.Helper()
	owner := uint32(os.Getuid())
	if err := ancestryError(os.TempDir(), owner); err != nil {
		test.Fatal(err)
	}
	root := test.TempDir()
	if err := check(root); err != nil {
		test.Fatalf("protected_fixture_temp_ancestry: reader refused fixture root %q: %v", root, err)
	}
	return root
}
