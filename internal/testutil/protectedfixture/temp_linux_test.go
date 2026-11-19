package protectedfixture

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
)

// Claim: under umask 022 the returned fixture passes the unchanged exact-0700 reader check, while a widened leaf still refuses.
func TestTempDirUmask022(test *testing.T) {
	previous := syscall.Umask(0022)
	defer syscall.Umask(previous)
	owner, group := uint32(os.Getuid()), uint32(os.Getgid())
	check := func(root string) error {
		return (protectedio.Reader{}).CheckDirectory(context.Background(), root, protectedio.FilePolicy{UID: owner, GID: group, Mode: 0700}, owner)
	}
	root := TempDir(test, check)
	if err := check(root); err != nil {
		test.Fatalf("umask 022 fixture refused: %v", err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		test.Fatal(err)
	}
	if err := check(root); !errors.Is(err, protectedio.ErrProtection) {
		test.Fatalf("widened fixture leaf admitted: %v", err)
	}
}

// Claim: GOTMPDIR selects the checked fixture tree even when TMPDIR names an unsafe tree; unsafe ancestry itself remains covered by TestTempAncestry.
func TestTempDirUsesGoTempRoot(test *testing.T) {
	parent := test.TempDir()
	test.Setenv("GOTMPDIR", parent)
	test.Setenv("TMPDIR", "/tmp")
	test.Run("selected-tree", func(test *testing.T) {
		root := TempDir(test, func(root string) error { return ancestryError(root, uint32(os.Getuid())) })
		if filepath.Dir(filepath.Dir(root)) != parent {
			test.Fatalf("fixture used the wrong temporary tree: %q", root)
		}
	})
}

// Claim: the fixture preflight accepts a safe ancestry and names the offending writable, special-bit, symlink or foreign-owner ancestor instead of skipping a control.
func TestTempAncestry(test *testing.T) {
	for _, mode := range []fs.FileMode{0770, 0702, 0700 | fs.ModeSticky, 0700 | fs.ModeSetgid, 0700 | fs.ModeSetuid} {
		test.Run(mode.String(), func(test *testing.T) {
			root := test.TempDir()
			owner := uint32(os.Getuid())
			if err := ancestryError(root, owner); err != nil {
				test.Fatalf("valid ancestry control refused: %v", err)
			}
			if err := os.Chmod(root, mode); err != nil {
				test.Fatal(err)
			}
			if err := ancestryError(root, owner); err == nil || !strings.Contains(err.Error(), "protected_fixture_temp_ancestry: unsafe ancestor "+strconv.Quote(root)) {
				test.Fatalf("unsafe ancestry lacks named diagnostic: %v", err)
			}
		})
	}
	root := test.TempDir()
	owner := uint32(os.Getuid())
	if err := ancestryError(root, owner); err != nil {
		test.Fatal(err)
	}
	if err := ancestryError(root, owner+1); err == nil || !strings.Contains(err.Error(), "protected_fixture_temp_ancestry:") {
		test.Fatalf("foreign-owner ancestry lacks named diagnostic: %v", err)
	}
	alias := filepath.Join(test.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		test.Fatal(err)
	}
	if err := ancestryError(alias, owner); err == nil || !strings.Contains(err.Error(), strconv.Quote(alias)) {
		test.Fatalf("symlink ancestry lacks named diagnostic: %v", err)
	}
}
