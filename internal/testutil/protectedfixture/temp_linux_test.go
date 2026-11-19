package protectedfixture

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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
