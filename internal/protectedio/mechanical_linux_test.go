package protectedio

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: each forbidden ancestor permission or special bit refuses independently of group-write, beside a safe unchanged read.
func TestReviewerAncestorModeBits(test *testing.T) {
	for _, mode := range []fs.FileMode{0703, 0757, 0720, 0700 | fs.ModeSetuid, 0700 | fs.ModeSetgid, 0700 | fs.ModeSticky} {
		test.Run(mode.String(), func(test *testing.T) {
			path, policy := fixture(test, "inert", 0644)
			if _, contents, err := (Reader{}).Read(context.Background(), path, policy); err != nil || string(contents) != "inert" {
				test.Fatalf("ancestor mode valid control refused: %v", err)
			}
			parent := filepath.Dir(path)
			if err := os.Chmod(parent, mode); err != nil {
				test.Fatal(err)
			}
			observed, err := os.Stat(parent)
			if err != nil || observed.Mode() != fs.ModeDir|mode {
				test.Fatalf("ancestor mode precondition not installed: %v", err)
			}
			metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
			if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
				test.Fatalf("ancestor mode bits admitted %v or partial result: %v", mode, err)
			}
		})
	}
}

// Claim: exact directory modes include each special bit at both production permission modes, beside accepted controls.
func TestReviewerDirectorySpecialBits(test *testing.T) {
	for _, mode := range []fs.FileMode{0750, 0700} {
		for _, special := range []fs.FileMode{fs.ModeSetuid, fs.ModeSetgid, fs.ModeSticky} {
			test.Run(mode.String()+special.String(), func(test *testing.T) {
				path, policy := fixture(test, "inert", 0644)
				path = filepath.Dir(path)
				policy.Mode = mode
				if err := os.Chmod(path, mode); err != nil {
					test.Fatal(err)
				}
				if err := (Reader{}).CheckDirectory(context.Background(), path, policy, policy.UID); err != nil {
					test.Fatalf("directory special-bit valid control refused: %v", err)
				}
				if err := os.Chmod(path, mode|special); err != nil {
					test.Fatal(err)
				}
				observed, err := os.Stat(path)
				if err != nil || observed.Mode() != fs.ModeDir|mode|special {
					test.Fatalf("directory special-bit precondition not installed: %v", err)
				}
				if err := (Reader{}).CheckDirectory(context.Background(), path, policy, policy.UID); !errors.Is(err, ErrProtection) {
					test.Fatalf("directory special bits admitted %v: %v", special, err)
				}
			})
		}
	}
}

// Claim: a root-owned public passwd leaf is admitted at its production policy and refused for a non-root owner; no contents are logged or changed.
func TestReviewerLeafOwnerComparison(test *testing.T) {
	if os.Geteuid() == 0 {
		test.Fatal("leaf owner witness requires a non-root broker UID")
	}
	const path = "/etc/passwd"
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode != unix.S_IFREG|0644 || stat.Nlink != 1 || stat.Size < 0 || stat.Size > MaxBytes {
		test.Fatalf("public passwd root-owned fixture precondition failed: %v", err)
	}
	policy := FilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: MaxBytes}
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	if err != nil || metadata.UID != 0 || metadata.GID != 0 || metadata.Size != int64(len(contents)) {
		test.Fatalf("root-owned leaf valid production control refused: %v", err)
	}
	policy.UID = uint32(os.Geteuid())
	metadata, contents, err = (Reader{}).Read(context.Background(), path, policy)
	if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
		test.Fatalf("root-owned leaf admitted for non-root owner policy or partial result: %v", err)
	}
}
