package protectedio

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: production root zero is an exact owner/group/ancestor requirement, not an unset wildcard, beside unchanged non-root filesystem controls.
// These UID-zero refusals are ancestor-masked; the separate public-passwd witness isolates ordinary leaf-owner equality, not the zero-wildcard variant.
func TestRootZeroBoundary(test *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if uid == 0 || gid == 0 {
		test.Fatal("root-zero witness requires non-root process IDs")
	}
	for _, name := range []string{"file-owner", "file-group", "directory-owner", "directory-group", "ancestor-owner", "lock-owner", "lock-group"} {
		test.Run(name, func(test *testing.T) {
			ctx := context.Background()
			path, policy := fixture(test, "inert", 0644)
			policy.MaxBytes = 1 << 20
			switch name {
			case "file-owner", "file-group":
				if _, contents, err := (Reader{}).Read(ctx, path, policy); err != nil || string(contents) != "inert" {
					test.Fatalf("root-zero valid read control refused: %v", err)
				}
				if name == "file-owner" {
					policy.UID = 0
				} else {
					policy.GID = 0
				}
				metadata, contents, err := (Reader{}).Read(ctx, path, policy)
				if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
					test.Fatalf("root-zero %s admitted a test-owned file or partial result: %v", name, err)
				}
			case "directory-owner", "directory-group", "ancestor-owner":
				mode := fs.FileMode(0750)
				if name == "ancestor-owner" {
					mode = 0700
				}
				if err := os.Chmod(filepath.Dir(path), mode); err != nil {
					test.Fatal(err)
				}
				policy = FilePolicy{UID: uid, GID: gid, Mode: mode}
				if err := (Reader{}).CheckDirectory(ctx, filepath.Dir(path), policy, uid); err != nil {
					test.Fatalf("root-zero valid directory control refused: %v", err)
				}
				ancestor := uid
				switch name {
				case "directory-owner":
					policy.UID = 0
				case "directory-group":
					policy.GID = 0
				default:
					ancestor = 0
				}
				if err := (Reader{}).CheckDirectory(ctx, filepath.Dir(path), policy, ancestor); !errors.Is(err, ErrProtection) {
					test.Fatalf("root-zero %s admitted a test-owned directory: %v", name, err)
				}
			default:
				path, policy = lockFixture(test)
				gate, err := NewConfigGate(ctx, path, policy)
				called := false
				if err != nil || gate == nil {
					test.Fatalf("root-zero valid lock control refused: %v", err)
				}
				if err := gate.WithRead(ctx, func(context.Context) error { called = true; return nil }); err != nil || !called {
					test.Fatalf("root-zero valid lock window refused: %v", err)
				}
				if name == "lock-owner" {
					policy.UID = 0
				} else {
					policy.GID = 0
				}
				if refused, err := NewConfigGate(ctx, path, policy); !errors.Is(err, ErrProtection) || refused != nil {
					test.Fatalf("root-zero %s admitted a test-owned lock: %v", name, err)
				}
			}
		})
	}
}

// Claim: literal production file modes, single-link and 1-MiB/zero size limits, plus directory 0750/0700 modes, are enforced beside valid boundary reads/checks; fixture owners stay unprivileged.
func TestProductionPolicyComparisons(test *testing.T) {
	for _, name := range []string{"file-mode-0640", "file-mode-0644", "file-mode-zero", "file-group", "file-links", "file-size-max", "file-size-zero", "directory-mode-0750", "directory-mode-0700", "directory-mode-zero", "directory-owner", "directory-group"} {
		test.Run(name, func(test *testing.T) {
			mode := fs.FileMode(0640)
			if name == "file-mode-0644" {
				mode = 0644
			}
			contents := "inert"
			if name == "file-size-max" {
				contents = strings.Repeat("x", 1<<20)
			} else if name == "file-size-zero" {
				contents = ""
			}
			path, policy := fixture(test, contents, mode)
			policy.MaxBytes = 1 << 20
			if name == "file-size-zero" {
				policy.MaxBytes = 0
			}
			if strings.HasPrefix(name, "directory-") {
				policy.Mode, policy.Links, policy.MaxBytes = 0700, 0, 0
				if name == "directory-mode-0750" {
					policy.Mode = 0750
				}
				if err := os.Chmod(filepath.Dir(path), policy.Mode); err != nil {
					test.Fatal(err)
				}
				if err := (Reader{}).CheckDirectory(context.Background(), filepath.Dir(path), policy, uint32(os.Getuid())); err != nil {
					test.Fatalf("production directory comparison control refused: %v", err)
				}
				switch name {
				case "directory-owner":
					policy.UID++
				case "directory-group":
					policy.GID++
				case "directory-mode-zero":
					policy.Mode = 0
				default:
					policy.Mode = 0770
				}
				if err := (Reader{}).CheckDirectory(context.Background(), filepath.Dir(path), policy, uint32(os.Getuid())); !errors.Is(err, ErrProtection) {
					test.Fatalf("production directory comparison admitted %s: %v", name, err)
				}
				return
			}
			metadata, actual, err := (Reader{}).Read(context.Background(), path, policy)
			if err != nil || string(actual) != contents || metadata.Mode != mode || metadata.Links != 1 || metadata.Size != int64(len(contents)) {
				test.Fatalf("production file comparison control refused: %v", err)
			}
			switch name {
			case "file-mode-zero":
				policy.Mode = 0
			case "file-mode-0640", "file-mode-0644":
				policy.Mode = 0600
			case "file-group":
				policy.GID++
			case "file-links":
				err = os.Link(path, path+"-link")
			default:
				err = os.WriteFile(path, []byte(contents+"x"), mode)
			}
			if err != nil {
				test.Fatal(err)
			}
			metadata, actual, err = (Reader{}).Read(context.Background(), path, policy)
			if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || actual != nil {
				test.Fatalf("production file comparison admitted %s or partial output: %v", name, err)
			}
		})
	}
}

// Claim: invalid mode/link/size policies refuse before opening a safely missing leaf; a valid existing read and valid-policy absence distinguish each policy-shape guard from later metadata checks.
func TestPolicyShapeComparisons(test *testing.T) {
	for _, name := range []string{"mode", "links-zero", "links-two", "size-negative", "size-upper"} {
		test.Run(name, func(test *testing.T) {
			path, policy := fixture(test, "inert", 0640)
			policy.MaxBytes = 1 << 20
			if _, contents, err := (Reader{}).Read(context.Background(), path, policy); err != nil || string(contents) != "inert" {
				test.Fatalf("valid policy-shape read refused: %v", err)
			}
			missing := path + "-missing"
			if _, _, err := (Reader{}).Read(context.Background(), missing, policy); !errors.Is(err, fs.ErrNotExist) {
				test.Fatalf("valid policy-shape absence refused: %v", err)
			}
			switch name {
			case "mode":
				policy.Mode |= fs.ModeSetuid
			case "links-zero":
				policy.Links = 0
			case "links-two":
				policy.Links = 2
			case "size-negative":
				policy.MaxBytes = -1
			default:
				policy.MaxBytes = (1 << 20) + 1
			}
			metadata, contents, err := (Reader{}).Read(context.Background(), missing, policy)
			if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
				test.Fatalf("policy-shape comparison bypassed %s: %v", name, err)
			}
		})
	}
}

// Claim: the gate requires literal mode 0640 and size policy zero even when the neighboring policy admits the same inert file through ordinary Read.
func TestConfigGatePolicyComparisons(test *testing.T) {
	for _, name := range []string{"mode", "size"} {
		test.Run(name, func(test *testing.T) {
			path, policy := lockFixture(test)
			gate, err := NewConfigGate(context.Background(), path, policy)
			if err != nil || gate == nil {
				test.Fatalf("valid gate policy control refused: %v", err)
			}
			called := false
			if err := gate.WithRead(context.Background(), func(context.Context) error { called = true; return nil }); err != nil || !called {
				test.Fatalf("valid gate policy window refused: %v", err)
			}
			if name == "mode" {
				policy.Mode = 0644
				if err := os.Chmod(path, policy.Mode); err != nil {
					test.Fatal(err)
				}
			} else {
				policy.MaxBytes = 1
			}
			if _, contents, err := (Reader{}).Read(context.Background(), path, policy); err != nil || len(contents) != 0 {
				test.Fatalf("neighboring ordinary file policy refused: %v", err)
			}
			if gate, err := NewConfigGate(context.Background(), path, policy); !errors.Is(err, ErrProtection) || gate != nil {
				test.Fatalf("gate policy comparison admitted %s: %v", name, err)
			}
		})
	}
}
