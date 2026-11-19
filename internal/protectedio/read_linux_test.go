package protectedio

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/testutil/protectedfixture"
	"golang.org/x/sys/unix"
)

func fixtureRoot(test *testing.T) string {
	test.Helper()
	return protectedfixture.TempDir(test, func(root string) error {
		owner := uint32(os.Getuid())
		return (Reader{}).CheckDirectory(context.Background(), root, FilePolicy{UID: owner, GID: uint32(os.Getgid()), Mode: 0700}, owner)
	})
}

func fixture(test *testing.T, contents string, mode fs.FileMode) (string, FilePolicy) {
	test.Helper()
	path := filepath.Join(fixtureRoot(test), "record")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		test.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		test.Fatal(err)
	}
	return path, FilePolicy{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Mode: mode, Links: 1, MaxBytes: 128}
}

func refusedRead(test *testing.T, path string, policy FilePolicy) {
	test.Helper()
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
		test.Fatalf("protection refusal must return no identity or bytes: %v", err)
	}
}

func lockFixture(test *testing.T) (string, FilePolicy) {
	test.Helper()
	path, policy := fixture(test, "", 0640)
	if err := os.Chmod(filepath.Dir(path), 0750); err != nil {
		test.Fatal(err)
	}
	policy.MaxBytes = 0
	return path, policy
}

// Claim: actual descriptor reads return exact checked bytes and metadata; each adjacent inode/policy/ancestor violation refuses without returning partial data.
func TestProtectedFileAndAncestorProtection(test *testing.T) {
	for _, name := range []string{"mode", "setuid", "setgid", "sticky", "owner", "group", "hardlink", "symlink", "directory", "fifo", "size", "ancestor-mode", "ancestor-symlink", "noncanonical", "policy-links", "policy-size", "policy-special"} {
		test.Run(name, func(test *testing.T) {
			path, policy := fixture(test, "inert", 0640)
			metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
			if err != nil || string(contents) != "inert" || metadata.UID != policy.UID || metadata.GID != policy.GID || metadata.Mode != 0640 || metadata.Links != 1 || metadata.Size != 5 || metadata.Inode == 0 {
				test.Fatalf("valid checked-read control failed: %v", err)
			}
			switch name {
			case "mode":
				err = os.Chmod(path, 0600)
			case "setuid":
				err = os.Chmod(path, 0640|fs.ModeSetuid)
			case "setgid":
				err = os.Chmod(path, 0640|fs.ModeSetgid)
			case "sticky":
				err = os.Chmod(path, 0640|fs.ModeSticky)
			case "owner":
				policy.UID++
			case "group":
				policy.GID++
			case "hardlink":
				err = os.Link(path, path+"-link")
			case "symlink":
				err = os.Symlink(path, path+"-alias")
				path += "-alias"
			case "directory":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0640)
				}
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0640)
				}
			case "size":
				policy.MaxBytes = 4
			case "ancestor-mode":
				err = os.Chmod(filepath.Dir(path), 0770)
			case "ancestor-symlink":
				alias := filepath.Join(fixtureRoot(test), "alias")
				err = os.Symlink(filepath.Dir(path), alias)
				path = filepath.Join(alias, "record")
			case "noncanonical":
				path = filepath.Dir(path) + "/./record"
			case "policy-links":
				policy.Links = 2
			case "policy-size":
				policy.MaxBytes = MaxBytes + 1
			case "policy-special":
				policy.Mode |= fs.ModeSetuid
			}
			if err != nil {
				test.Fatal(err)
			}
			refusedRead(test, path, policy)
		})
	}
}

// Claim: only safely checked missing leaves report absence; unsafe ancestors, cancellation and changed opened inodes do not yield data or absence.
func TestProtectedAbsenceCancellationAndRecheck(test *testing.T) {
	path, policy := fixture(test, "inert", 0640)
	if err := os.Remove(path); err != nil {
		test.Fatal(err)
	}
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	if !errors.Is(err, fs.ErrNotExist) || metadata != (Identity{}) || contents != nil {
		test.Fatal("safe leaf absence not classified")
	}
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		test.Fatal(err)
	}
	refusedRead(test, path, policy)
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("inert"), 0640); err != nil {
		test.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		test.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metadata, contents, err = (Reader{}).Read(ctx, path, policy)
	if !errors.Is(err, context.Canceled) || metadata != (Identity{}) || contents != nil {
		test.Fatal("cancelled read returned evidence")
	}
	opened, err := openFile(context.Background(), path, policy)
	if err != nil {
		test.Fatal(err)
	}
	defer opened.close()
	if err := os.WriteFile(path, []byte("other"), 0640); err != nil {
		test.Fatal(err)
	}
	if !errors.Is(opened.current(context.Background()), ErrProtection) {
		test.Fatal("same-sized in-place write escaped recheck")
	}
}

// Claim: real flock excludes an exclusive writer, retains the original installer inode, rejects nonempty locks and reentry, and respects a bounded cancelled callback.
func TestConfigurationLockContinuity(test *testing.T) {
	for _, name := range []string{"contention", "replacement", "nonempty", "directory-mode", "callback-replacement", "cancel", "reentry"} {
		test.Run(name, func(test *testing.T) {
			path, policy := lockFixture(test)
			gate, err := NewConfigGate(context.Background(), path, policy)
			if err != nil {
				test.Fatal(err)
			}
			writer, err := os.Open(path)
			if err != nil {
				test.Fatal(err)
			}
			defer writer.Close()
			called := false
			if err := gate.WithRead(context.Background(), func(ctx context.Context) error {
				called = true
				if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
					test.Fatalf("shared read gate failed to exclude writer: %v", err)
				}
				return nil
			}); err != nil || !called {
				test.Fatalf("valid lock control failed: %v", err)
			}
			if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				test.Fatalf("read gate did not release lock: %v", err)
			}
			if err := unix.Flock(int(writer.Fd()), unix.LOCK_UN); err != nil {
				test.Fatal(err)
			}
			called = false
			if name == "contention" {
				if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					test.Fatal(err)
				}
				defer unix.Flock(int(writer.Fd()), unix.LOCK_UN)
			}
			if name == "replacement" {
				if err := os.WriteFile(path+"-new", nil, 0640); err != nil {
					test.Fatal(err)
				}
				if err := os.Chmod(path+"-new", 0640); err != nil {
					test.Fatal(err)
				}
				if err := os.Rename(path+"-new", path); err != nil {
					test.Fatal(err)
				}
			}
			if name == "nonempty" {
				if err := os.WriteFile(path, []byte("x"), 0640); err != nil {
					test.Fatal(err)
				}
			}
			if name == "directory-mode" {
				if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
					test.Fatal(err)
				}
			}
			err = gate.WithRead(context.Background(), func(ctx context.Context) error {
				called = true
				switch name {
				case "callback-replacement":
					if err := os.WriteFile(path+"-new", nil, 0640); err != nil {
						return err
					}
					if err := os.Chmod(path+"-new", 0640); err != nil {
						return err
					}
					return os.Rename(path+"-new", path)
				case "cancel":
					<-ctx.Done()
					return ctx.Err()
				case "reentry":
					return gate.WithRead(ctx, func(context.Context) error { test.Fatal("nested callback ran"); return nil })
				}
				return nil
			})
			if name == "cancel" {
				if !errors.Is(err, context.DeadlineExceeded) {
					test.Fatalf("wrong deadline refusal: %v", err)
				}
			} else if !errors.Is(err, ErrProtection) {
				test.Fatalf("wrong lock refusal: %v", err)
			}
			if (name == "contention" || name == "replacement" || name == "nonempty" || name == "directory-mode") && called {
				test.Fatal("refused lock ran callback")
			}
		})
	}
}

// Claim: deterministic leaf or ancestor replacement after a valid descriptor walk is detected by the retained descriptor/name joins, without relying on a timed race.
func TestDescriptorNameReplacement(test *testing.T) {
	for _, name := range []string{"leaf", "ancestor"} {
		test.Run(name, func(test *testing.T) {
			path, policy := fixture(test, "inert", 0640)
			opened, err := openFile(context.Background(), path, policy)
			if err != nil {
				test.Fatal(err)
			}
			defer opened.close()
			if err := opened.current(context.Background()); err != nil {
				test.Fatalf("valid descriptor/name control failed: %v", err)
			}
			source := path
			if name == "ancestor" {
				source = filepath.Dir(path)
			}
			if err := os.Rename(source, source+"-old"); err != nil {
				test.Fatal(err)
			}
			if name == "ancestor" {
				if err := os.Mkdir(source, 0700); err != nil {
					test.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte("inert"), 0640); err != nil {
				test.Fatal(err)
			}
			if err := os.Chmod(path, 0640); err != nil {
				test.Fatal(err)
			}
			if !errors.Is(opened.current(context.Background()), ErrProtection) {
				test.Fatal("replacement escaped descriptor/name recheck")
			}
		})
	}
}

// Claim: sibling creation changes directory metadata but does not replace a protected ancestor; an unrelated sibling must not invalidate a valid read window.
func TestDirectorySiblingDoesNotReplaceLock(test *testing.T) {
	path, policy := lockFixture(test)
	gate, err := NewConfigGate(context.Background(), path, policy)
	if err != nil {
		test.Fatal(err)
	}
	if err := gate.WithRead(context.Background(), func(context.Context) error { return os.WriteFile(path+"-sibling", nil, 0600) }); err != nil {
		test.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.WithRead(ctx, func(context.Context) error { return nil }); err != nil {
		test.Fatal(err)
	}
}
