package protectedio

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: valid low-level opens, reads, directory checks and gate windows return usable results without panic; malformed paths refuse the protection contract before cancellation.
func TestMechanicalDecisionControls(test *testing.T) {
	path := filepath.Join(test.TempDir(), "record")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("inert"), 0640); err != nil {
		test.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		test.Fatal(err)
	}
	policy := FilePolicy{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Mode: 0640, Links: 1, MaxBytes: 128}
	ctx := context.Background()
	for _, name := range []string{"open", "openFile", "Read", "directory", "gate", "missing-leaf", "missing-ancestor", "directory-file", "nil-context", "path-root", "path-relative", "path-unclean", "path-nul"} {
		test.Run(name, func(test *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					test.Fatalf("mechanical decision control panicked: %v", recovered)
				}
			}()
			switch name {
			case "open", "openFile":
				var result *opened
				var err error
				if name == "open" {
					result, err = open(ctx, path, policy.UID, false)
				} else {
					result, err = openFile(ctx, path, policy)
				}
				if err != nil || result == nil || len(result.parts) == 0 {
					test.Fatalf("mechanical open control refused or returned no descriptors: %v", err)
				}
				result.close()
			case "Read":
				metadata, contents, err := (Reader{}).Read(ctx, path, policy)
				if err != nil || string(contents) != "inert" || metadata.UID != policy.UID || metadata.GID != policy.GID || metadata.Mode != 0640 || metadata.Size != 5 {
					test.Fatalf("mechanical read control refused or incomplete: %v", err)
				}
			case "missing-leaf", "missing-ancestor", "directory-file":
				target, want, directory := path+"-missing", error(fs.ErrNotExist), false
				if name == "missing-ancestor" {
					target, want = filepath.Join(filepath.Dir(path), "missing", "record"), ErrProtection
				}
				if name == "directory-file" {
					target, want, directory = path, ErrProtection, true
				}
				result, err := open(ctx, target, policy.UID, directory)
				if result != nil {
					result.close()
				}
				if !errors.Is(err, want) || result != nil {
					test.Fatalf("mechanical %s returned wrong refusal or descriptors: %v", name, err)
				}
			case "directory":
				directoryPolicy := FilePolicy{UID: policy.UID, GID: policy.GID, Mode: 0700}
				if err := (Reader{}).CheckDirectory(ctx, filepath.Dir(path), directoryPolicy, policy.UID); err != nil {
					test.Fatalf("mechanical directory control refused: %v", err)
				}
			case "gate":
				lock, lockPolicy := lockFixture(test)
				gate, err := NewConfigGate(ctx, lock, lockPolicy)
				if err != nil || gate == nil {
					test.Fatalf("mechanical gate control refused: %v", err)
				}
				called := false
				if err := gate.WithRead(ctx, func(context.Context) error { called = true; return nil }); err != nil || !called {
					test.Fatalf("mechanical gate window refused: %v called=%v", err, called)
				}
			default:
				invalid := map[string]string{"path-root": "/", "path-relative": path[1:], "path-unclean": filepath.Dir(path) + "/../record", "path-nul": path + "\x00"}
				badctx, cancel := context.WithCancel(ctx)
				cancel()
				if name == "nil-context" {
					badctx = nil
					invalid[name] = path
				}
				result, err := open(badctx, invalid[name], policy.UID, false)
				if result != nil {
					result.close()
				}
				if !errors.Is(err, ErrProtection) || result != nil {
					test.Fatalf("mechanical path guard returned wrong refusal: %v", err)
				}
			}
		})
	}
}

type cancelAtContext struct {
	context.Context
	cancel    context.CancelFunc
	calls, at int
}

// Claim: cancellation observed while checking a failed ancestor open is preserved, beside the uncanceled regular-file control.
func TestMechanicalOpenFailureCancellation(test *testing.T) {
	path, policy := fixture(test, "inert", 0644)
	result, err := open(context.Background(), path, policy.UID, false)
	if err != nil || result == nil {
		test.Fatalf("mechanical failure-cancellation valid control refused: %v", err)
	}
	result.close()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAtContext{Context: base, cancel: cancel, at: 2}
	result, err = open(ctx, path+"/child", policy.UID, false)
	if result != nil {
		result.close()
	}
	if !errors.Is(err, context.Canceled) || result != nil {
		test.Fatalf("mechanical failed-open cancellation changed: %v", err)
	}
}

func (ctx *cancelAtContext) Err() error {
	ctx.calls++
	if ctx.calls == ctx.at {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

// Claim: factory read failures and gate nil-input refusals preserve the exact refusal without constructing a usable gate or invoking a callback.
func TestMechanicalGateRefusals(test *testing.T) {
	for _, name := range []string{"leaf-mode", "read-canceled", "nil-context", "nil-callback"} {
		test.Run(name, func(test *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					test.Fatalf("mechanical gate refusal panicked: %v", recovered)
				}
			}()
			path, policy := lockFixture(test)
			gate, err := NewConfigGate(context.Background(), path, policy)
			if err != nil || gate == nil {
				test.Fatalf("mechanical gate refusal valid control refused: %v", err)
			}
			called := false
			if err := gate.WithRead(context.Background(), func(context.Context) error { called = true; return nil }); err != nil || !called {
				test.Fatalf("mechanical gate refusal valid window refused: %v", err)
			}
			switch name {
			case "leaf-mode":
				if err := os.Chmod(path, 0600); err != nil {
					test.Fatal(err)
				}
				if refused, err := NewConfigGate(context.Background(), path, policy); !errors.Is(err, ErrProtection) || refused != nil {
					test.Fatalf("mechanical bad lock read admitted at construction: %v", err)
				}
			case "read-canceled":
				base, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx := &cancelAtContext{Context: base, cancel: cancel, at: 4}
				if refused, err := NewConfigGate(ctx, path, policy); !errors.Is(err, context.Canceled) || refused != nil {
					test.Fatalf("mechanical lock read cancellation changed: %v", err)
				}
			default:
				called = false
				ctx, callback := context.Context(context.Background()), func(context.Context) error { called = true; return nil }
				if name == "nil-context" {
					ctx = nil
				} else {
					callback = nil
				}
				if err := gate.WithRead(ctx, callback); !errors.Is(err, ErrProtection) || called {
					test.Fatalf("mechanical nil gate input admitted: %v callback=%v", err, called)
				}
			}
		})
	}
}

// Claim: a task-owned proc stat file with kernel-reported size zero refuses nonempty bytes, beside a valid ordinary file; no process contents are logged.
func TestMechanicalReadByteCount(test *testing.T) {
	path, policy := fixture(test, "inert", 0644)
	if _, contents, err := (Reader{}).Read(context.Background(), path, policy); err != nil || string(contents) != "inert" {
		test.Fatalf("mechanical byte-count valid control refused: %v", err)
	}
	path = "/proc/" + strconv.Itoa(os.Getpid()) + "/stat"
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Mode != unix.S_IFREG|0444 || stat.Size != 0 || stat.Nlink != 1 || stat.Uid != policy.UID || stat.Gid != policy.GID {
		test.Fatalf("task-owned proc stat precondition failed: %v", err)
	}
	policy.Mode, policy.MaxBytes = 0444, MaxBytes
	metadata, contents, err := (Reader{}).Read(context.Background(), path, policy)
	if !errors.Is(err, ErrProtection) || metadata != (Identity{}) || contents != nil {
		test.Fatalf("mechanical byte count admitted inconsistent proc size or partial result: %v", err)
	}
}

// Claim: metadata conversion preserves every permission bit and sameNode distinguishes file kinds while ignoring only directory size/link churn.
func TestMechanicalMetadataComparisons(test *testing.T) {
	for bit := uint(0); bit < 9; bit++ {
		stat := unix.Stat_t{Mode: unix.S_IFREG | 1<<bit}
		if observed := identity(stat); observed.Mode != fs.FileMode(1<<bit) {
			test.Fatalf("mechanical permission bit %d lost: %v", bit, observed.Mode)
		}
	}
	for _, kind := range []uint32{unix.S_IFREG, unix.S_IFIFO, unix.S_IFSOCK, unix.S_IFLNK, unix.S_IFCHR, unix.S_IFBLK, unix.S_IFDIR} {
		first := unix.Stat_t{Mode: kind | 0644, Nlink: 1, Size: 3}
		if !sameNode(first, first) {
			test.Fatal("mechanical same-node valid control refused")
		}
		second := first
		second.Mode = unix.S_IFREG | 0644
		if kind != unix.S_IFREG && sameNode(first, second) {
			test.Fatal("mechanical different inode kinds admitted")
		}
		second = first
		second.Nlink++
		second.Size++
		if sameNode(first, second) != (kind == unix.S_IFDIR) {
			test.Fatal("mechanical directory-only metadata normalization differs")
		}
	}
}

// Claim: each descriptor metadata, mtime and ctime comparison refuses an independently mismatched pin, beside an accepted actual descriptor control.
func TestMechanicalDescriptorComparisons(test *testing.T) {
	for _, name := range []string{"mode", "mtime", "ctime"} {
		test.Run(name, func(test *testing.T) {
			path, policy := fixture(test, "inert", 0644)
			result, err := openFile(context.Background(), path, policy)
			if err != nil || result == nil {
				test.Fatalf("mechanical descriptor open control refused: %v", err)
			}
			defer result.close()
			if err := result.current(context.Background()); err != nil {
				test.Fatalf("mechanical descriptor current control refused: %v", err)
			}
			pin := &result.parts[len(result.parts)-1].stat
			switch name {
			case "mode":
				pin.Mode ^= 0100
			case "mtime":
				pin.Mtim.Sec--
			case "ctime":
				pin.Ctim.Sec--
			}
			if err := result.current(context.Background()); !errors.Is(err, ErrProtection) {
				test.Fatalf("mechanical descriptor %s comparison admitted: %v", name, err)
			}
		})
	}
}

// Claim: the lock factory checks its parent immediately, not only at the first window, beside a valid freshly built gate.
func TestMechanicalGateConstructionParent(test *testing.T) {
	path, policy := lockFixture(test)
	if gate, err := NewConfigGate(context.Background(), path, policy); err != nil || gate == nil {
		test.Fatalf("mechanical construction valid control refused: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		test.Fatal(err)
	}
	if gate, err := NewConfigGate(context.Background(), path, policy); !errors.Is(err, ErrProtection) || gate != nil {
		test.Fatalf("mechanical construction parent admitted: %v", err)
	}
}
