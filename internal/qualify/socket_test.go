//go:build linux

package qualify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// This syscall implementation and its constructor are compiled only in tests.
// A matched boundary must be reached exactly once; no environment selector exists.
type fixtureCommandSyscalls struct {
	name   string
	err    error
	hits   int
	after  bool
	before func() error
}

func (f *fixtureCommandSyscalls) run(name string, call func() error) error {
	if name != f.name {
		return call()
	}
	f.hits++
	if f.before != nil {
		if e := f.before(); e != nil {
			return e
		}
	}
	if f.after {
		if e := call(); e != nil {
			return e
		}
	}
	return f.err
}
func withFixtureCommandSyscalls(path string, f *fixtureCommandSyscalls) driver {
	return driver{path: path, environment: []string{}, ops: f}
}
func requireNoReservation(t *testing.T, evidence string) {
	t.Helper()
	entries, err := os.ReadDir(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "run.json" {
			t.Fatalf("reservation entry survived: %s", entry.Name())
		}
	}
}

// Claim: EIO/EACCES at either socket-entry open or post-bind Fstat refuses with
// 69, no report/run.json, and no socket/directory. Pre-bind errors also refuse;
// the native positive control persists pending rows and removes the reservation.
// The shim executes before one real syscall; no candidate is ever executed.
func TestReviewSocketMetadataFailure(t *testing.T) {
	for _, point := range []string{"fstat:socket-entry", "open:socket-entry", "open:evidence", "fstat:evidence", "bind:socket", "control"} {
		for _, fault := range []struct {
			name string
			err  error
		}{{"EIO", unix.EIO}, {"EACCES", unix.EACCES}} {
			t.Run(point+"/"+fault.name, func(t *testing.T) {
				path, c, evidence := setup(t)
				shim := &fixtureCommandSyscalls{}
				if point != "control" {
					shim.name, shim.err = point, fault.err
				}
				var out bytes.Buffer
				status := withFixtureCommandSyscalls(path, shim).run(context.Background(), []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}, &out)
				if status != 69 {
					t.Fatalf("exit %d want 69", status)
				}
				if point != "control" {
					if shim.hits != 1 {
						t.Fatalf("fault hits=%d want 1", shim.hits)
					}
					if out.Len() != 0 {
						t.Error("failed socket metadata observation emitted a pending report")
					}
					if _, e := os.Lstat(filepath.Join(evidence, "run.json")); !os.IsNotExist(e) {
						t.Error("failed socket metadata observation created run.json")
					}
				} else {
					var r report
					if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil || r.Disposition != "pending" || len(r.Cases) != len(qualification.RequiredCases()) {
						t.Fatal("positive control has no pending report")
					}
					b, e := os.ReadFile(filepath.Join(evidence, "run.json"))
					if e != nil || !bytes.Equal(b, bytes.TrimSpace(out.Bytes())) {
						t.Fatal("positive control report not persisted")
					}
				}
				requireNoReservation(t, evidence)
			})
		}
	}
}

// Claim: teardown reports lookup/unlink errors and replacements, preserves the
// affected entry, and never recurses into a nonempty or replaced directory.
// Successful teardown uses retained pathname-inode identity and removes both.
func TestPrivateSocketTeardown(t *testing.T) {
	for _, mode := range []string{"normal", "socket-replaced", "socket-symlink", "directory-replaced", "directory-not-empty", "socket-lookup-EIO", "socket-lookup-EACCES", "directory-lookup-EIO", "unlink-EACCES"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			shim := &fixtureCommandSyscalls{}
			s, e := (driver{ops: shim}).reserve(context.Background(), dir, qualification.Hash([]byte("fixture candidate")))
			if e != nil {
				t.Fatal(e)
			}
			// Holding the socket entry prevents inode reuse after a replacement.
			var held unix.Stat_t
			if e := unix.Fstat(int(s.entry.Fd()), &held); e != nil || !sameObject(held, s.socketInfo) {
				t.Fatal("socket entry descriptor not retained")
			}
			st, e := os.Lstat(s.path)
			if e != nil || st.Mode().Perm() != 0600 {
				t.Fatal("socket mode")
			}
			privateDir := filepath.Dir(s.path)
			st, e = os.Stat(privateDir)
			if e != nil || st.Mode().Perm() != 0700 {
				t.Fatal("private directory mode")
			}
			want := error(unix.ESTALE)
			switch mode {
			case "socket-replaced", "socket-symlink":
				if e := os.Remove(s.path); e != nil {
					t.Fatal(e)
				}
				if mode == "socket-replaced" {
					e = os.WriteFile(s.path, []byte("replacement"), 0600)
				} else {
					e = os.Symlink("missing-target", s.path)
				}
				if e != nil {
					t.Fatal(e)
				}
			case "directory-replaced":
				if e := os.Rename(privateDir, privateDir+".original"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(privateDir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(privateDir, "replacement"), []byte("keep"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-not-empty":
				if e := os.WriteFile(filepath.Join(privateDir, "replacement"), []byte("keep"), 0600); e != nil {
					t.Fatal(e)
				}
				want = unix.ENOTEMPTY
			case "socket-lookup-EIO", "socket-lookup-EACCES":
				shim.name, shim.err = "lookup:socket-teardown", unix.EIO
				if mode == "socket-lookup-EACCES" {
					shim.err = unix.EACCES
				}
				want = shim.err
			case "directory-lookup-EIO":
				shim.name, shim.err, want = "lookup:directory-teardown", unix.EIO, unix.EIO
			case "unlink-EACCES":
				shim.name, shim.err, want = "unlink:socket", unix.EACCES, unix.EACCES
			}
			e = s.close()
			if mode == "normal" {
				if e != nil {
					t.Fatal(e)
				}
				requireNoReservation(t, dir)
				return
			}
			if !errors.Is(e, qualification.ErrUnavailable) || !errors.Is(e, want) {
				t.Fatalf("teardown did not report %v: %v", want, e)
			}
			if shim.name != "" && shim.hits != 1 {
				t.Fatalf("teardown fault hits=%d", shim.hits)
			}
			if _, e := os.Lstat(privateDir); e != nil {
				t.Fatal("affected directory removed")
			}
			if mode == "socket-replaced" {
				b, e := os.ReadFile(s.path)
				if e != nil || string(b) != "replacement" {
					t.Fatal("replacement removed")
				}
			}
			if mode == "socket-symlink" {
				target, e := os.Readlink(s.path)
				if e != nil || target != "missing-target" {
					t.Fatal("symlink replacement removed")
				}
			}
			if mode == "socket-lookup-EIO" || mode == "socket-lookup-EACCES" || mode == "unlink-EACCES" {
				st, e := os.Lstat(s.path)
				if e != nil || st.Mode()&os.ModeSocket == 0 {
					t.Fatal("unverified socket removed")
				}
			}
			if mode == "directory-replaced" || mode == "directory-not-empty" {
				b, e := os.ReadFile(filepath.Join(privateDir, "replacement"))
				if e != nil || string(b) != "keep" {
					t.Fatal("directory replacement removed")
				}
			}
		})
	}
}

// Claim: a teardown lookup failure is returned before run.json/stdout, rather
// than silently publishing a pending report. Directory-close errors after a
// checked report fsync also refuse stdout; the already-written file may remain.
func TestCommandCleanupFailure(t *testing.T) {
	for _, point := range []string{"lookup:socket-teardown", "close:report-directory"} {
		t.Run(point, func(t *testing.T) {
			path, c, evidence := setup(t)
			shim := &fixtureCommandSyscalls{name: point, err: unix.EIO, after: point == "close:report-directory"}
			var out bytes.Buffer
			if status := withFixtureCommandSyscalls(path, shim).run(context.Background(), []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}, &out); status != 69 || out.Len() != 0 {
				t.Fatalf("cleanup failure published report: status=%d bytes=%d", status, out.Len())
			}
			if shim.hits != 1 {
				t.Fatalf("fault hits=%d", shim.hits)
			}
			_, e := os.Lstat(filepath.Join(evidence, "run.json"))
			if point == "lookup:socket-teardown" && !os.IsNotExist(e) {
				t.Fatal("teardown failure created report")
			}
			if point == "close:report-directory" {
				if e != nil {
					t.Fatal("durably written report missing")
				}
				requireNoReservation(t, evidence)
			}
		})
	}
}

// Claim: before bind, a directory whose descriptor cannot be opened or measured
// is preserved rather than deleted without an identity check. No socket or
// report is created, and the reservation reports the injected error exactly once.
func TestPrivateSocketUnverifiedDirectory(t *testing.T) {
	for _, point := range []string{"open:socket-directory", "fstat:socket-directory"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			shim := &fixtureCommandSyscalls{name: point, err: unix.EIO}
			s, e := (driver{ops: shim}).reserve(context.Background(), dir, qualification.Hash([]byte("fixture candidate")))
			if s != nil || !errors.Is(e, qualification.ErrUnavailable) || !errors.Is(e, unix.EIO) || shim.hits != 1 {
				t.Fatalf("unverified directory accepted: socket=%v err=%v hits=%d", s, e, shim.hits)
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 1 || !entries[0].IsDir() {
				t.Fatal("unverified directory removed")
			}
			children, e := os.ReadDir(filepath.Join(dir, entries[0].Name()))
			if e != nil || len(children) != 0 {
				t.Fatal("unverified directory acquired an endpoint or report")
			}
		})
	}
}
