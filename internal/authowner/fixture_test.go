//go:build linux

package authowner

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Claim: caching the fixture measurement never bypasses the real owner digest
// check. A matching executable copy admits; changing one byte refuses New.
func TestFixtureExecutableDigestRechecked(t *testing.T) {
	f := newFixture(t, "rotate")
	f.e.Close()
	image, err := os.ReadFile(fakeExecutable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vendor")
	if err = os.WriteFile(path, image, 0700); err != nil {
		t.Fatal(err)
	}
	c := f.c
	c.Executable = path
	e, err := New(context.Background(), c, f.m, f.t, fakeClassifier{})
	if err != nil {
		t.Fatal("matching copy control", err)
	}
	e.Close()
	image[len(image)-1] ^= 1
	if err = os.WriteFile(path, image, 0700); err != nil {
		t.Fatal(err)
	}
	e, err = New(context.Background(), c, f.m, f.t, fakeClassifier{})
	if e != nil {
		e.Close()
	}
	if err != ErrUnavailable || e != nil {
		t.Fatal("changed executable admitted", err)
	}
}

// Restore the full baseline after each case, writing only changed or missing
// records. All unexpected owner records are still removed.
func restoreFixtureRecords(t *testing.T, dir string, baseline map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := baseline[name]; !ok && strings.HasPrefix(name, "owner-") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, raw := range baseline {
		path := filepath.Join(dir, name)
		// Cleanup compares bytes without repeating the store's JSON parser. The
		// case's before/after assertions still use the real strict store reader.
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err == nil {
			previous, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal("read fixture record", readErr, closeErr)
			}
			if bytes.Equal(previous, raw) {
				continue
			}
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Claim: fixture restoration repairs malformed and missing records, removes
// unexpected owner writes, and leaves the matching control's bytes/mtime alone.
func TestFixtureRecordRestore(t *testing.T) {
	f := newFixture(t, "rotate")
	f.e.Close()
	dir := filepath.Dir(authorityRecordPath(f, "owner-checkpoint.json"))
	for _, name := range []string{"owner-missing.json", "owner-control.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"revision":1}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := f.disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(dir, "owner-control.json")
	stamp := time.Unix(100, 0)
	if err := os.Chtimes(control, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "owner-missing.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owner-checkpoint.json", "owner-extra.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`not-json`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	restoreFixtureRecords(t, dir, baseline)
	after, err := f.disk.Records()
	if err != nil || len(after) != len(baseline) {
		t.Fatal("restore record set", err)
	}
	for name, raw := range baseline {
		if !bytes.Equal(after[name], raw) {
			t.Fatal("restore record bytes", name)
		}
	}
	info, err := os.Stat(control)
	if err != nil || !info.ModTime().Equal(stamp) {
		t.Fatal("matching control was rewritten", err)
	}
}
