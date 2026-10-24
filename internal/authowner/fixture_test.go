//go:build linux

package authowner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/store"
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
func restoreFixtureRecords(t *testing.T, disk *store.Account, dir string, baseline map[string][]byte) {
	t.Helper()
	current, err := disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	for name := range current {
		if _, ok := baseline[name]; !ok && strings.HasPrefix(name, "owner-") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, raw := range baseline {
		if previous, ok := current[name]; ok && bytes.Equal(previous, raw) {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Claim: fixture restoration repairs changed and missing records, removes
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
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"revision":2}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	restoreFixtureRecords(t, f.disk, dir, baseline)
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
