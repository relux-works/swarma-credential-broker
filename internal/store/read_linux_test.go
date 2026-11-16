//go:build linux

package store

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// Single-record reads refuse path traversal, symlinks and protection drift,
// without opening an unrelated bad record. Fixed errors contain no path/data.
func TestSelectedReadProtection(t *testing.T) {
	for _, a := range []*Account{nil, {}} {
		if b, err := a.Read("owner-good.json"); !errors.Is(err, ErrUnavailable) || b != nil {
			t.Fatal("zero account read admitted")
		}
	}
	_, a := fresh(t, nil)
	if a.Put("owner-good.json", 0, record{"fixture-install", 1, "metadata"}) != nil {
		t.Fatal("control write failed")
	}
	if a.root.Symlink("missing", "owner-other.json") != nil {
		t.Fatal("unreadable sibling setup failed")
	}
	b, err := a.Read("owner-good.json")
	if err != nil || !bytes.Contains(b, []byte("metadata")) {
		t.Fatal("selected read inspected sibling")
	}
	for _, n := range []string{"../owner-good.json", "identity.json", "pending-owner-good.json", "owner-other.json"} {
		if b, err := a.Read(n); !errors.Is(err, ErrUnavailable) || b != nil {
			t.Fatal("unsafe selected read accepted")
		}
	}
	if b, err := a.Read("owner-absent.json"); !errors.Is(err, ErrNotFound) || b != nil {
		t.Fatal("missing selected record misclassified")
	}
	if a.root.Chmod("owner-good.json", 0644) != nil {
		t.Fatal("mode plant failed")
	}
	if b, err := a.Read("owner-good.json"); !errors.Is(err, ErrUnavailable) || b != nil {
		t.Fatal("unsafe record mode accepted")
	}
	if a.root.Chmod("owner-good.json", 0600) != nil {
		t.Fatal("mode control failed")
	}
	if _, err := a.Read("owner-good.json"); err != nil {
		t.Fatal("protected record refused")
	}
	if a.root.Chmod(".", os.ModeDir|0755) != nil {
		t.Fatal("directory mode plant failed")
	}
	if b, err := a.Read("owner-good.json"); !errors.Is(err, ErrUnavailable) || b != nil {
		t.Fatal("unsafe account mode accepted")
	}
}
