//go:build linux

package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fresh(t *testing.T, h Durability) (*Store, *Account) {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "store"), "fixture-install", uint32(os.Geteuid()), true, h)
	if e != nil {
		t.Fatal("store setup failed")
	}
	t.Cleanup(func() { s.Close() })
	a, e := s.Account("fixture-account", true)
	if e != nil {
		t.Fatal("account setup failed")
	}
	return s, a
}

type record struct {
	Installation string `json:"installation_id"`
	Revision     uint64 `json:"revision"`
	State        string `json:"state"`
}

// Claim: wrong owner/modes, symlinks, absent store and a second live owner are refused; a fresh protected store opens.
func TestProtectionAndSingleton(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	if _, e := Open(root, "fixture", uint32(os.Geteuid()), false, nil); e == nil {
		t.Fatal("missing store opened")
	}
	s, e := Open(root, "fixture", uint32(os.Geteuid()), true, nil)
	if e != nil {
		t.Fatal("protected store refused")
	}
	if _, e = Open(root, "fixture", uint32(os.Geteuid()), false, nil); e == nil {
		t.Fatal("second singleton admitted")
	}
	s.Close()
	if _, e = Open(root, "fixture", uint32(os.Geteuid())+1, false, nil); e == nil {
		t.Fatal("wrong expected owner accepted")
	}
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(root, "fixture", uint32(os.Geteuid()), false, nil); e == nil {
		t.Fatal("wrong mode accepted")
	}
	os.Chmod(root, 0700)
	os.Chmod(filepath.Join(root, "identity.json"), 0644)
	if _, e = Open(root, "fixture", uint32(os.Geteuid()), false, nil); e == nil {
		t.Fatal("wrong record mode accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(root, link)
	if _, e = Open(link, "fixture", uint32(os.Geteuid()), false, nil); e == nil {
		t.Fatal("store symlink followed")
	}
}

// Claim: record publication orders write/fsync/rename/directory-fsync; stale revisions and pre-rename failures do not replace the old record.
func TestDurabilityAndCAS(t *testing.T) {
	var stages []string
	fail := ""
	_, a := fresh(t, func(stage string) error {
		stages = append(stages, stage)
		if stage == fail {
			return errors.New("fixture I/O failure")
		}
		return nil
	})
	stages = nil
	if e := a.Put("lease-example.json", 0, record{"fixture-install", 1, "active"}); e != nil {
		t.Fatal("initial commit failed")
	}
	if !reflect.DeepEqual(stages, []string{"write", "file-sync", "rename", "directory-sync"}) {
		t.Fatal("wrong durability ordering")
	}
	if e := a.Put("lease-example.json", 0, record{"fixture-install", 1, "released"}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale revision accepted")
	}
	before, _ := a.Records()
	fail = "file-sync"
	if e := a.Put("lease-example.json", 1, record{"fixture-install", 2, "released"}); e == nil {
		t.Fatal("injected fault ignored")
	}
	after, e := a.Records()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("pre-rename fault changed published record")
	}
	fail = ""
	if e = a.Put("lease-example.json", 1, record{"fixture-install", 2, "released"}); e != nil {
		t.Fatal("valid successor refused")
	}
}

// Claim: initialization never adopts a nonempty account after its identity is removed; record symlinks and post-open permission widening are refused.
func TestAccountProtection(t *testing.T) {
	s, a := fresh(t, nil)
	f, err := a.root.OpenFile("foreign.json", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fixture creation failed")
	}
	f.Close()
	if a.root.Remove("identity.json") != nil {
		t.Fatal("fixture identity removal failed")
	}
	a.lock.Close()
	a.root.Close()
	delete(s.accounts, "fixture-account")
	if _, err = s.Account("fixture-account", true); err == nil {
		t.Fatal("nonempty account adopted")
	}
	_, a = fresh(t, nil)
	if a.root.Symlink("identity.json", "lease-link.json") != nil {
		t.Fatal("fixture link failed")
	}
	if _, err = a.Records(); err == nil {
		t.Fatal("record link followed")
	}
	a.root.Remove("lease-link.json")
	if a.root.Chmod(".", 0755) != nil {
		t.Fatal("fixture chmod failed")
	}
	if a.Healthy() == nil {
		t.Fatal("widened directory accepted")
	}
	if a.root.Chmod(".", 0700) != nil || a.Healthy() != nil {
		t.Fatal("protected control refused")
	}
}
