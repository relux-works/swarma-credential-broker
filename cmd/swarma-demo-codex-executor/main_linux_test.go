//go:build linux

package main

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrongIdentityRefusesBeforeFD3OrAuthority(t *testing.T) {
	if os.Getuid() >= 30000 && os.Getuid() <= 30019 {
		t.Skip("wrong-identity fixture requires another UID")
	}
	if got := run(context.Background(), nil); got != 69 {
		t.Fatal("wrong UID did not refuse")
	}
	if got := run(context.Background(), []string{"--untrusted"}); got != 69 {
		t.Fatal("untrusted argv did not refuse")
	}
}

func TestInheritedServiceDescriptorRefused(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "descriptor")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	fd, e := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if e != nil {
		t.Fatal(e)
	}
	inherited := os.NewFile(uintptr(fd), "synthetic-service-descriptor")
	defer inherited.Close()
	if _, e = unix.FcntlInt(inherited.Fd(), unix.F_SETFD, 0); e != nil {
		t.Fatal(e)
	}
	if inheritedDescriptorsSafe() {
		t.Fatal("unexpected inheritable descriptor admitted")
	}
	if _, e = unix.FcntlInt(inherited.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); e != nil {
		t.Fatal(e)
	}
}
func TestMetadataExclusiveBoundedNoFollow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outcome.json")
	v := map[string]any{"launch_id": strings.Repeat("a", 64), "lease_id": "synthetic-lease", "worker_generation": strings.Repeat("b", 32), "policy_generation": 1, "state": "turn_completed"}
	if e := writeRecord(path, v); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(path)
	if e != nil || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		t.Fatal("metadata custody or bound")
	}
	if e = writeRecord(path, v); e == nil {
		t.Fatal("metadata overwritten")
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("unchanged"), 0600)
	alias := filepath.Join(dir, "alias")
	os.Symlink(target, alias)
	if e = writeRecord(alias, v); e == nil {
		t.Fatal("metadata followed symlink")
	}
	b, e := os.ReadFile(target)
	if e != nil || string(b) != "unchanged" {
		t.Fatal("target changed")
	}
	long := map[string]string{"state": strings.Repeat("x", 4090)}
	encoded, _ := json.Marshal(long)
	if len(encoded)+1 <= 4096 {
		t.Fatal("bad boundary fixture")
	}
	if e = writeRecord(filepath.Join(dir, "too-large"), long); e == nil {
		t.Fatal("oversized metadata emitted")
	}
}
