//go:build linux

package timeconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Claim: an unrelated owned empty descriptor is absent in the target with or
// without FD_CLOEXEC; the parent's descriptor and flags remain intact.
func TestCollectorChildDescriptorIsolation(t *testing.T) {
	dir := protectedTemp(t)
	f, err := os.OpenFile(filepath.Join(dir, "descriptor.fixture"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD, 200)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if fd != 200 {
		t.Fatal("fixture descriptor unavailable")
	}
	exe := executableFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(exe), "scenario"), []byte("descriptor"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []int{unix.FD_CLOEXEC, 0} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags); err != nil {
			t.Fatal(err)
		}
		b, err := (SystemRunner{}).Run(context.Background(), exe, []string{"-c", "tracking"}, 2*time.Second, 256)
		if err != nil || string(b) != "closed" {
			t.Errorf("unrelated descriptor reached collector: flags=%d output=%q error=%v", flags, b, err)
		}
		got, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || got != flags {
			t.Fatal("parent descriptor modified")
		}
	}
}

// Claim: the shared and protected service loaders accept canonical bounds but
// refuse capitalization aliases, duplicate/unknown members and nulls. Failure
// leaves an existing destination unchanged rather than publishing partial data.
func TestPolicyCaseVariantMembers(t *testing.T) {
	shared := testPolicy()
	shared.MaxOffset = PlatformMaxOffset
	p := shared
	p.MaxOffset = time.Millisecond
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(protectedTemp(t), "policy.json")
	check := func(t *testing.T, raw []byte, valid bool) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		for _, load := range []func() (Policy, error){func() (Policy, error) { return DecodePolicy(raw) }, func() (Policy, error) { return LoadPolicy(path, uint32(os.Geteuid())) }, func() (Policy, error) { return LoadServicePolicy(path, uint32(os.Geteuid()), shared) }} {
			got, err := load()
			if valid && (err != nil || got.MaxOffset != time.Millisecond) {
				t.Fatal("canonical control refused", err)
			}
			if !valid && err == nil {
				t.Fatal("invalid member accepted")
			}
		}
		if !valid {
			before := Policy{Source: Off}
			after := before
			if json.Unmarshal(raw, &after) == nil || after.Source != before.Source {
				t.Fatal("failed decode changed destination")
			}
		}
	}
	check(t, b, true)
	for _, key := range []string{"MAX_OFFSET_NS", "Max_Offset_Ns", "max_offset_ns", "unknown"} {
		t.Run(key, func(t *testing.T) {
			check(t, []byte(strings.TrimSuffix(string(b), "}")+`,"`+key+`":500000000}`), false)
		})
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		for _, alias := range []string{strings.ToUpper(key), key} {
			value := fields[key]
			if alias == key {
				value = json.RawMessage("null")
			}
			raw := strings.Replace(string(b), `"`+key+`":`+string(fields[key]), `"`+alias+`":`+string(value), 1)
			check(t, []byte(raw), false)
		}
	}
	check(t, b, true)
}

// Claim: unavailable/blocked close_range never attempts the target exec; the
// successful control requests isolation of all FDs above 2 with a private table.
func TestCollectorDescriptorIsolationFailsClosed(t *testing.T) {
	for _, failure := range []error{unix.ENOSYS, unix.EINVAL, unix.EPERM, nil} {
		calls := 0
		err := execIsolatedCollector(func(first, last uint, flags uint) error {
			if first != 3 || last != ^uint(0) || flags != unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC {
				t.Fatal("incomplete isolation")
			}
			return failure
		}, func(path string, args, env []string) error { calls++; return unix.ENOENT }, "/fixture/collector", []string{"-c", "tracking"})
		if err == nil || failure != nil && calls != 0 || failure == nil && calls != 1 {
			t.Fatal("isolation failure reached target")
		}
	}
}
