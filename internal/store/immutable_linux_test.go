//go:build linux

package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func immutableLimits() ImmutableLimits { return ImmutableLimits{MaxRecordBytes, 8 << 20, 64, 8 << 20} }
func immutableUnit(seed string) []EncodedImmutable {
	a := []byte(`{"data":"` + seed + `"}`)
	b := []byte(`{"manifest":"` + seed + `"}`)
	return []EncodedImmutable{{"owner-fresh-object-" + immutableHash(a) + ".json", a}, {"owner-fresh-manifest-" + immutableHash(b) + ".json", b}}
}
func immutableState(t *testing.T, s *Store, a *Account) map[string]string {
	t.Helper()
	path := filepath.Join(s.path, a.name)
	names, e := os.ReadDir(path)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, n := range names {
		b, e := os.ReadFile(filepath.Join(path, n.Name()))
		if e != nil {
			t.Fatal(e)
		}
		out[n.Name()] = string(b)
	}
	return out
}

// Claim: exact byte/count equality admits the complete immutable unit, while
// either next byte or file refuses before any create; controls are charged.
func TestImmutableAggregate(t *testing.T) {
	for _, kind := range []string{"bytes", "count"} {
		t.Run(kind, func(t *testing.T) {
			s, a := fresh(t, nil)
			l := immutableLimits()
			snap, _, e := a.ReadImmutableBounded(nil, l)
			if e != nil {
				t.Fatal(e)
			}
			unit := immutableUnit("one")
			l.TotalBytes = snap.Bytes + uint64(len(unit[0].Bytes)+len(unit[1].Bytes))
			l.TotalRecords = snap.Records + 2
			before := immutableState(t, s, a)
			bad := l
			if kind == "bytes" {
				bad.TotalBytes--
			} else {
				bad.TotalRecords--
			}
			if e = a.AppendImmutableBounded(unit, bad); !errors.Is(e, ErrImmutableLimit) {
				t.Fatalf("wrong capacity refusal: %v", e)
			}
			if !reflect.DeepEqual(before, immutableState(t, s, a)) {
				t.Fatal("capacity refusal wrote a prefix")
			}
			if e = a.AppendImmutableBounded(unit, l); e != nil {
				t.Fatal("exact boundary refused", e)
			}
			_, raw, e := a.ReadImmutableBounded([]string{unit[0].Name, unit[1].Name}, l)
			if e != nil || !bytes.Equal(raw[0], unit[0].Bytes) || !bytes.Equal(raw[1], unit[1].Bytes) {
				t.Fatal("exact read failed", e)
			}
		})
	}
}

// Claim: a zero-byte abandoned object and a torn pending object remain charged.
func TestImmutablePendingQuota(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero", true: "pending"}[pending], func(t *testing.T) {
			s, a := fresh(t, nil)
			l := immutableLimits()
			name := immutableUnit("abandoned")[0].Name
			raw := []byte{}
			if pending {
				name = "pending-" + name
				raw = []byte("partial")
			}
			if e := os.WriteFile(filepath.Join(s.path, a.name, name), raw, 0600); e != nil {
				t.Fatal(e)
			}
			l.TotalRecords = 4
			before := immutableState(t, s, a)
			if e := a.AppendImmutableBounded(immutableUnit("new"), l); !errors.Is(e, ErrImmutableLimit) {
				t.Fatal("abandoned file uncharged", e)
			}
			if !reflect.DeepEqual(before, immutableState(t, s, a)) {
				t.Fatal("pending failure mutated state")
			}
			l.TotalRecords = 5
			if e := a.AppendImmutableBounded(immutableUnit("new"), l); e != nil {
				t.Fatal("nearby valid count refused", e)
			}
		})
	}
}

// Claim: cooperating handles sharing an account serialize the complete census
// and batch, admitting exactly one unit when only one fits. This is not race qualification.
func TestImmutableConcurrentAdmission(t *testing.T) {
	_, a := fresh(t, nil)
	l := immutableLimits()
	l.TotalRecords = 4
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, seed := range []string{"a", "b"} {
		wg.Add(1)
		go func(seed string) { defer wg.Done(); results <- a.AppendImmutableBounded(immutableUnit(seed), l) }(seed)
	}
	wg.Wait()
	close(results)
	ok, limited := 0, 0
	for e := range results {
		if e == nil {
			ok++
		} else if errors.Is(e, ErrImmutableLimit) {
			limited++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || limited != 1 {
		t.Fatalf("overcommit/results: %d %d", ok, limited)
	}
}

// Claim: an existing immutable name refuses even for a matching next request;
// malformed old bytes cannot be silently overwritten or accepted as idempotence.
func TestImmutableExistingName(t *testing.T) {
	s, a := fresh(t, nil)
	unit := immutableUnit("same")
	if e := os.WriteFile(filepath.Join(s.path, a.name, unit[0].Name), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	before := immutableState(t, s, a)
	if e := a.AppendImmutableBounded(unit, immutableLimits()); !errors.Is(e, ErrConflict) {
		t.Fatal("existing name accepted", e)
	}
	if !reflect.DeepEqual(before, immutableState(t, s, a)) {
		t.Fatal("existing content overwritten")
	}
	_, valid := fresh(t, nil)
	if e := valid.AppendImmutableBounded(unit, immutableLimits()); e != nil {
		t.Fatal(e)
	}
}

// Claim: descriptor reads refuse owned synthetic symlinks and multi-link files,
// while a separately protected regular single-link object is readable.
func TestImmutableReadBoundary(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, a := fresh(t, nil)
			raw := []byte(`{"x":1}`)
			external := filepath.Join(t.TempDir(), "original")
			if e := os.WriteFile(external, raw, 0600); e != nil {
				t.Fatal(e)
			}
			name := "owner-fresh-object-" + immutableHash(raw) + ".json"
			path := filepath.Join(s.path, a.name, name)
			var e error
			if kind == "symlink" {
				e = os.Symlink(external, path)
			} else {
				e = os.Link(external, path)
			}
			if e != nil {
				t.Fatal(e)
			}
			_, got, e := a.ReadImmutableBounded([]string{name}, immutableLimits())
			if !errors.Is(e, ErrUnavailable) || got != nil {
				t.Fatalf("forbidden %s read: %v", kind, e)
			}
			if e = a.AppendImmutableBounded(immutableUnit("destination"), immutableLimits()); !errors.Is(e, ErrUnavailable) {
				t.Fatal("linked destination account admitted append", e)
			}
			kept, e := os.ReadFile(external)
			if e != nil || !bytes.Equal(kept, raw) {
				t.Fatal("external linked bytes changed", e)
			}

			_, valid := fresh(t, nil)
			unit := immutableUnit("valid")
			if e = valid.AppendImmutableBounded(unit, immutableLimits()); e != nil {
				t.Fatal(e)
			}
			if _, _, e = valid.ReadImmutableBounded([]string{unit[0].Name}, immutableLimits()); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Claim: permission failures stay structured; bounded control metadata is checked
// before parsing and missing/oversized control documents are never empty history.
func TestImmutableIORefusal(t *testing.T) {
	for _, kind := range []string{"permission", "missing", "oversized", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, a := fresh(t, nil)
			path := filepath.Join(s.path, a.name)
			switch kind {
			case "permission":
				n := immutableUnit("hidden")[0].Name
				if e := os.WriteFile(filepath.Join(path, n), []byte("x"), 0000); e != nil {
					t.Fatal(e)
				}
			case "missing":
				if e := os.Remove(filepath.Join(path, "identity.json")); e != nil {
					t.Fatal(e)
				}
			case "oversized":
				if e := os.WriteFile(filepath.Join(path, "identity.json"), bytes.Repeat([]byte("x"), 257), 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown":
				if e := os.WriteFile(filepath.Join(path, "other.json"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			_, raw, e := a.ReadImmutableBounded(nil, immutableLimits())
			if !errors.Is(e, ErrUnavailable) || raw != nil {
				t.Fatalf("unstructured failure: %v", e)
			}
		})
	}
	_, a := fresh(t, nil)
	if _, _, e := a.ReadImmutableBounded(nil, immutableLimits()); e != nil {
		t.Fatal("valid metadata refused", e)
	}
}

// Claim: an injected failure after exclusive create preserves a charged prefix;
// the next full unit cannot reclaim that space or report confirmed no-commit.
func TestImmutableFaultCharge(t *testing.T) {
	s, a := fresh(t, nil)
	l := immutableLimits()
	l.TotalRecords = 4
	a.hook = func(stage string) error {
		if stage == "immutable-create" {
			return ErrUnavailable
		}
		return nil
	}
	if e := a.AppendImmutableBounded(immutableUnit("lost"), l); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	a.hook = nil
	before := immutableState(t, s, a)
	if len(before) != 3 {
		t.Fatal("partial file erased", len(before))
	}
	if e := a.AppendImmutableBounded(immutableUnit("next"), l); !errors.Is(e, ErrImmutableLimit) {
		t.Fatal("partial space refunded", e)
	}
	if !reflect.DeepEqual(before, immutableState(t, s, a)) {
		t.Fatal("refused second unit mutated state")
	}
}

// Claim: raw primitive requests are bounded and names/digests are checked before writes.
func TestImmutableInvalidBatch(t *testing.T) {
	s, a := fresh(t, nil)
	before := immutableState(t, s, a)
	for _, change := range []func([]EncodedImmutable) []EncodedImmutable{func(b []EncodedImmutable) []EncodedImmutable { b[0].Name = "../escape"; return b }, func(b []EncodedImmutable) []EncodedImmutable {
		b[0].Bytes = bytes.Repeat([]byte("x"), MaxRecordBytes+1)
		return b
	}, func(b []EncodedImmutable) []EncodedImmutable { b[0].Name = b[1].Name; return b }, func(b []EncodedImmutable) []EncodedImmutable { b[0].Bytes = []byte("changed"); return b }} {
		if e := a.AppendImmutableBounded(change(immutableUnit("unit")), immutableLimits()); e == nil {
			t.Fatal("invalid batch accepted")
		}
		if !reflect.DeepEqual(before, immutableState(t, s, a)) {
			t.Fatal("invalid batch wrote")
		}
	}
}

// Claim: an error acknowledging the last directory sync is uncertain: all
// immutable files remain charged and a retry cannot treat them as absent.
func TestImmutableLostAcknowledgement(t *testing.T) {
	s, a := fresh(t, nil)
	l := immutableLimits()
	calls := 0
	a.hook = func(stage string) error {
		if stage == "immutable-directory-sync" {
			calls++
			if calls == 2 {
				return ErrUnavailable
			}
		}
		return nil
	}
	unit := immutableUnit("ack")
	if e := a.AppendImmutableBounded(unit, l); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	a.hook = nil
	before := immutableState(t, s, a)
	if len(before) != 4 {
		t.Fatal("lost complete unit", len(before))
	}
	if e := a.AppendImmutableBounded(unit, l); !errors.Is(e, ErrConflict) {
		t.Fatal("uncertain result adopted as absence", e)
	}
	if !reflect.DeepEqual(before, immutableState(t, s, a)) {
		t.Fatal("retry mutated uncertain unit")
	}
}

// Claim: a cyclic destination link and a replaced account directory refuse
// both read and append without following the replacement or altering outside bytes.
// This is a deterministic replacement fixture, not adversarial timing qualification.
func TestImmutableReplacementBoundary(t *testing.T) {
	for _, kind := range []string{"cycle", "account-link", "root-link"} {
		t.Run(kind, func(t *testing.T) {
			s, a := fresh(t, nil)
			path := filepath.Join(s.path, a.name)
			unit := immutableUnit("replacement")
			outside := filepath.Join(t.TempDir(), "outside")
			if e := os.Mkdir(outside, 0700); e != nil {
				t.Fatal(e)
			}
			canary := filepath.Join(outside, "canary")
			if e := os.WriteFile(canary, []byte("unchanged"), 0600); e != nil {
				t.Fatal(e)
			}
			if kind == "cycle" {
				if e := os.Symlink(unit[0].Name, filepath.Join(path, unit[0].Name)); e != nil {
					t.Fatal(e)
				}
			} else if kind == "root-link" {
				if e := os.Rename(s.path, s.path+"-retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(outside, s.path); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.Rename(path, path+"-retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(outside, path); e != nil {
					t.Fatal(e)
				}
			}
			if _, got, e := a.ReadImmutableBounded([]string{unit[0].Name}, immutableLimits()); !errors.Is(e, ErrUnavailable) || got != nil {
				t.Fatal("replacement read admitted", e)
			}
			if e := a.AppendImmutableBounded(unit, immutableLimits()); !errors.Is(e, ErrUnavailable) {
				t.Fatal("replacement append admitted", e)
			}
			b, e := os.ReadFile(canary)
			if e != nil || string(b) != "unchanged" {
				t.Fatal("outside mutated", e)
			}
			validS, valid := fresh(t, nil)
			_ = validS
			if e := valid.AppendImmutableBounded(unit, immutableLimits()); e != nil {
				t.Fatal("regular neighbor refused", e)
			}
		})
	}
}
