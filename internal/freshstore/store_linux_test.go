//go:build linux

package freshstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type testFixture struct {
	f            *Fixture
	a            *store.Account
	path, canary string
}

func limits() Limits {
	return Limits{1 << 20, 8 << 20, 64, 4 << 20, 8, 786432, 8 << 20, 64 << 20, 128 << 20}
}
func binding() Binding {
	return Binding{"i", "s", strings.Repeat("0", 64), "g:" + strings.Repeat("1", 64)}
}
func testHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fixture(t *testing.T, l Limits) testFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "registry")
	s, e := store.Open(root, "i", uint32(os.Geteuid()), true, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	a, e := s.Account("content", true)
	if e != nil {
		t.Fatal(e)
	}
	f, e := NewFixture(a, l)
	if e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256([]byte("content"))
	canary := filepath.Join(base, "committed.json")
	if e = os.WriteFile(canary, []byte("unchanged-root"), 0600); e != nil {
		t.Fatal(e)
	}
	return testFixture{f, a, filepath.Join(root, "account-"+hex.EncodeToString(d[:])), canary}
}
func state(t *testing.T, f testFixture) map[string]string {
	t.Helper()
	files, e := os.ReadDir(f.path)
	if e != nil {
		t.Fatal(e)
	}
	s := map[string]string{}
	for _, n := range files {
		b, e := os.ReadFile(filepath.Join(f.path, n.Name()))
		if e != nil {
			t.Fatal(e)
		}
		s[n.Name()] = string(b)
	}
	b, e := os.ReadFile(f.canary)
	if e != nil {
		t.Fatal(e)
	}
	s["external-canary"] = string(b)
	return s
}
func expected(s Stored) Expected { return Expected{binding(), Schema, s.ManifestDigest, s.Inventory} }
func inputA() []Input            { return []Input{{"a", "blob", []byte("x")}} }
func twoInputs() []Input         { return []Input{{"a", "blob", []byte("x")}, {"b", "blob", []byte("yz")}} }
func literalRef() Ref {
	return Ref{literalObjectADigest, uint64(len(literalObjectA)), "blob", "a", 1, testHash([]byte("x"))}
}

// Claim: real Retain and ReadExact produce the frozen complete encoded bytes,
// identities and independent inventory, and returned raw copies never alias storage.
func TestFreshFrozenVectors(t *testing.T) {
	for _, two := range []bool{false, true} {
		f := fixture(t, limits())
		in := inputA()
		obj, man, d := literalObjectA, literalManifestA, literalManifestADigest
		if two {
			in = twoInputs()
			man = literalManifestAb
			d = literalManifestAbDigest
		}
		s, e := f.f.Retain(binding(), in)
		if e != nil {
			t.Fatal(e)
		}
		if s.ManifestDigest != d || s.Inventory[0] != literalRef() {
			t.Fatalf("frozen identity differs: %+v", s)
		}
		independent := []Ref{literalRef()}
		if two {
			independent = append(independent, Ref{literalObjectBDigest, 300, "blob", "b", 2, testHash([]byte("yz"))})
		}
		if !reflect.DeepEqual(s.Inventory, independent) {
			t.Fatal("complete frozen inventory differs")
		}

		_, raw, e := f.a.ReadImmutableBounded([]string{objectName(literalObjectADigest), manifestName(d)}, limits().store())
		if e != nil || string(raw[0]) != obj || string(raw[1]) != man {
			t.Fatal("frozen bytes differ", e)
		}
		got, e := f.f.ReadExact(expected(s))
		if e != nil || !bytes.Equal(got[0], []byte("x")) {
			t.Fatal(e)
		}
		if two && (len(got) != 2 || string(got[1]) != "yz") {
			t.Fatal("second raw output differs")
		}
		got[0][0] = 'q'
		again, e := f.f.ReadExact(expected(s))
		if e != nil || string(again[0]) != "x" {
			t.Fatal("raw output aliases", e)
		}
		c, e := os.ReadFile(f.canary)
		if e != nil || string(c) != "unchanged-root" {
			t.Fatal("current root changed")
		}
	}
}

// Claim: the inclusive encoded-record boundary passes with exact frozen hash;
// R+1 and base64 expansion refuse before any write, despite raw bytes fitting.
func TestFreshEncodedBoundary(t *testing.T) {
	f := fixture(t, limits())
	raw := bytes.Repeat([]byte("x"), boundaryRaw)
	before := state(t, f)
	for _, in := range [][]Input{{{boundaryName + "a", "blob", raw}}, {{"a", "blob", bytes.Repeat([]byte("x"), 786432)}}} {
		if _, e := f.f.Retain(binding(), in); !errors.Is(e, ErrLimit) {
			t.Fatal("encoded expansion accepted", e)
		}
		if !reflect.DeepEqual(before, state(t, f)) {
			t.Fatal("oversize wrote a prefix")
		}
	}
	s, e := f.f.Retain(binding(), []Input{{boundaryName, "blob", raw}})
	if e != nil {
		t.Fatal("inclusive boundary refused", e)
	}
	if s.Inventory[0].Encoded != 1<<20 || s.Inventory[0].Digest != boundaryDigest {
		t.Fatal("boundary identity differs")
	}
	got, e := f.f.ReadExact(expected(s))
	if e != nil || !bytes.Equal(got[0], raw) {
		t.Fatal("boundary read failed", e)
	}
}

// Claim: identity is SHA256 of exact raw bytes, including line endings,
// distinct Unicode spellings and binary data;
// the public Retain path must not normalize even one byte before hashing.
func TestFreshRawIdentity(t *testing.T) {
	for _, raw := range [][]byte{[]byte("x"), []byte("x\n"), []byte("x\r"), []byte("x\r\n"), []byte("é"), []byte("e\u0301"), {0xff, 0x00, 0x7f}} {
		f := fixture(t, limits())
		s, e := f.f.Retain(binding(), []Input{{"a", "blob", raw}})
		if e != nil || s.Inventory[0].RawDigest != testHash(raw) {
			t.Fatal("raw identity normalized", e)
		}
		got, e := f.f.ReadExact(expected(s))
		if e != nil || !bytes.Equal(got[0], raw) {
			t.Fatal(e)
		}
	}
}

// Claim: inventory is nonempty, complete, strictly ordered and unique before
// Retain writes; invalid input cannot change even the external root canary.
func TestFreshInventoryOrder(t *testing.T) {
	f := fixture(t, limits())
	before := state(t, f)
	for _, in := range [][]Input{nil, {{"a", "blob", []byte("x")}, {"a", "blob", []byte("y")}}, {{"b", "blob", []byte("x")}, {"a", "blob", []byte("y")}}} {
		if _, e := f.f.Retain(binding(), in); !errors.Is(e, ErrInvalid) {
			t.Fatal("inventory order admitted", e)
		}
		if !reflect.DeepEqual(before, state(t, f)) {
			t.Fatal("invalid inventory wrote")
		}
	}
	if _, e := f.f.Retain(binding(), twoInputs()); e != nil {
		t.Fatal("ordered neighbor refused", e)
	}
}
func storedBytes(t *testing.T, f testFixture, obj, man []byte, ref Ref) Expected {
	t.Helper()
	if e := f.a.AppendImmutableBounded([]store.EncodedImmutable{{Name: objectName(testHash(obj)), Bytes: obj}, {Name: manifestName(testHash(man)), Bytes: man}}, limits().store()); e != nil {
		t.Fatal(e)
	}
	return Expected{binding(), Schema, testHash(man), []Ref{ref}}
}

// Claim: malformed persisted canonical grammar refuses through ReadExact, not
// only a parser helper; every table row has an accepting exact-byte neighbor.
func TestFreshCanonical(t *testing.T) {
	mutations := map[string]func(string) string{
		"trailing":      func(s string) string { return s + "\n" },
		"CRLF":          func(s string) string { return s + "\r\n" },
		"DEL":           func(s string) string { return strings.Replace(s, `"scope":"s"`, "\"scope\":\"s\x7f\"", 1) },
		"unicode-space": func(s string) string { return "\u00a0" + s },
		"comment":       func(s string) string { return s + "//comment" },
		"invalid-utf8":  func(s string) string { return s + "\xff" }, "BOM": func(s string) string { return "\xef\xbb\xbf" + s }, "CR": func(s string) string { return s + "\r" }, "escape": func(s string) string {
			return strings.Replace(s, `"installation_id":"i"`, `"installation_id":"\u0069"`, 1)
		}, "unknown": func(s string) string { return s[:len(s)-1] + `,"z":1}` }, "duplicate": func(s string) string { return s[:len(s)-1] + `,"scope":"s"}` }, "zero-number": func(s string) string { return strings.Replace(s, `"revision":1`, `"revision":01`, 1) }, "overflow": func(s string) string { return strings.Replace(s, `"raw":1`, `"raw":18446744073709551616`, 1) }, "array-comma": func(s string) string { return strings.Replace(s, `],"installation_id"`, `,],"installation_id"`, 1) }, "control": func(s string) string { return strings.Replace(s, `"scope":"s"`, "\"scope\":\"s\x01\"", 1) }}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			f := fixture(t, limits())
			w := storedBytes(t, f, []byte(literalObjectA), []byte(mut(literalManifestA)), literalRef())
			before := state(t, f)
			raw, e := f.f.ReadExact(w)
			if !errors.Is(e, ErrInvalid) || raw != nil {
				t.Fatalf("noncanonical admitted: %v", e)
			}
			if !reflect.DeepEqual(before, state(t, f)) {
				t.Fatal("read refusal mutated")
			}
			valid := fixture(t, limits())
			s, e := valid.f.Retain(binding(), inputA())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = valid.f.ReadExact(expected(s)); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Claim: a complete exact request binds all headers and inventory fields. A
// modified retained manifest must not be reinterpreted using a trusted bool.
func TestFreshExactInventory(t *testing.T) {
	mods := map[string]func([]byte) []byte{
		"scope": func(b []byte) []byte { return bytes.Replace(b, []byte(`"scope":"s"`), []byte(`"scope":"t"`), 1) }, "pin": func(b []byte) []byte {
			return bytes.Replace(b, []byte(strings.Repeat("0", 64)), []byte(strings.Repeat("2", 64)), 1)
		}, "prev": func(b []byte) []byte {
			return bytes.Replace(b, []byte("g:"+strings.Repeat("1", 64)), []byte("g:"+strings.Repeat("2", 64)), 1)
		}, "raw-length": func(b []byte) []byte { return bytes.Replace(b, []byte(`"raw":1`), []byte(`"raw":2`), 1) }, "encoded-length": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"encoded":`+strconvU(uint64(len(literalObjectA)))), []byte(`"encoded":1`), 1)
		}, "raw-digest": func(b []byte) []byte {
			return bytes.Replace(b, []byte(testHash([]byte("x"))), []byte(strings.Repeat("f", 64)), 1)
		}, "omitted": func(b []byte) []byte { return manifestBytes(binding(), nil) }, "extra": func(b []byte) []byte {
			return manifestBytes(binding(), []Ref{literalRef(), {strings.Repeat("3", 64), 10, "blob", "b", 1, strings.Repeat("4", 64)}})
		}, "duplicate": func(b []byte) []byte { return manifestBytes(binding(), []Ref{literalRef(), literalRef()}) }}
	for name, mut := range mods {
		t.Run(name, func(t *testing.T) {
			f := fixture(t, limits())
			w := storedBytes(t, f, []byte(literalObjectA), mut([]byte(literalManifestA)), literalRef())
			if raw, e := f.f.ReadExact(w); !errors.Is(e, ErrInvalid) || raw != nil {
				t.Fatalf("bad inventory admitted: %v", e)
			}
		})
	}
	f := fixture(t, limits())
	s, e := f.f.Retain(binding(), twoInputs())
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Expected){func(w *Expected) { w.Schema = "other" }, func(w *Expected) { w.Installation = "j" }, func(w *Expected) { w.Scope = "t" }, func(w *Expected) { w.Pin = strings.Repeat("2", 64) }, func(w *Expected) { w.Previous = "" }, func(w *Expected) { w.Inventory = w.Inventory[:1] }, func(w *Expected) { w.Inventory[0], w.Inventory[1] = w.Inventory[1], w.Inventory[0] }} {
		w := expected(s)
		w.Inventory = append([]Ref(nil), s.Inventory...)
		change(&w)
		if raw, e := f.f.ReadExact(w); !errors.Is(e, ErrInvalid) || raw != nil {
			t.Fatal("wrong independent request admitted", e)
		}
	}
	if _, e = f.f.ReadExact(expected(s)); e != nil {
		t.Fatal(e)
	}
}
func strconvU(n uint64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

// Claim: strict base64 spelling, exact object lengths/digests and raw digests
// remain necessary even when a manifest is otherwise canonical and complete.
func TestFreshObjectMismatch(t *testing.T) {
	for _, name := range []string{"padding", "newline", "scope", "length", "encoded-digest", "raw-digest"} {
		t.Run(name, func(t *testing.T) {
			obj := []byte(literalObjectA)
			r := literalRef()
			switch name {
			case "padding":
				obj = bytes.Replace(obj, []byte("eA=="), []byte("eB=="), 1)
			case "newline":
				obj = bytes.Replace(obj, []byte("eA=="), []byte("eA=\n="), 1)
			case "scope":
				obj = bytes.Replace(obj, []byte(`"scope":"s"`), []byte(`"scope":"t"`), 1)
			}
			r.Digest = testHash(obj)
			r.Encoded = uint64(len(obj))
			if name == "length" {
				r.Raw = 2
			}
			if name == "raw-digest" {
				r.RawDigest = strings.Repeat("f", 64)
			}
			f := fixture(t, limits())
			man := manifestBytes(binding(), []Ref{r})
			w := storedBytes(t, f, obj, man, r)
			if name == "encoded-digest" {
				path := filepath.Join(f.path, objectName(r.Digest))
				if e := os.WriteFile(path, []byte(literalObjectB), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if raw, e := f.f.ReadExact(w); !errors.Is(e, ErrInvalid) || raw != nil {
				t.Fatal("object mismatch admitted", e)
			}
		})
	}
}

// Claim: every required bound rejects zero/overflow, and actual unit/raw/read/
// memory/work/count bounds refuse with unchanged state, while sufficient limits pass.
func TestFreshFiniteAdmission(t *testing.T) {
	f := fixture(t, limits())
	for _, field := range []string{"RecordBytes", "RetainedBytes", "RetainedRecords", "UnitBytes", "Dependencies", "RawObjectBytes", "ReadBytes", "MemoryBytes", "WorkBytes"} {
		bad := limits()
		reflect.ValueOf(&bad).Elem().FieldByName(field).SetUint(0)
		if _, e := NewFixture(f.a, bad); !errors.Is(e, ErrInvalid) {
			t.Fatalf("zero %s accepted: %v", field, e)
		}
	}
	bad := limits()
	bad.RetainedBytes = ^uint64(0)
	if _, e := NewFixture(f.a, bad); !errors.Is(e, ErrInvalid) {
		t.Fatal("overflow limit accepted", e)
	}
	for _, field := range []string{"UnitBytes", "Dependencies", "RawObjectBytes", "MemoryBytes", "WorkBytes", "ReadBytes"} {
		t.Run(field, func(t *testing.T) {
			l := limits()
			switch field {
			case "UnitBytes":
				l.UnitBytes = 1
			case "Dependencies":
				l.Dependencies = 1
			case "RawObjectBytes":
				l.RawObjectBytes = 1
			case "MemoryBytes":
				l.MemoryBytes = 4*512 + 512*(l.RetainedRecords+4) + 4096
			case "WorkBytes":
				l.WorkBytes = 8*(l.RetainedBytes+512) + 1024*(l.RetainedRecords+4)
			case "ReadBytes":
				l.ReadBytes = 512
			}
			g := fixture(t, l)
			before := state(t, g)
			s, e := g.f.Retain(binding(), twoInputs())
			if field == "ReadBytes" {
				if e != nil {
					t.Fatal(e)
				}
				if raw, e := g.f.ReadExact(expected(s)); !errors.Is(e, ErrLimit) || raw != nil {
					t.Fatal("read cap ignored", e)
				}
			} else {
				if !errors.Is(e, ErrLimit) {
					t.Fatal("finite bound ignored", e)
				}
				if !reflect.DeepEqual(before, state(t, g)) {
					t.Fatal("finite refusal wrote")
				}
			}
		})
	}
	if _, ok := add(^uint64(0), 1); ok {
		t.Fatal("checked add overflow")
	}
	if _, ok := mul(^uint64(0), 2); ok {
		t.Fatal("checked multiply overflow")
	}
}

// Claim: aggregate equality is inclusive; retained controls, zero-byte and pending
// files consume their full count/length and capacity refusal leaves no new root.
func TestFreshAggregateBoundary(t *testing.T) {
	for _, mode := range []string{"bytes", "count", "pending", "zero"} {
		t.Run(mode, func(t *testing.T) {
			l := limits()
			l.Dependencies = 1
			g := fixture(t, l)
			extra := uint64(0)
			count := uint64(0)
			if mode == "pending" || mode == "zero" {
				name := objectName(strings.Repeat("f", 64))
				raw := []byte{}
				if mode == "pending" {
					name = "pending-" + name
					raw = []byte("xx")
				}
				if e := os.WriteFile(filepath.Join(g.path, name), raw, 0600); e != nil {
					t.Fatal(e)
				}
				extra = uint64(len(raw))
				count = 1
			}
			snap, _, e := g.a.ReadImmutableBounded(nil, l.store())
			if e != nil {
				t.Fatal(e)
			}
			unit := uint64(len(literalObjectA) + len(literalManifestA))
			l.UnitBytes = unit
			l.RetainedBytes = snap.Bytes + unit
			l.RetainedRecords = 4 + count
			bad := l
			if mode == "bytes" || mode == "pending" {
				bad.RetainedBytes--
			} else {
				bad.RetainedRecords--
			}
			limited, e := NewFixture(g.a, bad)
			if e != nil {
				t.Fatal(e)
			}
			before := state(t, g)
			if _, e = limited.Retain(binding(), inputA()); !errors.Is(e, ErrLimit) {
				t.Fatalf("aggregate ignored (%d): %v", extra, e)
			}
			if !reflect.DeepEqual(before, state(t, g)) {
				t.Fatal("aggregate refusal mutated")
			}
			valid, e := NewFixture(g.a, l)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = valid.Retain(binding(), inputA()); e != nil {
				t.Fatal("equality refused", e)
			}
		})
	}
}

// Claim: genesis is explicit; a named predecessor must be retained and match
// schema/scope/pin, without implying current-root authority or recursive history.
func TestFreshPredecessor(t *testing.T) {
	g := fixture(t, limits())
	b := binding()
	b.Previous = ""
	if _, e := g.f.Retain(b, inputA()); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	b.Previous = "m:" + strings.Repeat("e", 64)
	if _, e := g.f.Retain(b, inputA()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing predecessor became genesis", e)
	}
	s, e := g.f.Retain(binding(), inputA())
	if e != nil {
		t.Fatal(e)
	}
	b = binding()
	b.Previous = "m:" + s.ManifestDigest
	b.Scope = "t"
	if _, e = g.f.Retain(b, inputA()); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	b.Scope = "s"
	next, e := g.f.Retain(b, inputA())
	if e != nil {
		t.Fatal(e)
	}
	w := Expected{b, Schema, next.ManifestDigest, next.Inventory}
	if _, e = g.f.ReadExact(w); e != nil {
		t.Fatal(e)
	}
}

// Claim: selected actual bytes plus the fixed controls fit exactly at 1290;
// one byte less refuses without partial output or changing persisted state.
func TestFreshReadBytesEquality(t *testing.T) {
	for _, n := range []uint64{1290, 1289} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			l := limits()
			l.ReadBytes = n
			f := fixture(t, l)
			s, e := f.f.Retain(binding(), inputA())
			if e != nil {
				t.Fatal(e)
			}
			before := state(t, f)
			got, e := f.f.ReadExact(expected(s))
			if n == 1290 {
				if e != nil || len(got) != 1 || string(got[0]) != "x" {
					t.Fatalf("exact read boundary: %v %q", e, got)
				}
			} else if !errors.Is(e, ErrLimit) || got != nil {
				t.Fatalf("below boundary: %v %q", e, got)
			}
			if !reflect.DeepEqual(before, state(t, f)) {
				t.Fatal("read changed persisted state")
			}
		})
	}
}

// Claim: exact logical buffer/work limits admit the small unit, and one unit
// less refuses before any immutable create; this is not an RSS measurement.
func TestFreshCostEquality(t *testing.T) {
	for _, field := range []string{"MemoryBytes", "WorkBytes"} {
		t.Run(field, func(t *testing.T) {
			l := limits()
			required := uint64(4*(778+512) + 4 + 512*(l.RetainedRecords+1+4) + 4096)
			if field == "WorkBytes" {
				required = 8*(l.RetainedBytes+778+512+1) + 1024*(l.RetainedRecords+1+4)
			}
			for _, n := range []uint64{required - 1, required} {
				reflect.ValueOf(&l).Elem().FieldByName(field).SetUint(n)
				f := fixture(t, l)
				before := state(t, f)
				_, e := f.f.Retain(binding(), inputA())
				if n == required {
					if e != nil {
						t.Fatal("exact cost refused", e)
					}
				} else {
					if !errors.Is(e, ErrLimit) {
						t.Fatal("undersized cost accepted", e)
					}
					if !reflect.DeepEqual(before, state(t, f)) {
						t.Fatal("cost refusal wrote")
					}
				}
			}
		})
	}
}

// Claim: the closed ASCII identifier grammar rejects case variants, Unicode
// normalization pairs and path syntax before retention; ordered ASCII remains valid.
func TestFreshIdentifierGrammar(t *testing.T) {
	f := fixture(t, limits())
	before := state(t, f)
	for _, name := range []string{"A", "é", "e\u0301", "../a", "a/b", "a\\b", "a\x7f", "a\n", strings.Repeat("a", 65)} {
		if _, e := f.f.Retain(binding(), []Input{{name, "blob", []byte("x")}}); !errors.Is(e, ErrInvalid) {
			t.Fatalf("name accepted %q: %v", name, e)
		}
		if !reflect.DeepEqual(before, state(t, f)) {
			t.Fatal("invalid name mutated state")
		}
	}
	if _, e := f.f.Retain(binding(), twoInputs()); e != nil {
		t.Fatal("ASCII positive refused", e)
	}
}
