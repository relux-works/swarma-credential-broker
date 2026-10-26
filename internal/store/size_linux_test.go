//go:build linux

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Claim: a base64-expanded record above the read ceiling must be refused by Put,
// rather than successfully publishing bytes that Records cannot read back.
func TestOversizedWriteRegression(t *testing.T) {
	_, a := fresh(t, nil)
	v := struct {
		record
		Payload []byte `json:"payload"`
	}{record{"fixture-install", 1, "active"}, make([]byte, 786432)}
	b, err := wire.Encode(v)
	if err != nil || len(v.Payload) >= 1<<20 || len(b) <= 1<<20 {
		t.Fatal("invalid base64 expansion fixture")
	}
	err = a.Put("lease-size.json", 0, v)
	if err == nil {
		_, readErr := a.Records()
		t.Fatalf("oversized write accepted (%d encoded bytes); read-back error: %v", len(b), readErr)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong refusal: %v", err)
	}
	rows, err := a.Records()
	if err != nil || len(rows) != 0 {
		t.Fatal("refused oversized write changed records")
	}
}

type sizeWriter struct {
	name string
	file string
	put  func(*Account, string, uint64, any) error
}

func sizeWriters() []sizeWriter {
	return []sizeWriter{
		{"put", "lease-size.json", func(a *Account, name string, prior uint64, v any) error {
			return a.Put(name, prior, v)
		}},
		{"replace", "lease-size.json", func(a *Account, name string, _ uint64, v any) error {
			return replace(a.root, name, v, a.hook)
		}},
		{"append", "owner-size.json", func(a *Account, name string, _ uint64, v any) error {
			return a.Append(name, v)
		}},
	}
}

func sizedRecord(t *testing.T, n int, rev uint64, fill string) (record, []byte) {
	t.Helper()
	v := record{"fixture-install", rev, ""}
	b, err := wire.Encode(v)
	if err != nil || n < len(b) || len(fill) != 1 {
		t.Fatal("invalid size fixture")
	}
	v.State = strings.Repeat(fill, n-len(b))
	b, err = wire.Encode(v)
	if err != nil || len(b) != n {
		t.Fatal("fixture is not the exact encoded size")
	}
	return v, b
}

func watchRecordWrites(t *testing.T, path string) func() {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if _, err = unix.InotifyAddWatch(fd, path, unix.IN_CREATE|unix.IN_DELETE|unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		var events [4096]byte
		n, err := unix.Read(fd, events[:])
		if n > 0 || !errors.Is(err, unix.EAGAIN) {
			t.Fatal("refused write produced filesystem events or lost observation", n, err)
		}
	}
}

func recordListing(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// Claim: Put, replace and Append accept/read exactly 1 MiB of canonical bytes,
// including JSON whose noncanonical encoding is larger. Limit+1 preserves all
// prior bytes/listings with no write events, temporary file or durability stage.
func TestRecordSizeBoundary(t *testing.T) {
	const limit = 1 << 20 // Independent requirement: the read ceiling must not grow.
	if MaxRecordBytes != limit {
		t.Fatal("read ceiling changed")
	}
	for _, writer := range sizeWriters() {
		for _, fill := range []string{"x", "<"} {
			t.Run(writer.name+"/"+fill, func(t *testing.T) {
				var stages []string
				s, a := fresh(t, func(stage string) error { stages = append(stages, stage); return nil })
				v, encoded := sizedRecord(t, limit, 1, fill)
				if fill == "<" {
					raw, err := json.Marshal(v)
					if err != nil || len(raw) <= limit {
						t.Fatal("fixture does not shrink during canonicalization")
					}
				}
				if err := writer.put(a, writer.file, 0, v); err != nil {
					t.Fatal("exact limit refused", err)
				}
				before, err := a.Records()
				if err != nil || !bytes.Equal(before[writer.file], encoded) {
					t.Fatal("exact limit did not round trip")
				}
				path := filepath.Join(s.path, a.name)
				b, err := ReadProtected(filepath.Join(path, writer.file), a.uid)
				if err != nil || !bytes.Equal(b, encoded) {
					t.Fatal("protected reader disagrees at exact limit")
				}
				names := recordListing(t, path)
				assertNoWrites := watchRecordWrites(t, path)
				stages = nil
				name := writer.file
				if writer.name == "append" {
					name = "owner-next.json"
				}
				v, _ = sizedRecord(t, limit+1, 2, fill)
				err = writer.put(a, name, 1, v)
				if !errors.Is(err, ErrTooLarge) || !errors.Is(err, ErrUnavailable) {
					t.Fatal("limit+1 did not return the mapped size refusal", err)
				}
				assertNoWrites()
				after, err := a.Records()
				if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(names, recordListing(t, path)) || len(stages) != 0 {
					t.Fatal("refused write changed bytes, directory or durability state", err, stages)
				}
				if err = writer.put(a, name, 1, record{"fixture-install", 2, "valid successor"}); err != nil {
					t.Fatal("refusal prevented a valid successor", err)
				}
			})
		}
	}
}

type changingSizeRecord struct {
	calls int
}

func (v *changingSizeRecord) MarshalJSON() ([]byte, error) {
	v.calls++
	state := "checked"
	if v.calls > 1 {
		state = strings.Repeat("x", 1<<20)
	}
	return json.Marshal(record{"fixture-install", 1, state})
}

// Claim: every writer publishes its one checked encoding, so a changing
// Marshaler cannot substitute a larger value between validation and writing.
func TestRecordEncodingOnce(t *testing.T) {
	for _, writer := range sizeWriters() {
		t.Run(writer.name, func(t *testing.T) {
			_, a := fresh(t, nil)
			v := &changingSizeRecord{}
			if err := writer.put(a, writer.file, 0, v); err != nil {
				t.Fatal(err)
			}
			rows, err := a.Records()
			var got record
			if err != nil || wire.Decode(rows[writer.file], &got) != nil || got.State != "checked" || v.calls != 1 {
				t.Fatal("writer did not retain the checked encoding", v.calls, err)
			}
		})
	}
}

// Claim: an oversized initial identity is refused before directory/lock creation
// or sync; a readable identity at the limit also cannot publish a larger policy
// watermark. The shared guard covers initialization and installation writers.
func TestInitialRecordSizeRefusal(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "store")
	names := recordListing(t, parent)
	assertNoWrites := watchRecordWrites(t, parent)
	var stages []string
	hook := func(stage string) error { stages = append(stages, stage); return nil }
	s, err := Open(path, strings.Repeat("x", 1<<20), uint32(os.Geteuid()), true, hook)
	if s != nil {
		s.Close()
		t.Fatal("oversized identity opened")
	}
	if !errors.Is(err, ErrTooLarge) || len(stages) != 0 || !reflect.DeepEqual(names, recordListing(t, parent)) {
		t.Fatal("initial refusal changed the parent", err, stages)
	}
	assertNoWrites()
	base, err := wire.Encode(identity{"store-identity/1", "", 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, strings.Repeat("x", (1<<20)-len(base)), uint32(os.Geteuid()), true, hook)
	if err != nil {
		t.Fatal("exact-limit identity refused", err)
	}
	t.Cleanup(func() { s.Close() })
	before, err := ReadProtected(filepath.Join(path, "identity.json"), s.uid)
	if err != nil || len(before) != 1<<20 {
		t.Fatal("exact-limit identity is not readable", err)
	}
	names = recordListing(t, path)
	assertNoWrites = watchRecordWrites(t, path)
	stages = nil
	if err = s.PolicyGeneration(1, true); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized watermark accepted", err)
	}
	assertNoWrites()
	after, err := ReadProtected(filepath.Join(path, "identity.json"), s.uid)
	if err != nil || !bytes.Equal(before, after) || len(stages) != 0 || !reflect.DeepEqual(names, recordListing(t, path)) {
		t.Fatal("watermark refusal changed store state", err, stages)
	}
}
