//go:build linux

package qualification

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// syscallFault and its only constructor compile in tests, not the command.
// Each injection executes at one real storage operation boundary, before the
// kernel call; an unvisited fault is a failing test rather than a skipped case.
type syscallFault struct {
	trace []string
	at    int
	name  string
	err   error
	hits  int
}

func (s *syscallFault) run(name string, call func() error) error {
	s.trace = append(s.trace, name)
	if len(s.trace) == s.at || s.name == name {
		s.hits++
		if s.err != nil {
			return s.err
		}
	}
	return call()
}
func withFixtureSyscalls(r Repository, s *syscallFault) Repository { r.ops = s; return r }
func sealFixtureList(t *testing.T, dir string, list []byte) {
	t.Helper()
	b, e := wire.Encode(activation{Kind: "qualification-activation/1", ListSHA256: Hash(list)})
	check(t, e)
	check(t, os.WriteFile(filepath.Join(dir, "activation.json"), b, 0600))
}
func resetPublication(t *testing.T, r Repository, rec Record, existing bool) {
	t.Helper()
	b, e := wire.Encode(rec)
	check(t, e)
	for _, name := range []string{"in-progress", "pending-list", "pending-activation", "activation.json", "qualified.json", "record-" + Hash(b) + ".json"} {
		e = os.Remove(filepath.Join(r.Path, name))
		if e != nil && !os.IsNotExist(e) {
			check(t, e)
		}
	}
	if existing {
		check(t, os.WriteFile(filepath.Join(r.Path, "record-"+Hash(b)+".json"), b, 0600))
		list, e := wire.Encode(List{Kind: "qualified-list/1", Entries: []Entry{{rec.Identity, Hash(b)}}})
		check(t, e)
		check(t, os.WriteFile(filepath.Join(r.Path, "qualified.json"), list, 0600))
		// Exercise invalidating an old activation without granting pre-test authority.
		check(t, os.WriteFile(filepath.Join(r.Path, "activation.json"), []byte("{}"), 0600))
	}
}

// Claim: only ENOENT admits an absent fence. Present fences and injected EIO or
// EACCES at that lookup refuse with unavailable; each named shim must fire once.
func TestReviewFenceStatFailure(t *testing.T) {
	for _, mode := range []string{"EIO", "EACCES", "present", "absent"} {
		t.Run(mode, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			check(t, r.Publish(context.Background(), rec))
			s := &syscallFault{}
			if mode == "present" || mode == "EIO" {
				check(t, os.WriteFile(filepath.Join(r.Path, "in-progress"), []byte("stale"), 0600))
			}
			if mode == "EIO" || mode == "EACCES" {
				s.name = "lookup:in-progress"
				s.err = unix.EIO
				if mode == "EACCES" {
					s.err = unix.EACCES
				}
			}
			test := withFixtureSyscalls(r, s)
			_, _, e := test.Read(context.Background())
			if mode == "absent" {
				check(t, e)
			} else if !errors.Is(e, ErrUnavailable) {
				t.Fatalf("fence proof unavailable, got %v", e)
			}
			if s.err != nil && s.hits != 1 {
				t.Fatalf("fault not hit exactly once: %d", s.hits)
			}
		})
	}
}

// Claim: the four original review flush faults, especially after fence unlink,
// return an error and cannot immediately admit a read; the no-fault control admits.
func TestReviewSyncFailure(t *testing.T) {
	for _, point := range []string{"file:in-progress", "evidence-directory", "file:pending-list", "fence-removal-directory", "control"} {
		t.Run(point, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			s := &syscallFault{}
			if point != "control" {
				s.name = "fsync:" + point
				s.err = unix.EIO
			}
			err := withFixtureSyscalls(r, s).Publish(context.Background(), rec)
			if point == "control" {
				check(t, err)
				_, _, e := r.Read(context.Background())
				check(t, e)
			} else {
				if s.hits != 1 || err == nil {
					t.Fatalf("required flush fault not observed: hits=%d err=%v", s.hits, err)
				}
				reject(t, r)
			}
		})
	}
}

func errorsFor(operation string) []error {
	kind, _, _ := strings.Cut(operation, ":")
	out := []error{unix.EIO}
	switch kind {
	case "lookup", "open", "open-create", "mkdir", "rename", "unlink":
		out = append(out, unix.EACCES)
	}
	switch kind {
	case "open-create", "mkdir", "write", "fsync", "rename":
		out = append(out, unix.ENOSPC)
	}
	return out
}

// Claim: each reached occurrence of lookup/open/fstat/read/write/fsync/rename/
// unlink/flock/mkdir fails closed for its applicable EIO/EACCES/ENOSPC errors.
// Publication starts unqualified; existing-list mode includes an old record and
// invalid activation, not an already-authorized tuple. A failed Read does not
// mutate valid authority. Before/after positive controls rule out reject-all.
func TestStorageErrorMatrix(t *testing.T) {
	for _, route := range []string{"publish-new", "publish-existing", "read"} {
		t.Run(route, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			existing := route == "publish-existing"
			resetPublication(t, r, rec, existing)
			invoke := func(test Repository) error {
				if route == "read" {
					_, _, e := test.Read(context.Background())
					return e
				}
				return test.Publish(context.Background(), rec)
			}
			if route == "read" {
				check(t, r.Publish(context.Background(), rec))
			}
			baseline := &syscallFault{}
			check(t, invoke(withFixtureSyscalls(r, baseline)))
			_, _, e := r.Read(context.Background())
			check(t, e)
			if len(baseline.trace) == 0 {
				t.Fatal("no syscall observations")
			}
			total := 0
			for i, operation := range baseline.trace {
				for _, fault := range errorsFor(operation) {
					t.Run(fmt.Sprintf("%04d/%s/%s", i, operation, fault), func(t *testing.T) {
						if route != "read" {
							resetPublication(t, r, rec, existing)
						}
						s := &syscallFault{at: i + 1, err: fault}
						err := invoke(withFixtureSyscalls(r, s))
						if s.hits != 1 || len(s.trace) != i+1 || s.trace[i] != operation {
							t.Fatalf("fault did not reach expected syscall: hits=%d", s.hits)
						}
						if err == nil {
							t.Fatal("injected syscall error reported success")
						}
						if route == "read" {
							if !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrInvalid) {
								t.Fatal("unstructured read refusal")
							}
							_, _, e := r.Read(context.Background())
							check(t, e)
						} else {
							reject(t, r)
						}
						total++
					})
				}
			}
			if route != "read" {
				resetPublication(t, r, rec, existing)
				check(t, invoke(r))
			}
			_, _, e = r.Read(context.Background())
			check(t, e)
			t.Logf("matrix operations=%d injected_errors=%d", len(baseline.trace), total)
		})
	}
}

// Claim: a complete protected activation for the exact list is necessary;
// malformed/missing/substituted activation or a prepared transaction refuses.
func TestActivationState(t *testing.T) {
	for _, mode := range []string{"missing", "kind", "digest", "null", "duplicate", "mode", "symlink", "pending", "valid"} {
		t.Run(mode, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			check(t, r.Publish(context.Background(), rec))
			path := filepath.Join(r.Path, "activation.json")
			switch mode {
			case "missing":
				check(t, os.Remove(path))
			case "kind":
				check(t, os.WriteFile(path, []byte(`{"kind":"other/1","list_sha256":"`+Hash(nil)+`"}`), 0600))
			case "digest":
				check(t, os.WriteFile(path, []byte(`{"kind":"qualification-activation/1","list_sha256":"`+Hash(nil)+`"}`), 0600))
			case "null":
				check(t, os.WriteFile(path, []byte(`{"kind":"qualification-activation/1","list_sha256":null}`), 0600))
			case "duplicate":
				b, e := os.ReadFile(path)
				check(t, e)
				b = append([]byte(`{"kind":"qualification-activation/1",`), b[1:]...)
				check(t, os.WriteFile(path, b, 0600))
			case "mode":
				check(t, os.Chmod(path, 0644))
			case "symlink":
				check(t, os.Rename(path, path+".original"))
				check(t, os.Symlink(path+".original", path))
			case "pending":
				check(t, os.WriteFile(filepath.Join(r.Path, "pending-activation"), []byte("prepared"), 0600))
			}
			if mode == "valid" {
				_, _, e := r.Read(context.Background())
				check(t, e)
			} else {
				reject(t, r)
			}
		})
	}
}
