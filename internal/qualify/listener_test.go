//go:build linux

package qualify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Claim: successful bind followed by listen ENOMEM/EIO or conversion failure
// refuses without stdout/run.json and removes the owned socket and directory.
// The shim verifies a real bound entry before faulting and must fire once.
// Public Command is the normal control; faulted runs use its native driver with
// a test-only syscall shim. The raw-close case closes the real descriptor first.
func TestReviewListenerInitializationCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, point string
		fault       error
		after       bool
	}{
		{name: "normal"},
		{name: "listen-ENOMEM", point: "listen:socket", fault: unix.ENOMEM},
		{name: "listen-EIO", point: "listen:socket", fault: unix.EIO},
		{name: "conversion-ENOSPC", point: "listener:socket", fault: unix.ENOSPC},
		{name: "conversion-after-EIO", point: "listener:socket", fault: unix.EIO, after: true},
		{name: "raw-close-EIO", point: "close:raw-socket", fault: unix.EIO, after: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, c, evidence := setup(t)
			args := []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}
			var output bytes.Buffer
			var status int
			if tc.point == "" {
				status = Command(context.Background(), args, path, []string{}, &output)
			} else {
				shim := &fixtureCommandSyscalls{name: tc.point, err: tc.fault, after: tc.after}
				shim.before = func() error {
					entries, e := os.ReadDir(evidence)
					if e != nil || len(entries) != 1 || !entries[0].IsDir() {
						t.Fatal("fault did not follow private directory creation")
					}
					st, e := os.Lstat(filepath.Join(evidence, entries[0].Name(), socketName))
					if e != nil || st.Mode()&os.ModeSocket == 0 {
						t.Fatal("fault did not follow successful bind")
					}
					return nil
				}
				status = withFixtureCommandSyscalls(path, shim).run(context.Background(), args, &output)
				if shim.hits != 1 {
					t.Fatalf("initialization fault hits=%d want 1", shim.hits)
				}
			}
			if status != 69 {
				t.Fatalf("command returned %d; want 69", status)
			}
			_, reportErr := os.Lstat(filepath.Join(evidence, "run.json"))
			if tc.point != "" {
				if output.Len() != 0 || !os.IsNotExist(reportErr) {
					t.Fatal("initialization failure produced a pending report")
				}
			} else {
				var r report
				if reportErr != nil || wire.Decode(bytes.TrimSpace(output.Bytes()), &r) != nil || r.Disposition != "pending" || len(r.Cases) != len(qualification.RequiredCases()) {
					t.Fatal("normal pending report missing")
				}
				b, e := os.ReadFile(filepath.Join(evidence, "run.json"))
				if e != nil || !bytes.Equal(b, bytes.TrimSpace(output.Bytes())) {
					t.Fatal("normal pending report not persisted")
				}
			}
			requireNoReservation(t, evidence)
		})
	}
}

// Claim: a failure after identity verification preserves a replacement and
// returns its original listen error together with unavailable/identity mismatch.
// Pre-bind uncertainty still preserves an empty unverified directory in
// TestPrivateSocketUnverifiedDirectory.
func TestListenerInitializationReplacement(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	shim := &fixtureCommandSyscalls{name: "listen:socket", err: unix.EIO}
	var replacement string
	shim.before = func() error {
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 1 {
			t.Fatal("reservation directory missing")
		}
		replacement = filepath.Join(dir, entries[0].Name(), socketName)
		if e := os.Remove(replacement); e != nil {
			t.Fatal(e)
		}
		return os.WriteFile(replacement, []byte("replacement"), 0600)
	}
	s, e := (driver{ops: shim}).reserve(context.Background(), dir, qualification.Hash([]byte("fixture candidate")))
	if s != nil || !errors.Is(e, qualification.ErrUnavailable) || !errors.Is(e, unix.EIO) || !errors.Is(e, unix.ESTALE) || shim.hits != 1 {
		t.Fatalf("replacement not reported: err=%v hits=%d", e, shim.hits)
	}
	b, e := os.ReadFile(replacement)
	if e != nil || string(b) != "replacement" {
		t.Fatal("replacement removed")
	}
}
