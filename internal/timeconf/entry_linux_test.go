//go:build linux

package timeconf

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: only the three compiled operations work through SystemRunner. Unknown
// or extended argv refuses; the target receives exactly the corresponding argv.
func TestCollectorClosedOperations(t *testing.T) {
	path := executableFixture(t)
	writeConfig(t, filepath.Join(filepath.Dir(path), "scenario"), "arguments")
	for _, args := range [][]string{{"-c", "tracking"}, {"-c", "-N", "tracking"}, {"-c", "authdata", "-a"}} {
		b, err := (SystemRunner{}).Run(context.Background(), path, args, 2*time.Second, 4096)
		if err != nil || string(b) != strings.Join(args, "|") {
			t.Fatal("compiled operation changed", err, string(b))
		}
	}
	for _, args := range [][]string{nil, {"tracking"}, {"-c", "tracking", "extra"}, {"-c", "sources"}, {"-c", "authdata"}, {"-c", "-N", "tracking", "extra"}} {
		b, err := (SystemRunner{}).Run(context.Background(), path, args, time.Second, 4096)
		if err != ErrUnavailable || len(b) != 0 {
			t.Fatal("non-compiled operation accepted")
		}
	}
}

// Claim: direct reserved entry with a verified descriptor strips injected
// environment values; replacing its original pathname cannot change the opened
// executable. Invalid operations/extra input refuse even with a valid descriptor.
func TestCollectorEntryEnvironmentAndDescriptor(t *testing.T) {
	path := executableFixture(t)
	writeConfig(t, filepath.Join(filepath.Dir(path), "scenario"), "environment")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !collectorExecutable(int(file.Fd())) {
		t.Fatal("fixture descriptor refused")
	}
	pinned := filepath.Join(filepath.Dir(path), "pinned-fixture")
	if os.Rename(path, pinned) != nil {
		t.Fatal("rename failed")
	}
	if os.WriteFile(path, []byte("unexecutable replacement"), 0600) != nil {
		t.Fatal("replacement failed")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args  []string
		valid bool
	}{
		{[]string{collectorExecMarker, "tracking"}, true},
		{[]string{collectorExecMarker, "tracking", path}, false},
		{[]string{collectorExecMarker, path}, false},
		{[]string{collectorExecMarker, "unknown"}, false},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, self, tc.args...)
		cmd.ExtraFiles = []*os.File{file}
		cmd.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "TIME_ENTRY_FIXTURE=present"}
		b, runErr := cmd.CombinedOutput()
		cancel()
		if tc.valid {
			if runErr != nil || !bytes.Equal(b, []byte(goodCSV)) {
				t.Fatal("fixed environment/pinned descriptor control refused", runErr, string(b))
			}
		} else {
			failure, ok := runErr.(*exec.ExitError)
			if !ok || failure.ExitCode() != 125 || len(b) != 0 {
				t.Fatal("invalid entry reached target", runErr, string(b))
			}
		}
	}
}

// Claim: parent-side verification refuses unsafe executable files and links;
// restoring a protected native fixture succeeds without changing its contents.
func TestCollectorExecutableProtection(t *testing.T) {
	path := executableFixture(t)
	run := func(path string) error {
		_, err := (SystemRunner{}).Run(context.Background(), path, []string{"-c", "tracking"}, 2*time.Second, 4096)
		return err
	}
	if err := run(path); err != nil {
		t.Fatal("native control refused", err)
	}
	link := path + "-link"
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink failed")
	}
	if run(link) != ErrUnavailable {
		t.Fatal("executable link accepted")
	}
	if os.Chmod(path, 0777) != nil {
		t.Fatal("chmod failed")
	}
	if run(path) != ErrUnavailable {
		t.Fatal("writable executable accepted")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("chmod failed")
	}
	if run(path) != ErrUnavailable {
		t.Fatal("non-executable accepted")
	}
	if os.Chmod(path, 0500) != nil {
		t.Fatal("chmod failed")
	}
	if err := run(path); err != nil {
		t.Fatal("native recovery refused", err)
	}
}
