//go:build linux

package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Fixture setup waits for the kernel's full-pipe state, not a scheduling delay.
// It never drains the pipe and leaves cancellation/deadline assertions intact.
func awaitPipeFull(t *testing.T, read *os.File) {
	t.Helper()
	raw, err := read.SyscallConn()
	must(t, err)
	var probe error
	var queued, capacity int
	err = raw.Read(func(fd uintptr) bool {
		capacity, probe = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0)
		if probe != nil {
			return true
		}
		queued, probe = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
		return probe != nil || queued == capacity
	})
	must(t, err)
	must(t, probe)
	if capacity <= 0 || queued != capacity {
		t.Fatal("pipe not full", queued, capacity)
	}
}

// Fixture files carry readiness from owned child processes. Watching before the
// first read avoids a missed close/rename without imposing a startup deadline.
func awaitFixtureBytes(path string, accept func([]byte) bool) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO); err != nil {
		return err
	}
	events := make([]byte, 4096)
	for {
		image, err := os.ReadFile(path)
		if err == nil && accept(image) {
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if _, err := unix.Read(fd, events); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// Claim: an already-published marker is accepted; a mismatched marker cannot
// release the waiter, and a later matching close wakes it without polling.
func TestFixtureReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	must(t, os.WriteFile(path, []byte("earlier"), 0600))
	must(t, awaitFixtureBytes(path, func(b []byte) bool { return string(b) == "earlier" }))
	checked := make(chan struct{})
	result := make(chan error, 1)
	exited := make(chan struct{})
	defer func() { os.WriteFile(path, []byte("ready"), 0600); <-exited }()
	first := true
	go func() {
		defer close(exited)
		result <- awaitFixtureBytes(path, func(b []byte) bool {
			if first {
				first = false
				close(checked)
			}
			return string(b) == "ready"
		})
	}()
	<-checked
	select {
	case <-result:
		t.Fatal("mismatched marker released waiter")
	default:
	}
	must(t, os.WriteFile(path, []byte("ready"), 0600))
	must(t, <-result)
}
