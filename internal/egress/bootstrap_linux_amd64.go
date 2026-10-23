//go:build linux && amd64

package egress

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
)

// Bootstrap is only for the separately built trusted launcher command. Candidate
// arguments begin with an absolute executable, with no ambient PATH lookup.
func Bootstrap() error {
	if len(os.Args) < 2 || !filepath.IsAbs(os.Args[1]) {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	// Prestart an explicitly unfiltered trusted transport thread. Installing a
	// listener on the sending thread first would deadlock its own sendmsg handoff.
	ready := make(chan struct{})
	send := make(chan int)
	sent := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		close(ready)
		fd := <-send
		sent <- unix.Sendmsg(3, []byte{1}, unix.UnixRights(fd), nil, 0)
		select {} // exec terminates this trusted bootstrap thread.
	}()
	<-ready
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	fd, err := install(notifyFilter(), unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	if err != nil {
		return err
	}
	send <- fd
	if err = <-sent; err != nil {
		return err
	}
	ack := make([]byte, 3)
	if n, e := unix.Read(3, ack); e != nil || n != 3 || ack[0] != 1 {
		return ErrUnavailable
	}
	// No candidate code runs until TSYNC succeeds. New threads/forks and exec
	// inherit the synchronized filter tree; failure never falls back unfiltered.
	if _, err = install(sealFilter(), unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH); err != nil {
		return err
	}
	if err = unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	for i := 0; i < int(binary.LittleEndian.Uint16(ack[1:])); i++ {
		if _, err = unix.FcntlInt(uintptr(4+i), unix.F_SETFD, 0); err != nil {
			return err
		}
	}
	unix.Close(fd)
	unix.Close(3)
	return unix.Exec(os.Args[1], os.Args[1:], os.Environ())
}
