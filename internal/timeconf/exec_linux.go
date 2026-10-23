//go:build linux

package timeconf

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

const collectorExecMarker = "--internal-timeconf-exec"

// Go's exec.Cmd has no child pre-exec hook. Re-execute the current binary to
// perform isolation before the target exec, without changing the parent's FD
// flags or running a shell. This reserved mode supplies no policy override.
func init() {
	if len(os.Args) < 2 || os.Args[1] != collectorExecMarker {
		return
	}
	if len(os.Args) < 3 || !cleanPath(os.Args[2]) {
		os.Exit(125)
	}
	runtime.LockOSThread()
	_ = execIsolatedCollector(unix.CloseRange, unix.Exec, os.Args[2], os.Args[3:])
	// Unsupported kernels, blocked syscalls and exec failures all refuse; never
	// fall back to executing a collector with inherited descriptors.
	os.Exit(125)
}

func execIsolatedCollector(closeRange func(uint, uint, uint) error, execTarget func(string, []string, []string) error, path string, args []string) error {
	// UNSHARE gives the locked thread a private descriptor table; CLOEXEC closes
	// every descriptor above stderr at the target exec. Linux 5.11+ is required.
	if err := closeRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return ErrUnavailable
	}
	return execTarget(path, append([]string{path}, args...), os.Environ())
}
