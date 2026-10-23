//go:build linux

package timeconf

import (
	"os"
	"runtime"
	"slices"

	"golang.org/x/sys/unix"
)

const collectorExecMarker = "--internal-timeconf-exec"
const collectorDescriptorPath = "/proc/self/fd/3"

func collectorEnvironment() []string { return []string{"LC_ALL=C", "LANG=C", "TZ=UTC"} }

func collectorArguments(operation string) ([]string, bool) {
	switch operation {
	case "tracking":
		return []string{"-c", "tracking"}, true
	case "tracking-names":
		return []string{"-c", "-N", "tracking"}, true
	case "authdata":
		return []string{"-c", "authdata", "-a"}, true
	default:
		return nil, false
	}
}
func collectorOperation(args []string) (string, bool) {
	for _, operation := range []string{"tracking", "tracking-names", "authdata"} {
		expected, _ := collectorArguments(operation)
		if slices.Equal(args, expected) {
			return operation, true
		}
	}
	return "", false
}

// CollectorEntry must be called by an embedding executable before its argument
// parser, and by a test executable's TestMain if it exercises SystemRunner.
// Importing this package never dispatches commands. The reserved entry accepts
// only one compiled operation and a parent-verified executable at descriptor 3.
// It accepts no executable pathname, arbitrary arguments or environment input.
func CollectorEntry() {
	if len(os.Args) < 2 || os.Args[1] != collectorExecMarker {
		return
	}
	if len(os.Args) != 3 {
		os.Exit(125)
	}
	args, ok := collectorArguments(os.Args[2])
	if !ok || !collectorExecutable(3) {
		os.Exit(125)
	}
	runtime.LockOSThread()
	_ = execIsolatedCollector(unix.CloseRange, unix.Exec, collectorDescriptorPath, args)
	// Missing descriptors, unavailable isolation and exec failures never fall
	// back to the embedding command or to an unverified executable path.
	os.Exit(125)
}

func collectorExecutable(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Mode&0111 != 0 && st.Mode&0022 == 0 && (st.Uid == 0 || st.Uid == uint32(os.Geteuid()))
}

func execIsolatedCollector(closeRange func(uint, uint, uint) error, execTarget func(string, []string, []string) error, path string, args []string) error {
	// UNSHARE confines flag changes to the locked thread's descriptor table.
	// Exec through the fixed proc descriptor path pins the verified file, like
	// the /proc-based fexecve implementation. CLOEXEC removes even descriptor 3
	// from the final native executable; scripts fail closed. Linux 5.11+ required.
	if err := closeRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return ErrUnavailable
	}
	return execTarget(path, append([]string{"chronyc"}, args...), collectorEnvironment())
}
