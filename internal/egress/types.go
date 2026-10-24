// Package egress confines accidental network use by a cooperative candidate.
// It is not a sandbox for hostile executables; see docs/egress-boundary.md.
package egress

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

var ErrUnavailable = errors.New("egress boundary unavailable")
var ErrEvidenceLimit = errors.New("egress evidence limit reached")

// Policy permits exact destination ports and exact filesystem Unix paths.
// An empty policy permits no addressed network traffic.
type Policy struct {
	Ports     []uint16
	UnixPaths []string
	MaxEvents int
}

// Config names a separately built trusted launcher and the fixed candidate argv.
// Env is explicit, never inherited. ExtraFiles become candidate descriptors 4+;
// descriptor 3 is private bootstrap transport and is closed before candidate exec.
// Only regular files and pipes may be inherited in explicit slots.
type Config struct {
	Launcher string
	// Started reports the supervised child PID before bootstrap is released.
	// It is parent-only bookkeeping and grants no network permission.
	Started func(int)
	// LauncherArgs precede Executable and Args, for an embedding executable's
	// private bootstrap entry point. They are never passed to the candidate.
	LauncherArgs          []string
	Executable            string
	Args                  []string
	Env                   []string
	Policy                Policy
	Stdin, Stdout, Stderr *os.File
	ExtraFiles            []*os.File
}

type Counts struct {
	Allowed uint64 `json:"allowed"`
	Refused uint64 `json:"refused"`
}
type Event struct {
	Syscall     string `json:"syscall"`
	Family      int    `json:"family"`
	Class       string `json:"class"`
	Port        uint16 `json:"port"`
	Verdict     string `json:"verdict"`
	MonotonicNS int64  `json:"monotonic_ns"`
}

// Allowed counts mean syscall continuations, not successful network operations.
// Incomplete is true if a run exceeded its evidence budget or supervision failed.
type Report struct {
	Events     []Event           `json:"events"`
	Summary    map[string]Counts `json:"summary"`
	Incomplete bool              `json:"incomplete"`
}

// ProxyEnvironment replaces all case variants, retaining the caller's other
// explicitly selected entries. The caller must reserve closedPort for the run;
// this helper cannot prove that a port will remain closed. NO_PROXY excludes
// loopback hosts for client compatibility; Policy independently gates ports.
func ProxyEnvironment(env []string, closedPort uint16, fakePorts []uint16) ([]string, error) {
	if closedPort == 0 {
		return nil, ErrUnavailable
	}
	proxy := "http://127.0.0.1:" + strconv.Itoa(int(closedPort))
	for _, p := range fakePorts {
		if p == 0 || p == closedPort {
			return nil, ErrUnavailable
		}
	}
	out := []string{}
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			return nil, ErrUnavailable
		}
		switch strings.ToUpper(k) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, e)
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		out = append(out, k+"="+proxy, strings.ToLower(k)+"="+proxy)
	}
	out = append(out, "NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1")
	return out, nil
}
