//go:build linux

package timeconf

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Runner permits bounded fixture execution without changing the production argv.
type Runner interface {
	Run(context.Context, string, []string, time.Duration, int) ([]byte, error)
}
type SystemRunner struct{}
type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(v []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(v) > b.limit-b.buffer.Len() {
		b.overflow = true
		return 0, ErrUnavailable
	}
	return b.buffer.Write(v)
}
func (SystemRunner) Run(ctx context.Context, path string, args []string, timeout time.Duration, limit int) ([]byte, error) {
	if !cleanPath(path) || timeout <= 0 || timeout > 10*time.Second || limit < 1 || limit > 65536 {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}
	cmd.Stdin = nil
	cmd.WaitDelay = 100 * time.Millisecond
	out := &boundedOutput{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil || out.overflow || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), out.buffer.Bytes()...), nil
}

// pathProtected forbids links and untrusted ancestor replacement. Root-owned
// sticky temporary directories may contain already-existing owned children.
func pathProtected(path string, uid uint32) error {
	if !cleanPath(path) {
		return ErrUnavailable
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		s, err := os.Lstat(dir)
		if err != nil || !s.IsDir() {
			return ErrUnavailable
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnavailable
		}
		if st.Uid != 0 && st.Uid != uid {
			return ErrUnavailable
		}
		if s.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && s.Mode()&os.ModeSticky != 0) {
			return ErrUnavailable
		}
		if dir == "/" {
			return nil
		}
	}
}
func protectedRead(path string, uid uint32, max int, private bool) ([]byte, error) {
	if max < 1 || pathProtected(path, uid) != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || s.Mode().Perm()&0022 != 0 {
		return nil, ErrUnavailable
	}
	if private {
		if st.Uid != uid || s.Mode() != 0600 {
			return nil, ErrUnavailable
		}
	} else if st.Uid != 0 && st.Uid != uid {
		return nil, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, ErrUnavailable
	}
	return b, nil
}

func LoadPolicy(path string, uid uint32) (Policy, error) {
	b, err := protectedRead(path, uid, 65536, true)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	return DecodePolicy(b)
}

// LoadServicePolicy rejects a looser service override during its protected read.
func LoadServicePolicy(path string, uid uint32, shared Policy) (Policy, error) {
	p, err := LoadPolicy(path, uid)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	return ServicePolicy(shared, p)
}

type SystemCollector struct{ Runner Runner }

func (c SystemCollector) Collect(ctx context.Context, p Policy) (Evidence, error) {
	var e Evidence
	if p.Validate() != nil || p.Source == Off || ctx.Err() != nil {
		return e, ErrUnavailable
	}
	// Check the executable tuple on every collection; no PATH or shell lookup.
	if pathProtected(p.Chronyc, uint32(os.Geteuid())) != nil {
		return e, ErrUnavailable
	}
	s, err := os.Lstat(p.Chronyc)
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 || s.Mode().Perm()&0022 != 0 {
		return e, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return e, ErrUnavailable
	}
	for _, path := range p.SourceFiles {
		if ctx.Err() != nil {
			return Evidence{}, ErrUnavailable
		}
		b, err := protectedRead(path, uint32(os.Geteuid()), p.MaxOutputBytes, false)
		if err != nil {
			return Evidence{}, ErrUnavailable
		}
		sources, err := ParseSources(b)
		if err != nil {
			return Evidence{}, ErrUnavailable
		}
		e.Sources.Count += sources.Count
		e.Sources.Entries = append(e.Sources.Entries, sources.Entries...)
	}
	if e.Sources.Count == 0 {
		return Evidence{}, ErrUnavailable
	}
	e.Sources.AllNTS = true
	runner := c.Runner
	if runner == nil {
		runner = SystemRunner{}
	}
	b, err := runner.Run(ctx, p.Chronyc, []string{"-c", "tracking"}, p.Timeout, p.MaxOutputBytes)
	if err != nil || len(b) > p.MaxOutputBytes {
		return Evidence{}, ErrUnavailable
	}
	e.Tracking, err = ParseTracking(b)
	if err != nil {
		return Evidence{}, ErrUnavailable
	}
	// Numeric entries match directly. For configured names, ask chronyd for its
	// original source name; no forward/reverse DNS inference is authority.
	if !selectedConfigured(e.Sources, e.Tracking) {
		b, err = runner.Run(ctx, p.Chronyc, []string{"-c", "-N", "tracking"}, p.Timeout, p.MaxOutputBytes)
		if err != nil || len(b) > p.MaxOutputBytes {
			return Evidence{}, ErrUnavailable
		}
		named, err := ParseTracking(b)
		if err != nil || named.ReferenceID != e.Tracking.ReferenceID || !named.Reference.Equal(e.Tracking.Reference) || named.Stratum != e.Tracking.Stratum || !selectedConfigured(e.Sources, named) {
			return Evidence{}, ErrUnavailable
		}
		named.Name = named.Address
		named.Address = e.Tracking.Address
		e.Tracking = named
	}
	if p.Source == NTSAuthData {
		b, err = runner.Run(ctx, p.Chronyc, []string{"-c", "authdata", "-a"}, p.Timeout, p.MaxOutputBytes)
		if err != nil || len(b) > p.MaxOutputBytes {
			return Evidence{}, ErrUnavailable
		}
		e.Authentication, err = ParseAuthData(b)
		if err != nil {
			return Evidence{}, ErrUnavailable
		}
	}
	return e, nil
}

type SystemClock struct{}

func (SystemClock) Read(ctx context.Context) (ClockPoint, error) {
	if ctx.Err() != nil {
		return ClockPoint{}, ErrUnavailable
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ClockPoint{}, ErrUnavailable
	}
	boot = bytes.TrimSpace(boot)
	if len(boot) != 36 {
		return ClockPoint{}, ErrUnavailable
	}
	for i, c := range boot {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return ClockPoint{}, ErrUnavailable
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ClockPoint{}, ErrUnavailable
		}
	}
	var elapsed, wall unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &elapsed) != nil || unix.ClockGettime(unix.CLOCK_REALTIME, &wall) != nil {
		return ClockPoint{}, ErrUnavailable
	}
	return ClockPoint{Now: time.Unix(wall.Sec, wall.Nsec).UTC(), Elapsed: time.Duration(elapsed.Sec)*time.Second + time.Duration(elapsed.Nsec), Boot: string(boot)}, nil
}

// Production selects no source when policy is absent. Only the embedding
// service's protected static policy may supply an explicit source; no environment
// variable or command argument selects or overrides it.
func Production(policy *Policy, incident func(Incident)) (*Provider, error) {
	p := Policy{Source: Off}
	if policy != nil {
		p = *policy
	}
	return New(p, SystemCollector{}, SystemClock{}, incident)
}
