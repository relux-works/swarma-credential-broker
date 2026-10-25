//go:build linux

package qualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// IdentityObserver measures current inputs; historical records are never an
// observer. Each unavailable input keeps both publication and leasing closed.
type IdentityObserver interface {
	Version(context.Context) (string, error)
	Executable(context.Context) (Measurement, error)
	Schema(context.Context) (Measurement, error)
	Runner(context.Context) (Measurement, error)
	Platform(context.Context) (Measurement, error)
	Configuration(context.Context) (Measurement, error)
	Properties(context.Context) (Measurement, error)
	Catalog(context.Context) (Measurement, Catalog, error)
}
type NativeObserver struct {
	ExecutablePath   string
	StaticPolicy     []byte
	ExecutableSHA256 string
	LauncherPath     string
	ScratchRoot      string
	Evidence         *CandidateEvidence
}

func (o NativeObserver) Properties(context.Context) (Measurement, error) {
	return Measurement{}, ErrUnavailable
}
func measure(name string, b []byte) Measurement { return Measurement{name + "/1", Hash(b)} }
func hashFile(ctx context.Context, f *os.File) (string, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 512<<20+1))
	if e != nil || n > 512<<20 || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// OpenExecutable uses no-follow opens for every path component, and retains the
// verified object for hashing. It never executes or reads credential files.
func OpenExecutable(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for n, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if n < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, ErrUnavailable
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "candidate")
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0111 == 0 || s.Mode().Perm()&0022 != 0 {
		f.Close()
		return nil, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func (o NativeObserver) Executable(ctx context.Context) (Measurement, error) {
	f, e := OpenExecutable(o.ExecutablePath)
	if e != nil {
		return Measurement{}, e
	}
	defer f.Close()
	s, e := hashFile(ctx, f)
	return Measurement{"executable/1", s}, e
}
func (o NativeObserver) Runner(ctx context.Context) (Measurement, error) {
	f, e := os.Open("/proc/self/exe")
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	defer f.Close()
	s, e := hashFile(ctx, f)
	if e != nil {
		return Measurement{}, e
	}
	b, ok := debug.ReadBuildInfo()
	if !ok {
		return Measurement{}, ErrUnavailable
	}
	revision := ""
	for _, v := range b.Settings {
		if v.Key == "vcs.revision" {
			revision = v.Value
		}
	}
	return measure("runner", []byte(s+"\x00"+b.Main.Version+"\x00"+revision)), nil
}
func (o NativeObserver) Platform(ctx context.Context) (Measurement, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return Measurement{}, ErrUnavailable
	}
	osRelease, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(osRelease), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && (k == "ID" || k == "VERSION_ID") {
			values[k] = strings.Trim(v, "\"'")
		}
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return Measurement{}, ErrUnavailable
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "--version")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	line, e := platformSystemdVersion(command)
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	b, e := wire.Encode(map[string]any{"os_id": values["ID"], "os_version": values["VERSION_ID"], "kernel_release": unix.ByteSliceToString(u.Release[:]), "kernel_version": unix.ByteSliceToString(u.Version[:]), "systemd": line, "architecture": runtime.GOARCH})
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	return measure("platform", b), nil
}

func platformSystemdVersion(command *exec.Cmd) (string, error) {
	var output cappedOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	command.WaitDelay = 100 * time.Millisecond
	if command.Run() != nil {
		return "", ErrUnavailable
	}
	line, _, _ := strings.Cut(output.buffer.String(), "\n")
	if !strings.HasPrefix(line, "systemd ") {
		return "", ErrUnavailable
	}
	return line, nil
}

func (o NativeObserver) Configuration(ctx context.Context) (Measurement, error) {
	fields, e := wire.Parse(o.StaticPolicy)
	if e != nil || ctx.Err() != nil {
		return Measurement{}, ErrUnavailable
	}
	b, e := wire.Encode(map[string]any{"static_policy": fields, "harness": "codex_cli", "channel": "external-token", "profile": "codex-refresher-v0", "source_policy": "ephemeral-only/1", "containment": "supervisor/1"})
	if e != nil {
		return Measurement{}, ErrUnavailable
	}
	return measure("configuration", b), nil
}
func Observe(ctx context.Context, o IdentityObserver) (Identity, Catalog, []string) {
	var i Identity
	var catalog Catalog
	missing := []string{}
	var e error
	i.Version, e = o.Version(ctx)
	if e != nil {
		missing = append(missing, "version/1")
	}
	for name, entry := range map[string]struct {
		f   func(context.Context) (Measurement, error)
		out *Measurement
	}{"executable": {o.Executable, &i.Executable}, "schema": {o.Schema, &i.Schema}, "runner": {o.Runner, &i.Runner}, "platform": {o.Platform, &i.Platform}, "configuration": {o.Configuration, &i.Configuration}, "properties": {o.Properties, &i.Properties}} {
		*entry.out, e = entry.f(ctx)
		if e != nil || entry.out.Observer != name+"/1" || !validHash(entry.out.SHA256) {
			missing = append(missing, name+"/1")
		}
	}
	i.Catalog, catalog, e = o.Catalog(ctx)
	raw, encodeErr := wire.Encode(catalog)
	if e != nil || encodeErr != nil || catalog.Models == nil || i.Catalog.Observer != "catalog/1" || i.Catalog.SHA256 != Hash(raw) {
		missing = append(missing, "catalog/1")
	}
	if ctx.Err() != nil {
		missing = append(missing, "context")
	}
	return i, catalog, missing
}

// cappedOutput bounds even a misbehaving tool's output before allocation grows.
type cappedOutput struct{ buffer bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	if len(p) > 65536-b.buffer.Len() {
		return 0, ErrUnavailable
	}
	return b.buffer.Write(p)
}
