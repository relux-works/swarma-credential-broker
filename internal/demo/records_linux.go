//go:build linux

// Package demo consumes the fixed demonstration's public, root-owned authority.
// It never writes a roster, launch record, qualification or credential store.
package demo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	RosterPath        = "/etc/swarma-demo/roster.json"
	AuthorityPath     = "/etc/swarma-demo/broker-authority.json"
	QualificationPath = "/etc/swarma-demo/codex-qualification.json"
	LaunchDirectory   = "/run/swarma-demo/launch-records"
	ExecutorID        = "swarma-demo-codex-executor"
	ExecutorPath      = "/usr/local/libexec/swarma/swarma-demo-codex-executor"
	// FrozenCopySourceRevision is P1's copied user-manager source, not its program pin.
	FrozenCopySourceRevision = "7d705966aa92acaebea2d55060dcb84ddf7e5031"
	PlanMax                  = 48 * 1024
)

var ErrRefused = errors.New("demo_authority_refused")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var generation = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var boot = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func Generation(s string) bool { return generation.MatchString(s) && s != strings.Repeat("0", 32) }
func Identifier(s string) bool { return identifier.MatchString(s) }
func Hash(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// decodeClosed accepts ordinary JSON as P1 does, including whitespace. It rejects
// duplicate/case-aliased/missing/unknown/null members and non-integral numbers.
func decodeClosed(b []byte, dst any) error {
	if !utf8.Valid(b) {
		return ErrRefused
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 12 {
			return nil, ErrRefused
		}
		t, e := d.Token()
		if e != nil {
			return nil, ErrRefused
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, ErrRefused
					}
					s, ok := k.(string)
					if !ok || strings.ContainsRune(s, 0) {
						return nil, ErrRefused
					}
					if _, ok = m[s]; ok {
						return nil, ErrRefused
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[s] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, ErrRefused
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					if len(a) >= 64 {
						return nil, ErrRefused
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, ErrRefused
				}
				return a, nil
			}
			return nil, ErrRefused
		}
		if s, ok := t.(string); ok && (len(s) > 65536 || strings.ContainsRune(s, 0)) {
			return nil, ErrRefused
		}
		return t, nil
	}
	v, e := read(0)
	if e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrRefused
	}
	if !shape(v, reflect.TypeOf(dst).Elem()) {
		return ErrRefused
	}
	if wire.Decode(b, dst) != nil {
		return ErrRefused
	}
	return nil
}
func shape(v any, t reflect.Type) bool {
	if v == nil {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			k := strings.Split(f.Tag.Get("json"), ",")[0]
			x, ok := m[k]
			if !ok || !shape(x, f.Type) {
				return false
			}
		}
		return true
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok || len(m) > 64 {
			return false
		}
		for _, x := range m {
			if !shape(x, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !shape(x, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Bool:
		_, ok := v.(bool)
		return ok
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint32, reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		_, e := n.Int64()
		return e == nil
	}
	return false
}

// openRooted refuses links in every component, untrusted directory ownership,
// and writable ancestors. The selected record remains open through its read.
func openRooted(path string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrRefused
	}
	fd, e := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRefused
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrRefused
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		n, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, ErrRefused
		}
		fd = n
	}
	if directory {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, ErrRefused
		}
	}
	return os.NewFile(uintptr(fd), "demo-public-record"), nil
}
func readRoot(path string, mode os.FileMode, cap int) ([]byte, error) {
	f, e := openRooted(path, false)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return nil, ErrRefused
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
		return nil, ErrRefused
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(cap+1)))
	if e != nil || len(b) > cap {
		return nil, ErrRefused
	}
	end, e := f.Stat()
	if e != nil || info.Size() != end.Size() || info.ModTime() != end.ModTime() {
		return nil, ErrRefused
	}
	return b, nil
}

type LaunchRecord struct {
	ExecutionID string `json:"execution_id"`
	UID         uint32 `json:"uid"`
	Generation  string `json:"generation"`
	PlanSHA256  string `json:"plan_sha256"`
	BootID      string `json:"boot_id"`
}

func LaunchPath(id string) (string, error) {
	if !Identifier(id) {
		return "", ErrRefused
	}
	return LaunchDirectory + "/" + id + ".json", nil
}
func ReadLaunch(id string) (LaunchRecord, error) {
	path, e := LaunchPath(id)
	if e != nil {
		return LaunchRecord{}, e
	}
	return readLaunch(path, id)
}
func readLaunch(path, id string) (LaunchRecord, error) {
	var r LaunchRecord
	b, e := readRoot(path, 0444, 4096)
	if e != nil || decodeClosed(b, &r) != nil || r.ExecutionID != id || !Identifier(id) || r.UID < 30000 || r.UID > 30019 || !Generation(r.Generation) || !hash.MatchString(r.PlanSHA256) || !boot.MatchString(r.BootID) {
		return LaunchRecord{}, ErrRefused
	}
	return r, nil
}
