//go:build linux

package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/pelletier/go-toml/v2"
)

var reserved = map[string]bool{
	"CODEX_ACCESS_TOKEN": true, "CODEX_API_KEY": true, "OPENAI_API_KEY": true,
	"OPENAI_API_BASE": true, "OPENAI_BASE_URL": true, "CODEX_AUTH": true,
	"CODEX_REFRESH_TOKEN_URL_OVERRIDE": true, "CODEX_APP_SERVER_LOGIN_ISSUER": true,
	"CODEX_AUTHAPI_BASE_URL": true,
}

func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func openRegular(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, e := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), abs)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not regular")
	}
	return f, nil
}
func cleanEnvironment(home string) []string {
	return []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
}
func inspectSources(o Options, env []string) (string, error) {
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if reserved[key] || strings.HasPrefix(key, "OPENAI_") || strings.Contains(key, "AUTH_HELPER") || strings.HasPrefix(key, "CODEX_ANKI_") || key == "CHATGPT_BASE_URL" || key == "CODEX_CONFIG" || key == "CODEX_PROFILE" || key == "CODEX_MODEL" || key == "CODEX_MODEL_PROVIDER" {
			return "", refuse("credential_source_conflict", 69)
		}
	}
	if _, err := os.Lstat(filepath.Join(o.LaunchHome, "auth.json")); err == nil {
		return "", refuse("credential_source_conflict", 69)
	} else if !os.IsNotExist(err) {
		return "", refuse("credential_injection_unavailable", 69)
	}
	// All effective user/project layers are inspected. Unknown configuration is
	// refused: admitting a key needs an explicit source and permission review.
	paths := []string{filepath.Join(o.LaunchHome, "config.toml")}
	// The selected release searches only up to the nearest .git marker; with
	// no marker the project root is cwd. Do not inspect unrelated user homes.
	projectRoot := o.Cwd
	for d := o.Cwd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			projectRoot = d
			break
		} else if !os.IsNotExist(err) {
			return "", refuse("credential_injection_unavailable", 69)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	for d := o.Cwd; ; d = filepath.Dir(d) {
		paths = append(paths, filepath.Join(d, ".codex", "config.toml"))
		if d == projectRoot {
			break
		}
	}
	// System/managed layers require separate qualification. Their presence is
	// refused here rather than assuming they contain no helpers or overrides.
	for _, path := range []string{"/etc/codex/config.toml", "/etc/codex/requirements.toml", "/etc/codex/managed_config.toml"} {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return "", refuse("credential_injection_unavailable", 69)
		}
		paths = append(paths, path)
	}
	for _, path := range append([]string{filepath.Join(o.LaunchHome, "hooks.json"), filepath.Join(o.LaunchHome, "mcp.json")}, projectSourceFiles(o.Cwd, projectRoot)...) {
		if _, err := os.Lstat(path); err == nil {
			return "", refuse("credential_source_conflict", 69)
		} else if !os.IsNotExist(err) {
			return "", refuse("credential_injection_unavailable", 69)
		}
	}
	var fingerprints []byte
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			fingerprints = append(fingerprints, []byte(path+"\x00absent\x00")...)
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return "", refuse("credential_injection_unavailable", 69)
		}
		f, err := openRegular(path)
		if err != nil {
			return "", refuse("credential_injection_unavailable", 69)
		}
		data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
		f.Close()
		if err != nil || len(data) > 1<<20 {
			return "", refuse("credential_injection_unavailable", 69)
		}
		var cfg map[string]any
		if toml.Unmarshal(data, &cfg) != nil {
			clear(data)
			return "", refuse("credential_injection_unavailable", 69)
		}
		if conflicting(cfg) {
			clear(data)
			return "", refuse("credential_source_conflict", 69)
		}
		for k, v := range cfg {
			if k != "cli_auth_credentials_store" || v != "ephemeral" {
				clear(data)
				return "", refuse("credential_injection_unavailable", 69)
			}
		}
		fingerprints = append(fingerprints, []byte(path+"\x00"+digest(data)+"\x00")...)
		clear(data)
	}
	return digest(fingerprints), nil
}
func conflicting(m map[string]any) bool {
	for key, value := range m {
		k := strings.ToLower(key)
		if strings.Contains(k, "auth") && k != "cli_auth_credentials_store" || strings.Contains(k, "token") || strings.Contains(k, "api_key") || k == "env_key" || k == "http_headers" || k == "env_http_headers" || strings.Contains(k, "helper") || strings.Contains(k, "issuer") || strings.Contains(k, "base_url") || k == "model_provider" || k == "model_providers" || k == "mcp_servers" || strings.Contains(k, "hook") || k == "plugins" {
			return true
		}
		if k == "cli_auth_credentials_store" && value != "ephemeral" {
			return true
		}
		if nested, ok := value.(map[string]any); ok && conflicting(nested) {
			return true
		}
		if array, ok := value.([]any); ok {
			for _, v := range array {
				if nested, ok := v.(map[string]any); ok && conflicting(nested) {
					return true
				}
			}
		}
	}
	return false
}
func validatePolicy(o Options, p Policy) error {
	if !p.Qualified || p.Release != "codex-cli 0.163.0" || !isSHA256(p.SchemaSHA256) {
		return refuse("lease_harness_unqualified", 69)
	}
	if p.UID != uint32(os.Getuid()) || p.Account != o.Account || p.Profile != o.Profile || p.PolicyGeneration == 0 || !isSHA256(p.BindingDigest) || !isSHA256(p.ConfigSHA256) || p.Endpoint == "" {
		return refuse("lease_binding_mismatch", 69)
	}
	allowed := false
	for _, effort := range p.Catalog[o.Model] {
		if effort == o.ReasoningEffort {
			allowed = true
		}
	}
	if !allowed {
		return refuse("invalid_model_effort", 64)
	}
	return checkExecutable(p)
}
func checkExecutable(p Policy) error {
	f, err := openPinned(p)
	if err != nil {
		return refuse("lease_harness_unqualified", 69)
	}
	f.Close()
	return nil
}

// Execute the verified open object, not a second lookup through a potentially
// replaced pathname. Same-UID tampering remains outside the interim guarantee.
func openPinned(p Policy) (*os.File, error) {
	if !filepath.IsAbs(p.Executable) {
		return nil, errors.New("not absolute")
	}
	f, err := openRegular(p.Executable)
	if err != nil {
		return nil, err
	}
	fail := func() (*os.File, error) { f.Close(); return nil, errors.New("unqualified executable") }
	info, err := f.Stat()
	if err != nil || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return fail()
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 && st.Uid != uint32(os.Getuid()) {
		return fail()
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != p.ExecutableSHA256 {
		return fail()
	}
	if _, err = f.Seek(0, 0); err != nil {
		return fail()
	}
	return f, nil
}
func samePolicy(a, b Policy) bool { return reflect.DeepEqual(a, b) }

type homeGuard struct {
	lock    *os.File
	state   string
	started bool
}

func lockHome(home string) (*homeGuard, error) {
	info, err := os.Lstat(home)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, refuse("credential_injection_unavailable", 69)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		return nil, refuse("credential_injection_unavailable", 69)
	}
	fd, err := syscall.Open(filepath.Join(home, ".run-codex.lock"), syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_CREAT|syscall.O_RDWR, 0600)
	if err != nil {
		return nil, refuse("credential_injection_unavailable", 69)
	}
	f := os.NewFile(uintptr(fd), "launch-lock")
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, refuse("lease_owner_unavailable", 75)
	}
	state := filepath.Join(home, ".run-codex-unresolved")
	if _, err = os.Lstat(state); err == nil || !os.IsNotExist(err) {
		f.Close()
		return nil, refuse("lease_owner_unavailable", 75)
	}
	return &homeGuard{lock: f, state: state}, nil
}
func (h *homeGuard) intent() error {
	f, err := os.OpenFile(h.state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString("unresolved\n")
	if err == nil {
		err = f.Sync()
	}
	e := f.Close()
	if err == nil {
		err = e
	}
	if err == nil {
		d, e := os.Open(filepath.Dir(h.state))
		if e != nil {
			return e
		}
		err = d.Sync()
		d.Close()
	}
	h.started = true
	return err
}
func (h *homeGuard) close(clean bool) error {
	var err error
	if clean && h.started {
		err = os.Remove(h.state)
	}
	closeErr := h.lock.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

// ConfigurationDigest inspects the supported effective configuration without
// touching credential contents. Qualification records bind this private value.
func ConfigurationDigest(o Options, environment []string) (string, error) {
	return inspectSources(o, environment)
}

func resolve(ctx context.Context, d Dependencies, o Options) (Policy, error) {
	if d.Authority == nil {
		return Policy{}, refuse("lease_harness_unqualified", 69)
	}
	p, e := d.Authority.Resolve(ctx, o)
	if e != nil {
		return Policy{}, refuse("lease_binding_mismatch", 69)
	}
	return p, validatePolicy(o, p)
}

func projectSourceFiles(cwd, root string) []string {
	var result []string
	for d := cwd; ; d = filepath.Dir(d) {
		result = append(result, filepath.Join(d, ".codex", "hooks.json"), filepath.Join(d, ".mcp.json"))
		if d == root {
			break
		}
	}
	return result
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
