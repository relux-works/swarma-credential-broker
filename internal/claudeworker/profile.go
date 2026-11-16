// Package claudeworker constructs an inactive Claude launch environment with
// no vendor material. It neither starts a harness nor qualifies gateway routing.
package claudeworker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

var ErrProfile = errors.New("claude worker profile refused")
var ErrEnvironment = errors.New("claude worker environment refused")

// Profile contains only a locally generated nonsecret placeholder and launch
// metadata. Its placeholder is not an authenticated listener mapping; no wire
// format or production admission is assigned by this package.
type Profile struct {
	home        string
	endpoint    string
	placeholder string
}

// NewProfile builds a local-only candidate. Endpoint isolation, per-launch
// mapping, subscription behavior and exact-release qualification remain closed.
func NewProfile(home, endpoint string) (*Profile, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.Opaque != "" || u.Host == "" || strings.ContainsAny(endpoint, "\x00\r\n") || !filepath.IsAbs(home) || filepath.Clean(home) != home || strings.ContainsAny(home, "\x00\r\n") {
		return nil, ErrProfile
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return nil, ErrProfile
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrProfile
	}
	return &Profile{home, endpoint, "swarma-nonsecret-" + hex.EncodeToString(nonce[:])}, nil
}

// Environment constructs a fresh environment, never inheriting os.Environ.
// The subscription variable contains only the candidate placeholder. This
// preserves the selected subscription kind; it asserts no vendor acceptance.
func (p *Profile) Environment() ([]string, error) {
	if p == nil || p.placeholder == "" {
		return nil, ErrProfile
	}
	env := []string{
		"HOME=" + p.home,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8",
		"ANTHROPIC_BASE_URL=" + p.endpoint,
		"CLAUDE_CODE_OAUTH_TOKEN=" + p.placeholder,
	}
	if err := p.ValidateEnvironment(env); err != nil {
		return nil, err
	}
	return env, nil
}

// ValidateEnvironment is the final composition tripwire. A future executor
// must call it after all layers and before exec. It accepts exactly this
// profile, rejecting duplicate/extra keys and any replaced placeholder/source.
// Values, including a rejected real token, never appear in errors.
func (p *Profile) ValidateEnvironment(env []string) error {
	if p == nil || p.placeholder == "" || len(env) != 5 {
		return ErrEnvironment
	}
	want := map[string]string{
		"HOME": p.home, "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
		"ANTHROPIC_BASE_URL": p.endpoint, "CLAUDE_CODE_OAUTH_TOKEN": p.placeholder,
	}
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		expected, exists := want[name]
		if !ok || !exists || value != expected {
			return ErrEnvironment
		}
		delete(want, name)
	}
	return nil
}
