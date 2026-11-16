package claudeworker

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const fakeToken = "FAKE_CLAUDE_TOKEN_NOT_A_CREDENTIAL_a1"

func candidate(t *testing.T) *Profile {
	t.Helper()
	p, err := NewProfile(t.TempDir(), "http://127.0.0.1:43123")
	if err != nil {
		t.Fatal("profile control refused")
	}
	return p
}

func assertNoMaterial(t *testing.T, b []byte) {
	t.Helper()
	if bytes.Contains(b, []byte(fakeToken)) {
		t.Fatal("fixture material escaped worker boundary")
	}
}

// Profiles accept numeric local listeners with an explicit port, while remote,
// credential-bearing, redirected/config-bearing and malformed inputs refuse.
// URL validation is not a kernel routing or listener-ownership qualification.
func TestLocalProfileNeighbors(t *testing.T) {
	home := t.TempDir()
	for _, endpoint := range []string{
		"http://127.0.0.1:43123", "http://[::1]:43123/", "https://127.0.0.1:43123",
	} {
		if _, err := NewProfile(home, endpoint); err != nil {
			t.Fatal("local endpoint control failed")
		}
	}
	for _, endpoint := range []string{
		"https://api.anthropic.com:443", "http://localhost:43123", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://127.0.0.1:65536", "http://user:password@127.0.0.1:43123", "http://127.0.0.1:43123?q=1",
		"http://127.0.0.1:43123?", "http://127.0.0.1:43123/#fragment", "http://127.0.0.1:43123/other",
		"file:///tmp/gateway", "http://127.0.0.1:43123\n", "http://127.0.0.1:43123/" + fakeToken,
	} {
		p, err := NewProfile(home, endpoint)
		if !errors.Is(err, ErrProfile) || p != nil {
			t.Fatal("unsafe endpoint admitted")
		}
		assertNoMaterial(t, []byte(err.Error()))
	}
	for _, path := range []string{"relative", home + "/../other", home + "\x00"} {
		if p, err := NewProfile(path, "http://127.0.0.1:43123"); !errors.Is(err, ErrProfile) || p != nil {
			t.Fatal("unsafe home admitted")
		}
	}
}

// Each final-composition negative has a fresh exact-profile positive control.
// Real or alternate tokens, inherited sources, duplicate/extra keys and another
// launch's placeholder refuse without returning or printing rejected values.
func TestWorkerEnvironmentTripwire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]string, *Profile) []string
	}{
		{"real-subscription-token", func(env []string, _ *Profile) []string { env[4] = "CLAUDE_CODE_OAUTH_TOKEN=" + fakeToken; return env }},
		{"empty-subscription", func(env []string, _ *Profile) []string { env[4] = "CLAUDE_CODE_OAUTH_TOKEN="; return env }},
		{"api-key", func(env []string, _ *Profile) []string { env[4] = "ANTHROPIC_API_KEY=" + fakeToken; return env }},
		{"auth-token", func(env []string, _ *Profile) []string { env[4] = "ANTHROPIC_AUTH_TOKEN=" + fakeToken; return env }},
		{"opaque-extra-secret", func(env []string, _ *Profile) []string { return append(env, "UNRELATED="+fakeToken) }},
		{"inherited-source", func(env []string, _ *Profile) []string { return append(env, "ANTHROPIC_API_KEY=") }},
		{"duplicate", func(env []string, _ *Profile) []string { env[2] = env[4]; return env }},
		{"missing", func(env []string, _ *Profile) []string { return env[:4] }},
		{"malformed", func(env []string, _ *Profile) []string { env[4] = "CLAUDE_CODE_OAUTH_TOKEN"; return env }},
		{"provider-bypass", func(env []string, _ *Profile) []string {
			env[3] = "ANTHROPIC_BASE_URL=https://api.anthropic.com"
			return env
		}},
		{"foreign-placeholder", func(env []string, p *Profile) []string {
			other, err := NewProfile(p.home, p.endpoint)
			if err != nil {
				t.Fatal("foreign fixture failed")
			}
			env[4] = "CLAUDE_CODE_OAUTH_TOKEN=" + other.placeholder
			return env
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := candidate(t)
			env, err := p.Environment()
			if err != nil || p.ValidateEnvironment(env) != nil {
				t.Fatal("valid profile control failed")
			}
			assertNoMaterial(t, []byte(strings.Join(env, "\x00")))
			bad := tc.mutate(append([]string(nil), env...), p)
			err = p.ValidateEnvironment(bad)
			if !errors.Is(err, ErrEnvironment) {
				t.Fatal("worker environment tripwire bypassed")
			}
			assertNoMaterial(t, []byte(err.Error()))
			if p.ValidateEnvironment(env) != nil {
				t.Fatal("refusal changed valid profile")
			}
		})
	}
}

// Fresh construction does not inherit ambient credentials or reuse another
// profile's placeholder; zero values fail closed rather than yielding an env.
func TestFreshEnvironmentAndZeroValues(t *testing.T) {
	p := candidate(t)
	env, err := p.Environment()
	if err != nil {
		t.Fatal("fresh environment failed")
	}
	assertNoMaterial(t, []byte(strings.Join(env, "\x00")))
	env[4] = "CLAUDE_CODE_OAUTH_TOKEN=" + fakeToken
	fresh, err := p.Environment()
	if err != nil || p.ValidateEnvironment(fresh) != nil {
		t.Fatal("caller changed stored profile")
	}
	assertNoMaterial(t, []byte(strings.Join(fresh, "\x00")))
	for _, zero := range []*Profile{nil, {}} {
		if env, err := zero.Environment(); !errors.Is(err, ErrProfile) || env != nil {
			t.Fatal("zero profile admitted")
		}
		if !errors.Is(zero.ValidateEnvironment(fresh), ErrEnvironment) {
			t.Fatal("zero profile validated env")
		}
	}
}
