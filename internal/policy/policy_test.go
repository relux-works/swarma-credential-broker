package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: protected config rejects unknown/duplicate fields, wrong modes/UID, duplicate vendor mappings and unsafe duration; valid authority derives bindings independently of request input.
func TestProtectedConfiguration(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	c := policy.Config{SocketPath: filepath.Join(t.TempDir(), "socket"), StoreRoot: e.Root, Policy: e.Policy}
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(b []byte) {
		t.Helper()
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture write failed")
		}
	}
	b, _ := wire.Encode(c)
	write(b)
	if _, err := policy.Load(path, e.UID); err != nil {
		t.Fatal("valid config refused")
	}
	if _, err := policy.Load(path, e.UID+1); err == nil {
		t.Fatal("wrong owner accepted")
	}
	os.Chmod(path, 0644)
	if _, err := policy.Load(path, e.UID); err == nil {
		t.Fatal("public config accepted")
	}
	os.Chmod(path, 0600)
	write(append([]byte(`{"unknown":true,`), b[1:]...))
	if _, err := policy.Load(path, e.UID); err == nil {
		t.Fatal("unknown config field accepted")
	}
	write(append([]byte(`{"socket_path":"untrusted",`), b[1:]...))
	if _, err := policy.Load(path, e.UID); err == nil {
		t.Fatal("duplicate config field accepted")
	}
	for _, mutate := range []func(*policy.Policy){func(p *policy.Policy) { p.Accounts[1].VendorID = p.Accounts[0].VendorID }, func(p *policy.Policy) { p.MaxLeaseSeconds = 1 << 62 }, func(p *policy.Policy) { p.Generation = 0 }} {
		p := e.Policy.Clone()
		mutate(&p)
		if p.Validate(e.UID) == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	bad := e.Request
	bad.Binding.PolicyGeneration++
	if _, err := e.Policy.Check(e.UID, bad); lease.ErrorCode(err) != "lease_binding_mismatch" {
		t.Fatal("client binding accepted")
	}
	if _, err := e.Policy.Check(e.UID, e.Request); err != nil {
		t.Fatal("valid binding refused")
	}
	c.SocketPath = filepath.Join(e.Root, "socket")
	nested, _ := wire.Encode(c)
	write(nested)
	if _, err := policy.Load(path, e.UID); lease.ErrorCode(err) != "lease_not_authorised" {
		t.Fatal("socket inside data tree accepted")
	}

}

// Claim: returned policy snapshots cannot mutate the manager's immutable authority and generation replacement is strictly increasing.
func TestPolicySnapshot(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	p := e.Manager.Policy()
	p.Accounts[0].AllowedUIDs[0]++
	if !e.Manager.Policy().Peer(e.UID) {
		t.Fatal("snapshot mutated authority")
	}
	if e.Manager.Replace(e.Policy) == nil {
		t.Fatal("same generation accepted")
	}
	p = e.Policy.Clone()
	p.Generation++
	if e.Manager.Replace(p) != nil {
		t.Fatal("successor generation refused")
	}
}
