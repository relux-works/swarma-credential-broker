//go:build linux

package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	static "github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func staticFixture(t *testing.T, f *fixture) (string, static.Config) {
	t.Helper()
	p := f.a.p
	c := static.Config{SocketPath: filepath.Join(f.root, "broker.sock"), StoreRoot: filepath.Join(f.root, "store"), Policy: static.Policy{Installation: "fixture-installation", Generation: p.PolicyGeneration, BrokerUID: p.BrokerUID, Executable: p.Executable, ExecutableSHA256: p.ExecutableSHA256, MaxLeaseSeconds: 3600, Accounts: []static.Account{{Label: p.Account, VendorID: p.ChatGPTAccountID, AllowedUIDs: []uint32{p.UID}, Profiles: []string{p.Profile}, Endpoint: p.Endpoint, ReleaseVersion: "0.163.0", QualificationID: "fixture-evidence", Enabled: true}}}}
	path := filepath.Join(f.root, "policy.json")
	writeStatic(t, path, c)
	return path, c
}
func writeStatic(t *testing.T, path string, c static.Config) {
	t.Helper()
	b, e := wire.Encode(c)
	must(t, e)
	must(t, os.WriteFile(path, b, 0600))
}

// qualifiedFixture is compiled only into tests. No production constructor can
// select this provider, and the CLI has no qualification override.
func qualifiedFixture(path string, p Policy) Dependencies {
	a := &protectedAuthority{path: path, qualifiedSet: func(context.Context) ([]Policy, error) { return []Policy{p}, nil }}
	return Dependencies{Authority: a, Connect: a.connect, Supervisor: supervisorPath}
}
func boundFixturePolicy(f *fixture, c static.Config) Policy {
	p := f.a.p
	p.BindingDigest = c.Policy.Binding(p.UID, c.Policy.Accounts[0], p.Profile).Digest
	return p
}

// Claim: a protected nonempty qualification reference does not qualify a release;
// Command refuses before connecting, taking a lease or starting any probe/child.
func TestProductionQualifiedSetEmpty(t *testing.T) {
	f := newFixture(t, nil)
	path, _ := staticFixture(t, f)
	d := ProtectedDependencies(path, nil)
	d.Connect = func(context.Context) (BrokerClient, error) { t.Fatal("unqualified release connected"); return nil, nil }
	got := Command(context.Background(), f.args(), IO{strings.NewReader("prompt"), &f.out, &f.err}, d)
	requireStatus(t, got, 69, f.err.String())
	if !strings.Contains(f.err.String(), "lease_harness_unqualified") {
		t.Fatal("qualification refusal lost")
	}
	assertAbsent(t, filepath.Join(f.home, "server-pid"))
	assertAbsent(t, filepath.Join(f.home, "version-probe"))
	assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
	assertAbsent(t, f.output)
}

// Claim: authority derives identity/binding from protected policy and the kernel;
// unreadable/unprotected policy, caller selectors and stale tuple evidence cannot
// grant a lease. Only a test-compiled exact tuple is admitted by the control.
func TestProtectedAuthority(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "mode", "symlink", "unknown-account", "profile", "disabled", "uid", "generation", "digest", "reference", "qualified-digest", "qualified-config", "network", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, nil)
			path, c := staticFixture(t, f)
			p := boundFixturePolicy(f, c)
			options := f.o
			want := "lease_harness_unqualified"
			switch mode {
			case "missing":
				must(t, os.Remove(path))
				want = "lease_binding_mismatch"
			case "mode":
				must(t, os.Chmod(path, 0644))
				want = "lease_binding_mismatch"
			case "symlink":
				must(t, os.Rename(path, path+".regular"))
				must(t, os.Symlink(path+".regular", path))
				want = "lease_binding_mismatch"
			case "unknown-account":
				options.Account = "absent"
				want = "lease_account_unknown"
			case "profile":
				options.Profile = "absent"
				want = "lease_not_authorised"
			case "disabled":
				c.Policy.Accounts[0].Enabled = false
				writeStatic(t, path, c)
				want = "lease_not_authorised"
			case "uid":
				c.Policy.Accounts[0].AllowedUIDs = []uint32{}
				writeStatic(t, path, c)
				want = "lease_not_authorised"
			case "generation":
				c.Policy.Generation++
				writeStatic(t, path, c)
			case "digest":
				c.Policy.ExecutableSHA256 = strings.Repeat("c", 64)
				writeStatic(t, path, c)
			case "reference":
				c.Policy.Accounts[0].QualificationID = ""
				writeStatic(t, path, c)
			case "qualified-digest":
				p.ExecutableSHA256 = strings.Repeat("c", 64)
			case "qualified-config":
				p.ConfigSHA256 = ""
			case "network":
				c.Policy.Accounts[0].NetworkRequired = true
				writeStatic(t, path, c)
				want = "lease_network_enforcement_unavailable"
			}
			d := qualifiedFixture(path, p)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
				want = "lease_binding_mismatch"
			}
			got, e := d.Authority.Resolve(ctx, options)
			if mode == "valid" {
				must(t, e)
				if !got.Qualified || got.BindingDigest != c.Policy.Binding(uint32(os.Geteuid()), c.Policy.Accounts[0], options.Profile).Digest || got.BrokerUID != c.Policy.BrokerUID {
					t.Fatal("policy identity mismatch")
				}
			} else {
				refusalCode(t, e, want, 69)
			}
		})
	}
}

// Claim: Connect rereads the same protected configuration; changed socket or
// policy cannot silently redirect a resolved authority to a new server.
func TestProtectedConnectRecheck(t *testing.T) {
	f := newFixture(t, nil)
	path, c := staticFixture(t, f)
	d := qualifiedFixture(path, boundFixturePolicy(f, c))
	_, e := d.Authority.Resolve(context.Background(), f.o)
	must(t, e)
	c.SocketPath = filepath.Join(f.root, "other.sock")
	writeStatic(t, path, c)
	_, e = d.Connect(context.Background())
	refusalCode(t, e, "lease_binding_mismatch", 69)
}
