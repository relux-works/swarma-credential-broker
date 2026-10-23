//go:build linux

package runner

import (
	"context"
	"os"
	"reflect"
	"sync"

	static "github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// DefaultPolicyPath is operator-owned configuration, never a CLI/environment
// identity selector. The current protected file contract supports interim R2;
// unreadable service-user policy remains refused rather than copied to callers.
const DefaultPolicyPath = "/etc/swarma-credential-broker/config.json"

type protectedAuthority struct {
	path     string
	mu       sync.Mutex
	resolved *static.Config
	// Tests may select the fixture seam only through a test-compiled constructor.
	qualifiedSet func(context.Context) ([]Policy, error)
	observer     qualification.IdentityObserver
}

func (a *protectedAuthority) productionQualifiedSet(ctx context.Context, c static.Config, o Options, p Policy) ([]Policy, error) {
	rec, catalog, e := c.Qualified(ctx, a.path, a.observer)
	if e != nil {
		return nil, e
	}
	fp, e := ConfigurationDigest(o, nil)
	if e != nil {
		return nil, e
	}
	p.Qualified = true
	p.Release = "codex-cli " + rec.Identity.Version
	p.SchemaSHA256 = rec.Identity.Schema.SHA256
	p.ConfigSHA256 = fp
	p.Catalog = map[string][]string{}
	for _, m := range catalog.Models {
		p.Catalog[m.Name] = append([]string(nil), m.Efforts...)
	}
	return []Policy{p}, nil
}

// ProtectedDependencies connects the operator-selected static policy to the
// runner. Production qualification has no caller-controlled override.
func ProtectedDependencies(path string, environment []string) Dependencies {
	a := &protectedAuthority{path: path}
	return Dependencies{Authority: a, Connect: a.connect, Environment: environment}
}
func (a *protectedAuthority) load(ctx context.Context) (static.Config, error) {
	if ctx.Err() != nil {
		return static.Config{}, refuse("lease_binding_mismatch", 69)
	}
	c, e := static.Load(a.path, uint32(os.Geteuid()))
	if e != nil || ctx.Err() != nil {
		return static.Config{}, refuse("lease_binding_mismatch", 69)
	}
	return c, nil
}
func (a *protectedAuthority) Resolve(ctx context.Context, o Options) (Policy, error) {
	c, e := a.load(ctx)
	if e != nil {
		return Policy{}, e
	}
	uid := uint32(os.Geteuid())
	account, e := c.Policy.Admit(uid, o.Account, o.Profile)
	if e != nil {
		if r, ok := e.(*wire.Error); ok && r.Code == "lease_account_unknown" {
			return Policy{}, refuse("lease_account_unknown", 69)
		}
		return Policy{}, refuse("lease_not_authorised", 69)
	}
	binding := c.Policy.Binding(uid, account, o.Profile)
	p := Policy{Account: account.Label, Profile: o.Profile, Endpoint: account.Endpoint, Executable: c.Policy.Executable, ExecutableSHA256: c.Policy.ExecutableSHA256, ChatGPTAccountID: account.VendorID, BindingDigest: binding.Digest, UID: uid, BrokerUID: c.Policy.BrokerUID, PolicyGeneration: c.Policy.Generation}
	if account.NetworkRequired {
		return Policy{}, refuse("lease_network_enforcement_unavailable", 69)
	}
	var set []Policy
	if a.qualifiedSet != nil {
		set, e = a.qualifiedSet(ctx)
	} else {
		set, e = a.productionQualifiedSet(ctx, c, o, p)
	}
	if e != nil || ctx.Err() != nil {
		return Policy{}, refuse("lease_harness_unqualified", 69)
	}
	for _, candidate := range set {
		identity := candidate
		identity.Qualified = false
		identity.Release = ""
		identity.SchemaSHA256 = ""
		identity.ConfigSHA256 = ""
		identity.Catalog = nil
		if !reflect.DeepEqual(identity, p) || !candidate.Qualified || account.ReleaseVersion != "0.163.0" || account.QualificationID == "" {
			continue
		}
		if candidate.Release != "codex-cli 0.163.0" || !isSHA256(candidate.SchemaSHA256) || !isSHA256(candidate.ConfigSHA256) {
			continue
		}
		// Copy the catalog, so a provider cannot mutate this authority snapshot.
		p = candidate
		p.Catalog = make(map[string][]string, len(candidate.Catalog))
		for model, efforts := range candidate.Catalog {
			p.Catalog[model] = append([]string(nil), efforts...)
		}
		a.mu.Lock()
		copy := c
		a.resolved = &copy
		a.mu.Unlock()
		return p, nil
	}
	return Policy{}, refuse("lease_harness_unqualified", 69)
}
func (a *protectedAuthority) connect(ctx context.Context) (BrokerClient, error) {
	c, e := a.load(ctx)
	if e != nil {
		return nil, e
	}
	a.mu.Lock()
	same := a.resolved != nil && reflect.DeepEqual(c, *a.resolved)
	a.mu.Unlock()
	if !same {
		return nil, refuse("lease_binding_mismatch", 69)
	}
	return DialBroker(ctx, c.SocketPath)
}
