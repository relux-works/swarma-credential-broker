//go:build linux

package demo

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type Projection struct {
	SocketPath string       `json:"socket_path"`
	BrokerUID  uint32       `json:"broker_uid"`
	Binding    wire.Binding `json:"binding"`
	RosterPath string       `json:"roster_path"`
}

// Qualification is public operator testimony installed only after live VM
// qualification and human account confirmation. It is never emitted by this code.
// AccountReference is the human-confirmed account/read email, not a token.
type Qualification struct {
	ChatGPTAccountID string                `json:"chatgpt_account_id"`
	AccountReference string                `json:"account_reference"`
	Executable       string                `json:"executable"`
	Release          string                `json:"release"`
	SchemaSHA256     string                `json:"schema_sha256"`
	ConfigSHA256     string                `json:"config_sha256"`
	Catalog          qualification.Catalog `json:"catalog"`
	Evidence         qualification.Record  `json:"evidence"`
}

func ReadProjection() (Projection, error) {
	var p Projection
	b, e := readRoot(AuthorityPath, 0644, 16384)
	if e != nil || decodeClosed(b, &p) != nil || p.BrokerUID != 1102 || p.RosterPath != RosterPath || !filepath.IsAbs(p.SocketPath) || filepath.Clean(p.SocketPath) != p.SocketPath || p.Binding.Harness != "codex_cli" || p.Binding.Channel != "external-token" || !hash.MatchString(p.Binding.Digest) || !hash.MatchString(p.Binding.ExecutableSHA256) || p.Binding.PolicyGeneration == 0 || p.Binding.PolicyGeneration > 9007199254740991 || p.Binding.Account == "" || p.Binding.Profile == "" || !strings.HasPrefix(p.Binding.Endpoint, "https://") {
		return Projection{}, ErrRefused
	}
	return p, nil
}
func ReadQualification() (Qualification, error) {
	var q Qualification
	b, e := readRoot(QualificationPath, 0644, 128*1024)
	if e != nil || decodeClosed(b, &q) != nil || q.ChatGPTAccountID == "" || q.AccountReference == "" || q.Executable == "" || q.Executable[0] != '/' || q.Release != "codex-cli 0.163.0" || !hash.MatchString(q.SchemaSHA256) || !hash.MatchString(q.ConfigSHA256) || q.Evidence.Publishable() != nil || q.Evidence.Identity.Schema.SHA256 != q.SchemaSHA256 {
		return Qualification{}, ErrRefused
	}
	catalog, e := wire.Encode(q.Catalog)
	if e != nil || qualification.Hash(catalog) != q.Evidence.Identity.Catalog.SHA256 {
		return Qualification{}, ErrRefused
	}
	return q, nil
}

// Authority re-reads all public evidence on every resolution. It does not read
// the private daemon configuration or managed login home.
type Authority struct {
	Launch        LaunchRecord
	UID           uint32
	mu            sync.Mutex
	pinned        bool
	failed        bool
	projection    Projection
	qualification Qualification
	roster        Roster
}

func (a *Authority) Resolve(ctx context.Context, o runner.Options) (runner.Policy, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return runner.Policy{}, ErrRefused
	}
	if ctx.Err() != nil {
		return runner.Policy{}, ErrRefused
	}
	p, e := ReadProjection()
	if e != nil {
		return runner.Policy{}, e
	}
	q, e := ReadQualification()
	if e != nil {
		return runner.Policy{}, e
	}
	r, e := ReadRoster(p.RosterPath)
	if e != nil {
		return runner.Policy{}, e
	}
	if a.pinned && (!reflect.DeepEqual(p, a.projection) || !reflect.DeepEqual(q, a.qualification) || !reflect.DeepEqual(r, a.roster)) {
		a.failed = true
		return runner.Policy{}, ErrRefused
	}
	a.pinned = true
	a.projection = p
	a.qualification = q
	a.roster = r
	currentBoot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(currentBoot)) != a.Launch.BootID {
		return runner.Policy{}, ErrRefused
	}
	row, e := r.Principal(a.UID, a.Launch)
	if e != nil || row.Workspace != o.Cwd || !FixedExecutorApproved(r) {
		return runner.Policy{}, ErrRefused
	}
	current, e := ReadLaunch(a.Launch.ExecutionID)
	if e != nil || current != a.Launch {
		return runner.Policy{}, ErrRefused
	}
	b := p.Binding
	if o.Account != b.Account || o.Profile != b.Profile || q.Evidence.Identity.Executable.SHA256 != b.ExecutableSHA256 {
		return runner.Policy{}, ErrRefused
	}
	// Recompute the existing binding preimage, including this kernel worker UID.
	preimage := map[string]any{"uid": a.UID, "profile": b.Profile, "harness": b.Harness, "account": b.Account, "channel": b.Channel, "endpoint": b.Endpoint, "executable_sha256": b.ExecutableSHA256, "policy_generation": b.PolicyGeneration}
	encoded, e := wire.Encode(preimage)
	if e != nil || Hash(encoded) != b.Digest {
		return runner.Policy{}, ErrRefused
	}
	config, e := runner.ConfigurationDigest(o, nil)
	if e != nil || config != q.ConfigSHA256 {
		return runner.Policy{}, ErrRefused
	}
	catalog := map[string][]string{}
	for _, m := range q.Catalog.Models {
		if m.Name == "" || catalog[m.Name] != nil {
			return runner.Policy{}, ErrRefused
		}
		catalog[m.Name] = append([]string{}, m.Efforts...)
	}
	policy := runner.Policy{Account: b.Account, Profile: b.Profile, Endpoint: b.Endpoint, Executable: q.Executable, ExecutableSHA256: b.ExecutableSHA256, Release: q.Release, SchemaSHA256: q.SchemaSHA256, ConfigSHA256: q.ConfigSHA256, ChatGPTAccountID: q.ChatGPTAccountID, BindingDigest: b.Digest, UID: a.UID, BrokerUID: p.BrokerUID, PolicyGeneration: b.PolicyGeneration, Qualified: true, Catalog: catalog}
	// The root qualification record attests the measured live identity; no caller
	// flag, fake record, absent record or pending case can reach this assignment.
	return policy, nil
}
func SameProjection(a, b Projection) bool { return reflect.DeepEqual(a, b) }
