// Package policy implements the interim protected static authority.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"path/filepath"
	"strings"
	"time"
)

type Account struct {
	Label           string   `json:"label"`
	VendorID        string   `json:"vendor_account_id"`
	AllowedUIDs     []uint32 `json:"allowed_uids"`
	Profiles        []string `json:"profiles"`
	Endpoint        string   `json:"endpoint"`
	ReleaseVersion  string   `json:"release_version"`
	QualificationID string   `json:"qualification_id"`
	Enabled         bool     `json:"enabled"`
	NetworkRequired bool     `json:"network_required"`
}
type Policy struct {
	TimeConfidence   *timeconf.Policy `json:"time_confidence,omitempty"`
	Installation     string           `json:"installation_id"`
	Generation       uint64           `json:"policy_generation"`
	BrokerUID        uint32           `json:"broker_uid"`
	Executable       string           `json:"executable"`
	ExecutableSHA256 string           `json:"executable_sha256"`
	MaxLeaseSeconds  int64            `json:"max_lease_seconds"`
	Accounts         []Account        `json:"accounts"`
}
type Config struct {
	SocketPath string `json:"socket_path"`
	StoreRoot  string `json:"store_root"`
	Policy     Policy `json:"policy"`
}

func Load(path string, uid uint32) (Config, error) {
	var c Config
	b, e := store.ReadProtected(path, uid)
	if e != nil {
		return c, e
	}
	if wire.Decode(b, &c) != nil || c.Policy.Validate(uid) != nil || !filepath.IsAbs(c.SocketPath) || !filepath.IsAbs(c.StoreRoot) {
		return c, wire.Refuse("lease_not_authorised")
	}
	rel, e := filepath.Rel(c.StoreRoot, c.SocketPath)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return c, wire.Refuse("lease_not_authorised")
	}
	return c, nil
}
func (p Policy) Validate(uid uint32) error {
	if p.TimeConfidence != nil && (p.TimeConfidence.Validate() != nil || p.TimeConfidence.BackwardTolerance != 0) {
		return wire.Refuse("lease_not_authorised")
	}
	if p.Installation == "" || p.Generation == 0 || p.Generation > 9007199254740991 || p.BrokerUID != uid || !filepath.IsAbs(p.Executable) || !Hash(p.ExecutableSHA256) || p.MaxLeaseSeconds <= 0 || p.MaxLeaseSeconds > int64((1<<63-1)/time.Second) {
		return wire.Refuse("lease_not_authorised")
	}
	labels := map[string]bool{}
	vendors := map[string]bool{}
	for _, a := range p.Accounts {
		if a.Label == "" || a.VendorID == "" || labels[a.Label] || vendors[a.VendorID] || !strings.HasPrefix(a.Endpoint, "https://") {
			return wire.Refuse("lease_not_authorised")
		}
		labels[a.Label] = true
		vendors[a.VendorID] = true
	}
	return nil
}
func Hash(s string) bool {
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
func contains[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func (p Policy) Peer(uid uint32) bool {
	for _, a := range p.Accounts {
		if a.Enabled && contains(a.AllowedUIDs, uid) {
			return true
		}
	}
	return false
}
func (p Policy) Visible(uid uint32) []Account {
	out := []Account{}
	for _, a := range p.Accounts {
		if a.Enabled && contains(a.AllowedUIDs, uid) {
			out = append(out, a)
		}
	}
	return out
}
func (p Policy) Admit(uid uint32, label, profile string) (Account, error) {
	var a Account
	profileAllowed := false
	for _, v := range p.Accounts {
		if v.Enabled && contains(v.AllowedUIDs, uid) && contains(v.Profiles, profile) {
			profileAllowed = true
		}
		if v.Label == label {
			a = v
		}
	}
	if !profileAllowed {
		return a, wire.Refuse("lease_not_authorised")
	}
	if a.Label == "" {
		return a, wire.Refuse("lease_account_unknown")
	}
	if !a.Enabled || !contains(a.AllowedUIDs, uid) || !contains(a.Profiles, profile) {
		return a, wire.Refuse("lease_not_authorised")
	}
	return a, nil
}
func (p Policy) Binding(uid uint32, a Account, profile string) wire.Binding {
	b := wire.Binding{Harness: "codex_cli", Profile: profile, Account: a.Label, Channel: "external-token", Endpoint: a.Endpoint, ExecutableSHA256: p.ExecutableSHA256, PolicyGeneration: p.Generation}
	tuple := map[string]any{"uid": uid, "profile": profile, "harness": b.Harness, "account": a.Label, "channel": b.Channel, "endpoint": a.Endpoint, "executable_sha256": p.ExecutableSHA256, "policy_generation": p.Generation}
	raw, _ := wire.Encode(tuple)
	sum := sha256.Sum256(raw)
	b.Digest = hex.EncodeToString(sum[:])
	return b
}
func (p Policy) Check(uid uint32, r wire.LeaseRequest) (Account, error) {
	a, e := p.Admit(uid, r.Account, r.Profile)
	if e != nil {
		return a, e
	}
	if r.Harness != "codex_cli" {
		return a, wire.Refuse("lease_harness_mismatch")
	}
	if r.Channel != "external-token" {
		return a, wire.Refuse("lease_channel_unsupported")
	}
	if a.NetworkRequired || string(r.Network) != "null" {
		return a, wire.Refuse("lease_network_enforcement_unavailable")
	}
	if a.ReleaseVersion != "0.163.0" || a.QualificationID == "" {
		return a, wire.Refuse("lease_harness_unqualified")
	}
	if r.Binding != p.Binding(uid, a, r.Profile) {
		return a, wire.Refuse("lease_binding_mismatch")
	}
	if !contains(r.Executor.Capabilities, "credential-injection/1") || r.Executor.Version == "" || !wire.ASCII(r.LaunchID, 128) {
		return a, wire.Refuse("credential_injection_unavailable")
	}
	return a, nil
}

// Clone prevents configuration callers from changing a published authority snapshot.
func (p Policy) Clone() Policy {
	b, _ := json.Marshal(p)
	var c Policy
	_ = json.Unmarshal(b, &c)
	return c
}
