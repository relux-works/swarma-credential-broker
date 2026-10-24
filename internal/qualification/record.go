// Package qualification owns protected exact-release evidence and publication.
package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var ErrUnavailable = errors.New("qualification_unavailable")
var ErrInvalid = errors.New("qualification_invalid")

const Revision = "codex-refresher-v0/1"

// Measurement binds a digest to a closed, named current observer. No diagnostic
// text, environment, material or opaque observation payload belongs in a record.
type Measurement struct {
	Observer string `json:"observer"`
	SHA256   string `json:"sha256"`
}
type Identity struct {
	Version       string      `json:"version"`
	Executable    Measurement `json:"executable"`
	Schema        Measurement `json:"schema"`
	Runner        Measurement `json:"runner"`
	Platform      Measurement `json:"platform"`
	Configuration Measurement `json:"configuration"`
	Properties    Measurement `json:"properties"`
	Catalog       Measurement `json:"catalog"`
}
type Model struct {
	Name    string   `json:"name"`
	Efforts []string `json:"efforts"`
}
type Catalog struct {
	Models []Model `json:"models"`
}

// Control stores argv, never shell text or output. Executed commands must equal
// the registry's fixed descriptor-bound argv, so arbitrary text has no channel.
type Control struct {
	Verdict    string   `json:"verdict"`
	Executed   bool     `json:"executed"`
	Command    []string `json:"command"`
	ExitCode   int      `json:"exit_code"`
	Artifacts  []string `json:"artifacts"`
	DurationNS int64    `json:"duration_ns"`
	BoundNS    int64    `json:"bound_ns"`
}
type Case struct {
	ID       string  `json:"id"`
	Positive Control `json:"positive"`
	Negative Control `json:"negative"`
}
type Record struct {
	Kind             string   `json:"kind"`
	Identity         Identity `json:"identity"`
	Suite            string   `json:"suite_revision"`
	Mode             string   `json:"mode"`
	Cases            []Case   `json:"cases"`
	Approval         string   `json:"live_approval_ref"`
	AccountCheck     string   `json:"account_identity_check"`
	OperatorAccepted bool     `json:"operator_accepted"`
	CompletedAt      string   `json:"completed_at"`
	Disposition      string   `json:"disposition"`
}

// RequiredCases is the fixed v0 registry. Unimplemented bodies stay pending
// without execution credit or an invented exit.
func RequiredCases() []string {
	return []string{
		"peer-denied", "account-denied", "account-unknown", "release-unqualified", "source-conflict", "home-auth-present", "renew-unknown-digest", "renew-contention", "renew-late", "queue-full", "daemon-death", "replacement-contention", "rotation-crash", "cleanup-interrupted", "absence-unreadable", "store-missing", "store-rollback", "transient-ambiguous", "reenrol-unresolved", "duplicate-account", "owner-mismatch", "lease-ended", "time-untrusted", "init-without-capability", "resume-conflict", "frame-oversized", "frame-zero-length", "frame-truncated-header", "frame-malformed-first", "peer-identity-unavailable", "profile-unsupported",
		"external-login", "account-identity", "managed-refresh", "inference-401", "renew-account-mismatch", "renew-failure", "queue-fairness", "callback-unanswered", "callback-late", "child-inheritance", "network-policy", "approved-routing", "headless-inference", "effective-source", "vendor-callback-timeout",
	}
}

// CaseCommand names the retained broker worker descriptor, never a shell or
// candidate path. The worker separately measures the approved candidate at FD6.
func CaseCommand(id, control string) []string {
	return []string{"/proc/self/fd/4", "qualification-case", id, control}
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func (i Identity) Validate() error {
	if i.Version != "0.163.0" {
		return ErrInvalid
	}
	for name, m := range map[string]Measurement{"executable": i.Executable, "schema": i.Schema, "runner": i.Runner, "platform": i.Platform, "configuration": i.Configuration, "properties": i.Properties, "catalog": i.Catalog} {
		if m.Observer != name+"/1" || !validHash(m.SHA256) {
			return ErrInvalid
		}
	}
	return nil
}
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if wire.Decode(raw, &r) != nil || r.Validate() != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func (r Record) Validate() error {
	if r.Kind != "qualification/1" || r.Identity.Validate() != nil || r.Suite != Revision || (r.Mode != "fake" && r.Mode != "live") {
		return ErrInvalid
	}
	when, e := time.Parse(time.RFC3339, r.CompletedAt)
	if e != nil || when.UTC().Format("2006-01-02T15:04:05Z") != r.CompletedAt {
		return ErrInvalid
	}
	if r.Disposition != "pending" && r.Disposition != "failed" && r.Disposition != "accepted" {
		return ErrInvalid
	}
	if r.AccountCheck != "pending" && r.AccountCheck != "matched" && r.AccountCheck != "mismatched" {
		return ErrInvalid
	}
	if r.Mode == "fake" && r.Approval != "" || r.Mode == "live" && !validHash(r.Approval) {
		return ErrInvalid
	}
	required := RequiredCases()
	if len(r.Cases) != len(required) {
		return ErrInvalid
	}
	for n, c := range r.Cases {
		if c.ID != required[n] {
			return ErrInvalid
		}
		for name, x := range map[string]Control{"positive": c.Positive, "negative": c.Negative} {
			if x.BoundNS <= 0 || x.BoundNS > int64(10*time.Minute) || x.DurationNS < 0 || x.DurationNS > x.BoundNS || x.Command == nil || x.Artifacts == nil {
				return ErrInvalid
			}
			if x.Verdict == "pending" {
				if x.Executed || x.ExitCode != -1 || x.DurationNS != 0 || len(x.Command) != 0 || len(x.Artifacts) != 0 {
					return ErrInvalid
				}
			} else {
				if x.Verdict != "passed" && x.Verdict != "failed" || !x.Executed || x.ExitCode < 0 || x.ExitCode > 255 || x.DurationNS == 0 || !reflect.DeepEqual(x.Command, CaseCommand(c.ID, name)) || len(x.Artifacts) == 0 {
					return ErrInvalid
				}
				if x.Verdict == "passed" && x.ExitCode != 0 {
					return ErrInvalid
				}
				for _, a := range x.Artifacts {
					if !validHash(a) {
						return ErrInvalid
					}
				}
			}
		}
	}
	return nil
}
func (r Record) Publishable() error {
	if r.Validate() != nil || r.Mode != "live" || r.Disposition != "accepted" || !r.OperatorAccepted || r.AccountCheck != "matched" {
		return ErrInvalid
	}
	for _, c := range r.Cases {
		for _, x := range []Control{c.Positive, c.Negative} {
			if x.Verdict != "passed" || !x.Executed || x.ExitCode != 0 {
				return ErrInvalid
			}
		}
	}
	return nil
}
func Pending(i Identity) Record {
	r := Record{Kind: "qualification/1", Identity: i, Suite: Revision, Mode: "fake", Cases: []Case{}, AccountCheck: "pending", CompletedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Disposition: "pending"}
	for _, id := range RequiredCases() {
		c := Control{Verdict: "pending", Command: []string{}, ExitCode: -1, Artifacts: []string{}, BoundNS: int64(30 * time.Second)}
		r.Cases = append(r.Cases, Case{id, c, c})
	}
	return r
}
