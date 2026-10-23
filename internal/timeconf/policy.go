// Package timeconf collects independent clock confidence for local services.
package timeconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"
)

var ErrUnavailable = errors.New("time_confidence_unavailable")

type Source string

const (
	Off         Source = "off"
	NTSConfig   Source = "chrony-nts-config"
	NTSAuthData Source = "chrony-nts-authdata"
)

// Platform ceilings are the shared confidence policy. Services may only narrow
// these values through their protected policy; absence still selects Off.
const (
	PlatformMaxSyncAge        = 1024 * time.Second
	PlatformMaxOffset         = 500 * time.Millisecond
	PlatformMaxRootDistance   = time.Second
	PlatformAuthorityWindow   = 5 * time.Minute
	PlatformBackwardTolerance = time.Second
)

// Policy uses explicit integer nanoseconds. An omitted service policy is off;
// an enabled policy must supply every bound and a closed list of source files.
// Resync is either "new-authenticated-sync" or "operator" (no reset shipped).
type Policy struct {
	Source            Source        `json:"source"`
	Chronyc           string        `json:"chronyc"`
	SourceFiles       []string      `json:"source_files,omitempty"`
	MaxSyncAge        time.Duration `json:"max_sync_age_ns"`
	MaxOffset         time.Duration `json:"max_offset_ns"`
	MaxRootDistance   time.Duration `json:"max_root_distance_ns"`
	AuthorityWindow   time.Duration `json:"authority_window_ns"`
	BackwardTolerance time.Duration `json:"backward_tolerance_ns"`
	StepTolerance     time.Duration `json:"step_tolerance_ns"`
	Timeout           time.Duration `json:"timeout_ns"`
	MaxOutputBytes    int           `json:"max_output_bytes"`
	Resync            string        `json:"resync"`
}

func cleanPath(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" }
func (p Policy) Validate() error {
	if p.Source == Off {
		if p.Chronyc != "" || len(p.SourceFiles) != 0 || p.MaxSyncAge != 0 || p.MaxOffset != 0 || p.MaxRootDistance != 0 || p.AuthorityWindow != 0 || p.BackwardTolerance != 0 || p.StepTolerance != 0 || p.Timeout != 0 || p.MaxOutputBytes != 0 || p.Resync != "" {
			return ErrUnavailable
		}
		return nil
	}
	if p.Source != NTSConfig && p.Source != NTSAuthData {
		return ErrUnavailable
	}
	if !cleanPath(p.Chronyc) || len(p.SourceFiles) == 0 || len(p.SourceFiles) > 32 || p.MaxSyncAge <= 0 || p.MaxSyncAge > PlatformMaxSyncAge || p.MaxOffset <= 0 || p.MaxOffset > PlatformMaxOffset || p.MaxRootDistance <= 0 || p.MaxRootDistance > PlatformMaxRootDistance || p.AuthorityWindow <= 0 || p.AuthorityWindow > PlatformAuthorityWindow || p.AuthorityWindow > p.MaxSyncAge || p.BackwardTolerance < 0 || p.BackwardTolerance > PlatformBackwardTolerance || p.StepTolerance <= 0 || p.StepTolerance > time.Minute || p.Timeout <= 0 || p.Timeout > 10*time.Second || p.MaxOutputBytes < 256 || p.MaxOutputBytes > 65536 || (p.Resync != "new-authenticated-sync" && p.Resync != "operator") {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, path := range p.SourceFiles {
		if !cleanPath(path) || seen[path] {
			return ErrUnavailable
		}
		seen[path] = true
	}
	return nil
}

// DecodePolicy rejects duplicate/unknown keys, nulls, trailing values and missing
// required enabled bounds. It can also validate policy nested by another service.
func DecodePolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) > 65536 {
		return p, ErrUnavailable
	}
	if json.Unmarshal(b, &p) != nil {
		return Policy{}, ErrUnavailable
	}
	return p, nil
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	// Avoid recursively calling this method while preserving strict nested reads.
	type plain Policy
	var value plain
	if len(b) > 65536 {
		return ErrUnavailable
	}
	// Validate the complete exact member inventory before typed decoding. Go's
	// struct decoder alone accepts case variants of JSON tags.
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok || !policyMember(key) || seen[key] {
			return ErrUnavailable
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrUnavailable
		}
	}
	if _, err = d.Token(); err != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return ErrUnavailable
	}
	q := Policy(value)
	if q.Validate() != nil {
		return ErrUnavailable
	}
	if q.Source != Off && !seen["backward_tolerance_ns"] {
		return ErrUnavailable
	}
	*p = q
	return nil
}

// policyMember is case-sensitive and intentionally independent of json's
// struct field matching. New policy fields must enter this closed inventory.
func policyMember(key string) bool {
	switch key {
	case "source", "chronyc", "source_files", "max_sync_age_ns", "max_offset_ns", "max_root_distance_ns", "authority_window_ns", "backward_tolerance_ns", "step_tolerance_ns", "timeout_ns", "max_output_bytes", "resync":
		return true
	default:
		return false
	}
}

// ServicePolicy accepts only restrictions of a separately loaded shared policy.
// Source selection, executable and the complete configuration inventory remain
// shared authority. Operator-only recovery is stricter than automatic resync.
func ServicePolicy(shared, service Policy) (Policy, error) {
	if shared.Validate() != nil || service.Validate() != nil {
		return Policy{}, ErrUnavailable
	}
	if service.Source == Off {
		return service, nil
	}
	if shared.Source == Off || (service.Source != shared.Source && !(shared.Source == NTSConfig && service.Source == NTSAuthData)) || service.Chronyc != shared.Chronyc || len(service.SourceFiles) != len(shared.SourceFiles) {
		return Policy{}, ErrUnavailable
	}
	for i, path := range shared.SourceFiles {
		if service.SourceFiles[i] != path {
			return Policy{}, ErrUnavailable
		}
	}
	if service.MaxSyncAge > shared.MaxSyncAge || service.MaxOffset > shared.MaxOffset || service.MaxRootDistance > shared.MaxRootDistance || service.AuthorityWindow > shared.AuthorityWindow || service.StepTolerance > shared.StepTolerance || service.BackwardTolerance > shared.BackwardTolerance || service.Timeout > shared.Timeout || service.MaxOutputBytes > shared.MaxOutputBytes || shared.Resync == "operator" && service.Resync != "operator" {
		return Policy{}, ErrUnavailable
	}
	service.SourceFiles = append([]string(nil), service.SourceFiles...)
	return service, nil
}
