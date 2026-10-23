package policy_test

import (
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/timeconf"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: broker static policy rejects a nonzero backward tolerance and invalid
// enabled settings, with explicit zero/off and complete zero-threshold controls.
func TestBrokerTimeConfidencePolicy(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	p := e.Policy.Clone()
	p.TimeConfidence = &timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: time.Minute, MaxOffset: time.Millisecond, MaxRootDistance: time.Millisecond, AuthorityWindow: time.Second, StepTolerance: time.Millisecond, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	if p.Validate(e.UID) != nil {
		t.Fatal("valid zero threshold refused")
	}
	q := p.Clone()
	q.TimeConfidence.BackwardTolerance = time.Nanosecond
	if q.Validate(e.UID) == nil {
		t.Fatal("nonzero broker threshold accepted")
	}
	if p.TimeConfidence.BackwardTolerance != 0 {
		t.Fatal("clone mutated policy")
	}
	p.TimeConfidence.MaxOffset = 0
	if p.Validate(e.UID) == nil {
		t.Fatal("missing enabled bound accepted")
	}
	p.TimeConfidence = &timeconf.Policy{Source: timeconf.Off}
	if p.Validate(e.UID) != nil {
		t.Fatal("explicit off refused")
	}
}

// Claim: protected broker loading keeps the canonical time bound and rejects
// aliases/duplicates/nulls nested in that object, including a looser case alias.
func TestBrokerTimePolicyCaseVariantMembers(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	p := e.Policy.Clone()
	p.TimeConfidence = &timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: time.Minute, MaxOffset: time.Millisecond, MaxRootDistance: time.Millisecond, AuthorityWindow: time.Second, StepTolerance: time.Millisecond, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("chmod failed")
	}
	path := filepath.Join(dir, "policy.json")
	b, err := json.Marshal(policy.Config{SocketPath: filepath.Join(dir, "broker.sock"), StoreRoot: filepath.Join(dir, "store"), Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	load := func(raw []byte) error {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := policy.Load(path, e.UID)
		return err
	}
	if err := load(b); err != nil {
		t.Fatal("canonical control refused", err)
	}
	for _, key := range []string{"MAX_OFFSET_NS", "Max_Offset_Ns", "max_offset_ns", "unknown"} {
		raw := strings.Replace(string(b), `"max_offset_ns":1000000`, `"max_offset_ns":1000000,"`+key+`":500000000`, 1)
		if err := load([]byte(raw)); err == nil {
			t.Fatal("broker accepted alias/duplicate/unknown", key)
		}
	}
	for _, key := range []string{"MAX_OFFSET_NS", "Max_Offset_Ns"} {
		raw := strings.Replace(string(b), `"max_offset_ns":`, `"`+key+`":`, 1)
		if err := load([]byte(raw)); err == nil {
			t.Fatal("broker accepted variant without canonical member", key)
		}
	}
	raw := strings.Replace(string(b), `"max_offset_ns":1000000`, `"max_offset_ns":null`, 1)
	if err := load([]byte(raw)); err == nil {
		t.Fatal("broker accepted null")
	}
	if err := load(b); err != nil {
		t.Fatal("canonical recovery control refused", err)
	}
}
