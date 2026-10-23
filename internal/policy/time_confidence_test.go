package policy_test

import (
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/timeconf"
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
