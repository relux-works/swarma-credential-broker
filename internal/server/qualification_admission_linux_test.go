//go:build linux

package server

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
)

// Claim: the admission constructor rejects longer authority and other digests;
// its shared budget permits one request in total, then only bounded lease
// follow-ups. Ordinary server instances have no fixture method budget.
func TestQualificationAdmissionBudget(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	var pid atomic.Int64
	pid.Store(int64(os.Getpid()))
	if _, err := NewQualificationAdmission(e.Manager, e.Policy.ExecutableSHA256, e.UID, &pid); err == nil {
		t.Fatal("long authority admitted")
	}
	e.Manager.Close()
	p := e.Policy.Clone()
	p.MaxLeaseSeconds = 5
	m, err := lease.New(p, e.Store, e.Owner, lease.Options{MaxActive: 1, MaxPending: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = NewQualificationAdmission(m, "wrong", e.UID, &pid); err == nil {
		t.Fatal("other digest admitted")
	}
	s, err := NewQualificationAdmission(m, p.ExecutableSHA256, e.UID, &pid)
	if err != nil {
		t.Fatal(err)
	}
	if !s.qualificationCall("lease.request") || !s.qualificationCall("lease.release") || s.qualificationCall("lease.request") {
		t.Fatal("one request budget bypassed")
	}
	if s.qualificationCall("status") {
		t.Fatal("unknown method admitted")
	}
	for i := 0; i < 4; i++ {
		if !s.qualificationCall("lease.renew") {
			t.Fatal("bounded follow-up refused")
		}
	}
	if s.qualificationCall("lease.renew") {
		t.Fatal("method budget exceeded")
	}
	if New(m).qualificationCall != nil {
		t.Fatal("ordinary admission changed")
	}
}
