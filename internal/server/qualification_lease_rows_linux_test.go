//go:build linux

package server

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
)

// Claim: only the three fixed row budgets are constructible. Request and total
// method ceilings refuse and count every excess/unknown method; production New
// has no fixture budget. This does not substitute for kernel origin row tests.
func TestLeaseRowAuthorityBudget(t *testing.T) {
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) { p.MaxLeaseSeconds = 30 })
	var pid atomic.Int64
	pid.Store(int64(os.Getpid()))
	for _, c := range []struct {
		id                string
		requests, methods int
	}{{"renew-unknown-digest", 1, 3}, {"renew-contention", 8, 24}, {"queue-full", 65, 195}} {
		t.Run(c.id, func(t *testing.T) {
			s, b, err := NewQualificationLeaseRow(e.Manager, e.Policy.ExecutableSHA256, e.UID, &pid, c.id, func(int) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < c.requests; i++ {
				if !s.qualificationCall("lease.request") {
					t.Fatal("request below ceiling refused")
				}
			}
			if s.qualificationCall("lease.request") {
				t.Fatal("request ceiling bypassed")
			}
			for i := c.requests; i < c.methods; i++ {
				if !s.qualificationCall("lease.renew") {
					t.Fatal("method below ceiling refused")
				}
			}
			if s.qualificationCall("lease.release") || s.qualificationCall("status") {
				t.Fatal("method ceiling bypassed")
			}
			r, m, f := b.Counts()
			if r != c.requests || m != c.methods || f != 3 {
				t.Fatal("budget counters", r, m, f)
			}
		})
	}
	for _, id := range []string{"account-unknown", "unknown", ""} {
		if _, _, err := NewQualificationLeaseRow(e.Manager, e.Policy.ExecutableSHA256, e.UID, &pid, id, func(int) bool { return true }); err == nil {
			t.Fatal("undeclared row admitted")
		}
	}
	if _, _, err := NewQualificationLeaseRow(e.Manager, e.Policy.ExecutableSHA256, e.UID, &pid, "queue-full", nil); err == nil {
		t.Fatal("missing origin admitted")
	}
	if _, _, err := NewQualificationLeaseRow(e.Manager, "wrong", e.UID, &pid, "queue-full", func(int) bool { return true }); err == nil {
		t.Fatal("wrong image admitted")
	}
	if New(e.Manager).qualificationCall != nil {
		t.Fatal("production authority changed")
	}
}
