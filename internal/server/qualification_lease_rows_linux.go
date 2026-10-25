//go:build linux

package server

import (
	"sync"
	"sync/atomic"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// LeaseRowBudget belongs only to a row-scoped synthetic listener. Counts are
// parent observations; clients cannot supply or reset them.
type LeaseRowBudget struct {
	mu                         sync.Mutex
	requests, methods, refused int
	maxRequests, maxMethods    int
}

func (b *LeaseRowBudget) admit(method string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.methods >= b.maxMethods || (method != "lease.request" && method != "lease.renew" && method != "lease.release") || method == "lease.request" && b.requests >= b.maxRequests {
		b.refused++
		return false
	}
	b.methods++
	if method == "lease.request" {
		b.requests++
	}
	return true
}
func (b *LeaseRowBudget) Counts() (requests, methods, refused int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests, b.methods, b.refused
}

// NewQualificationLeaseRow is separate from the single-lease authority. It
// permits only these fixed synthetic scripts, with the same kernel PID/UID and
// live attested origin check. Production New and manager defaults are unchanged.
func NewQualificationLeaseRow(m *lease.Manager, digest string, uid uint32, pid *atomic.Int64, row string, live func(int) bool) (*Server, *LeaseRowBudget, error) {
	requests, methods := 0, 0
	switch row {
	case "renew-unknown-digest":
		requests, methods = 1, 3
	case "renew-contention":
		requests, methods = 8, 24
	case "queue-full":
		requests, methods = 65, 195
	default:
		return nil, nil, wire.Refuse("lease_owner_unavailable")
	}
	if m == nil || m.Policy().MaxLeaseSeconds != 30 || len(m.Policy().Accounts) != 2 || live == nil {
		return nil, nil, wire.Refuse("lease_owner_unavailable")
	}
	s, _, err := newQualificationPeer(m, digest, uid, pid, false, live)
	if err != nil {
		return nil, nil, err
	}
	budget := &LeaseRowBudget{maxRequests: requests, maxMethods: methods}
	s.qualificationCall = budget.admit
	return s, budget, nil
}
