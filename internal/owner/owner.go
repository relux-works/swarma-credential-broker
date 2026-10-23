// Package owner defines the boundary to the durable, contained auth owner.
package owner

import (
	"context"
	"time"
)

const (
	Active      = "active"
	Transient   = "refresh_failed_transient"
	Reauth      = "reauth_required"
	Unavailable = "owner_unavailable"
)

// Snapshot is usable only after the adapter reconciles writer absence, store
// freshness, trusted time and exact release qualification. Material stays in memory.
type Snapshot struct {
	State            string
	AccessToken      string
	AccountID        string
	PlanType         string
	ExpiresAt        time.Time
	AuthorityUntil   time.Time
	Generation       uint64
	Trusted          bool
	Fresh            bool
	Qualified        bool
	PolicyGeneration uint64
	QualificationID  string
	ExecutableSHA256 string
}

// Owner must serialize all vendor work, including across daemon replacement.
// Refresh returns only after durable reconciliation; cancellation is not absence.
// No caller holds its state lock over either method. Errors contain no material.
// New refresh admission requires live demand after Snapshot. Once admitted,
// Refresh uses the manager lifetime so a contained attempt can reconcile after
// its response waiters expire; waiter loss never authorizes a new attempt.
// Protected owner records use the account's owner-*.json namespace. The adapter
// validates/reconciles them before returning usable evidence; leases ignore them.
type Owner interface {
	Snapshot(context.Context, string) (Snapshot, error)
	Refresh(context.Context, string, uint64) (Snapshot, error)
}
type Stopped struct{}

func (Stopped) Snapshot(context.Context, string) (Snapshot, error) {
	return Snapshot{State: Unavailable}, nil
}
func (Stopped) Refresh(context.Context, string, uint64) (Snapshot, error) {
	return Snapshot{State: Unavailable}, nil
}
