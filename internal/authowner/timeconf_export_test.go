//go:build linux

package authowner

import (
	"context"
	"testing"
	"time"
)

// ConfidenceFixture exposes existing synthetic vendor/manager fixtures only to
// external tests, so the production adapter can be exercised without a cycle.
type ConfidenceFixture struct{ f *fixture }

func NewConfidenceFixture(t *testing.T) *ConfidenceFixture {
	t.Helper()
	return &ConfidenceFixture{newFixture(t, "hang")}
}
func (x *ConfidenceFixture) Now() time.Time   { return x.f.t.now }
func (x *ConfidenceFixture) Use(c Confidence) { x.f.e.confidence = c }
func (x *ConfidenceFixture) Admit(ctx context.Context) error {
	return x.f.e.AdmitFreshHome(ctx, x.f.c.Accounts[0].Label)
}
func (x *ConfidenceFixture) Renew(ctx context.Context) error {
	_, err := x.f.e.Refresh(ctx, x.f.c.Accounts[0].Label, 1)
	return err
}
func (x *ConfidenceFixture) Records() (map[string][]byte, error) { return x.f.disk.Records() }
func (x *ConfidenceFixture) Starts() int                         { return x.f.m.count() }
func (x *ConfidenceFixture) Gate(started chan struct{}, gate <-chan struct{}) {
	x.f.m.mu.Lock()
	defer x.f.m.mu.Unlock()
	x.f.m.started = started
	x.f.m.gate = gate
}
func (x *ConfidenceFixture) Stopped() bool {
	x.f.m.mu.Lock()
	defer x.f.m.mu.Unlock()
	for _, o := range x.f.m.observation {
		if o.StopCompleted && o.Empty && o.PopulatedZero {
			return true
		}
	}
	return false
}
