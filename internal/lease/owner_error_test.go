package lease_test

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type unchangedOwner struct{ owner.Owner }

func (unchangedOwner) Refresh(context.Context, string, uint64) (owner.Snapshot, error) {
	return owner.Snapshot{State: owner.Unavailable}, owner.ErrRenewFailed
}

// Claim: an unchanged-material refusal from the contained owner crosses the
// lease boundary as renew_failed; normal initial issuance remains usable.
func TestOwnerUnchangedRefusalPreserved(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	e.Manager.Close()
	m, err := lease.New(e.Policy, e.Store, unchangedOwner{e.Owner}, lease.Options{Now: func() time.Time { return e.Now }}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	initial := m.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
	if initial.Err != nil {
		t.Fatal("positive lease control", initial.Err)
	}
	r := initial.Result.(wire.LeaseResult)
	out := m.Call(context.Background(), e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now())
	if lease.ErrorCode(out.Err) != "renew_failed" {
		t.Fatal("unchanged refusal lost", lease.ErrorCode(out.Err))
	}
}
