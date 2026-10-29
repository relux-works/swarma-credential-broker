package policy_test

import (
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"testing"
)

// Claim: observer authority is explicit and disjoint from every configured
// worker UID (including disabled accounts); default policies add no observer.
func TestAllowlistRoleConfiguration(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	p := e.Policy.Clone()
	observer := e.UID + 1
	if p.Observer(observer) {
		t.Fatal("implicit observer")
	}
	p.ObserverUIDs = []uint32{observer}
	if p.Validate(e.UID) != nil || !p.Peer(observer) || !p.Observer(observer) {
		t.Fatal("explicit observer refused")
	}
	for _, mode := range []string{"worker", "disabled-worker", "broker", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			q := p.Clone()
			switch mode {
			case "worker":
				q.Accounts[0].AllowedUIDs = append(q.Accounts[0].AllowedUIDs, observer)
			case "disabled-worker":
				q.Accounts[1].Enabled = false
				q.Accounts[1].AllowedUIDs = []uint32{observer}
			case "broker":
				q.ObserverUIDs = []uint32{e.UID}
				// Isolate broker/observer separation from the independent worker
				// collision gate; otherwise that second gate masks this case.
				q.Accounts[0].AllowedUIDs = nil
			case "duplicate":
				q.ObserverUIDs = append(q.ObserverUIDs, observer)
			}
			if q.Validate(e.UID) == nil {
				t.Fatal("colliding authority admitted")
			}
			if _, err := q.Admit(observer, e.Account, "example"); err == nil {
				t.Fatal("observer worker admission")
			}
		})
	}
}
