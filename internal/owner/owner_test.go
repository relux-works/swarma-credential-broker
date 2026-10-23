package owner

import (
	"context"
	"testing"
)

// Claim: the shipped owner adapter cannot issue material or perform refresh without a real reconciled owner implementation.
func TestStopped(t *testing.T) {
	s := Stopped{}
	for _, read := range []func() (Snapshot, error){func() (Snapshot, error) { return s.Snapshot(context.Background(), "fixture") }, func() (Snapshot, error) { return s.Refresh(context.Background(), "fixture", 1) }} {
		v, err := read()
		if err != nil || v.State != Unavailable || v.AccessToken != "" || v.Qualified || v.Fresh {
			t.Fatal("stopped owner usable")
		}
	}
}
