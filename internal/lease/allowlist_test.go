package lease_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: source-check I/O is outside state locks, and replacement/cancellation/
// failed-store transition never lets its late result authorize the old tuple.
func TestAllowlistFinalGenerationFence(t *testing.T) {
	for _, mode := range []string{"valid", "source-error", "replace", "cancel", "failed-store"} {
		t.Run(mode, func(t *testing.T) {
			var env *testutil.Env
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := lease.Options{ObservePolicy: func(context.Context, policy.Policy) error {
				if mode == "source-error" {
					return errors.New("synthetic-private-sentinel")
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "replace" || mode == "failed-store" {
					p := env.Policy.Clone()
					p.Generation++
					if mode == "failed-store" {
						env.Store.Close()
					}
					err := env.Manager.Replace(p)
					if mode == "replace" && err != nil {
						t.Fatal(err)
					}
					if mode == "failed-store" && err == nil {
						t.Fatal("store failure not applied")
					}
				}
				return nil
			}}
			env = testutil.NewPolicy(t, opts, func(p *policy.Policy) { p.ObserverUIDs = []uint32{p.BrokerUID + 1} })
			r := wire.AllowlistRequest{TargetUID: env.UID, Account: env.Account, Profile: env.Request.Profile, Harness: env.Request.Harness, Channel: env.Request.Channel, Binding: env.Request.Binding, ExpectedGeneration: env.Policy.Generation}
			out := env.Manager.Call(ctx, env.UID+1, "allowlist.check", r, time.Now())
			if mode == "valid" {
				if out.Err != nil || out.Result == nil {
					t.Fatal("valid observation refused")
				}
			} else {
				if out.Err == nil || out.Result != nil {
					t.Fatal("late source result admitted")
				}
				code := lease.ErrorCode(out.Err)
				if code != "allowlist_unavailable" && code != "request_deadline_exceeded" {
					t.Fatal("not a closed source refusal")
				}
			}
			if mode != "failed-store" {
				env.NoLeaseRecords(t)
			}
			if calls, _ := env.Owner.Counts(); calls != 0 {
				t.Fatal("observation refreshed")
			}
		})
	}
}
