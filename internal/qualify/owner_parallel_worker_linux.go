//go:build linux

package qualify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func parallelScenario(s string) bool {
	switch s {
	case "death-live", "death-complete", "stop-successor", "contention-resolved-a", "contention-resolved-b", "contention-unresolved-a", "contention-unresolved-b":
		return true
	}
	return false
}
func parallelUnresolved(s string) bool {
	return s == "death-live" || s == "death-complete" || strings.HasPrefix(s, "contention-unresolved-")
}
func parallelPartial(s string) bool { return parallelUnresolved(s) && s != "death-complete" }
func parallelCompose(c ownerContext, ch *ownerChannel) int {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	raw, _ := wire.Encode(c)
	mux := newParallelMux(ctx, ch, qualificationHash(raw), false)
	defer mux.close()
	ch.rpc = mux.call
	if mux.call("constructor", c.Member, nil) != nil {
		return 1
	}
	stage := "store"
	fail := func() int {
		if mux.send("notice", "startup", 0, stage, errors.New("owner_startup_refused")) != nil {
			return 1
		}
		f, e := mux.nextFrame()
		if e != nil || f.Op != "close" {
			return 1
		}
		return 0
	}
	s, e := store.Open(filepath.Join(c.Root, "metadata"), "synthetic-install", uint32(os.Geteuid()), false, nil)
	if e != nil {
		return fail()
	}
	defer s.Close()
	stage = "account"
	disk, e := s.Account(ownerLabel, false)
	if e != nil {
		return fail()
	}
	clock := &lifecycleClock{value: c.Now}
	adapter := &ownerAdapter{ch: ch, clock: clock}
	cfg := authowner.Config{Installation: "synthetic-install", DaemonInstance: lease.RandomID(), DaemonUnit: "synthetic-owner.service", WriterPrefix: "synthetic-writer-", PolicyGeneration: 1, Executable: "/proc/self/fd/6", ExecutableSHA256: c.Candidate, QualificationID: "synthetic-evidence", MaxAttempts: 4, ProactiveWindow: time.Minute, Accounts: []authowner.AccountConfig{{Label: ownerLabel, VendorID: "synthetic-vendor", Home: filepath.Join(c.Root, "home"), HomeID: c.HomeID, Disk: disk}}}
	stage = "owner"
	engine, e := authowner.New(ctx, cfg, adapter, adapter, nil)
	if e != nil {
		return fail()
	}
	defer engine.Close()
	p := ownerPolicy(c)
	stage = "lease"
	manager, e := lease.New(p, s, engine, lease.Options{Now: clock.now, MaxActive: 2, MaxPending: 2, MaxWaiters: 2, Observe: func(event lease.Event) {
		if mux.call("call-event", event, nil) != nil {
			cancel()
		}
	}, Qualification: func(_ context.Context, q policy.Policy) error {
		if !reflect.DeepEqual(p, q) {
			return errors.New("synthetic tuple mismatch")
		}
		return nil
	}}, false)
	if e != nil {
		return fail()
	}
	defer manager.Close()
	if mux.send("notice", "startup", 0, "lease", nil) != nil {
		return 1
	}
	active := make(chan struct{}, 2)
	counts := ownerBudget{}
	for i := 0; i < 12; i++ {
		cmd, e := mux.nextFrame()
		if e != nil {
			return 1
		}
		if cmd.Op == "close" {
			if len(active) != 0 {
				return 1
			}
			return 0
		}
		switch cmd.Op {
		case "lease.request":
			counts.Requests++
		case "lease.renew":
			counts.Renewals++
		case "lease.release":
			counts.Releases++
		default:
			return 1
		}
		if counts.Requests > 3 || counts.Renewals > 5 || counts.Releases > 2 || counts.Requests+counts.Renewals+counts.Releases > 8 {
			return 1
		}
		select {
		case active <- struct{}{}:
		default:
			return 1
		}
		go func(cmd parallelFrame) {
			result := parallelOutcome{}
			params, e := parallelParams(p, cmd)
			if e == nil {
				out := manager.Call(ctx, p.BrokerUID, cmd.Op, params, time.Now())
				result.PolicyGeneration = out.Generation
				e = out.Err
				if e == nil {
					if r, ok := out.Result.(wire.LeaseResult); ok {
						e = manager.Publish(ctx, p.BrokerUID, out.Generation, r, func(context.Context, time.Time) error { result.Lease = r; return nil })
					} else if r, ok := out.Result.(wire.ReleaseResult); ok {
						result.Release = r
					} else {
						e = errors.New("parallel result kind")
					}
				}
			}
			<-active
			if mux.send("notice", cmd.Op, cmd.ID, result, e) != nil {
				cancel()
			}
		}(cmd)
	}
	return 1
}

type parallelOutcome struct {
	Lease            wire.LeaseResult
	Release          wire.ReleaseResult
	PolicyGeneration uint64
}

func parallelParams(p policy.Policy, f parallelFrame) (any, error) {
	switch f.Op {
	case "lease.request":
		a := p.Accounts[0]
		return wire.LeaseRequest{Harness: "codex_cli", Profile: wire.Profile, Account: ownerLabel, Channel: "external-token", Binding: p.Binding(p.BrokerUID, a, wire.Profile), Network: []byte("null"), LaunchID: "synthetic-launch", Executor: wire.Executor{Version: "fixture", Capabilities: []string{"credential-injection/1"}}}, nil
	case "lease.renew":
		var v wire.Renew
		e := wire.Decode(f.Data, &v)
		return v, e
	case "lease.release":
		var v wire.Release
		e := wire.Decode(f.Data, &v)
		return v, e
	}
	return nil, errors.New("parallel operation")
}
