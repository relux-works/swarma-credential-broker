//go:build linux

package qualify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

type lifecycleFact struct {
	Scenario              string
	Origins               []ownerEpochFact
	Crashes               []egress.TerminationFacts
	Gate                  *lifecycleGate
	Writers               []writerFact
	Budgets               []ownerBudget
	Clocks                [2]int
	Frames                [2]int
	Inputs                []ownerStopFact
	Endpoint              []string
	Starts, Stops, Events int
	Peak                  int
	Checkpoints           [2]authowner.Checkpoint
	Calls                 []string
}

func lifecyclePublication(root string, r wire.LeaseResult, token string, generation uint64) error {
	cp, _, _, e := ownerRecordsBound(root, 32)
	b, x := os.ReadFile(filepath.Join(ownerAccountPath(root), store.LeaseName(r.LeaseID)))
	var rec lease.Record
	if e != nil || x != nil || wire.Decode(b, &rec) != nil || r.Payload.AccessToken != token || r.Payload.AccountID != "synthetic-vendor" || r.Payload.PlanType != "plus" || cp.TokenGeneration != generation || rec.OfferedGeneration != generation || rec.OfferedDigest != lease.Digest(token) || rec.State != "active" {
		return errors.New("lifecycle publication/generation mismatch")
	}
	return nil
}
func lifecyclePending(cp authowner.Checkpoint, intents []authowner.Intent, events []authowner.Evidence) error {
	if cp.State != "owner_unavailable" || cp.TokenGeneration != 1 || cp.StoreGeneration != 1 || len(intents) != 1 || cp.PendingAttempt != intents[0].Attempt || !cp.RetryAt.IsZero() || cp.Failures != 0 {
		return errors.New("ambiguous/partial owner resolved or retried")
	}
	for _, e := range events {
		if e.Phase == "resolved" || e.Outcome == authowner.Safe {
			return errors.New("ambiguous owner acquired resolution")
		}
	}
	return nil
}
func lifecycleRun(ctx context.Context, broker, candidate *os.File, digest, scenario string) (fact lifecycleFact, execution rowExecution, network map[string]egress.Counts, err error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		err = errors.New("lifecycle requires row deadline")
		return
	}
	work, cancel := context.WithDeadline(ctx, deadline.Add(-5*time.Second))
	defer cancel()
	fact.Scenario = scenario
	fact.Crashes = []egress.TerminationFacts{}
	network = map[string]egress.Counts{}
	root, e := os.MkdirTemp("", "qualification-lifecycle-")
	if e != nil {
		err = e
		return
	}
	defer func() {
		if e := os.RemoveAll(root); e != nil {
			err = errors.Join(err, e)
		}
	}()
	c, tokens, e := ownerSeed(root, digest, scenario)
	if e != nil {
		err = e
		return
	}
	audit, e := newLifecycleAudit(root)
	if e != nil {
		err = e
		return
	}
	defer unix.Close(audit.fd)
	m := &lifecycleModel{c: c, initial: c.Now, ctx: work, broker: broker, audit: audit}
	var current *ownerSession
	defer func() {
		if current != nil {
			current.cancel()
			<-current.done
			current.ch.r.Close()
			current.ch.w.Close()
			current.origin.Close()
		}
		for _, w := range m.writers {
			w.cleanup()
			fact.Writers = append(fact.Writers, w.fact)
			for k, v := range w.session.report.Summary {
				n := network[k]
				n.Allowed += v.Allowed
				n.Refused += v.Refused
				network[k] = n
			}
		}
		if e := audit.drain("closed"); e != nil {
			err = errors.Join(err, e)
		}
		fact.Starts, fact.Stops, fact.Events = m.starts, m.stops, audit.events
		fact.Peak = m.peak
		fact.Inputs = m.inputs
		fact.Endpoint = m.endpoint
		fact.Gate = m.gate
	}()
	var grant wire.LeaseResult
	call := func(s *ownerSession, op string, value any, want string) (wire.LeaseResult, error) {
		r, e := s.call(op, value, want)
		status := want
		if errors.Is(e, errOwnerHeld) {
			status = "interrupted-no-response"
		} else if e == nil && r.Payload.AccessToken != "" {
			status = "published"
		} else if e != nil {
			status = "failed"
		}
		fact.Calls = append(fact.Calls, op+":"+status)
		if e == nil {
			e = audit.drain("owner")
		}
		return r, e
	}
	step := func(s *ownerSession, epoch int, when time.Time) error {
		if when.Before(m.c.Now) {
			return errors.New("lifecycle clock reversed")
		}
		m.c.Now = when
		fact.Clocks[epoch-1]++
		if fact.Clocks[epoch-1] > 3 {
			return errors.New("lifecycle clock budget")
		}
		_, e := call(s, "clock", when, "")
		return e
	}
	pending := func() error {
		cp, is, es, e := m.records()
		if e != nil {
			return e
		}
		if scenario == "cleanup-incomplete" {
			for _, event := range es {
				if event.Phase == "absent" {
					return errors.New("partial constructor recorded absence")
				}
			}
		}
		return lifecyclePending(cp, is, es)
	}
	for epoch := 1; epoch <= 2; epoch++ {
		c.Epoch = epoch
		c.Now = m.c.Now
		s, e := startOwner(work, c, broker, candidate, m)
		if e != nil {
			err = e
			return
		}
		current = s
		startup, e := s.receive("startup")
		if epoch == 2 && scenario != "safe-safe-committed" && scenario != "rotation-committed" && scenario != "cleanup-complete" {
			if proofError := pending(); proofError != nil {
				err = proofError
				return
			}
		}
		var stage string
		if e != nil || startup.Error != "" || wire.Decode(startup.Data, &stage) != nil || stage != "lease" {
			err = errors.New("lifecycle actual lease startup missing")
			return
		}
		run := func() error {
			if epoch == 1 {
				grant, e = call(s, "lease.request", nil, "")
				if e != nil {
					return e
				}
				if e = lifecyclePublication(root, grant, tokens[0], 1); e != nil {
					return e
				}
				renew := wire.Renew{LeaseID: grant.LeaseID, RejectedSHA256: lease.Digest(tokens[0])}
				want := "lease_owner_unavailable"
				if scenario == "safe-safe-committed" {
					want = "renew_failed"
				}
				if scenario == "rotation-committed" {
					want = ""
				}
				rotated, e := call(s, "lease.renew", renew, want)
				crash := scenario == "rotation-no-store" || scenario == "rotation-no-proof" || scenario == "cleanup-incomplete" || scenario == "cleanup-complete"
				if crash {
					if !errors.Is(e, errOwnerHeld) {
						return errors.New("exact synchronous crash gate missing")
					}
					return m.crash(s)
				}
				if e != nil {
					return e
				}
				if scenario == "safe-safe-committed" {
					fact.Clocks[0]++
					cp, is, es, e := m.records()
					if e != nil || len(is) != 1 || len(es) != 5 || cp.State != owner.Transient || cp.Failures != 1 || !cp.RetryAt.Equal(m.initial.Add(4*time.Second)) || !es[len(es)-1].ResolvedAt.Equal(m.initial.Add(3*time.Second)) {
						return errors.New("Safe retry does not start at resolution")
					}
					if _, e = call(s, "lease.renew", renew, "renew_failed"); e != nil {
						return e
					}
					if m.starts != 1 {
						return errors.New("Safe early demand started writer")
					}
				} else if scenario == "rotation-committed" {
					if e = lifecyclePublication(root, rotated, tokens[1], 2); e != nil {
						return e
					}
				} else if e = pending(); e != nil {
					return e
				}
				if _, e = call(s, "lease.release", wire.Release{LeaseID: grant.LeaseID}, ""); e != nil {
					return e
				}
				if scenario == "ambiguous-old" || scenario == "ambiguous-new" {
					if _, e = call(s, "lease.request", nil, "lease_owner_unavailable"); e != nil {
						return e
					}
					if e = step(s, epoch, m.c.Now.Add(61*time.Second)); e != nil {
						return e
					}
					if _, e = call(s, "lease.request", nil, "lease_owner_unavailable"); e != nil {
						return e
					}
					return pending()
				}
				return nil
			}
			renew := wire.Renew{LeaseID: grant.LeaseID, RejectedSHA256: lease.Digest(tokens[0])}
			switch scenario {
			case "safe-safe-committed":
				grant, e = call(s, "lease.request", nil, "")
				if e != nil {
					return e
				}
				if e = lifecyclePublication(root, grant, tokens[0], 1); e != nil {
					return e
				}
				renew.LeaseID = grant.LeaseID
				cp, _, _, e := m.records()
				if e != nil || cp.Failures != 1 || !cp.RetryAt.Equal(m.initial.Add(4*time.Second)) {
					return errors.New("Safe retry lost at restart")
				}
				if _, e = call(s, "lease.renew", renew, "renew_failed"); e != nil {
					return e
				}
				if m.starts != 1 {
					return errors.New("Safe pre-due restart started")
				}
				if e = step(s, epoch, cp.RetryAt); e != nil {
					return e
				}
				if _, e = call(s, "lease.renew", renew, "renew_failed"); e != nil {
					return e
				}
				cp, _, _, e = m.records()
				if e != nil || cp.Failures != 2 || !cp.RetryAt.Equal(m.c.Now.Add(2*time.Second)) || m.starts != 2 {
					return errors.New("second Safe backoff/history mismatch")
				}
				due := cp.RetryAt
				if e = step(s, epoch, due.Add(-time.Second)); e != nil {
					return e
				}
				if _, e = call(s, "lease.renew", renew, "renew_failed"); e != nil {
					return e
				}
				if m.starts != 2 {
					return errors.New("Safe early second demand started")
				}
				if e = step(s, epoch, due); e != nil {
					return e
				}
				for i := 0; i < 2; i++ {
					r, e := call(s, "lease.renew", renew, "")
					if e != nil {
						return e
					}
					if e = lifecyclePublication(root, r, tokens[1], 2); e != nil {
						return e
					}
				}
				_, e = call(s, "lease.release", wire.Release{LeaseID: grant.LeaseID}, "")
				return e
			case "rotation-committed":
				r, e := call(s, "lease.request", nil, "")
				if e != nil {
					return e
				}
				if e = lifecyclePublication(root, r, tokens[1], 2); e != nil {
					return e
				}
				_, e = call(s, "lease.release", wire.Release{LeaseID: r.LeaseID}, "")
				return e
			case "cleanup-complete":
				r, e := call(s, "lease.renew", renew, "")
				if e != nil {
					return e
				}
				if e = lifecyclePublication(root, r, tokens[1], 2); e != nil {
					return e
				}
				q, e := call(s, "lease.request", nil, "")
				if e != nil {
					return e
				}
				if e = lifecyclePublication(root, q, tokens[1], 2); e != nil {
					return e
				}
				for _, id := range []string{grant.LeaseID, q.LeaseID} {
					if _, e = call(s, "lease.release", wire.Release{LeaseID: id}, ""); e != nil {
						return e
					}
				}
				return nil
			default:
				if scenario != "ambiguous-old" && scenario != "ambiguous-new" {
					if _, e = call(s, "lease.renew", renew, "lease_owner_unavailable"); e != nil {
						return e
					}
					if _, e = call(s, "lease.release", wire.Release{LeaseID: grant.LeaseID}, ""); e != nil {
						return e
					}
				}
				if _, e = call(s, "lease.request", nil, "lease_owner_unavailable"); e != nil {
					return e
				}
				if scenario == "rotation-no-store" || scenario == "rotation-no-proof" {
					if e = step(s, epoch, m.c.Now.Add(61*time.Second)); e != nil {
						return e
					}
				}
				if _, e = call(s, "lease.request", nil, "lease_owner_unavailable"); e != nil {
					return e
				}
				return pending()
			}
		}
		e = run()
		if e != nil {
			err = e
			return
		}
		crashed := s.termination.Facts().Valid()
		if !crashed {
			if e = s.close(); e != nil {
				err = e
				return
			}
		} else {
			s.ch.r.Close()
			s.ch.w.Close()
			s.origin.Close()
			s.cancel()
		}
		current = nil
		origin := ownerEpochFact{Command: s.command, Image: s.image, Verified: s.execution.Handshake, Entered: s.execution.Started, Joined: s.execution.Joined, Exit: s.execution.CaseExit, Waits: s.waits}
		if crashed {
			cert := s.termination.Facts()
			origin.Verified = cert.Verified
			origin.Entered = cert.Entered
			origin.Exit = cert.Exit
			fact.Crashes = append(fact.Crashes, cert)
		}
		fact.Origins = append(fact.Origins, origin)
		fact.Budgets = append(fact.Budgets, s.budget)
		fact.Frames[epoch-1] = s.ch.reads + s.ch.writes
		execution = s.execution
		for k, v := range s.report.Summary {
			n := network[k]
			n.Allowed += v.Allowed
			n.Refused += v.Refused
			network[k] = n
		}
		cp, _, _, e := m.records()
		if e != nil {
			err = e
			return
		}
		fact.Checkpoints[epoch-1] = cp
	}
	return
}
