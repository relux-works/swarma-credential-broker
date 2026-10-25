//go:build linux

package qualify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

func parallelRun(ctx context.Context, broker, candidate *os.File, digest, scenario string) (fact lifecycleFact, execution rowExecution, network map[string]egress.Counts, err error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		err = errors.New("parallel row deadline missing")
		return
	}
	work, cancel := context.WithDeadline(ctx, deadline.Add(-5*time.Second))
	defer cancel()
	ownerDiagnosticScenario(work, scenario)
	defer func() { ownerDiagnosticFailure(work, err) }()
	root, e := os.MkdirTemp("", "qualification-parallel-")
	if e != nil {
		err = e
		return
	}
	defer func() { err = errors.Join(err, os.RemoveAll(root)) }()
	c, tokens, e := ownerSeed(root, digest, scenario)
	if e != nil {
		err = e
		return
	}
	c.Member = "O1"
	audit, e := newLifecycleAudit(root)
	if e != nil {
		err = e
		return
	}
	defer unix.Close(audit.fd)
	fact.Scenario = scenario
	fact.Crashes = []egress.TerminationFacts{}
	fact.Calls = []string{}
	fact.Parallel = &parallelFacts{Candidates: []parallelCandidate{}, Cleanup: []string{}}
	network = map[string]egress.Counts{}
	m := &lifecycleModel{c: c, initial: c.Now, ctx: work, broker: broker, audit: audit, endpoint: []string{}}
	h := &parallelHarness{ctx: work, ledger: m, fact: &fact}
	defer func() {
		for _, s := range h.sessions {
			if !s.closed {
				s.base.cancel()
				endWait := ownerDiagnosticWait(work, "parallel cleanup join")
				<-s.base.done
				endWait(nil)
				s.mux.close()
				s.base.origin.Close()
				for _, f := range s.images {
					f.Close()
				}
			}
			for k, v := range s.base.report.Summary {
				n := network[k]
				n.Allowed += v.Allowed
				n.Refused += v.Refused
				network[k] = n
			}
		}
		for _, w := range m.writers {
			planned := w.fact.Stop.Valid()
			w.cleanup()
			if !planned {
				w.fact.Origin.Joined = w.session.execution.Joined
				w.fact.Origin.Exit = w.session.execution.CaseExit
				w.fact.Origin.Waits = w.session.waits
				if w.session.err == nil || w.session.waits != 1 || !w.session.report.Incomplete {
					err = errors.Join(err, errors.New("parallel forced cleanup incomplete"))
				} else {
					fact.Parallel.Cleanup = append(fact.Parallel.Cleanup, w.session.err.Error())
				}
			}
			fact.Writers = append(fact.Writers, w.fact)
			for k, v := range w.session.report.Summary {
				n := network[k]
				n.Allowed += v.Allowed
				n.Refused += v.Refused
				network[k] = n
			}
		}
		err = errors.Join(err, audit.drain("closed"))
		fact.Starts = m.starts
		fact.Stops = m.stops
		fact.Events = audit.events
		fact.Peak = m.peak
		fact.Inputs = m.inputs
		fact.Endpoint = m.endpoint
		fact.Gate = m.gate
	}()
	run := func() error {
		o1, e := h.start(c, broker, candidate)
		if e != nil {
			return e
		}
		if e = h.startup(o1); e != nil {
			return e
		}
		var grants []wire.LeaseResult
		count := 1
		if strings.HasPrefix(scenario, "contention-unresolved-") {
			count = 2
		}
		for i := 0; i < count; i++ {
			r, e := h.call(o1, "lease.request", nil, "", tokens[0], 1)
			if e != nil {
				return e
			}
			grants = append(grants, r)
		}
		renew := func(r wire.LeaseResult, token string) wire.Renew {
			return wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(token)}
		}
		if parallelUnresolved(scenario) {
			id, e := h.command(o1, "lease.renew", renew(grants[0], tokens[0]))
			if e != nil {
				return e
			}
			_, e = h.take(o1, func(f parallelFrame) bool { return false })
			if !errors.Is(e, errOwnerHeld) {
				return fmt.Errorf("running gate missing: %v", e)
			}
			fact.Parallel.Results = append(fact.Parallel.Results, parallelResult{Member: o1.member, Method: "lease.renew", LeaseID: grants[0].LeaseID, Rejected: lease.Digest(tokens[0]), Command: id, Error: "interrupted-no-response"})
			if e = m.crash(o1.base); e != nil {
				return e
			}
			if e = h.finish(o1, true); e != nil {
				return e
			}
		} else {
			if _, e = h.call(o1, "lease.renew", renew(grants[0], tokens[0]), "", tokens[1], 2); e != nil {
				return e
			}
			if _, e = h.call(o1, "lease.release", wire.Release{LeaseID: grants[0].LeaseID}, "", "", 0); e != nil {
				return e
			}
			if e = h.finish(o1, false); e != nil {
				return e
			}
		}
		cp, _, _, e := m.records()
		if e != nil {
			return e
		}
		fact.Checkpoints[0] = cp
		history, e := parallelHistory(root)
		if e != nil {
			return e
		}
		c.Epoch = 2
		c.Member = "O2"
		var winner *parallelSession
		if strings.HasPrefix(scenario, "contention-") {
			winner, e = h.contend(c, broker, candidate)
		} else {
			winner, e = h.start(c, broker, candidate)
			if e == nil {
				e = h.startup(winner)
			}
		}
		if e != nil {
			return e
		}
		if parallelUnresolved(scenario) {
			if e = parallelPending(m); e != nil {
				return e
			}
			if len(grants) == 2 {
				if e = h.overlap(winner, grants, tokens[0], "lease_owner_unavailable", "", 0); e != nil {
					return e
				}
			} else {
				if _, e = h.call(winner, "lease.renew", renew(grants[0], tokens[0]), "lease_owner_unavailable", "", 0); e != nil {
					return e
				}
			}
			if len(grants) == 2 {
				if _, e = h.call(winner, "lease.renew", renew(grants[0], tokens[0]), "lease_owner_unavailable", "", 0); e != nil {
					return e
				}
			}
			for _, r := range grants {
				if _, e = h.call(winner, "lease.release", wire.Release{LeaseID: r.LeaseID}, "", "", 0); e != nil {
					return e
				}
			}
			for i := 0; i < 2; i++ {
				if _, e = h.call(winner, "lease.request", nil, "lease_owner_unavailable", "", 0); e != nil {
					return e
				}
			}
			if e = parallelPending(m); e != nil {
				return e
			}
			if parallelPartial(scenario) {
				if e = m.writer.challenge(); e != nil {
					return e
				}
				fact.Parallel.LiveAtAssertion = true
			}
		} else {
			grants = nil
			count = 1
			if strings.HasPrefix(scenario, "contention-") {
				count = 2
			}
			for i := 0; i < count; i++ {
				r, e := h.call(winner, "lease.request", nil, "", tokens[1], 2)
				if e != nil {
					return e
				}
				grants = append(grants, r)
			}
			_, a2 := ownerMaterial(c.Now, "successor")
			if count == 2 {
				if e = h.overlap(winner, grants, tokens[1], "", a2, 3); e != nil {
					return e
				}
			} else {
				if _, e = h.call(winner, "lease.renew", renew(grants[0], tokens[1]), "", a2, 3); e != nil {
					return e
				}
			}
			for _, r := range grants {
				if _, e = h.call(winner, "lease.renew", renew(r, tokens[1]), "", a2, 3); e != nil {
					return e
				}
			}
			if m.starts != 2 {
				return errors.New("second successor or missing successor")
			}
			for _, r := range grants {
				if _, e = h.call(winner, "lease.release", wire.Release{LeaseID: r.LeaseID}, "", "", 0); e != nil {
					return e
				}
			}
		}
		if e = h.finish(winner, false); e != nil {
			return e
		}
		execution = winner.base.execution
		cp, _, _, e = m.records()
		fact.Checkpoints[1] = cp
		fact.Parallel.HistoryPreserved = parallelSameHistory(root, history)
		if !fact.Parallel.HistoryPreserved {
			return errors.New("parallel retained history changed")
		}
		return e
	}
	err = run()
	return
}
func (h *parallelHarness) contend(c ownerContext, broker, candidate *os.File) (*parallelSession, error) {
	var candidates []*parallelSession
	var gates []parallelFrame
	for _, member := range []string{"A", "B"} {
		c.Member = member
		s, e := h.start(c, broker, candidate)
		if e != nil {
			return nil, e
		}
		candidates = append(candidates, s)
	}
	for _, s := range candidates {
		f, e := h.take(s, func(f parallelFrame) bool { return f.Kind == "rpc" && f.Op == "constructor" })
		if e != nil {
			return nil, e
		}
		var member string
		if wire.Decode(f.Data, &member) != nil || member != s.member {
			return nil, errors.New("contender context")
		}
		gates = append(gates, f)
		h.fact.Parallel.Candidates = append(h.fact.Parallel.Candidates, parallelCandidate{Member: s.member, Context: s.base.command[2], Constructor: true, Origin: s.index})
	}
	if !candidates[0].base.origin.Live(int(candidates[0].base.pid.Load())) || !candidates[1].base.origin.Live(int(candidates[1].base.pid.Load())) {
		return nil, errors.New("contenders not simultaneously live")
	}
	ownerDiagnosticPhase(h.ctx, "both constructors held")
	h.fact.Parallel.Together = true
	win := 0
	if strings.HasSuffix(c.Scenario, "-b") {
		win = 1
	}
	lose := 1 - win
	winner, loser := candidates[win], candidates[lose]
	if e := winner.mux.replyTo(gates[win], nil, nil); e != nil {
		return nil, e
	}
	ready, e := h.take(winner, func(f parallelFrame) bool { return f.Kind == "rpc" && f.Op == "ready" })
	if e != nil {
		return nil, e
	}
	if e = h.lockHeld(); e != nil {
		return nil, e
	}
	h.fact.Parallel.Candidates[win].Ready = true
	h.fact.Parallel.Candidates[win].LockHeld = true
	ownerDiagnosticPhase(h.ctx, "winner ready and store lock held")
	h.fact.Parallel.Winner = winner.member
	if e = loser.mux.replyTo(gates[lose], nil, nil); e != nil {
		return nil, e
	}
	startup, e := h.take(loser, func(f parallelFrame) bool { return true })
	var stage string
	if e != nil || startup.Kind != "notice" || startup.ID != 0 || startup.Op != "startup" || startup.Error != "owner_startup_refused" || wire.Decode(startup.Data, &stage) != nil || stage != "store" {
		return nil, errors.New("loser store startup failure missing")
	}
	h.fact.Parallel.Candidates[lose].Startup = stage
	ownerDiagnosticPhase(h.ctx, "loser store refusal received")
	h.fact.Parallel.Candidates[lose].Error = startup.Error
	if e = h.finish(loser, false); e != nil {
		return nil, e
	}
	if e = winner.mux.replyTo(ready, nil, nil); e != nil {
		return nil, e
	}
	if e = h.startup(winner); e != nil {
		return nil, e
	}
	h.fact.Parallel.Candidates[win].Startup = "lease"
	return winner, nil
}
func (h *parallelHarness) overlap(s *parallelSession, grants []wire.LeaseResult, rejected, want, token string, generation uint64) error {
	first, e := h.command(s, "lease.renew", wire.Renew{LeaseID: grants[0].LeaseID, RejectedSHA256: lease.Digest(rejected)})
	if e != nil {
		return e
	}
	isEvent := func(f parallelFrame, kind, id string) bool {
		var ev lease.Event
		return f.Kind == "rpc" && f.Op == "call-event" && wire.Decode(f.Data, &ev) == nil && ev.Kind == kind && ev.LeaseID == id
	}
	gate, e := h.take(s, func(f parallelFrame) bool { return isEvent(f, "dequeue", grants[0].LeaseID) })
	if e != nil {
		return e
	}
	ownerDiagnosticPhase(h.ctx, "first dequeue held")
	overlap := &parallelOverlap{First: grants[0].LeaseID, Second: grants[1].LeaseID, Dequeue: h.sequence, Hold: "dequeue"}
	if want == "" {
		if e = s.mux.replyTo(gate, nil, nil); e != nil {
			return e
		}
		gate, e = h.take(s, func(f parallelFrame) bool {
			var v struct {
				Method string `json:"method"`
			}
			return f.Kind == "rpc" && f.Op == "native" && json.Unmarshal(f.Data, &v) == nil && v.Method == "account/read"
		})
		if e != nil {
			return e
		}
		ownerDiagnosticPhase(h.ctx, "native account/read held")
		overlap.Hold = "native"
	}
	second, e := h.command(s, "lease.renew", wire.Renew{LeaseID: grants[1].LeaseID, RejectedSHA256: lease.Digest(rejected)})
	if e != nil {
		return e
	}
	arrival, e := h.take(s, func(f parallelFrame) bool { return isEvent(f, "arrival", grants[1].LeaseID) })
	if e != nil {
		return e
	}
	ownerDiagnosticPhase(h.ctx, "second arrival held")
	overlap.Arrival = h.sequence
	if e = s.mux.replyTo(arrival, nil, nil); e != nil {
		return e
	}
	h.sequence++
	overlap.Resume = h.sequence
	h.fact.Parallel.Overlap = overlap
	if e = h.serve(s, gate); e != nil {
		return e
	}
	// Call's response observation is after account work and before return. Hold
	// one caller there while its neighbor completes Call and Publish, so Publish
	// does not race the neighbor's intentionally nonblocking owner Snapshot.
	response, e := h.take(s, func(f parallelFrame) bool {
		return isEvent(f, "response", grants[0].LeaseID) || isEvent(f, "response", grants[1].LeaseID)
	})
	if e != nil {
		return e
	}
	ownerDiagnosticPhase(h.ctx, "response callback held")
	held, other := first, second
	if isEvent(response, "response", grants[1].LeaseID) {
		held, other = second, first
	}
	if _, e = h.result(s, other, want, token, generation); e != nil {
		return e
	}
	if e = s.mux.replyTo(response, nil, nil); e != nil {
		return e
	}
	_, e = h.result(s, held, want, token, generation)
	return e
}
