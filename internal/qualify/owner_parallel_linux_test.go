//go:build linux && amd64

package qualify

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Claim: actual G-running owner death leaves a freshly challenged singleton W;
// partial/live and complete/Unknown recovery both refuse without a successor.
// An independent normal committed history admits exactly one A2 successor.
func TestOwnerDaemonDeathPair(t *testing.T) {
	for _, f := range lifecycleTest(t, "death-live", "death-complete", "stop-successor") {
		t.Logf("%s frames=%v entries=%d callbacks=%d children=%d", f.Scenario, f.Parallel.Frames, f.Parallel.Entries, len(f.Parallel.Events), f.Parallel.Children)
	}
}

// Claim: both real-lock schedules have two entered contenders, an actual store
// loser and one server. Distinct valid rejected-token Calls overlap at observed
// callbacks; positives publish A2/gen3 once, negatives retain Unknown. Arrival
// precedes queue insertion, so this establishes no queued-waiter count.
func TestOwnerReplacementContentionPair(t *testing.T) {
	for _, f := range lifecycleTest(t, "contention-resolved-a", "contention-resolved-b", "contention-unresolved-a", "contention-unresolved-b") {
		t.Logf("%s frames=%v entries=%d callbacks=%d children=%d", f.Scenario, f.Parallel.Frames, f.Parallel.Entries, len(f.Parallel.Events), f.Parallel.Children)
	}
}

// Claim: aggregate evidence cannot invent queued waiters, lose either observed
// callback, replace the actual store failure with a served refusal, substitute
// policy generation for token generation, or erase the running crash epoch.
func TestOwnerParallelEvidenceBounds(t *testing.T) {
	for _, scenario := range []string{"contention-resolved-a", "contention-unresolved-b"} {
		f := lifecycleTest(t, scenario)[0]
		raw, e := wire.Encode(f)
		if e != nil {
			t.Fatal(e)
		}
		plants := []func(*lifecycleFact){func(f *lifecycleFact) { f.Parallel.Overlap.Queued = 2 }, func(f *lifecycleFact) { f.Parallel.Overlap.Arrival = 0 }, func(f *lifecycleFact) { f.Parallel.Candidates[0].Startup = "lease_owner_unavailable" }, func(f *lifecycleFact) { f.Parallel.Results[0].OfferedGeneration = 0 }, func(f *lifecycleFact) { f.Starts++ }, func(f *lifecycleFact) { f.Parallel.HistoryPreserved = false }}
		for _, plant := range plants {
			var copy lifecycleFact
			if wire.Decode(raw, &copy) != nil {
				t.Fatal("parallel fact codec")
			}
			plant(&copy)
			if validParallelFact(copy) {
				t.Fatal("unobserved parallel evidence accepted")
			}
		}
	}
}

// Claim: this pure ordering check requires complete Stop and committed retained
// history before a successor, alongside the separate physical-join certificate
// checked by the Start path. A partial manager result alone is insufficient.
func TestOwnerParallelSuccessorOrder(t *testing.T) {
	after := authowner.Observation{Complete: true, StopCompleted: true, Empty: true, PopulatedZero: true}
	m := &lifecycleModel{writers: []*lifecycleWriter{{fact: writerFact{Attempt: "prior"}}}, inputs: []ownerStopFact{{After: after}}}
	cp := authowner.Checkpoint{TokenGeneration: 2, StoreGeneration: 2, RetainedAttempts: 1}
	is := make([]authowner.Intent, 2)
	var es []authowner.Evidence
	for _, phase := range []string{"submitted", "running", "stopping", "absent", "resolved"} {
		es = append(es, authowner.Evidence{Binding: authowner.Binding{Attempt: "prior"}, Phase: phase, Outcome: authowner.Committed})
	}
	if e := m.successorOrder(cp, is, es); e != nil {
		t.Fatal("valid successor rejected", e)
	}
	m.inputs[0].After.Complete = false
	if m.successorOrder(cp, is, es) == nil {
		t.Fatal("successor accepted before complete Stop")
	}
	m.inputs[0].After = after
	es[4].Outcome = authowner.Unknown
	if m.successorOrder(cp, is, es) == nil {
		t.Fatal("successor accepted without committed history")
	}
}

// Claim: the pure multiplex codec accepts a correlated frame/reply but refuses
// cross-context, sequence, direction, budget and replay errors independently of
// process capabilities. It never treats malformed evidence as a lease refusal.
func TestOwnerParallelMuxContracts(t *testing.T) {
	fresh := func() *parallelMux {
		return &parallelMux{ctx: context.Background(), context: strings.Repeat("a", 64), parent: true, pending: map[int]parallelWait{}, outstanding: map[int]string{}, events: make(chan parallelFrame, 2)}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	mCanceled := fresh()
	mCanceled.ctx = canceled
	if !errors.Is(mCanceled.call("ready", nil, nil), context.Canceled) {
		t.Fatal("canceled RPC admitted")
	}
	normal := parallelFrame{Seq: 1, ID: 1, Context: strings.Repeat("a", 64), Kind: "rpc", Op: "ready"}
	if e := fresh().accept(normal); e != nil {
		t.Fatal(e)
	}
	for _, plant := range []func(*parallelFrame){func(f *parallelFrame) { f.Context = strings.Repeat("b", 64) }, func(f *parallelFrame) { f.Seq = 2 }, func(f *parallelFrame) { f.ID = 2 }, func(f *parallelFrame) { f.Kind = "command" }, func(f *parallelFrame) { f.Kind = "reply" }} {
		f := normal
		plant(&f)
		if fresh().accept(f) == nil {
			t.Fatal("invalid multiplex frame accepted")
		}
	}
	m := fresh()
	m.reads = 512
	overflow := normal
	overflow.Seq = 513
	if m.accept(overflow) == nil {
		t.Fatal("frame overflow accepted")
	}
	m = fresh()
	answer := make(chan parallelFrame, 1)
	m.pending[1] = parallelWait{"ready", answer}
	f := normal
	f.Kind = "reply"
	if m.accept(f) != nil || (<-answer).ID != 1 {
		t.Fatal("correlated reply refused")
	}
	f.Seq = 2
	if m.accept(f) == nil {
		t.Fatal("duplicate reply accepted")
	}
}

// Claim: all two-row sides retain their 30s bound including every independent
// schedule and joined cleanup, and each artifact still needs parent binding.
func TestOwnerParallelRows(t *testing.T) {
	broker, _, _ := ownerTools(t)
	lifecycleObserverProbe(t)
	path, c, root := setup(t)
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = broker.Name()
	var records []rowExecutionRecord
	d.executions = &records
	for _, id := range []string{"daemon-death", "replacement-contention"} {
		q := qualification.Case{ID: id}
		for _, side := range []string{"positive", "negative"} {
			x := d.runRow(context.Background(), c.Policy, root, id, side)
			if !x.Executed || x.Verdict != "passed" || x.DurationNS <= 0 || x.DurationNS > x.BoundNS || x.BoundNS != int64(30*time.Second) {
				t.Fatal("parallel row bound", id, side, x)
			}
			t.Logf("%s/%s all variants and cleanup %s", id, side, time.Duration(x.DurationNS))
			if side == "positive" {
				q.Positive = x
			} else {
				q.Negative = x
			}
		}
		if e := validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, q, records); e != nil {
			t.Fatal(e)
		}
		if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, q) == nil {
			t.Fatal("unbound parallel artifact accepted")
		}
	}
}

// Claim: a typed owner refusal cannot carry even a non-token lease payload.
// The neighboring empty refusal is accepted through the same collector/audit.
func TestOwnerParallelRefusalPayload(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	c, _, e := ownerSeed(root, strings.Repeat("a", 64), "death-live")
	if e != nil {
		t.Fatal(e)
	}
	audit, e := newLifecycleAudit(c.Root)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(audit.fd)
	h := &parallelHarness{ledger: &lifecycleModel{c: c, audit: audit}, fact: &lifecycleFact{Parallel: &parallelFacts{}}}
	for _, leak := range []bool{false, true} {
		out := parallelOutcome{}
		if leak {
			out.Lease.Payload.AccountID = "unexpected"
		}
		data, e := wire.Encode(out)
		if e != nil {
			t.Fatal(e)
		}
		s := &parallelSession{issued: map[int]parallelFrame{1: {ID: 1, Op: "lease.request"}}, results: map[int]parallelFrame{1: {ID: 1, Op: "lease.request", Error: "lease_owner_unavailable", Data: data}}, finished: map[int]bool{}}
		_, e = h.result(s, 1, "lease_owner_unavailable", "", 0)
		if !leak && e != nil {
			t.Fatal("empty refusal rejected", e)
		}
		if leak && (e == nil || !strings.Contains(e.Error(), "parallel exact outcome")) {
			t.Fatal("refusal payload accepted", e)
		}
	}
}
