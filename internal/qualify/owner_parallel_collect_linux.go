//go:build linux

package qualify

import (
	"reflect"
	"strings"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func validParallelFact(f lifecycleFact) bool {
	p := f.Parallel
	contend := strings.HasPrefix(f.Scenario, "contention-")
	negative := parallelUnresolved(f.Scenario)
	owners, starts := 2, 2
	if contend {
		owners = 3
	}
	if negative {
		starts = 1
	}
	if p == nil || len(f.Origins) != owners || len(f.Budgets) != owners || len(p.Frames) != owners || f.Starts != starts || len(f.Writers) != starts || f.Peak != 1 || f.Events <= 0 || f.Events > 2048 || p.Entries <= 0 || p.Entries > 64 || p.Children < 1 || p.Children > 3 || !p.HistoryPreserved || len(p.Events) > 64 || f.Clocks != [2]int{} {
		return false
	}
	first := ownerBudget{Requests: 1, Renewals: 1, Releases: 1}
	second := ownerBudget{Requests: 1, Renewals: 2, Releases: 1}
	if negative {
		first = ownerBudget{Requests: 1, Renewals: 1}
		second = ownerBudget{Requests: 2, Renewals: 1, Releases: 1}
	}
	if contend {
		if negative {
			first.Requests = 2
			second = ownerBudget{Requests: 2, Renewals: 3, Releases: 2}
		} else {
			second = ownerBudget{Requests: 2, Renewals: 4, Releases: 2}
		}
	}
	win := 1
	member := "O2"
	if contend {
		if len(p.Candidates) != 2 || !p.Together || p.Overlap == nil {
			return false
		}
		member = "A"
		if strings.HasSuffix(f.Scenario, "-b") {
			member = "B"
			win = 2
		}
		if p.Winner != member {
			return false
		}
		for i, c := range p.Candidates {
			index := i + 1
			if c.Member != []string{"A", "B"}[i] || c.Origin != index || c.Context != f.Origins[index].Command[2] || !c.Constructor {
				return false
			}
			if index == win {
				if !c.Ready || !c.LockHeld || c.Startup != "lease" || c.Error != "" {
					return false
				}
			} else {
				if c.Ready || c.LockHeld || c.Startup != "store" || c.Error != "owner_startup_refused" || f.Budgets[index] != (ownerBudget{}) {
					return false
				}
			}
		}
		if p.Candidates[0].Context == p.Candidates[1].Context || !validParallelOverlap(p, member, negative) {
			return false
		}
	} else if len(p.Candidates) != 0 || p.Overlap != nil || p.Winner != "" {
		return false
	}
	if f.Budgets[0] != first || f.Budgets[win] != second {
		return false
	}
	for i, o := range f.Origins {
		exit := 0
		if i == 0 && negative {
			exit = -1
		}
		if p.Frames[i] <= 0 || p.Frames[i] > 512 || o.Command[0] != "/proc/self/fd/4" || o.Command[1] != "qualification-owner" || !policy.Hash(o.Command[2]) || !policy.Hash(o.Image) || o.Image != f.Origins[0].Image || !o.Verified || !o.Entered || !o.Joined || o.Waits != 1 || o.Exit != exit {
			return false
		}
	}
	if negative {
		if len(f.Crashes) != 1 || f.Gate == nil || f.Gate.Phase != "running" || f.Gate.State != "terminal-joined" || f.Gate.Context != f.Origins[0].Command[2] || !policy.Hash(f.Gate.Prefix) || len(f.Gate.Nonce) != 32 || f.Gate.Call <= 0 || !terminationShape(f.Crashes[0], f.Gate.Context) {
			return false
		}
		g := *f.Gate
		g.State = "sealed"
		b, _ := wire.Encode(g)
		if f.Crashes[0].Gate != qualificationHash(b) {
			return false
		}
	} else if len(f.Crashes) != 0 || f.Gate != nil {
		return false
	}
	partial := parallelPartial(f.Scenario)
	if p.LiveAtAssertion != partial || len(p.Cleanup) != boolInt(partial) || f.Stops != starts || len(f.Inputs) != starts || len(f.Endpoint) != 2*boolInt(!negative) {
		return false
	}
	for i, w := range f.Writers {
		o := w.Origin
		if w.Attempt == "" || w.Start == 0 || !o.Verified || !o.Entered || !o.Joined || o.Waits != 1 || o.Exit != -1 || o.Command[0] != "/proc/self/fd/4" || o.Command[1] != "qualification-writer" || o.Image != f.Origins[0].Image || w.Survived != (negative && i == 0) || w.Persisted != !negative {
			return false
		}
		if partial {
			if w.Stop.SignalSent || p.Cleanup[0] == "" || f.Inputs[i].After.Complete || f.Inputs[i].After.StopCompleted || f.Inputs[i].After.Empty || f.Inputs[i].After.PopulatedZero {
				return false
			}
		} else if !terminationShape(w.Stop, o.Command[2]) || !f.Inputs[i].After.Complete || !f.Inputs[i].After.StopCompleted || !f.Inputs[i].After.Empty || !f.Inputs[i].After.PopulatedZero {
			return false
		}
	}
	cp := f.Checkpoints[1]
	if negative {
		if cp.State != "owner_unavailable" || cp.TokenGeneration != 1 || cp.StoreGeneration != 1 || cp.RetainedAttempts != 0 || cp.PendingAttempt == "" || !cp.RetryAt.IsZero() || cp.Failures != 0 {
			return false
		}
	} else if cp.State != "active" || cp.TokenGeneration != 3 || cp.StoreGeneration != 3 || cp.RetainedAttempts != 2 || cp.PendingAttempt != "" {
		return false
	}
	counts := map[string]ownerBudget{}
	digests := map[uint64]string{}
	for _, r := range p.Results {
		if r.Member != "O1" && r.Member != member || r.Command <= 0 {
			return false
		}
		b := counts[r.Member]
		switch r.Method {
		case "lease.request":
			b.Requests++
		case "lease.renew":
			b.Renewals++
		case "lease.release":
			b.Releases++
		default:
			return false
		}
		counts[r.Member] = b
		if r.Error != "" {
			want := "lease_owner_unavailable"
			if r.Member == "O1" {
				want = "interrupted-no-response"
			}
			if r.Error != want || r.Published || r.TokenDigest != "" || !negative {
				return false
			}
			continue
		}
		if r.Method != "lease.release" {
			g := uint64(2)
			if r.Member == "O1" && r.Method == "lease.request" {
				g = 1
			}
			if r.Member != "O1" && r.Method == "lease.renew" {
				g = 3
			}
			if !r.Published || r.LeaseID == "" || r.PolicyGeneration != 1 || r.TokenGeneration != g || r.OfferedGeneration != g || !policy.Hash(r.TokenDigest) || r.Method == "lease.renew" && r.ObservedGeneration != g-1 || r.Method == "lease.request" && r.ObservedGeneration != g {
				return false
			}
			if old := digests[g]; old != "" && old != r.TokenDigest {
				return false
			}
			digests[g] = r.TokenDigest
		}
	}
	return reflect.DeepEqual(counts, map[string]ownerBudget{"O1": first, member: second})
}
func validParallelOverlap(p *parallelFacts, member string, negative bool) bool {
	o := p.Overlap
	if o == nil || o.Queued != 0 || o.First == "" || o.Second == "" || o.First == o.Second || o.Dequeue <= 0 || o.Arrival <= o.Dequeue || o.Resume <= o.Arrival {
		return false
	}
	hold := "native"
	if negative {
		hold = "dequeue"
	}
	if o.Hold != hold {
		return false
	}
	deq, arrival := false, false
	for _, e := range p.Events {
		if e.Member == member && e.Kind == "dequeue" && e.LeaseID == o.First && e.Sequence == o.Dequeue {
			deq = true
		}
		if e.Member == member && e.Kind == "arrival" && e.LeaseID == o.Second && e.Sequence == o.Arrival {
			arrival = true
		}
	}
	return deq && arrival
}
