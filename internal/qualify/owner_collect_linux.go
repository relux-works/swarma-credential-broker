//go:build linux

package qualify

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func (d driver) runOwnerRow(parent context.Context, p policy.Policy, root, id, side string) (control qualification.Control) {
	control = pendingRowControl()
	execution := newRowExecution()
	defer func() { d.recordExecution(id, side, execution) }()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	start := time.Now()
	image := "/proc/self/exe"
	if d.rowExecutable != "" {
		image = d.rowExecutable
	}
	broker, e := os.Open(image)
	if d.rowExecutable != "" {
		broker.Close()
		broker, e = qualification.OpenExecutable(image)
	}
	if e != nil {
		return
	}
	defer broker.Close()
	candidate, e := qualification.OpenExecutable(p.Executable)
	if e != nil {
		return
	}
	defer candidate.Close()
	digest, e := descriptorDigest(candidate)
	if e != nil || digest != p.ExecutableSHA256 {
		return
	}
	facts := ownerRowFacts{Scope: "fake-only owner-core/1"}
	network := map[string]egress.Counts{}
	scripts := []string{"current"}
	if id == "absence-unreadable" {
		scripts = []string{"complete"}
	}
	if side == "negative" {
		scripts = ownerStoreFaults
		if id == "absence-unreadable" {
			scripts = append(append([]string{}, ownerAbsenceFaults...), "partial")
		}
	}
	passed := true
	for i, scenario := range scripts {
		recovery := "refused"
		if side == "positive" {
			recovery = "intact"
		}
		if id == "absence-unreadable" && side == "negative" && i == 8 {
			recovery = "complete-on-construction"
		}
		fact, x, n, e := ownerScenarioRun(ctx, broker, candidate, digest, scenario, recovery)
		facts.Scenarios = append(facts.Scenarios, fact)
		execution = x
		for k, v := range n {
			old := network[k]
			old.Allowed += v.Allowed
			old.Refused += v.Refused
			network[k] = old
		}
		if e != nil {
			passed = false
			break
		}
	}
	control = executionControl(id, side, execution, time.Since(start))
	if !control.Executed {
		return
	}
	refusal := rowPositive(id)
	if side == "negative" {
		refusal = rowRefusal(id)
	}
	observation := rowObservation{ID: id, Side: side, Candidate: digest, NoEffects: true, Refusal: refusal, Envelopes: []rowEnvelope{}, Owner: &facts}
	if passed && validOwnerEffects(observation) {
		control.Verdict = "passed"
	} else {
		execution.Diagnostic = "observation_invalid"
	}
	a := rowArtifact{Kind: "qualification-row-control/1", Candidate: digest, ID: id, Side: side, Control: control, Observation: observation, Network: network, Execution: &execution}
	b, e := wire.Encode(a)
	if e != nil {
		return
	}
	f, e := os.OpenFile(rowFile(root, id, side), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	_, e = f.Write(b)
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return
	}
	execution.artifact = qualification.Hash(b)
	control.Artifacts = []string{execution.artifact}
	return
}
func validOwnerEffects(o rowObservation) bool {
	if !ownerRow(o.ID) {
		return o.Owner == nil
	}
	if o.Owner == nil || o.Owner.Scope != "fake-only owner-core/1" || len(o.Envelopes) != 0 {
		return false
	}
	scripts := []string{"current"}
	if o.ID == "absence-unreadable" {
		scripts = []string{"complete"}
	}
	if o.Side == "negative" {
		scripts = ownerStoreFaults
		if o.ID == "absence-unreadable" {
			scripts = append(append([]string{}, ownerAbsenceFaults...), "partial")
		}
	}
	if len(o.Owner.Scenarios) != len(scripts) {
		return false
	}
	for i, f := range o.Owner.Scenarios {
		starts := 0
		if o.ID == "absence-unreadable" || strings.HasPrefix(scripts[i], "intent-") {
			starts = 1
		}
		if f.Scenario != scripts[i] || f.Starts != starts || f.Stops < starts || f.Stops > 2 || len(f.Budgets) != 2 || len(f.Startup) != 2 || f.Startup[0] != "lease-ready" {
			return false
		}
		b1, b2 := ownerBudget{Requests: 1, Releases: 1}, ownerBudget{Requests: 1, Releases: 1}
		if starts == 1 {
			b1.Renewals = 2
		}
		if o.Side == "negative" {
			b2 = ownerBudget{Requests: 1}
			if f.Startup[1] != "lease-ready" {
				b2 = ownerBudget{}
			}
			if o.ID == "store-missing" {
				b1.Requests = 3
				if !f.Audited || f.Inventory[0] == 0 || f.Inventory[1] == 0 || f.Inventory[1] != f.Inventory[2] || !strings.Contains(scripts[i], "-mode") && f.Tombstones == 0 {
					return false
				}
			} else {
				b1.Requests = 2
				b1.Prerequisites = 1
			}
		}
		if o.ID == "absence-unreadable" && i == 8 {
			b2 = ownerBudget{Requests: 1, Releases: 1}
			if f.Recovery != "complete-on-construction" || f.Generation != 2 {
				return false
			}
		}
		if len(f.Origins) != 2 || len(f.Inputs) != f.Stops {
			return false
		}
		for _, origin := range f.Origins {
			if !policy.Hash(origin.Image) || !origin.Verified || !origin.Entered || !origin.Joined || origin.Exit != 0 || origin.Waits != 1 || origin.Command[0] != "/proc/self/fd/4" || origin.Command[1] != "qualification-owner" || !policy.Hash(origin.Command[2]) {
				return false
			}
		}
		stage := "lease-ready"
		if o.ID == "store-missing" && o.Side == "negative" {
			switch scripts[i] {
			case "home-absent", "home-mode":
				stage = "owner-refused"
			case "metadata-absent":
				stage = "store-refused"
			case "checkpoint-mode", "intent-mode-committed", "intent-mode-pending":
				stage = "lease-refused"
			}
		}
		if f.Startup[1] != stage {
			return false
		}
		mode := "complete"
		if starts == 1 && o.Side == "negative" {
			mode = scripts[i]
			if o.ID == "store-missing" {
				mode = "complete"
				if strings.HasSuffix(scripts[i], "-pending") {
					mode = "partial"
				}
			}
		}
		for j, input := range f.Inputs {
			expectedMode := mode
			if j == 1 && f.Recovery == "complete-on-construction" {
				expectedMode = "complete"
			}
			if !ownerStopMatches(input, expectedMode) {
				return false
			}
		}
		generation := uint64(0)
		recovery := "refused"
		stops := starts
		if o.Side == "positive" {
			recovery = "intact"
			generation = 1
			if o.ID == "absence-unreadable" {
				generation = 2
			}
		} else if o.ID == "absence-unreadable" {
			generation = 1
			if scripts[i] != "boot" && scripts[i] != "epoch" {
				stops = 2
			}
			if i == 8 {
				generation = 2
				recovery = "complete-on-construction"
			}
		}
		if f.Generation != generation || f.Recovery != recovery || f.Stops != stops {
			return false
		}
		if f.Budgets[0] != b1 || f.Budgets[1] != b2 {
			return false
		}
	}
	return true
}

func ownerStopMatches(f ownerStopFact, mode string) bool {
	b := f.Before
	if !b.Complete || !b.RestartNo || b.MainPID != 42 || b.ProcessStart != 1 || b.Active != "active" || b.Substate != "running" || b.Unit == "" || b.Invocation != "synthetic-invocation" || b.Cgroup != "/synthetic-writer" || b.CgroupID != "synthetic-cgroup" || b.Properties != "synthetic-properties" {
		return false
	}
	v := b
	v.MainPID = 0
	v.Active = "inactive"
	v.Substate = "dead"
	v.StopCompleted = true
	v.Empty = true
	v.PopulatedZero = true
	err := ""
	switch mode {
	case "stop-denied":
		err = "synthetic_stop_denied"
	case "unit-missing":
		err = "synthetic_unit_missing"
	case "partial":
		v.Complete = false
	case "invocation":
		v.Invocation += "-conflict"
	case "cgroup":
		v.Cgroup = ""
	case "pid-only":
		v.Empty = false
		v.PopulatedZero = false
	case "boot":
		v.Identity.Boot += "-changed"
	case "epoch":
		v.Identity.Epoch += "-changed"
	}
	return reflect.DeepEqual(f.After, v) && f.Error == err
}
