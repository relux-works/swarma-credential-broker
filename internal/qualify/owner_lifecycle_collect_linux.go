//go:build linux

package qualify

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type lifecycleEffects struct {
	Scope     string
	Scenarios []lifecycleFact
}

func lifecycleRow(id string) bool {
	return id == "transient-ambiguous" || id == "rotation-crash" || id == "cleanup-interrupted"
}
func lifecycleScripts(id, side string) []string {
	switch id {
	case "transient-ambiguous":
		if side == "positive" {
			return []string{"safe-safe-committed"}
		}
		return []string{"ambiguous-old", "ambiguous-new"}
	case "rotation-crash":
		if side == "positive" {
			return []string{"rotation-committed"}
		}
		return []string{"rotation-no-store", "rotation-no-proof"}
	case "cleanup-interrupted":
		if side == "positive" {
			return []string{"cleanup-complete", "rotation-committed"}
		}
		return []string{"cleanup-incomplete"}
	}
	return nil
}
func terminationShape(f egress.TerminationFacts, context string) bool {
	return f.Context == context && policy.Hash(f.Gate) && f.PID > 0 && f.Signal == 9 && f.Exit == -1 && f.Waits == 1 && f.WaitError != "" && f.Verified && f.Entered && f.SignalSent && f.TraceComplete && f.Joined
}
func validLifecycleFact(f lifecycleFact) bool {
	if !lifecycleScenario(f.Scenario) || len(f.Origins) != 2 || len(f.Budgets) != 2 || f.Peak != 1 || f.Events <= 0 || f.Events > 2048 {
		return false
	}
	expected := [2]ownerBudget{{Requests: 1, Renewals: 1}, {Requests: 2, Renewals: 1, Releases: 1}}
	clocks := [2]int{}
	starts, stops := 1, 2
	crash := f.Scenario == "rotation-no-store" || f.Scenario == "rotation-no-proof" || f.Scenario == "cleanup-complete" || f.Scenario == "cleanup-incomplete"
	switch f.Scenario {
	case "safe-safe-committed":
		expected = [2]ownerBudget{{Requests: 1, Renewals: 2, Releases: 1}, {Requests: 1, Renewals: 5, Releases: 1}}
		clocks = [2]int{1, 3}
		starts, stops = 3, 3
	case "ambiguous-old", "ambiguous-new":
		expected = [2]ownerBudget{{Requests: 3, Renewals: 1, Releases: 1}, {Requests: 2}}
		clocks = [2]int{1, 0}
	case "rotation-no-store", "rotation-no-proof":
		clocks = [2]int{0, 1}
		stops = 1
	case "cleanup-complete":
		expected[1] = ownerBudget{Requests: 1, Renewals: 1, Releases: 2}
	case "rotation-committed":
		expected = [2]ownerBudget{{Requests: 1, Renewals: 1, Releases: 1}, {Requests: 1, Releases: 1}}
		stops = 1
	}
	if f.Starts != starts || f.Stops != stops || len(f.Writers) != starts || len(f.Endpoint) != starts || f.Clocks != clocks || !reflect.DeepEqual(f.Budgets, expected[:]) || len(f.Inputs) != stops-boolInt(crash && f.Scenario != "rotation-no-store" && f.Scenario != "rotation-no-proof") {
		return false
	}
	for i, o := range f.Origins {
		if f.Frames[i] <= 0 || f.Frames[i] > 512 {
			return false
		}
		exit := 0
		if i == 0 && crash {
			exit = -1
		}
		if o.Command[0] != "/proc/self/fd/4" || o.Command[1] != "qualification-owner" || !policy.Hash(o.Command[2]) || !policy.Hash(o.Image) || !o.Verified || !o.Entered || !o.Joined || o.Waits != 1 || o.Exit != exit || o.Image != f.Origins[0].Image {
			return false
		}
	}
	if crash {
		if len(f.Crashes) != 1 || f.Gate == nil || f.Gate.State != "terminal-joined" || f.Gate.Call < 1 || len(f.Gate.Nonce) != 32 || !policy.Hash(f.Gate.Prefix) || f.Gate.Context != f.Origins[0].Command[2] || !terminationShape(f.Crashes[0], f.Gate.Context) {
			return false
		}
		g := *f.Gate
		g.State = "sealed"
		raw, _ := wire.Encode(g)
		if f.Crashes[0].Gate != qualificationHash(raw) {
			return false
		}
		phase := "stop-before-absence"
		if f.Scenario == "rotation-no-store" || f.Scenario == "rotation-no-proof" {
			phase = f.Scenario
		}
		if g.Phase != phase {
			return false
		}
	} else if len(f.Crashes) != 0 || f.Gate != nil {
		return false
	}
	for i, w := range f.Writers {
		persisted := f.Scenario != "ambiguous-old" && f.Scenario != "rotation-no-store" && (f.Scenario != "safe-safe-committed" || i == 2)
		survivor := f.Scenario == "rotation-no-store" || f.Scenario == "rotation-no-proof"
		o := w.Origin
		if w.Attempt == "" || w.Start == 0 || w.Persisted != persisted || w.Survived != survivor || !o.Verified || !o.Entered || !o.Joined || o.Waits != 1 || o.Exit != -1 || o.Command[0] != "/proc/self/fd/4" || o.Command[1] != "qualification-writer" || o.Image != f.Origins[0].Image || !terminationShape(w.Stop, o.Command[2]) {
			return false
		}
	}
	cp := f.Checkpoints[1]
	if f.Scenario == "safe-safe-committed" || f.Scenario == "rotation-committed" || f.Scenario == "cleanup-complete" {
		if cp.State != "active" || cp.TokenGeneration != 2 || cp.StoreGeneration != 2 || cp.PendingAttempt != "" || cp.RetainedAttempts != uint64(starts) {
			return false
		}
	} else {
		if cp.State != "owner_unavailable" || cp.TokenGeneration != 1 || cp.StoreGeneration != 1 || cp.PendingAttempt == "" || !cp.RetryAt.IsZero() || cp.Failures != 0 {
			return false
		}
	}
	return true
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func validLifecycleEffects(o rowObservation) bool {
	if !lifecycleRow(o.ID) {
		return o.Lifecycle == nil
	}
	scripts := lifecycleScripts(o.ID, o.Side)
	if o.Lifecycle == nil || o.Lifecycle.Scope != "fake-only singleton owner-core/1" || len(o.Lifecycle.Scenarios) != len(scripts) || len(o.Envelopes) != 0 {
		return false
	}
	for i, f := range o.Lifecycle.Scenarios {
		if f.Scenario != scripts[i] || !validLifecycleFact(f) {
			return false
		}
	}
	return true
}
func (d driver) runLifecycleRow(parent context.Context, p policy.Policy, root, id, side string) (control qualification.Control) {
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
	broker, e := qualification.OpenExecutable(image)
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
	effects := lifecycleEffects{Scope: "fake-only singleton owner-core/1"}
	network := map[string]egress.Counts{}
	passed := true
	for _, scenario := range lifecycleScripts(id, side) {
		fact, x, n, e := lifecycleRun(ctx, broker, candidate, digest, scenario)
		effects.Scenarios = append(effects.Scenarios, fact)
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
	observation := rowObservation{ID: id, Side: side, Candidate: digest, NoEffects: true, Refusal: refusal, Envelopes: []rowEnvelope{}, Lifecycle: &effects}
	if passed && validLifecycleEffects(observation) && ctx.Err() == nil {
		control.Verdict = "passed"
	} else {
		execution.Diagnostic = "observation_invalid"
	}
	artifact := rowArtifact{Kind: "qualification-row-control/1", Candidate: digest, ID: id, Side: side, Control: control, Observation: observation, Network: network, Execution: &execution}
	raw, e := wire.Encode(artifact)
	if e != nil {
		return
	}
	f, e := os.OpenFile(rowFile(root, id, side), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	_, e = f.Write(raw)
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return
	}
	execution.artifact = qualification.Hash(raw)
	control.Artifacts = []string{execution.artifact}
	return
}
