package labcontractv0

import (
	"fmt"
	"reflect"
	"testing"
)

type observationUse struct {
	Floor, Seen, Observed, Receipt int64
	Open                           bool
	Baseline                       map[string]any
}

func nativeSnapshot(test *testing.T, response map[string]any) map[string]any {
	test.Helper()
	result := normalizedBounded(test, cloneObject(test, response))
	delete(result, "sequence")
	delete(result, "observed_monotonic_ms")
	return result
}

func validObservationUse(test *testing.T) observationUse {
	test.Helper()
	fixture := observationControl(test)
	return observationUse{Floor: 8, Seen: 8, Observed: 2100, Receipt: 2101, Open: true, Baseline: nativeSnapshot(test, fixture.Response)}
}

func observationAge(now, observed int64) string {
	if now < observed || now-observed >= 1200 {
		return "unknown_age"
	}
	return "valid"
}

func observationSchedule(before, receipt int64) string {
	if before < receipt+500 || before >= receipt+550 {
		return "unknown_schedule"
	}
	return "valid"
}

func observationPairBudget(now, entered int64) string {
	if now < entered || now-entered >= 1250 {
		return "unknown_pair_budget"
	}
	return "valid"
}

func observationWait(before, receipt int64) string {
	if before < receipt+250 || before >= receipt+300 {
		return "unknown_wait"
	}
	return "valid"
}

func observationCurrentBudget(elapsed int64) string {
	if elapsed < 0 || elapsed >= 300 {
		return "unknown_current_rpc"
	}
	return "valid"
}

func observationCurrentSchedule(before, receipt int64) string {
	if before < receipt+250 || before >= receipt+300 {
		return "unknown_current_schedule"
	}
	return "valid"
}

func observationCurrentWatchdog(now, lastSuccess int64) string {
	if now < lastSuccess || now-lastSuccess >= 750 {
		return "closed_current_watchdog"
	}
	return "valid"
}

func observationDispatch(elapsed int64) string {
	if elapsed < 0 || elapsed >= 50 {
		return "unknown_dispatch"
	}
	return "valid"
}

func observationClosure(elapsed int64) string {
	if elapsed < 0 || elapsed > 500 {
		return "unknown_closure"
	}
	return "valid"
}

func continuedObservation(state *observationUse, now int64) string {
	if !state.Open {
		return "closed"
	}
	if got := observationAge(now, state.Observed); got != "valid" {
		state.Open = false
		return got
	}
	return "valid"
}

func periodicObservation(test *testing.T, state *observationUse, next observationFixture, answered bool, now int64) string {
	test.Helper()
	refuse := func(reason string) string { state.Open = false; return reason }
	if got := continuedObservation(state, now); got != "valid" {
		return got
	}
	if !answered {
		return refuse("unknown_answer")
	}
	before, after := next.Expected["before_monotonic_ms"].(int64), next.Expected["after_monotonic_ms"].(int64)
	if got := observationSchedule(before, state.Receipt); got != "valid" {
		return refuse(got)
	}
	if now != after {
		return refuse("unknown_receipt")
	}
	next.Expected["sequence_high_water"] = state.Seen
	if got := observationAdmission(test, next, true); got != "valid" {
		return refuse("unknown_" + got)
	}
	if !reflect.DeepEqual(nativeSnapshot(test, next.Response), state.Baseline) {
		return refuse("unknown_native_snapshot")
	}
	if got := observationAge(now, next.Response["observed_monotonic_ms"].(int64)); got != "valid" {
		return refuse(got)
	}
	state.Seen = next.Response["sequence"].(int64)
	state.Observed, state.Receipt = next.Response["observed_monotonic_ms"].(int64), after
	return "continued"
}

func periodicControl(test *testing.T) observationFixture {
	test.Helper()
	fixture := observationControl(test)
	fixture.Response["sequence"] = int64(9)
	fixture.Response["observed_monotonic_ms"] = int64(2602)
	fixture.Expected["before_monotonic_ms"] = int64(2601)
	fixture.Expected["after_monotonic_ms"] = int64(2603)
	return fixture
}

func publicationKind(value any) bool {
	kind, ok := value.(string)
	if !ok {
		return false
	}
	return kind == "start" || kind == "commit" || kind == "debit" || kind == "stop" || kind == "invalidation"
}

func consumeObservationPair(test *testing.T, state *observationUse, kind string, first, final observationFixture, entered, now int64, fresh, cas, effectBound bool) string {
	test.Helper()
	state.Open = false
	if !publicationKind(kind) {
		return "unknown_publication_kind"
	}
	if entered < state.Receipt {
		return "unknown_pair_order"
	}
	if got := observationPairBudget(now, entered); got != "valid" {
		return got
	}
	if !fresh {
		return "unknown_pair_fresh"
	}
	if !effectBound {
		return "unknown_effect_binding"
	}
	if got := observationWait(first.Expected["before_monotonic_ms"].(int64), entered); got != "valid" {
		return got
	}
	if got := observationWait(final.Expected["before_monotonic_ms"].(int64), first.Expected["after_monotonic_ms"].(int64)); got != "valid" {
		return got
	}
	floor := max(state.Floor, state.Seen)
	first.Expected["sequence_high_water"] = floor
	final.Expected["sequence_high_water"] = max(floor, first.Response["sequence"].(int64))
	narrowing := kind == "stop" || kind == "invalidation"
	if observationJoinAdmission(test, first, true, narrowing) != "valid" || observationJoinAdmission(test, final, true, narrowing) != "valid" {
		return "unknown_pair_join"
	}
	if !reflect.DeepEqual(nativeSnapshot(test, first.Response), nativeSnapshot(test, final.Response)) {
		return "unknown_pair_snapshot"
	}
	stops, invalidations := final.Response["stops"].([]any), final.Response["invalidations"].([]any)
	if kind == "stop" && len(stops) == 0 || kind == "invalidation" && len(invalidations) == 0 {
		return "unknown_narrowing_evidence"
	}
	if now < final.Expected["after_monotonic_ms"].(int64) || now-final.Expected["before_monotonic_ms"].(int64) >= 250 {
		return "unknown_final_deadline"
	}
	if !cas {
		return "unknown_pair_cas"
	}
	state.Seen, state.Floor = final.Response["sequence"].(int64), final.Response["sequence"].(int64)
	state.Baseline = nativeSnapshot(test, final.Response)
	state.Observed, state.Receipt = final.Response["observed_monotonic_ms"].(int64), final.Expected["after_monotonic_ms"].(int64)
	state.Open = !narrowing
	return "published"
}

func consumptionPair(test *testing.T, kind string) (observationFixture, observationFixture) {
	test.Helper()
	first, final := freshObservationPair(test)
	first.Response["sequence"], final.Response["sequence"] = int64(9), int64(10)
	first.Expected["before_monotonic_ms"], first.Expected["after_monotonic_ms"] = int64(2351), int64(2353)
	first.Response["observed_monotonic_ms"] = int64(2352)
	final.Expected["before_monotonic_ms"], final.Expected["after_monotonic_ms"] = int64(2603), int64(2605)
	final.Response["observed_monotonic_ms"] = int64(2604)
	for _, fixture := range []*observationFixture{&first, &final} {
		switch kind {
		case "stop":
			fixture.Response["start"].(map[string]any)["phase"] = "terminal"
			stop := normalizedBounded(test, cloneObject(test, fixture.Stop))
			stop["phase"] = "terminal"
			fixture.Response["stops"] = []any{stop}
		case "invalidation":
			fixture.Response["start"].(map[string]any)["phase"] = "terminal"
			fixture.Response["invalidations"] = []any{fixture.Invalidation}
		}
	}
	return first, final
}

// Claim: each publication role consumes its own pair; singles, reuse, pipelining, missing native proof and failed publication cannot grant use or move the floor.
func TestLabObservationConsumptionPairs(test *testing.T) {
	for _, kind := range []string{"start", "commit", "debit", "stop", "invalidation"} {
		for _, mutation := range append(literalMutations(kind), wrongTypes(kind)...) {
			test.Run(kind+"/catalogue/"+mutation.Name, func(test *testing.T) {
				if !publicationKind(kind) {
					test.Fatal("valid publication role refused")
				}
				wanted := false
				for _, accepted := range []string{"start", "commit", "debit", "stop", "invalidation"} {
					if mutation.Value == accepted {
						wanted = true
					}
				}
				if got := publicationKind(mutation.Value); got != wanted {
					test.Fatalf("role operator admitted %v want %v", got, wanted)
				}
			})
		}
		test.Run(kind, func(test *testing.T) {
			control := func() observationUse {
				state := validObservationUse(test)
				first, final := consumptionPair(test, kind)
				if got := consumeObservationPair(test, &state, kind, first, final, 2101, 2605, true, true, true); got != "published" || state.Floor != 10 || state.Seen != 10 || state.Open != (kind != "stop" && kind != "invalidation") {
					test.Fatalf("valid consumption: %s state %+v", got, state)
				}
				return state
			}
			control()
			for _, name := range []string{"single", "current", "revocation", "floor", "seen", "replay-initial", "replay-final", "reuse-final", "pipeline", "fresh", "cas", "effect", "snapshot", "missing-proof", "deadline", "entry-order", "first-wait", "final-wait", "pair-budget"} {
				test.Run(name, func(test *testing.T) {
					control()
					state := validObservationUse(test)
					first, final := consumptionPair(test, kind)
					role, now, fresh, cas, effect := kind, int64(2605), true, true, true
					entered := int64(2101)
					wanted := "unknown_pair_join"
					switch name {
					case "single", "current", "revocation":
						role, wanted = name, "unknown_publication_kind"
					case "floor":
						state.Floor = 9
					case "seen":
						state.Seen = 9
					case "replay-initial":
						first.Response["sequence"] = int64(8)
					case "replay-final":
						final.Response["sequence"] = int64(9)
					case "reuse-final":
						state.Floor, state.Seen = 10, 10
					case "pipeline":
						state.Floor = 11
					case "fresh":
						fresh, wanted = false, "unknown_pair_fresh"
					case "cas":
						cas, wanted = false, "unknown_pair_cas"
					case "effect":
						effect, wanted = false, "unknown_effect_binding"
					case "snapshot":
						final.Response["store"].(map[string]any)["effects_revision"] = int64(99)
						wanted = "unknown_pair_snapshot"
					case "missing-proof":
						if kind == "stop" || kind == "invalidation" {
							for _, fixture := range []*observationFixture{&first, &final} {
								fixture.Response["stops"], fixture.Response["invalidations"] = []any{}, []any{}
							}
							wanted = "unknown_narrowing_evidence"
						} else {
							final.Response["complete"] = false
						}
					case "entry-order":
						entered, wanted = 2100, "unknown_pair_order"
					case "first-wait":
						first.Expected["before_monotonic_ms"], wanted = int64(2350), "unknown_wait"
					case "final-wait":
						final.Expected["before_monotonic_ms"], wanted = int64(2602), "unknown_wait"
					case "pair-budget":
						now, wanted = 3351, "unknown_pair_budget"
					case "deadline":
						now, wanted = 2853, "unknown_final_deadline"
					}
					oldFloor := state.Floor
					if got := consumeObservationPair(test, &state, role, first, final, entered, now, fresh, cas, effect); got != wanted || state.Open || state.Floor != oldFloor {
						test.Fatalf("consumption refusal: got %s want %s floor %d/%d open %v", got, wanted, state.Floor, oldFloor, state.Open)
					}
				})
			}
		})
	}
}

// Claim: periodic reads require unchanged complete native proof and increasing transport counters; every failure fences use without publishing or moving its floor.
func TestLabObservationPeriodicPairs(test *testing.T) {
	control := func() {
		state := validObservationUse(test)
		if got := periodicObservation(test, &state, periodicControl(test), true, 2603); got != "continued" || state.Floor != 8 || state.Seen != 9 || !state.Open {
			test.Fatalf("valid periodic: %s state %+v", got, state)
		}
		if got := continuedObservation(&state, 2604); got != "valid" || state.Observed != 2602 || state.Floor != 8 || !reflect.DeepEqual(state.Baseline, validObservationUse(test).Baseline) {
			test.Fatalf("current refreshed evidence: %s", got)
		}
	}
	control()
	for _, name := range []string{"closed", "timeout", "partial", "null", "counter-equal", "counter-regressed", "store-generation", "sequence-generation", "effects-sequence", "receipt-digest", "manager-sequence", "debit-sequence", "invalidation-sequence", "stopped", "pending-stop", "terminal-stop", "invalidation", "early", "late", "rpc-deadline", "receipt", "old-age", "future-age"} {
		test.Run(name, func(test *testing.T) {
			control()
			state, next := validObservationUse(test), periodicControl(test)
			answered, now, wanted := true, int64(2603), "unknown_native_snapshot"
			switch name {
			case "closed":
				state.Open = false
				wanted = "closed"
			case "timeout":
				answered, wanted = false, "unknown_answer"
			case "partial":
				next.Response["complete"], wanted = false, "unknown_completeness"
			case "null":
				next.Response["store"], wanted = nil, "unknown_shape"
			case "counter-equal":
				next.Response["sequence"], wanted = int64(8), "unknown_sequence"
			case "counter-regressed":
				next.Response["sequence"], wanted = int64(7), "unknown_sequence"
			case "store-generation":
				next.Response["store"].(map[string]any)["generation"], wanted = "22222222222222222222222222222222", "unknown_store_generation"
			case "sequence-generation":
				next.Response["sequence_generation"], wanted = "22222222222222222222222222222222", "unknown_sequence_generation"
			case "effects-sequence":
				next.Response["store"].(map[string]any)["effects_revision"] = int64(99)
			case "receipt-digest":
				next.Response["store"].(map[string]any)["receipts_sha256"] = "sha256:" + fmt.Sprintf("%064d", 2)
			case "manager-sequence":
				next.Response["store"].(map[string]any)["manager_head"].(map[string]any)["sequence"], wanted = int64(99), "unknown_manager_head"
			case "debit-sequence":
				next.Response["store"].(map[string]any)["debits_head"].(map[string]any)["sequence"] = int64(99)
			case "invalidation-sequence":
				next.Response["store"].(map[string]any)["invalidations_head"].(map[string]any)["sequence"] = int64(99)
			case "stopped":
				next.Response["start"].(map[string]any)["phase"], wanted = "terminal", "unknown_start_phase"
			case "pending-stop", "terminal-stop":
				stop := next.Stop
				if name == "terminal-stop" {
					stop["phase"] = "terminal"
				}
				next.Response["stops"], wanted = []any{stop}, "unknown_stop"
			case "invalidation":
				next.Response["invalidations"], wanted = []any{next.Invalidation}, "unknown_invalidation"
			case "early":
				next.Expected["before_monotonic_ms"], wanted = int64(2600), "unknown_schedule"
			case "late":
				next.Expected["before_monotonic_ms"], wanted = int64(2651), "unknown_schedule"
			case "rpc-deadline":
				next.Expected["after_monotonic_ms"], now, wanted = int64(2851), 2851, "unknown_interval"
			case "receipt":
				now, wanted = 2604, "unknown_receipt"
			case "old-age":
				now, wanted = 3300, "unknown_age"
			case "future-age":
				now, wanted = 2099, "unknown_age"
			}
			old := state
			oldBaseline := normalizedBounded(test, cloneObject(test, state.Baseline))
			if got := periodicObservation(test, &state, next, answered, now); got != wanted || state.Open || state.Floor != old.Floor || state.Seen != old.Seen || state.Observed != old.Observed || state.Receipt != old.Receipt || !reflect.DeepEqual(state.Baseline, oldBaseline) {
				test.Fatalf("periodic refusal: got %s want %s floor %d seen %d open %v", got, wanted, state.Floor, state.Seen, state.Open)
			}
			if got := periodicObservation(test, &state, periodicControl(test), true, 2603); got != "closed" {
				test.Fatalf("single reopened fence: %s", got)
			}
		})
	}
}

// Claim: every timing interval is tested just inside and outside both endpoints; the unchanged wire catalogue covers null/type/canonical integer operators.
func TestLabObservationTimingBoundaries(test *testing.T) {
	for _, rule := range []struct {
		name      string
		gate      func(int64) string
		low, high int64
	}{
		{"native-age", func(value int64) string { return observationAge(value, 0) }, 0, 1199},
		{"periodic-schedule", func(value int64) string { return observationSchedule(value, 0) }, 500, 549},
		{"pair-budget", func(value int64) string { return observationPairBudget(value, 0) }, 0, 1249},
		{"pair-wait", func(value int64) string { return observationWait(value, 0) }, 250, 299},
		{"current-rpc", observationCurrentBudget, 0, 299},
		{"current-schedule", func(value int64) string { return observationCurrentSchedule(value, 0) }, 250, 299},
		{"current-watchdog", func(value int64) string { return observationCurrentWatchdog(value, 0) }, 0, 749},
		{"closure", observationClosure, 0, 500},
		{"watchdog-dispatch", observationDispatch, 0, 49},
	} {
		test.Run(rule.name, func(test *testing.T) {
			for _, value := range []int64{rule.low - 1, rule.low, rule.low + 1, rule.high - 1, rule.high, rule.high + 1} {
				test.Run(fmt.Sprint(value), func(test *testing.T) {
					if got := rule.gate(rule.low); got != "valid" {
						test.Fatalf("valid low: %s", got)
					}
					if got := rule.gate(rule.high); got != "valid" {
						test.Fatalf("valid high: %s", got)
					}
					wanted := value >= rule.low && value <= rule.high
					if got := rule.gate(value) == "valid"; got != wanted {
						test.Fatalf("boundary %d admitted %v want %v", value, got, wanted)
					}
				})
			}
		})
	}
}

// Claim: worst-case response tails, cadence, scheduler, in-flight old current response, watchdog and closure fit the amended budgets; deleting any term or margin is detected.
func TestLabObservationBudgetArithmetic(test *testing.T) {
	const nativeGap, nativeFence, currentGap, currentWatchdog, closure, pair, endToEnd = 1050, 1200, 600, 750, 500, 1250, 3000
	if 250+500+50+250 != nativeGap || nativeGap+150 != nativeFence || 250+300+50 != currentGap || currentGap+150 != currentWatchdog || 1150+50 != nativeFence || 700+50 != currentWatchdog || nativeGap+100 != 1150 || currentGap+100 != 700 {
		test.Fatal("valid recurring budget arithmetic")
	}
	if 2*(250+50+250) != 1100 || 1100 >= pair || nativeFence+300+currentWatchdog+closure != 2750 || 2750+250 != endToEnd {
		test.Fatal("valid pair/closure arithmetic")
	}
	for _, bad := range []struct {
		name                                 string
		gap, fence, watchdog, close, ceiling int
	}{
		{"old-native-watchdog", nativeGap, 500, currentWatchdog, closure, endToEnd},
		{"old-current-watchdog", nativeGap, nativeFence, 500, closure, endToEnd},
		{"old-ceiling", nativeGap, nativeFence, currentWatchdog, closure, 1000},
	} {
		test.Run(bad.name, func(test *testing.T) {
			admitted := bad.gap < bad.fence && currentGap < bad.watchdog && bad.fence+300+bad.watchdog+bad.close < bad.ceiling
			if admitted {
				test.Fatal("incoherent former timing admitted")
			}
		})
	}
}

// Claim: admitting authentic narrowing evidence does not bypass its native selectors or incarnation joins, and never enables committed use.
func TestLabObservationNarrowingJoins(test *testing.T) {
	for _, kind := range []string{"stop", "invalidation"} {
		fields := []string{"generation", "start_id"}
		if kind == "invalidation" {
			fields = []string{"generation", "execution_id", "boot_id"}
		}
		for _, field := range fields {
			test.Run(kind+"/"+field, func(test *testing.T) {
				first, _ := consumptionPair(test, kind)
				if got := observationJoinAdmission(test, first, true, true); got != "valid" {
					test.Fatalf("valid narrowing: %s", got)
				}
				if got := observationAdmission(test, first, true); got != "start_phase" {
					test.Fatalf("narrowing enabled use: %s", got)
				}
				member := "stops"
				if kind == "invalidation" {
					member = "invalidations"
				}
				entry := first.Response[member].([]any)[0].(map[string]any)
				entry[field] = map[string]string{"generation": "22222222222222222222222222222222", "start_id": "other-start", "execution_id": "other-start", "boot_id": "22222222-2222-2222-2222-222222222222"}[field]
				if got := observationJoinAdmission(test, first, true, true); got != kind+"_join" {
					test.Fatalf("native narrowing join: got %s want %s_join", got, kind)
				}
			})
		}
	}
}

// Claim: cached current successes cannot refresh native age, a fence is irreversible by polling, and a replay-seen single cannot become the next pair candidate.
func TestLabObservationCurrentPairs(test *testing.T) {
	state := validObservationUse(test)
	if got := continuedObservation(&state, 3299); got != "valid" || state.Observed != 2100 {
		test.Fatalf("valid cached current: %s", got)
	}
	if got := continuedObservation(&state, 3300); got != "unknown_age" || state.Open {
		test.Fatalf("cached current extended native age: %s", got)
	}
	if got := continuedObservation(&state, 2100); got != "closed" {
		test.Fatalf("current reopened use: %s", got)
	}
	state = validObservationUse(test)
	if got := periodicObservation(test, &state, periodicControl(test), true, 2603); got != "continued" {
		test.Fatalf("valid single: %s", got)
	}
	first, final := consumptionPair(test, "start")
	first.Expected["before_monotonic_ms"], first.Expected["after_monotonic_ms"] = int64(2853), int64(2855)
	first.Response["observed_monotonic_ms"] = int64(2854)
	final.Expected["before_monotonic_ms"], final.Expected["after_monotonic_ms"] = int64(3105), int64(3107)
	final.Response["observed_monotonic_ms"] = int64(3106)
	if got := consumeObservationPair(test, &state, "start", first, final, 2603, 3107, true, true, true); got != "unknown_pair_join" || state.Open || state.Floor != 8 {
		test.Fatalf("single banked for publication: %s", got)
	}
	first, final = consumptionPair(test, "start")
	first.Response["sequence"], final.Response["sequence"] = int64(10), int64(11)
	first.Expected["before_monotonic_ms"], first.Expected["after_monotonic_ms"] = int64(2853), int64(2855)
	first.Response["observed_monotonic_ms"] = int64(2854)
	final.Expected["before_monotonic_ms"], final.Expected["after_monotonic_ms"] = int64(3105), int64(3107)
	final.Response["observed_monotonic_ms"] = int64(3106)
	if got := consumeObservationPair(test, &state, "start", first, final, 2603, 3107, true, true, true); got != "published" || state.Floor != 11 {
		test.Fatalf("fresh post-single publication: %s", got)
	}
}

// Claim: repeated slow valid singles and current checks retain both watchdog margins without advancing the publication floor; shorter legacy budgets refuse those same controls.
func TestLabObservationSlowControls(test *testing.T) {
	state := validObservationUse(test)
	for attempt := int64(0); attempt < 3; attempt++ {
		next := periodicControl(test)
		before := state.Receipt + 549
		next.Expected["before_monotonic_ms"], next.Expected["after_monotonic_ms"] = before, before+249
		next.Response["observed_monotonic_ms"], next.Response["sequence"] = before, state.Seen+1
		if got := periodicObservation(test, &state, next, true, before+249); got != "continued" || state.Floor != 8 || !state.Open {
			test.Fatalf("slow valid single: %s", got)
		}
	}
	if observationCurrentSchedule(299, 0) != "valid" || observationCurrentBudget(299) != "valid" || observationCurrentWatchdog(598, 0) != "valid" {
		test.Fatal("slow valid current closed")
	}
	if observationCurrentBudget(300) == "valid" || observationCurrentWatchdog(750, 0) == "valid" {
		test.Fatal("late current admitted")
	}
	if observationWait(249, 0) == "valid" || observationSchedule(550, 0) == "valid" {
		test.Fatal("burst or late single admitted")
	}
}
