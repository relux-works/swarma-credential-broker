package labcontractv0

import (
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const boundedFormat = "swarma-broker-lab-bounded-invocation/1"
const maxMicroUSD = int64(9007199254740991)

func parseUSDMicros(value any) (int64, bool) {
	text, ok := value.(string)
	if !ok || !regexp.MustCompile(`^(0|[1-9][0-9]{0,9})\.[0-9]{6}$`).MatchString(text) {
		return 0, false
	}
	amount, err := strconv.ParseInt(strings.ReplaceAll(text, ".", ""), 10, 64)
	return amount, err == nil && amount > 0 && amount <= maxMicroUSD
}

func usdOracle(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	parts := strings.Split(text, ".")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 10 || len(parts[1]) != 6 || len(parts[0]) > 1 && parts[0][0] == '0' {
		return false
	}
	for _, char := range parts[0] + parts[1] {
		if char < '0' || char > '9' {
			return false
		}
	}
	amount, ok := new(big.Int).SetString(parts[0]+parts[1], 10)
	return ok && amount.Sign() > 0 && amount.Cmp(big.NewInt(9007199254740991)) <= 0
}

func usdMutations() []grammarMutation {
	var result []grammarMutation
	for _, seed := range []string{"0.000001", "0.000002", "1.000000", "9007199254.740990", "9007199254.740991"} {
		cases := append(literalMutations(seed), separatorMutations(seed, strings.IndexByte(seed, '.'))...)
		cases = append(cases, wrongTypes(seed)...)
		for _, value := range []string{"0" + seed, "+" + seed, "-" + seed, seed + "0", seed[:len(seed)-1], seed + "e0", seed + "E+0", seed + "e-0"} {
			cases = append(cases, grammarMutation{"number-spelling-" + value, value, false})
		}
		for _, mutation := range cases {
			mutation.Name = seed + "/" + mutation.Name
			mutation.Admit = usdOracle(mutation.Value)
			result = append(result, mutation)
		}
	}
	for _, value := range []string{"0.000000", "0.000001", "0.000002", "9007199254.740990", "9007199254.740991", "9007199254.740992", "00.000000", "00.000001", "0.0000000", "0.0000010", "00000000000.000000", "10000000000.000000", "0.00001", "1.00000", "0.0000001", "1.0000001", "١.000001", "1．000001", "1.00000１"} {
		result = append(result, grammarMutation{"usd-boundary-" + value, value, usdOracle(value)})
	}
	return result
}

// Claim: independent exact-integer expectations and catalogue operators pin both USD bounds and canonical decimal spelling, never float rounding.
func TestLabBoundedUSDPairs(test *testing.T) {
	set, _ := loadContracts(test)
	for _, mutation := range usdMutations() {
		test.Run(mutation.Name, func(test *testing.T) {
			if err := checkValue("0.000001", "usd", set); err != nil {
				test.Fatalf("USD valid control: %v", err)
			}
			if admitted := checkValue(mutation.Value, "usd", set) == nil; admitted != mutation.Admit {
				test.Fatalf("USD grammar verdict: %v, expected %v", mutation.Value, mutation.Admit)
			}
		})
	}
	for _, amount := range []int64{0, 1, 2, maxMicroUSD - 1, maxMicroUSD, maxMicroUSD + 1} {
		value := fmt.Sprintf("%d.%06d", amount/1000000, amount%1000000)
		parsed, admitted := parseUSDMicros(value)
		if admitted != (amount >= 1 && amount <= maxMicroUSD) || admitted && parsed != amount {
			test.Fatalf("USD exact boundary: %d", amount)
		}
	}
}

type boundedCase struct {
	Name                 string         `json:"name"`
	Expected             string         `json:"expected"`
	Plan                 map[string]any `json:"plan"`
	Approval             map[string]any `json:"approval"`
	Launch               map[string]any `json:"launch_plan"`
	ExpectedPlan         string         `json:"expected_plan_sha256"`
	OwnerVerified        bool           `json:"owner_verified"`
	Revoked              bool           `json:"revoked"`
	ClockVerified        bool           `json:"clock_verified"`
	ControlsVerified     bool           `json:"controls_verified"`
	Now                  string         `json:"now"`
	Executor             string         `json:"executor_sha256"`
	ClientBinary         string         `json:"client_binary_sha256"`
	AvailableCapMicroUSD int64          `json:"available_cap_micro_usd"`
}

func boundedCases(test *testing.T) []boundedCase {
	test.Helper()
	var corpus struct {
		Format    string        `json:"format"`
		Synthetic bool          `json:"synthetic_only"`
		Live      bool          `json:"live_authority"`
		Cases     []boundedCase `json:"cases"`
	}
	decodeContract(test, "bounded-invocation-fixtures.json", &corpus)
	if corpus.Format != "swarma-lab-bounded-invocation-fixtures/1" || !corpus.Synthetic || corpus.Live || len(corpus.Cases) != 22 {
		test.Fatal("bounded corpus inventory")
	}
	return corpus.Cases
}

func boundedClone(test *testing.T, original boundedCase) boundedCase {
	test.Helper()
	original.Plan = cloneObject(test, original.Plan)
	original.Approval = cloneObject(test, original.Approval)
	original.Launch = cloneObject(test, original.Launch)
	return original
}

func boundedDigest(test *testing.T, object map[string]any) string {
	return "sha256:" + hashContract(canonicalObject(test, object))
}

func boundedTarget(test *testing.T, plan map[string]any) string {
	record := cloneObject(test, plan)
	delete(record, "approval_record_sha256")
	return boundedDigest(test, map[string]any{"domain": "swarma-broker-lab-bounded-invocation-target/1", "record": record})
}

func boundedRebind(test *testing.T, candidate *boundedCase) {
	test.Helper()
	candidate.Approval["invocation_sha256"] = boundedTarget(test, candidate.Plan)
	resealClosure(test, candidate.Approval)
	candidate.Plan["approval_record_sha256"] = boundedDigest(test, candidate.Approval)
	candidate.ExpectedPlan = boundedDigest(test, candidate.Plan)
	pins := candidate.Launch["pins"].(map[string]any)
	pins["invocation_sha256"] = candidate.Approval["invocation_sha256"]
	pins["off_vm_approval_sha256"] = candidate.Plan["approval_record_sha256"]
	for _, raw := range candidate.Launch["input_pins"].([]any) {
		pin := raw.(map[string]any)
		switch pin["name"] {
		case "bounded-invocation":
			pin["sha256"] = candidate.ExpectedPlan
		case "client-profile":
			pin["sha256"] = candidate.Plan["client_profile_sha256"]
		case "wire-profile":
			pin["sha256"] = candidate.Plan["wire_profile_sha256"]
		case "bounded-executor":
			pin["sha256"] = candidate.Plan["executor_sha256"]
		}
	}
}

func boundedShape(set contractSet, format string) recordShape {
	for _, shape := range set.Surfaces {
		if shape.Format == format {
			return shape
		}
	}
	return recordShape{}
}

func boundedAdmission(test *testing.T, candidate boundedCase, baseline boundedCase) string {
	test.Helper()
	set, _ := loadContracts(test)
	for _, item := range []struct {
		object map[string]any
		format string
	}{{candidate.Plan, boundedFormat}, {candidate.Approval, "swarma-broker-lab-off-vm-approval/1"}, {candidate.Launch, "swarma-broker-lab-launch-plan/1"}} {
		if err := checkRecord(canonicalObject(test, item.object), boundedShape(set, item.format), set); err != nil {
			return "shape"
		}
	}
	plan, _ := wire.Parse(canonicalObject(test, candidate.Plan))
	approval, _ := wire.Parse(canonicalObject(test, candidate.Approval))
	launch, _ := wire.Parse(canonicalObject(test, candidate.Launch))
	if plan["live_budget_approved"] != true {
		return "approval"
	}
	if !candidate.OwnerVerified {
		return "unknown_owner"
	}
	if candidate.Revoked {
		return "revoked"
	}
	if !candidate.ClockVerified {
		return "unknown_clock"
	}
	if !candidate.ControlsVerified {
		return "unknown_controls"
	}
	if plan["approval_record_sha256"] != boundedDigest(test, approval) {
		return "approval_digest"
	}
	if !approvalTargetValid(approval) {
		return "approval_seal"
	}
	if approval["invocation_sha256"] != boundedTarget(test, plan) {
		return "approval_target"
	}
	if candidate.ExpectedPlan != boundedDigest(test, plan) {
		return "plan_digest"
	}
	owner := approval["approval"].(map[string]any)
	now, nowErr := time.Parse(time.RFC3339Nano, candidate.Now)
	approved, _ := time.Parse(time.RFC3339Nano, owner["approved_at"].(string))
	expires, _ := time.Parse(time.RFC3339Nano, owner["expires_at"].(string))
	offVM, _ := time.Parse(time.RFC3339Nano, approval["off_vm_now"].(string))
	context := plan["context"].(map[string]any)
	qualification, _ := time.Parse(time.RFC3339Nano, context["qualification_expires_at"].(string))
	if nowErr != nil {
		return "unknown_clock"
	}
	if now.Before(approved) || offVM.Before(approved) || now.Before(offVM) || !now.Before(expires) || !now.Before(qualification) {
		return "approval_freshness"
	}
	for _, name := range []string{"context", "heads", "release_set_sha256", "access_attestation_sha256", "start_generation"} {
		if !reflect.DeepEqual(approval[name], normalizedBounded(test, baseline.Approval)[name]) {
			return "approval_current"
		}
	}
	if !reflect.DeepEqual(plan["context"], approval["context"]) {
		return "approval_context"
	}
	if plan["client_profile_sha256"] != "sha256:"+hashContract(readContract(test, "probe/client.json")) {
		return "client_pin"
	}
	if plan["wire_profile_sha256"] != "sha256:"+hashContract(readContract(test, "wire-fixtures.json")) {
		return "wire_pin"
	}
	var client struct {
		Model  string `json:"observed_model"`
		Output int64  `json:"observed_max_tokens"`
		Binary string `json:"binary_sha256"`
		Live   bool   `json:"live_budget_approved"`
	}
	decodeContract(test, "probe/client.json", &client)
	if client.Live || plan["model"] != client.Model || plan["max_output_tokens_per_invocation"] != client.Output {
		return "wire_values"
	}
	if candidate.ClientBinary != "sha256:"+client.Binary {
		return "client_binary"
	}
	if plan["executor_sha256"] != candidate.Executor {
		return "executor_pin"
	}
	if plan["max_wall_time_per_invocation_ms"].(int64) > plan["max_wall_time_total_ms"].(int64) {
		return "bound_relation"
	}
	amount, _ := parseUSDMicros(plan["max_total_cost_usd"])
	if candidate.AvailableCapMicroUSD < amount {
		return "vendor_cap"
	}
	pins := launch["pins"].(map[string]any)
	if !reflect.DeepEqual(launch["context"], context) || launch["operation_id"] != plan["operation_id"] || launch["target_generation"] != plan["target_generation"] || pins["invocation_sha256"] != approval["invocation_sha256"] || pins["off_vm_approval_sha256"] != plan["approval_record_sha256"] || pins["release_set_sha256"] != approval["release_set_sha256"] || pins["access_attestation_sha256"] != approval["access_attestation_sha256"] || !reflect.DeepEqual(launch["predecessor_heads"], approval["heads"]) {
		return "plan_join"
	}
	wanted := map[string]any{"bounded-invocation": candidate.ExpectedPlan, "client-profile": plan["client_profile_sha256"], "wire-profile": plan["wire_profile_sha256"], "bounded-executor": plan["executor_sha256"]}
	seen := map[string]bool{}
	for _, raw := range launch["input_pins"].([]any) {
		pin := raw.(map[string]any)
		name := pin["name"].(string)
		if seen[name] {
			return "plan_join"
		}
		seen[name] = true
		if expected, exists := wanted[name]; exists && pin["sha256"] != expected {
			return "plan_join"
		}
	}
	for name := range wanted {
		if !seen[name] {
			return "plan_join"
		}
	}
	return "admitted"
}

func normalizedBounded(test *testing.T, object map[string]any) map[string]any {
	result, err := wire.Parse(canonicalObject(test, object))
	if err != nil {
		test.Fatal(err)
	}
	return result
}

// Claim: published synthetic approval/client/executor joins admit only the valid control and refuse each negative at its named gate; these facts are not owner authority.
func TestLabBoundedAdmissionPairs(test *testing.T) {
	cases := boundedCases(test)
	control := cases[0]
	for _, candidate := range cases {
		test.Run(candidate.Name, func(test *testing.T) {
			if result := boundedAdmission(test, control, control); result != "admitted" {
				test.Fatalf("bounded valid control: %s", result)
			}
			if result := boundedAdmission(test, candidate, control); result != candidate.Expected {
				test.Fatalf("bounded admission: got %s want %s", result, candidate.Expected)
			}
		})
	}
}

// Claim: re-sealed joins still require every protected approval/launch member and input pin; fresh seals cannot substitute a current observation or full-plan digest.
func TestLabBoundedJoinPairs(test *testing.T) {
	control := boundedCases(test)[0]
	run := func(name, expected string, change func(*boundedCase)) {
		test.Run(name, func(test *testing.T) {
			if result := boundedAdmission(test, control, control); result != "admitted" {
				test.Fatalf("bounded valid control: %s", result)
			}
			candidate := boundedClone(test, control)
			change(&candidate)
			if result := boundedAdmission(test, candidate, control); result != expected {
				test.Fatalf("bounded join: got %s want %s", result, expected)
			}
		})
	}
	for _, field := range []string{"context", "heads", "release_set_sha256", "access_attestation_sha256", "start_generation"} {
		run("protected-"+field, "approval_current", func(candidate *boundedCase) {
			switch field {
			case "context":
				candidate.Approval[field].(map[string]any)["account"] = "PUBLIC-OTHER"
			case "heads":
				candidate.Approval[field].(map[string]any)["service"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "start_generation":
				candidate.Approval[field] = int64(2)
			default:
				candidate.Approval[field] = "sha256:" + strings.Repeat("0", 64)
			}
			boundedRebind(test, candidate)
		})
	}
	run("approval-seal", "approval_seal", func(candidate *boundedCase) {
		candidate.Approval["approval"].(map[string]any)["approved_sha256"] = "sha256:" + strings.Repeat("0", 64)
		candidate.Plan["approval_record_sha256"] = boundedDigest(test, candidate.Approval)
	})
	run("full-plan-digest", "plan_digest", func(candidate *boundedCase) { candidate.ExpectedPlan = "sha256:" + strings.Repeat("0", 64) })
	run("plan-approval-context", "approval_context", func(candidate *boundedCase) {
		candidate.Plan["context"].(map[string]any)["account"] = "PUBLIC-OTHER"
		boundedRebind(test, candidate)
	})
	for _, field := range []string{"context", "operation_id", "target_generation", "predecessor_heads"} {
		run("launch-"+field, "plan_join", func(candidate *boundedCase) {
			switch field {
			case "context":
				candidate.Launch[field].(map[string]any)["account"] = "PUBLIC-OTHER"
			case "predecessor_heads":
				candidate.Launch[field].(map[string]any)["service"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "operation_id":
				candidate.Launch[field] = strings.Repeat("0", 32)
			default:
				candidate.Launch[field] = "PUBLIC-OTHER"
			}
		})
	}
	for _, field := range []string{"invocation_sha256", "off_vm_approval_sha256", "release_set_sha256", "access_attestation_sha256"} {
		run("launch-pin-"+field, "plan_join", func(candidate *boundedCase) {
			candidate.Launch["pins"].(map[string]any)[field] = "sha256:" + strings.Repeat("0", 64)
		})
	}
	for _, name := range []string{"bounded-invocation", "client-profile", "wire-profile", "bounded-executor"} {
		for _, mode := range []string{"missing", "changed", "duplicate"} {
			run("input-"+name+"-"+mode, "plan_join", func(candidate *boundedCase) {
				pins := candidate.Launch["input_pins"].([]any)
				for index, raw := range pins {
					pin := raw.(map[string]any)
					if pin["name"] != name {
						continue
					}
					switch mode {
					case "missing":
						candidate.Launch["input_pins"] = append(pins[:index], pins[index+1:]...)
					case "changed":
						pin["sha256"] = "sha256:" + strings.Repeat("0", 64)
					case "duplicate":
						candidate.Launch["input_pins"] = append(pins, cloneObject(test, pin))
					}
					return
				}
				test.Fatal("missing test pin")
			})
		}
	}
	for _, field := range []string{"model", "max_invocations", "max_output_tokens_per_invocation", "max_total_cost_usd", "max_wall_time_per_invocation_ms", "max_wall_time_total_ms", "operation_id", "target_generation", "client_profile_sha256", "wire_profile_sha256", "executor_sha256", "context"} {
		run("approval-binds-"+field, "approval_target", func(candidate *boundedCase) {
			switch field {
			case "max_invocations":
				candidate.Plan[field] = int64(3)
			case "max_output_tokens_per_invocation":
				candidate.Plan[field] = int64(127999)
			case "max_wall_time_per_invocation_ms":
				candidate.Plan[field] = int64(4999)
			case "max_wall_time_total_ms":
				candidate.Plan[field] = int64(9999)
			case "max_total_cost_usd":
				candidate.Plan[field] = "0.100001"
			case "operation_id":
				candidate.Plan[field] = strings.Repeat("0", 32)
			case "context":
				candidate.Plan[field].(map[string]any)["account"] = "PUBLIC-OTHER"
			case "client_profile_sha256", "wire_profile_sha256", "executor_sha256":
				candidate.Plan[field] = "sha256:" + strings.Repeat("0", 64)
			default:
				candidate.Plan[field] = "PUBLIC-OTHER"
			}
		})
	}
	for _, row := range []struct {
		name, now string
		admitted  bool
	}{{"before", "2026-11-20T07:59:59Z", false}, {"at-approved", "2026-11-20T08:00:00Z", true}, {"before-expiry", "2026-11-20T08:09:59.999999999Z", true}, {"at-expiry", "2026-11-20T08:10:00Z", false}, {"after-expiry", "2026-11-20T08:10:00.000000001Z", false}} {
		run("time-"+row.name, map[bool]string{true: "admitted", false: "approval_freshness"}[row.admitted], func(candidate *boundedCase) { candidate.Now = row.now })
	}
	for _, name := range []string{"approved-in-future", "off-vm-before-approval", "off-vm-in-future", "qualification-expired"} {
		run(name, "approval_freshness", func(candidate *boundedCase) {
			switch name {
			case "approved-in-future":
				candidate.Approval["approval"].(map[string]any)["approved_at"] = "2026-11-20T08:00:02Z"
			case "off-vm-before-approval":
				candidate.Approval["off_vm_now"] = "2026-11-20T07:59:59Z"
			case "off-vm-in-future":
				candidate.Approval["off_vm_now"] = "2026-11-20T08:00:02Z"
			case "qualification-expired":
				candidate.Plan["context"].(map[string]any)["qualification_expires_at"] = candidate.Now
				candidate.Approval["context"].(map[string]any)["qualification_expires_at"] = candidate.Now
			}
			boundedRebind(test, candidate)
		})
	}
}

type boundedLedger struct {
	Attempts, Output, Cost, Reserved, AttemptMS, TotalMS int64
	Active, Stopped, Unknown                             bool
	PlanDigest, Operation                                string
}

type boundedLimits struct{ Count, Output, Cost, PerMS, TotalMS int64 }

func limitsFromPlan(test *testing.T, candidate boundedCase) boundedLimits {
	plan := normalizedBounded(test, candidate.Plan)
	cost, _ := parseUSDMicros(plan["max_total_cost_usd"])
	return boundedLimits{plan["max_invocations"].(int64), plan["max_output_tokens_per_invocation"].(int64), cost, plan["max_wall_time_per_invocation_ms"].(int64), plan["max_wall_time_total_ms"].(int64)}
}

func boundedStart(state *boundedLedger, limit boundedLimits, plan, operation string, quote, elapsed int64, quoteVerified bool) string {
	if state.Unknown {
		return "unknown"
	}
	if state.PlanDigest != plan || state.Operation != operation {
		return "ledger_join"
	}
	if elapsed < state.TotalMS {
		state.Unknown, state.Stopped = true, true
		state.Active = false
		return "unknown"
	}
	state.TotalMS = elapsed
	if state.Stopped || state.TotalMS >= limit.TotalMS || state.Cost >= limit.Cost {
		state.Stopped, state.Active = true, false
		return "exhausted"
	}
	if state.Active {
		return "status_only"
	}
	if state.Attempts >= limit.Count {
		state.Stopped = true
		return "exhausted"
	}
	if !quoteVerified || quote <= 0 {
		state.Unknown, state.Stopped = true, true
		return "unknown"
	}
	if quote > limit.Cost-state.Cost-state.Reserved {
		return "budget"
	}
	state.Attempts++
	state.Reserved += quote
	state.Active = true
	state.Output, state.AttemptMS = 0, 0
	return "started"
}

func boundedObserve(state *boundedLedger, limit boundedLimits, output, cost, attemptMS, totalMS int64, evidenceComplete bool) string {
	if state.Unknown {
		return "unknown"
	}
	if !state.Active {
		return "status_only"
	}
	if !evidenceComplete || output < state.Output || cost < state.Cost || attemptMS < state.AttemptMS || totalMS < state.TotalMS {
		state.Unknown, state.Stopped, state.Active = true, true, false
		return "unknown"
	}
	if output > limit.Output || cost > limit.Cost || attemptMS > limit.PerMS || totalMS > limit.TotalMS {
		state.Reserved = max(int64(0), state.Reserved-(cost-state.Cost))
		state.Output, state.Cost, state.AttemptMS, state.TotalMS = output, cost, attemptMS, totalMS
		state.Stopped, state.Active = true, false
		return "violation"
	}
	if cost-state.Cost > state.Reserved {
		state.Cost = cost
		state.Unknown, state.Stopped, state.Active = true, true, false
		return "unknown"
	}
	state.Reserved -= cost - state.Cost
	state.Output, state.Cost, state.AttemptMS, state.TotalMS = output, cost, attemptMS, totalMS
	if output == limit.Output || cost == limit.Cost || attemptMS == limit.PerMS || totalMS == limit.TotalMS {
		state.Stopped, state.Active = true, false
		return "stopped"
	}
	return "running"
}

func boundedSettle(state *boundedLedger, complete bool) string {
	if state.Unknown {
		return "unknown"
	}
	if !complete {
		state.Unknown, state.Stopped, state.Active = true, true, false
		return "unknown"
	}
	state.Reserved, state.Active = 0, false
	return "settled"
}

// Claim: the reference ledger reserves and counts before start, stops at each first bound, and never treats unknown usage or retry as free; native enforcement remains unproved.
func TestLabBoundedExecutorPairs(test *testing.T) {
	control := boundedCases(test)[0]
	limit := limitsFromPlan(test, control)
	fresh := func() boundedLedger {
		return boundedLedger{PlanDigest: control.ExpectedPlan, Operation: control.Plan["operation_id"].(string)}
	}
	start := func(test *testing.T, state *boundedLedger, quote int64) {
		test.Helper()
		if result := boundedStart(state, limit, control.ExpectedPlan, state.Operation, quote, 0, true); result != "started" {
			test.Fatalf("executor valid control: %s", result)
		}
	}
	for _, bound := range []string{"count", "output", "cost", "per-wall", "total-wall"} {
		for _, delta := range []int64{-1, 0, 1} {
			test.Run(fmt.Sprintf("%s/%d", bound, delta), func(test *testing.T) {
				valid := fresh()
				start(test, &valid, limit.Cost)
				state := fresh()
				if bound == "count" {
					state.Attempts = limit.Count + delta
					result := boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, 0, true)
					want := "exhausted"
					if delta < 0 {
						want = "started"
					}
					if result != want {
						test.Fatalf("count bound: %s want %s", result, want)
					}
					return
				}
				start(test, &state, limit.Cost)
				output, cost, per, total := int64(1), int64(1), int64(1), int64(1)
				switch bound {
				case "output":
					output = limit.Output + delta
				case "cost":
					cost = limit.Cost + delta
				case "per-wall":
					per = limit.PerMS + delta
					total = per
				case "total-wall":
					total = limit.TotalMS + delta
				}
				want := "running"
				if delta == 0 {
					want = "stopped"
				}
				if delta > 0 {
					want = "violation"
				}
				if result := boundedObserve(&state, limit, output, cost, per, total, true); result != want {
					test.Fatalf("first bound: %s want %s", result, want)
				}
				if bound == "cost" && state.Cost != cost {
					test.Fatal("observed cost debit lost")
				}
				if delta >= 0 {
					attempts := state.Attempts
					if result := boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, total, true); result != "exhausted" || state.Attempts != attempts || state.Active {
						test.Fatalf("retry after bound: %s", result)
					}
				}
			})
		}
	}
	for _, mode := range []string{"zero-quote", "unknown-quote", "over-remaining", "active-retry", "unknown-response", "unknown-settlement", "clock-regression", "output-regression", "cost-regression", "attempt-clock-regression", "total-clock-regression", "charge-exceeds-reservation", "changed-plan", "changed-operation", "gap-at-total-bound"} {
		test.Run(mode, func(test *testing.T) {
			valid := fresh()
			start(test, &valid, limit.Cost)
			state := fresh()
			want := "unknown"
			var result string
			switch mode {
			case "zero-quote":
				result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 0, 0, true)
			case "unknown-quote":
				result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, 0, false)
			case "over-remaining":
				want = "budget"
				result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, limit.Cost+1, 0, true)
			case "changed-plan":
				want = "ledger_join"
				result = boundedStart(&state, limit, "PUBLIC-OTHER", state.Operation, 1, 0, true)
			case "changed-operation":
				want = "ledger_join"
				result = boundedStart(&state, limit, control.ExpectedPlan, "PUBLIC-OTHER", 1, 0, true)
			case "gap-at-total-bound":
				want = "exhausted"
				result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, limit.TotalMS, true)
			default:
				quote := limit.Cost
				if mode == "charge-exceeds-reservation" {
					quote = 10
				}
				start(test, &state, quote)
				if result := boundedObserve(&state, limit, 2, 2, 2, 2, true); result != "running" {
					test.Fatal("observe valid control")
				}
				switch mode {
				case "active-retry":
					want = "status_only"
					result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, 2, true)
				case "unknown-settlement":
					result = boundedSettle(&state, false)
				case "clock-regression":
					result = boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, 1, true)
				default:
					output, cost, per, total := int64(3), int64(3), int64(3), int64(3)
					switch mode {
					case "output-regression":
						output = 1
					case "cost-regression":
						cost = 1
					case "attempt-clock-regression":
						per = 1
					case "total-clock-regression":
						total = 1
					case "charge-exceeds-reservation":
						cost = 11
					}
					result = boundedObserve(&state, limit, output, cost, per, total, mode != "unknown-response")
				}
			}
			if result != want {
				test.Fatalf("executor refusal: got %s want %s", result, want)
			}
			if want == "unknown" {
				reservation, attempts := state.Reserved, state.Attempts
				if !state.Unknown || !state.Stopped || state.Active {
					test.Fatal("unknown state not closed")
				}
				if result := boundedSettle(&state, true); result != "unknown" {
					test.Fatal("unknown settlement cleared")
				}
				if result := boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, state.TotalMS, true); result != "unknown" || state.Reserved != reservation || state.Attempts != attempts {
					test.Fatal("unknown debit or ordinal lost")
				}
			}
			if mode == "over-remaining" || mode == "changed-plan" || mode == "changed-operation" {
				if state.Active || state.Attempts != 0 || state.Reserved != 0 {
					test.Fatal("refusal partially started")
				}
			}
			if mode == "charge-exceeds-reservation" && (state.Cost != 11 || state.Reserved != 8 || state.Attempts != 1) {
				test.Fatal("unreserved authoritative debit lost")
			}
			if mode == "active-retry" && state.Attempts != 1 {
				test.Fatal("retry consumed new ordinal")
			}
		})
	}
	for _, mode := range []string{"final-active-status", "active-total-deadline", "active-cost-exhausted"} {
		test.Run(mode, func(test *testing.T) {
			valid := fresh()
			start(test, &valid, limit.Cost)
			state := fresh()
			start(test, &state, limit.Cost)
			elapsed, want := int64(0), "status_only"
			switch mode {
			case "final-active-status":
				state.Attempts = limit.Count
			case "active-total-deadline":
				elapsed, want = limit.TotalMS, "exhausted"
			case "active-cost-exhausted":
				state.Cost, want = limit.Cost, "exhausted"
			}
			attempts, reservation := state.Attempts, state.Reserved
			if result := boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, elapsed, true); result != want || state.Attempts != attempts || state.Reserved != reservation {
				test.Fatalf("active first-bound/status: %s want %s", result, want)
			}
			if want == "exhausted" && (!state.Stopped || state.Active) {
				test.Fatal("active bound not stopped")
			}
			if want == "status_only" && (!state.Active || state.Stopped) {
				test.Fatal("final active ordinal was restarted or aborted")
			}
		})
	}
	test.Run("settlement-and-count-persistence", func(test *testing.T) {
		state := fresh()
		start(test, &state, limit.Cost)
		if state.Attempts != 1 || state.Reserved != limit.Cost || !state.Active {
			test.Fatal("start not reserved/counted")
		}
		if boundedObserve(&state, limit, 1, 10, 1, 1, true) != "running" || state.Reserved != limit.Cost-10 {
			test.Fatal("reservation accounting")
		}
		if boundedSettle(&state, true) != "settled" || state.Reserved != 0 || state.Cost != 10 || state.Attempts != 1 {
			test.Fatal("settlement lost debit")
		}
		if boundedStart(&state, limit, control.ExpectedPlan, state.Operation, limit.Cost-10, 2, true) != "started" || state.Attempts != 2 {
			test.Fatal("equal remaining reservation refused")
		}
		if boundedSettle(&state, true) != "settled" || boundedStart(&state, limit, control.ExpectedPlan, state.Operation, 1, 3, true) != "exhausted" {
			test.Fatal("count reset after settlement")
		}
	})
}

// Claim: every applicable model-literal operator and the exact output pair are checked after a fresh synthetic approval, not masked by an old target or full-plan digest.
func TestLabBoundedProfileOperatorPairs(test *testing.T) {
	control := boundedCases(test)[0]
	model := control.Plan["model"].(string)
	for _, mutation := range append(literalMutations(model), wrongTypes(model)...) {
		test.Run("model/"+mutation.Name, func(test *testing.T) {
			if result := boundedAdmission(test, control, control); result != "admitted" {
				test.Fatal("profile valid control", result)
			}
			candidate := boundedClone(test, control)
			candidate.Plan["model"] = mutation.Value
			boundedRebind(test, &candidate)
			wanted := "wire_values"
			text, ok := mutation.Value.(string)
			validID := ok && len(text) >= 1 && len(text) <= 128
			for _, char := range []byte(text) {
				if char < 0x21 || char > 0x7e {
					validID = false
				}
			}
			if !validID {
				wanted = "shape"
			} else if text == model {
				wanted = "admitted"
			}
			if result := boundedAdmission(test, candidate, control); result != wanted {
				test.Fatalf("profile literal: got %s want %s", result, wanted)
			}
		})
	}
	for _, value := range []any{nil, false, "128000", []any{}, map[string]any{}, int64(0), int64(1), int64(127999), int64(128000), int64(128001)} {
		test.Run(fmt.Sprintf("output/%T-%v", value, value), func(test *testing.T) {
			if result := boundedAdmission(test, control, control); result != "admitted" {
				test.Fatal("profile valid control", result)
			}
			candidate := boundedClone(test, control)
			candidate.Plan["max_output_tokens_per_invocation"] = value
			boundedRebind(test, &candidate)
			wanted := "shape"
			if number, ok := value.(int64); ok && number >= 1 && number <= 128000 {
				wanted = "wire_values"
				if number == 128000 {
					wanted = "admitted"
				}
			}
			if result := boundedAdmission(test, candidate, control); result != wanted {
				test.Fatalf("profile output: got %s want %s", result, wanted)
			}
		})
	}
}
