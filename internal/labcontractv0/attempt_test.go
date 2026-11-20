package labcontractv0

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const gatewayPriceFormat = "swarma-broker-lab-model-price/1"
const gatewayLedgerFormat = "swarma-broker-lab-attempt-ledger/1"
const gatewayPriceMember = "contracts/lab-v0/model-price.json"

func gatewayFixture(test *testing.T) (boundedCase, map[string]any, map[string]any, map[string]any, map[string]any) {
	test.Helper()
	candidate := boundedClone(test, boundedCases(test)[0])
	candidate.Plan["max_total_cost_usd"] = "50.000000"
	candidate.AvailableCapMicroUSD = 50000000
	var price map[string]any
	decodeContract(test, "model-price.json", &price)
	price = normalizedBounded(test, price)
	set, fixtures := loadContracts(test)
	var ledger map[string]any
	for index, shape := range set.Surfaces {
		if shape.Format == gatewayLedgerFormat {
			ledger = normalizedBounded(test, fixtures[index].Valid)
		}
	}
	observation := observationControl(test).Response
	observation = normalizedBounded(test, observation)
	observation["invalidations"], observation["stops"] = []any{}, []any{}
	candidate.Plan["target_generation"] = observation["start"].(map[string]any)["generation"]
	asset := cloneObject(test, candidate.Release["assets"].([]any)[0].(map[string]any))
	asset["product"] = "gateway"
	asset["members"] = []any{map[string]any{"path": gatewayPriceMember, "mode": "0644", "sha256": boundedDigest(test, price)}}
	candidate.Release["assets"] = append(candidate.Release["assets"].([]any), asset)
	candidate.Approval["release_set_sha256"] = boundedDigest(test, candidate.Release)
	candidate.Launch["target_generation"] = candidate.Plan["target_generation"]
	boundedRebind(test, &candidate)
	observation["start"].(map[string]any)["plan_sha256"] = boundedDigest(test, candidate.Launch)
	observation["start"].(map[string]any)["operation_id"] = observation["operation_id"]
	ledger["context"], ledger["operation_id"] = candidate.Plan["context"], candidate.Plan["operation_id"]
	for name, value := range gatewayJoinValues(test, candidate, price, observation) {
		ledger[name] = value
	}
	ledger["attempts"] = []any{}
	ledger["previous_sha256"] = boundedDigest(test, map[string]any{"domain": "swarma-broker-lab-attempt-ledger-genesis/1", "operation_id": candidate.Plan["operation_id"]})
	group := gatewayGroupRecord(test, candidate, price, observation, 2000)
	ledger["group_sha256"] = boundedDigest(test, group)
	return candidate, price, observation, normalizedBounded(test, ledger), group
}

func gatewayJoinValues(test *testing.T, candidate boundedCase, price, observation map[string]any) map[string]any {
	return map[string]any{
		"context": candidate.Plan["context"], "operation_id": candidate.Plan["operation_id"],
		"plan_sha256": boundedDigest(test, candidate.Plan), "approval_record_sha256": boundedDigest(test, candidate.Approval),
		"release_set_sha256": boundedDigest(test, candidate.Release), "model_price_sha256": boundedDigest(test, price),
		"launch_plan_sha256": boundedDigest(test, candidate.Launch), "start_observation_sha256": boundedDigest(test, observation),
		"start_operation_id": observation["operation_id"], "start_id": observation["start_id"],
		"store_generation":    observation["store"].(map[string]any)["generation"],
		"manager_instance_id": observation["manager"].(map[string]any)["instance_id"],
		"boot_id":             observation["manager"].(map[string]any)["boot_id"],
		"start_receipt":       observation["receipts"].([]any)[0], "start_debit": observation["debits"].([]any)[0],
	}
}

func gatewayPricePin(test *testing.T, release, price map[string]any) bool {
	matches := 0
	for _, asset := range release["assets"].([]any) {
		object := asset.(map[string]any)
		for _, member := range object["members"].([]any) {
			file := member.(map[string]any)
			if file["path"] == gatewayPriceMember {
				if object["product"] != "gateway" || file["mode"] != "0644" || file["sha256"] != boundedDigest(test, price) {
					return false
				}
				matches++
			}
		}
	}
	return matches == 1
}

func gatewayJoins(test *testing.T, candidate boundedCase, price, observation, ledger, group map[string]any, admissionAccepted bool) string {
	set, _ := loadContracts(test)
	for _, record := range []struct {
		value  map[string]any
		format string
	}{{price, gatewayPriceFormat}, {ledger, gatewayLedgerFormat}, {group, "swarma-broker-lab-attempt-group/1"}} {
		if checkRecord(canonicalObject(test, record.value), boundedShape(set, record.format), set) != nil {
			return "shape"
		}
	}
	if boundedAdmission(test, candidate, candidate) != "admitted" {
		return "approval"
	}
	if !gatewayPricePin(test, candidate.Release, price) {
		return "price_pin"
	}
	if !gatewayPriceIdentity(test, price, candidate.Plan["model"]) {
		return "price_model"
	}
	if !admissionAccepted {
		return "admission_pair"
	}
	start := observation["start"].(map[string]any)
	if !observation["complete"].(bool) || !observation["store"].(map[string]any)["generation_current"].(bool) || start["phase"] != "admitted" || len(observation["stops"].([]any)) != 0 || len(observation["invalidations"].([]any)) != 0 {
		return "native_closed"
	}
	if len(observation["receipts"].([]any)) != 1 || len(observation["debits"].([]any)) != 1 {
		return "native_count"
	}
	if start["plan_sha256"] != boundedDigest(test, candidate.Launch) || start["generation"] != candidate.Plan["target_generation"] {
		return "native_plan"
	}
	if got := gatewayGroupAdmission(test, candidate, price, observation, group); got != "admit" {
		return got
	}
	for name, value := range gatewayJoinValues(test, candidate, price, observation) {
		if !reflect.DeepEqual(ledger[name], value) {
			return "join:" + name
		}
	}
	if ledger["group_sha256"] != boundedDigest(test, group) || ledger["group_started_monotonic_ms"] != group["group_started_monotonic_ms"] {
		return "group_ledger"
	}
	return "admit"
}

func gatewayPublishedPrice(test *testing.T) map[string]any {
	test.Helper()
	var price map[string]any
	decodeContract(test, "model-price.json", &price)
	return price
}

func gatewayRates(price map[string]any) ([5]int64, bool) {
	var result [5]int64
	names := []string{"input_usd_per_million", "output_usd_per_million", "cache_write_5m_usd_per_million", "cache_write_1h_usd_per_million", "cache_read_usd_per_million"}
	for index, name := range names {
		value, ok := parseUSDMicros(price["rates"].(map[string]any)[name])
		if !ok {
			return result, false
		}
		result[index] = value
	}
	return result, true
}

func gatewayCeil(products [][2]int64) (int64, bool) {
	total := int64(0)
	for _, pair := range products {
		if pair[0] < 0 || pair[1] < 0 || pair[1] != 0 && pair[0] > (maxMicroUSD-total)/pair[1] {
			return 0, false
		}
		total += pair[0] * pair[1]
	}
	return total/1000000 + boolInt(total%1000000 != 0), true
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func gatewayWorst(price map[string]any, output int64) (int64, bool) {
	rates, ok := gatewayRates(price)
	if !ok {
		return 0, false
	}
	input := max(rates[0], rates[2], rates[3], rates[4])
	if price["input_token_ceiling"] != int64(1000000) || output < 1 || output > price["output_token_ceiling"].(int64) {
		return 0, false
	}
	return gatewayCeil([][2]int64{{1000000, input}, {output, rates[1]}})
}

func gatewayCharge(test *testing.T, price, usage map[string]any, output int64) (int64, bool) {
	set, _ := loadContracts(test)
	if checkFields(usage, set.Structures["GatewayUsage"], set) != nil {
		return 0, false
	}
	input := usage["input_tokens"].(int64)
	generated := usage["output_tokens"].(int64)
	write5 := usage["cache_creation_5m_input_tokens"].(int64)
	write1 := usage["cache_creation_1h_input_tokens"].(int64)
	read := usage["cache_read_input_tokens"].(int64)
	if write5 > 1000000 || write1 > 1000000 || input > 1000000 || read > 1000000 || write5+write1 != usage["cache_creation_input_tokens"] || input+write5+write1+read > 1000000 || generated > output {
		return 0, false
	}
	rates, ok := gatewayRates(price)
	if !ok {
		return 0, false
	}
	return gatewayCeil([][2]int64{{input, rates[0]}, {generated, rates[1]}, {write5, rates[2]}, {write1, rates[3]}, {read, rates[4]}})
}

func gatewayFence(ledger *map[string]any, reason string) string {
	if strings.HasPrefix(reason, "unknown") || strings.HasPrefix(reason, "history") {
		(*ledger)["status"] = "unknown"
	} else if (*ledger)["status"] == "open" {
		(*ledger)["status"] = "stopped"
	}
	return reason
}

type gatewayProof struct {
	Approved, Current, Ceiling, Exclusive, Durable, CAS bool
	Head, Boot                                          string
}

func gatewayProofFor(test *testing.T, ledger map[string]any) gatewayProof {
	return gatewayProof{true, true, true, true, true, true, boundedDigest(test, ledger), ledger["boot_id"].(string)}
}

func gatewayHistory(test *testing.T, ledger, price map[string]any, limit boundedLimits) (int64, string) {
	total := int64(0)
	attempts := ledger["attempts"].([]any)
	if int64(len(attempts)) > limit.Count {
		return 0, "count"
	}
	for index, value := range attempts {
		record := value.(map[string]any)
		if record["ordinal"] != int64(index+1) {
			return 0, "ordinal"
		}

		if verdict := gatewayRecordAdmission(test, record, price, limit); verdict != "valid" {
			return 0, verdict
		}
		reserve, _ := parseUSDMicros(record["reservation_cost_usd"])
		charge := record["settled_micro_usd"].(int64)
		switch record["state"] {
		case "reserved":
			if index != len(attempts)-1 {
				return 0, "active"
			}
			charge = reserve
		case "unknown":
			return 0, "unknown"
		}

		if total > maxMicroUSD-charge {
			return 0, "overflow"
		}
		total += charge
	}
	return total, "ok"
}

func gatewayPersist(test *testing.T, ledger *map[string]any, next map[string]any, proof gatewayProof) string {
	if (*ledger)["sequence"].(int64) >= maxMicroUSD {
		return gatewayFence(ledger, "unknown_sequence")
	}
	if proof.Head != boundedDigest(test, *ledger) {
		return gatewayFence(ledger, "unknown_head")
	}
	if !proof.CAS {
		return gatewayFence(ledger, "unknown_cas")
	}
	if !proof.Durable {
		return gatewayFence(ledger, "unknown_persistence")
	}
	next["sequence"] = (*ledger)["sequence"].(int64) + 1
	next["previous_sha256"] = proof.Head
	*ledger = next
	return "committed"
}

func gatewayReserve(test *testing.T, ledger *map[string]any, price map[string]any, limit boundedLimits, proof gatewayProof, now int64) string {
	current := *ledger
	if !proof.Approved {
		return gatewayFence(ledger, "closed_approval")
	}
	if !proof.Current {
		return gatewayFence(ledger, "closed_current")
	}
	if !proof.Ceiling {
		return gatewayFence(ledger, "unknown_ceiling")
	}
	if !proof.Exclusive {
		return gatewayFence(ledger, "closed_route")
	}
	if current["status"] != "open" {
		return gatewayFence(ledger, "closed_group")
	}
	if proof.Boot != current["boot_id"] {
		return gatewayFence(ledger, "unknown_boot")
	}
	elapsed := now - current["group_started_monotonic_ms"].(int64)
	if elapsed < 0 {
		return gatewayFence(ledger, "unknown_clock")
	}
	if elapsed >= limit.TotalMS {
		return gatewayFence(ledger, "closed_total_time")
	}
	used, state := gatewayHistory(test, current, price, limit)
	if state != "ok" {
		return gatewayFence(ledger, "history_"+state)
	}
	attempts := current["attempts"].([]any)
	if len(attempts) > 0 && attempts[len(attempts)-1].(map[string]any)["state"] == "reserved" {
		return gatewayFence(ledger, "closed_active")
	}
	if int64(len(attempts)) >= limit.Count {
		return gatewayFence(ledger, "closed_count")
	}
	reserve, bounded := gatewayWorst(price, limit.Output)
	if !bounded {
		return gatewayFence(ledger, "unknown_price")
	}
	if reserve > limit.Cost-used {
		return gatewayFence(ledger, "closed_cost")
	}
	next := normalizedBounded(test, current)
	record := map[string]any{"ordinal": int64(len(attempts) + 1), "state": "reserved", "reservation_output_tokens": limit.Output, "reservation_cost_usd": fmt.Sprintf("%d.%06d", reserve/1000000, reserve%1000000), "settled_micro_usd": int64(0), "usage_complete": false, "usage": gatewayZeroUsage(), "usage_sha256": gatewayUnavailable(test), "upstream_request_id": "not-observed", "started_monotonic_ms": now, "settled_monotonic_ms": int64(0)}
	next["attempts"] = append(next["attempts"].([]any), record)
	return gatewayPersist(test, ledger, next, proof)
}

func gatewayZeroUsage() map[string]any {
	result := map[string]any{}
	for _, name := range []string{"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_creation_5m_input_tokens", "cache_creation_1h_input_tokens", "cache_read_input_tokens"} {
		result[name] = int64(0)
	}
	return result
}
func gatewayUnavailable(test *testing.T) string {
	return boundedDigest(test, map[string]any{"domain": "swarma-broker-lab-usage-unavailable/1"})
}

func gatewaySettle(test *testing.T, ledger *map[string]any, price map[string]any, limit boundedLimits, proof gatewayProof, usage map[string]any, requestID string, terminal, sameModelTier bool, now int64) string {
	current := *ledger
	attempts := current["attempts"].([]any)
	if (current["status"] != "open" && current["status"] != "stopped") || len(attempts) == 0 || attempts[len(attempts)-1].(map[string]any)["state"] != "reserved" {
		return "closed_settlement"
	}
	next := normalizedBounded(test, current)
	record := next["attempts"].([]any)[len(attempts)-1].(map[string]any)
	reservation, _ := parseUSDMicros(record["reservation_cost_usd"])
	cost, complete := gatewayCharge(test, price, usage, limit.Output)
	conclusive := terminal && sameModelTier && requestID != "" && requestID != "not-observed" && complete && cost <= reservation && now >= record["started_monotonic_ms"].(int64)
	record["settled_monotonic_ms"] = now
	if !conclusive {
		record["state"], record["settled_micro_usd"] = "unknown", reservation
		next["status"] = "unknown"
	} else {
		record["state"], record["settled_micro_usd"], record["usage_complete"] = "settled", cost, true
		record["usage"], record["usage_sha256"], record["upstream_request_id"] = usage, boundedDigest(test, usage), requestID
		total, _ := gatewayHistory(test, next, price, limit)
		if int64(len(attempts)) >= limit.Count || gatewayReached(limit, usage["output_tokens"].(int64), total, now-record["started_monotonic_ms"].(int64), now-current["group_started_monotonic_ms"].(int64)) || !proof.Approved || !proof.Current || proof.Boot != current["boot_id"] {
			next["status"] = "stopped"
		}
	}
	verdict := gatewayPersist(test, ledger, next, proof)
	if verdict != "committed" {
		return verdict
	}
	if !conclusive {
		return "unknown"
	}
	return "settled"
}

// Claim: each approval, price-member and native-start join refuses independently beside the fully joined owner-approved synthetic control; no fixture is live authority.
func TestLabGatewayJoinPairs(test *testing.T) {
	candidate, price, observation, ledger, group := gatewayFixture(test)
	if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != "admit" {
		test.Fatalf("joined valid control: %s", got)
	}
	for name, value := range gatewayJoinValues(test, candidate, price, observation) {
		test.Run(name, func(test *testing.T) {
			changed := normalizedBounded(test, ledger)
			switch typed := value.(type) {
			case string:
				if strings.HasPrefix(typed, "sha256:") {
					changed[name] = "sha256:" + strings.Repeat("b", 64)
				} else if len(typed) == 32 {
					changed[name] = strings.Repeat("c", 32)
					if changed[name] == typed {
						changed[name] = strings.Repeat("d", 32)
					}
				} else if name == "boot_id" {
					changed[name] = "22222222-2222-4333-8444-555555555555"
				} else {
					changed[name] = typed + "x"
				}
			case map[string]any:
				child := normalizedBounded(test, typed)
				if name == "context" {
					child["account"] = "other-account"
				} else {
					child["pid"] = int64(4322)
				}
				changed[name] = child
			}
			if reflect.DeepEqual(changed[name], value) {
				test.Fatal("join negative did not change its field")
			}
			if got := gatewayJoins(test, candidate, price, observation, changed, group, true); got != "join:"+name {
				test.Fatalf("join refusal: %s want %s", got, name)
			}
		})
	}
	test.Run("approval-denied", func(test *testing.T) {
		changed := boundedClone(test, candidate)
		changed.OwnerVerified = false
		if got := gatewayJoins(test, changed, price, observation, ledger, group, true); got != "approval" {
			test.Fatalf("approval chain refusal: %s", got)
		}
	})
	test.Run("publication-not-single", func(test *testing.T) {
		if got := gatewayJoins(test, candidate, price, observation, ledger, group, false); got != "admission_pair" {
			test.Fatalf("admission refusal: %s", got)
		}
	})
	for _, field := range []string{"stops", "invalidations", "phase", "generation_current", "complete", "plan", "generation", "receipts", "debits"} {
		test.Run("native-"+field, func(test *testing.T) {
			changed := normalizedBounded(test, observation)
			want := "native_closed"
			switch field {
			case "stops":
				changed[field] = []any{observationControl(test).Stop}
			case "invalidations":
				changed[field] = []any{observationControl(test).Invalidation}
			case "phase":
				changed["start"].(map[string]any)[field] = "terminal"
			case "generation_current":
				changed["store"].(map[string]any)[field] = false
			case "complete":
				changed[field] = false
			case "plan":
				changed["start"].(map[string]any)["plan_sha256"] = "sha256:" + strings.Repeat("b", 64)
				want = "native_plan"
			case "generation":
				changed["start"].(map[string]any)[field] = strings.Repeat("b", 32)
				want = "native_plan"
			default:
				changed[field] = []any{}
				want = "native_count"
			}
			if got := gatewayJoins(test, candidate, price, changed, ledger, group, true); got != want {
				test.Fatalf("native refusal: %s want %s", got, want)
			}
		})
	}
	for _, mutation := range []string{"missing", "duplicate", "product", "mode", "digest"} {
		test.Run("price-"+mutation, func(test *testing.T) {
			release := normalizedBounded(test, candidate.Release)
			assets := release["assets"].([]any)
			asset := assets[len(assets)-1].(map[string]any)
			member := asset["members"].([]any)[0].(map[string]any)
			switch mutation {
			case "missing":
				asset["members"] = []any{}
			case "duplicate":
				release["assets"] = append(assets, normalizedBounded(test, asset))
			case "product":
				asset["product"] = "manager"
			case "mode":
				member["mode"] = "0755"
			case "digest":
				member["sha256"] = "sha256:" + strings.Repeat("b", 64)
			}
			if !gatewayPricePin(test, candidate.Release, price) || gatewayPricePin(test, release, price) {
				test.Fatal("price-member refusal")
			}
		})
	}
}

// Claim: independent integer price witnesses cover all five disjoint usage terms, conservative cache maxima, ceiling/overflow and single upward rounding beside exact valid controls.
func TestLabGatewayPricePairs(test *testing.T) {
	_, price, _, _, _ := gatewayFixture(test)
	if reserve, ok := gatewayWorst(price, 128000); !ok || reserve != 10560000 {
		test.Fatal("worst-case valid control")
	}
	for index, pair := range []struct {
		field string
		want  int64
	}{{"input_tokens", 4}, {"output_tokens", 20}, {"cache_creation_5m_input_tokens", 5}, {"cache_creation_1h_input_tokens", 8}, {"cache_read_input_tokens", 1}} {
		test.Run(pair.field, func(test *testing.T) {
			usage := gatewayZeroUsage()
			usage[pair.field] = int64(1)
			if index == 2 || index == 3 {
				usage["cache_creation_input_tokens"] = int64(1)
			}
			cost, ok := gatewayCharge(test, price, usage, 128000)
			if !ok || cost != pair.want {
				test.Fatalf("price term: %d %v want %d", cost, ok, pair.want)
			}
		})
	}
	usage := gatewayZeroUsage()
	usage["cache_read_input_tokens"] = int64(5)
	if cost, ok := gatewayCharge(test, price, usage, 128000); !ok || cost != 1 {
		test.Fatal("round once valid control")
	}
	usage["input_tokens"] = int64(1)
	if cost, ok := gatewayCharge(test, price, usage, 128000); !ok || cost != 5 {
		test.Fatal("combined disjoint price")
	}
	for _, field := range []string{"input_tokens", "cache_creation_5m_input_tokens", "cache_creation_1h_input_tokens", "cache_read_input_tokens", "output_tokens", "cache_creation_input_tokens"} {
		test.Run("ceiling-"+field, func(test *testing.T) {
			valid := gatewayZeroUsage()
			value := int64(1000000)
			if field == "output_tokens" {
				value = 128000
			}
			if field == "cache_creation_input_tokens" {
				valid["cache_creation_5m_input_tokens"] = value
			}
			valid[field] = value
			if strings.Contains(field, "5m_") || strings.Contains(field, "1h_") {
				valid["cache_creation_input_tokens"] = value
			}
			if _, ok := gatewayCharge(test, price, valid, 128000); !ok {
				test.Fatal("ceiling valid control")
			}
			valid[field] = value + 1
			if field == "cache_creation_5m_input_tokens" || field == "cache_creation_1h_input_tokens" {
				valid["cache_creation_input_tokens"] = value + 1
			}
			if _, ok := gatewayCharge(test, price, valid, 128000); ok {
				test.Fatal("usage ceiling admitted")
			}
		})
	}
	if _, ok := gatewayCeil([][2]int64{{maxMicroUSD, 2}}); ok {
		test.Fatal("overflow admitted")
	}
	if value, ok := gatewayCeil([][2]int64{{maxMicroUSD, 1}}); !ok || value != 9007199255 {
		test.Fatal("overflow inside control")
	}
	for _, output := range []int64{0, 1, 127999, 128000, 128001} {
		test.Run(fmt.Sprint("output-", output), func(test *testing.T) {
			_, ok := gatewayWorst(price, output)
			if ok != (output >= 1 && output <= 128000) {
				test.Fatal("output bound")
			}
		})
	}
}

// Claim: every pre-forward authority/durability/bound refusal changes only the closed-use latch, not accounting; valid reservation consumes one ordinal before a separately allowed send.
func TestLabGatewayReservationPairs(test *testing.T) {
	for _, name := range []string{"valid", "approval", "current", "ceiling", "route", "status", "boot", "clock", "wall", "cost", "head", "cas", "durable", "sequence", "active", "ordinal", "history-unknown", "count"} {
		test.Run(name, func(test *testing.T) {
			candidate, price, _, ledger, _ := gatewayFixture(test)
			limit := limitsFromPlan(test, candidate)
			now := int64(2100)
			want := "committed"
			if name == "active" || name == "ordinal" || name == "history-unknown" || name == "count" {
				if gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), now) != "committed" {
					test.Fatal("reserve setup")
				}
				record := ledger["attempts"].([]any)[0].(map[string]any)
				switch name {
				case "active":
					want = "closed_active"
				case "ordinal":
					record["ordinal"] = int64(2)
					want = "history_ordinal"
				case "history-unknown":
					record["state"] = "unknown"
					record["settled_micro_usd"] = int64(10560000)
					want = "history_unknown"
				case "count":
					if gatewaySettle(test, &ledger, price, limit, gatewayProofFor(test, ledger), gatewayZeroUsage(), "fixture-request", true, true, 2101) != "settled" {
						test.Fatal("count setup")
					}
					limit.Count = 1
					want = "closed_count"
				}
			}
			proof := gatewayProofFor(test, ledger)
			switch name {
			case "approval":
				proof.Approved = false
				want = "closed_approval"
			case "current":
				proof.Current = false
				want = "closed_current"
			case "ceiling":
				proof.Ceiling = false
				want = "unknown_ceiling"
			case "route":
				proof.Exclusive = false
				want = "closed_route"
			case "status":
				ledger["status"] = "unknown"
				want = "closed_group"
			case "boot":
				proof.Boot = "other-boot"
				want = "unknown_boot"
			case "clock":
				now = 1999
				want = "unknown_clock"
			case "wall":
				now = 12000
				want = "closed_total_time"
			case "cost":
				limit.Cost = 10559999
				want = "closed_cost"
			case "head":
				proof.Head = "sha256:" + strings.Repeat("b", 64)
				want = "unknown_head"
			case "cas":
				proof.CAS = false
				want = "unknown_cas"
			case "durable":
				proof.Durable = false
				want = "unknown_persistence"
			case "sequence":
				ledger["sequence"] = maxMicroUSD
				proof = gatewayProofFor(test, ledger)
				want = "unknown_sequence"
			}
			before := normalizedBounded(test, ledger)
			got := gatewayReserve(test, &ledger, price, limit, proof, now)
			if got != want {
				test.Fatalf("reservation refusal: %s want %s", got, want)
			}
			if got != "committed" {
				if ledger["status"] == "open" {
					test.Fatal("refusal did not close group")
				}
				before["status"] = ledger["status"]
				if !reflect.DeepEqual(before, ledger) {
					test.Fatal("refused forward changed accounting")
				}
				if got := gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2101); got != "closed_group" {
					test.Fatalf("refusal reopened: %s", got)
				}
				return
			}
			records := ledger["attempts"].([]any)
			record := records[len(records)-1].(map[string]any)
			if record["ordinal"] != int64(len(records)) || record["reservation_cost_usd"] != "10.560000" || record["reservation_output_tokens"] != limit.Output || ledger["previous_sha256"] != proof.Head || ledger["sequence"] != before["sequence"].(int64)+1 {
				test.Fatal("durable reservation join")
			}
			if got := gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), now+1); got != "closed_active" {
				test.Fatalf("parallel retry: %s", got)
			}
		})
	}
	for _, cost := range []int64{10559999, 10560000, 10560001} {
		test.Run(fmt.Sprint("cost-", cost), func(test *testing.T) {
			candidate, price, _, ledger, _ := gatewayFixture(test)
			limit := limitsFromPlan(test, candidate)
			limit.Cost = cost
			got := gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2100)
			if (got == "committed") != (cost >= 10560000) {
				test.Fatal("reservation cost bound")
			}
		})
	}
}

// Claim: retries receive new durable ordinals only after complete settlement; uncertain responses charge full reservation and remain UNKNOWN, while first-bound stops cannot reopen.
func TestLabGatewaySettlementPairs(test *testing.T) {
	for _, name := range []string{"valid", "timeout", "disconnect", "missing-usage", "missing-cache", "partition", "model-tier", "request-id", "clock", "output", "per-wall", "total-wall", "count", "cost", "revoked", "current", "boot"} {
		test.Run(name, func(test *testing.T) {
			candidate, price, _, ledger, _ := gatewayFixture(test)
			limit := limitsFromPlan(test, candidate)
			if name == "count" {
				limit.Count = 1
			}
			if name == "cost" {
				limit.Cost = 10560000
			}
			if name == "total-wall" {
				limit.PerMS = limit.TotalMS
			}
			if gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2100) != "committed" {
				test.Fatal("settlement reserve control")
			}
			usage := gatewayZeroUsage()
			usage["input_tokens"], usage["output_tokens"] = int64(1), int64(1)
			terminal, same := true, true
			request := "fixture-upstream"
			now := int64(2101)
			wanted := "settled"
			status := "open"
			proof := gatewayProofFor(test, ledger)
			switch name {
			case "timeout", "disconnect":
				terminal = false
				wanted, status = "unknown", "unknown"
			case "missing-usage":
				usage = map[string]any{}
				wanted, status = "unknown", "unknown"
			case "missing-cache":
				delete(usage, "cache_creation_input_tokens")
				wanted, status = "unknown", "unknown"
			case "partition":
				usage["cache_creation_input_tokens"] = int64(1)
				wanted, status = "unknown", "unknown"
			case "model-tier":
				same = false
				wanted, status = "unknown", "unknown"
			case "request-id":
				request = "not-observed"
				wanted, status = "unknown", "unknown"
			case "clock":
				now = 2099
				wanted, status = "unknown", "unknown"
			case "output":
				usage["output_tokens"] = limit.Output
				status = "stopped"
			case "per-wall":
				now = 7100
				status = "stopped"
			case "total-wall":
				now = 12000
				status = "stopped"
			case "count":
				status = "stopped"
			case "cost":
				usage["input_tokens"], usage["output_tokens"] = int64(0), limit.Output
				usage["cache_creation_input_tokens"], usage["cache_creation_1h_input_tokens"] = int64(1000000), int64(1000000)
				status = "stopped"
			case "revoked":
				proof.Approved = false
				status = "stopped"
			case "current":
				proof.Current = false
				status = "stopped"
			case "boot":
				proof.Boot = "changed"
				status = "stopped"
			}
			if got := gatewaySettle(test, &ledger, price, limit, proof, usage, request, terminal, same, now); got != wanted {
				test.Fatalf("settlement verdict: %s want %s", got, wanted)
			}
			record := ledger["attempts"].([]any)[0].(map[string]any)
			if ledger["status"] != status {
				test.Fatalf("first-bound status: %s want %s", ledger["status"], status)
			}
			if wanted == "unknown" && record["settled_micro_usd"] != int64(10560000) {
				test.Fatal("unknown refunded reservation")
			}
			if wanted == "settled" {
				cost, ok := gatewayCharge(test, price, usage, limit.Output)
				if !ok || record["settled_micro_usd"] != cost || record["usage_sha256"] != boundedDigest(test, usage) {
					test.Fatal("authoritative usage settlement")
				}
			}
			proof = gatewayProofFor(test, ledger)
			got := gatewayReserve(test, &ledger, price, limit, proof, max(now, 2102))
			if status != "open" {
				if got != "closed_group" {
					test.Fatalf("sticky group reopened: %s", got)
				}
				return
			}
			if got != "committed" || ledger["attempts"].([]any)[1].(map[string]any)["ordinal"] != int64(2) {
				test.Fatalf("retry ordinal: %s", got)
			}
		})
	}
}

func gatewayMonitor(ledger *map[string]any, limit boundedLimits, proof gatewayProof, output, charged, now int64, complete bool) string {
	if (*ledger)["status"] != "open" {
		return "closed_group"
	}
	attempts := (*ledger)["attempts"].([]any)
	if len(attempts) == 0 {
		return "closed_no_attempt"
	}
	attempt := attempts[len(attempts)-1].(map[string]any)
	if !complete || proof.Boot != (*ledger)["boot_id"] || now < attempt["started_monotonic_ms"].(int64) || output < 0 || charged < 0 {
		return gatewayFence(ledger, "unknown_monitor")
	}
	if !proof.Approved || !proof.Current || gatewayReached(limit, output, charged, now-attempt["started_monotonic_ms"].(int64), now-(*ledger)["group_started_monotonic_ms"].(int64)) {
		return gatewayFence(ledger, "closed_bound")
	}
	return "open"
}

// Claim: ongoing output, cost and both wall bounds close at equality; negative/regressed evidence is UNKNOWN, approval/currentness close immediately, and no in-flight monitor frees a reservation.
func TestLabGatewayMonitorPairs(test *testing.T) {
	for _, rule := range []string{"output", "cost", "per-wall", "total-wall"} {
		for _, delta := range []int64{-1, 0, 1} {
			test.Run(fmt.Sprintf("%s/%d", rule, delta), func(test *testing.T) {
				candidate, price, _, ledger, _ := gatewayFixture(test)
				limit := limitsFromPlan(test, candidate)
				if rule == "total-wall" {
					limit.PerMS = limit.TotalMS
				}
				if gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2100) != "committed" {
					test.Fatal("monitor reserve control")
				}
				proof := gatewayProofFor(test, ledger)
				output, charged, now := int64(0), int64(0), int64(2101)
				switch rule {
				case "output":
					output = limit.Output + delta
				case "cost":
					charged = limit.Cost + delta
				case "per-wall":
					now = 2100 + limit.PerMS + delta
				case "total-wall":
					now = 2000 + limit.TotalMS + delta
				}
				before := normalizedBounded(test, ledger)
				got := gatewayMonitor(&ledger, limit, proof, output, charged, now, true)
				want := "open"
				if delta >= 0 {
					want = "closed_bound"
				}
				if got != want {
					test.Fatalf("monitor boundary: %s want %s", got, want)
				}
				before["status"] = ledger["status"]
				if !reflect.DeepEqual(before, ledger) {
					test.Fatal("monitor changed reservation")
				}
				if want != "open" && gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2102) != "closed_group" {
					test.Fatal("monitor stop reopened")
				}
			})
		}
	}
	for _, rule := range []string{"approval", "current", "boot", "partial", "regression", "negative-output", "negative-cost"} {
		test.Run(rule, func(test *testing.T) {
			candidate, price, _, ledger, _ := gatewayFixture(test)
			limit := limitsFromPlan(test, candidate)
			if gatewayReserve(test, &ledger, price, limit, gatewayProofFor(test, ledger), 2100) != "committed" {
				test.Fatal("monitor valid reserve")
			}
			proof := gatewayProofFor(test, ledger)
			output, cost, now := int64(0), int64(0), int64(2101)
			complete := true
			want := "unknown_monitor"
			if got := gatewayMonitor(&ledger, limit, proof, output, cost, now, true); got != "open" {
				test.Fatal("monitor valid control")
			}
			switch rule {
			case "approval":
				proof.Approved = false
				want = "closed_bound"
			case "current":
				proof.Current = false
				want = "closed_bound"
			case "boot":
				proof.Boot = "other"
			case "partial":
				complete = false
			case "regression":
				now = 2099
			case "negative-output":
				output = -1
			case "negative-cost":
				cost = -1
			}
			if got := gatewayMonitor(&ledger, limit, proof, output, cost, now, complete); got != want {
				test.Fatalf("monitor refusal: %s want %s", got, want)
			}
		})
	}
}

func gatewayEvidence(test *testing.T, ledger map[string]any, protectedHead, effect, release string, freshPublication bool) string {
	if !freshPublication {
		return "unknown_publication"
	}
	if boundedDigest(test, ledger) != protectedHead {
		return "unknown_head"
	}
	if effect != protectedHead || release != ledger["release_set_sha256"] {
		return "unknown_evidence"
	}
	return "joined"
}

// Claim: B4's existing effect digest binds the current protected full ledger and release, not a stale copied prefix or a periodic observation used as publication authority.
func TestLabGatewayEvidencePairs(test *testing.T) {
	_, _, _, ledger, _ := gatewayFixture(test)
	head := boundedDigest(test, ledger)
	release := ledger["release_set_sha256"].(string)
	for _, rule := range []string{"valid", "head", "effect", "release", "single"} {
		test.Run(rule, func(test *testing.T) {
			expected, effect, pin, fresh := head, head, release, true
			want := "joined"
			if got := gatewayEvidence(test, ledger, head, head, release, true); got != "joined" {
				test.Fatal("evidence valid control")
			}
			switch rule {
			case "head":
				expected = "sha256:" + strings.Repeat("b", 64)
				want = "unknown_head"
			case "effect":
				effect = "sha256:" + strings.Repeat("b", 64)
				want = "unknown_evidence"
			case "release":
				pin = "sha256:" + strings.Repeat("b", 64)
				want = "unknown_evidence"
			case "single":
				fresh = false
				want = "unknown_publication"
			}
			if got := gatewayEvidence(test, ledger, expected, effect, pin, fresh); got != want {
				test.Fatalf("evidence refusal: %s want %s", got, want)
			}
		})
	}
}

// Claim: published reserved/settled/UNKNOWN snapshots retain their exact accounting meaning, and a corrupted authoritative charge fails specifically at settlement beside the valid snapshot.
func TestLabGatewayFixturePairs(test *testing.T) {
	var corpus struct {
		Synthetic bool `json:"synthetic_only"`
		Live      bool `json:"live_authority"`
		Cases     []struct {
			Name     string         `json:"name"`
			Ledger   map[string]any `json:"ledger"`
			History  string         `json:"expected_history"`
			MicroUSD int64          `json:"expected_micro_usd"`
		} `json:"cases"`
	}
	decodeContract(test, "attempt-fixtures.json", &corpus)
	if !corpus.Synthetic || corpus.Live || len(corpus.Cases) != 3 {
		test.Fatal("accounting corpus")
	}
	candidate, price, _, _, _ := gatewayFixture(test)
	limit := limitsFromPlan(test, candidate)
	set, _ := loadContracts(test)
	for _, row := range corpus.Cases {
		test.Run(row.Name, func(test *testing.T) {
			ledger := normalizedBounded(test, row.Ledger)
			if err := checkRecord(canonicalObject(test, ledger), boundedShape(set, gatewayLedgerFormat), set); err != nil {
				test.Fatal("accounting fixture shape:", err)
			}
			amount, state := gatewayHistory(test, ledger, price, limit)
			if amount != row.MicroUSD || state != row.History {
				test.Fatalf("accounting fixture: %d %s", amount, state)
			}
			if row.Name == "settled" {
				record := ledger["attempts"].([]any)[0].(map[string]any)
				record["settled_micro_usd"] = int64(3721)
				if _, state := gatewayHistory(test, ledger, price, limit); state != "settlement" {
					test.Fatalf("settlement corruption: %s", state)
				}
			}
		})
	}
}

// Claim: re-approving a shape-valid changed public price field cannot silently select another source/model/ceiling/rate; each price identity joins the reviewed file, not its release label alone.
func TestLabGatewayPriceIdentityPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	shape := boundedShape(set, gatewayPriceFormat)
	var valid map[string]any
	for index, row := range set.Surfaces {
		if row.Format == gatewayPriceFormat {
			valid = normalizedBounded(test, fixtures[index].Valid)
		}
	}
	for _, field := range fixtureFields(valid, shape, set) {
		if strings.HasPrefix(field.Type, "@") || strings.HasPrefix(field.Type, "=") {
			continue
		}
		test.Run(fmt.Sprint(field.Path), func(test *testing.T) {
			candidate, price, observation, ledger, group := gatewayFixture(test)
			if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != "admit" {
				test.Fatal("price identity valid control:", got)
			}
			changed := normalizedBounded(test, price)
			var value any
			switch field.Type {
			case "usd":
				value = "9.000000"
			case "id":
				value = "other-public-source"
			case "time":
				value = "2026-11-10T00:00:00Z"
			case "digest":
				value = "sha256:" + strings.Repeat("b", 64)
			case "positive":
				value = int64(1000001)
			case "output-tokens":
				value = int64(127999)
			default:
				test.Fatalf("uncovered price grammar: %s", field.Type)
			}
			putPath(changed, field.Path, value)
			if checkRecord(canonicalObject(test, changed), shape, set) != nil {
				test.Fatal("price mutation not shape-valid")
			}
			assets := candidate.Release["assets"].([]any)
			assets[len(assets)-1].(map[string]any)["members"].([]any)[0].(map[string]any)["sha256"] = boundedDigest(test, changed)
			candidate.Approval["release_set_sha256"] = boundedDigest(test, candidate.Release)
			boundedRebind(test, &candidate)
			if got := gatewayJoins(test, candidate, changed, observation, ledger, group, true); got != "price_model" {
				test.Fatalf("price identity refusal: %s", got)
			}
		})
	}
}

// Claim: swapping either or both native receipt/debit incarnations cannot retarget the gateway ledger away from the accepted start observation.
func TestLabGatewayPairedRolePairs(test *testing.T) {
	for _, sides := range [][]string{nil, {"start_receipt"}, {"start_debit"}, {"start_receipt", "start_debit"}} {
		test.Run(strings.Join(sides, "+"), func(test *testing.T) {
			candidate, price, observation, ledger, group := gatewayFixture(test)
			if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != "admit" {
				test.Fatal("paired native valid control:", got)
			}
			for _, side := range sides {
				ledger[side].(map[string]any)["execution_id"] = "other-execution"
				ledger[side].(map[string]any)["pid"] = int64(9999)
			}
			got := gatewayJoins(test, candidate, price, observation, ledger, group, true)
			if len(sides) == 0 {
				if got != "admit" {
					test.Fatal("paired own control")
				}
			} else if got != "join:start_receipt" && got != "join:start_debit" {
				test.Fatalf("paired native refusal: %s", got)
			}
		})
	}
}

func gatewayGroupRecord(test *testing.T, candidate boundedCase, price, observation map[string]any, started int64) map[string]any {
	joins := gatewayJoinValues(test, candidate, price, observation)
	group := map[string]any{"format": "swarma-broker-lab-attempt-group/1", "group_started_monotonic_ms": started}
	for _, name := range []string{"context", "operation_id", "plan_sha256", "approval_record_sha256", "release_set_sha256", "model_price_sha256", "launch_plan_sha256", "start_operation_id", "start_id", "boot_id"} {
		group[name] = joins[name]
	}
	return normalizedBounded(test, group)
}

func gatewayGroupAdmission(test *testing.T, candidate boundedCase, price, observation, group map[string]any) string {
	expected := gatewayGroupRecord(test, candidate, price, observation, group["group_started_monotonic_ms"].(int64))
	if !reflect.DeepEqual(group, expected) {
		return "group_join"
	}
	now := observation["observed_monotonic_ms"].(int64)
	started := group["group_started_monotonic_ms"].(int64)
	if now < started || now-started >= limitsFromPlan(test, candidate).TotalMS {
		return "group_deadline"
	}
	return "admit"
}

// Claim: the protected preauthorization group binds every immutable join and its original total clock; future/expired clocks and substituted ledger group digests refuse beside the exact admission control.
func TestLabGatewayGroupPairs(test *testing.T) {
	candidate, price, observation, ledger, group := gatewayFixture(test)
	for field, value := range group {
		if field == "format" || field == "group_started_monotonic_ms" {
			continue
		}
		test.Run("join-"+field, func(test *testing.T) {
			changed := normalizedBounded(test, group)
			if text, ok := value.(string); ok {
				if strings.HasPrefix(text, "sha256:") {
					changed[field] = "sha256:" + strings.Repeat("e", 64)
				} else if field == "operation_id" {
					changed[field] = strings.Repeat("e", 32)
				} else if field == "boot_id" {
					changed[field] = "22222222-2222-4333-8444-555555555555"
				} else {
					changed[field] = text + "x"
				}
			} else {
				changed[field].(map[string]any)["account"] = "other-account"
			}
			if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != "admit" {
				test.Fatal("group join valid control:", got)
			}
			if got := gatewayJoins(test, candidate, price, observation, ledger, changed, true); got != "group_join" {
				test.Fatalf("group join refusal: %s", got)
			}
		})
	}
	for _, rule := range []string{"valid", "group-clock-future", "group-clock-expiry", "group-plan", "ledger-digest", "ledger-clock"} {
		test.Run(rule, func(test *testing.T) {
			candidate, price, observation, ledger, group := gatewayFixture(test)
			if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != "admit" {
				test.Fatal("group valid control:", got)
			}
			wanted := "admit"
			switch rule {
			case "group-clock-future":
				group["group_started_monotonic_ms"] = int64(2101)
				wanted = "group_deadline"
			case "group-clock-expiry":
				observation["observed_monotonic_ms"] = int64(12000)
				wanted = "group_deadline"
			case "group-plan":
				group["plan_sha256"] = "sha256:" + strings.Repeat("b", 64)
				wanted = "group_join"
			case "ledger-digest":
				ledger["group_sha256"] = "sha256:" + strings.Repeat("b", 64)
				wanted = "group_ledger"
			case "ledger-clock":
				ledger["group_started_monotonic_ms"] = int64(2001)
				wanted = "group_ledger"
			}
			if got := gatewayJoins(test, candidate, price, observation, ledger, group, true); got != wanted {
				test.Fatalf("group refusal: %s want %s", got, wanted)
			}
		})
	}
}

func gatewayRecordAdmission(test *testing.T, record, price map[string]any, limit boundedLimits) string {
	set, _ := loadContracts(test)
	if checkFields(record, set.Structures["GatewayAttempt"], set) != nil {
		return "record_shape"
	}
	reserve, ok := parseUSDMicros(record["reservation_cost_usd"])
	worst, bounded := gatewayWorst(price, limit.Output)
	if !ok || !bounded || reserve != worst || record["reservation_output_tokens"] != limit.Output {
		return "reservation"
	}
	switch record["state"] {
	case "reserved", "unknown":
		if record["usage_complete"] != false || !reflect.DeepEqual(record["usage"], gatewayZeroUsage()) || record["upstream_request_id"] != "not-observed" || record["usage_sha256"] != gatewayUnavailable(test) {
			return "absence_metadata"
		}
		if record["state"] == "reserved" && (record["settled_micro_usd"] != int64(0) || record["settled_monotonic_ms"] != int64(0)) {
			return "reserved_metadata"
		}
		if record["state"] == "unknown" && record["settled_micro_usd"] != reserve {
			return "unknown_charge"
		}
	case "settled":
		wanted, complete := gatewayCharge(test, price, record["usage"].(map[string]any), limit.Output)
		if record["usage_complete"] != true || !complete || record["settled_micro_usd"] != wanted || wanted > reserve || record["usage_sha256"] != boundedDigest(test, record["usage"].(map[string]any)) || record["upstream_request_id"] == "not-observed" || record["settled_monotonic_ms"].(int64) < record["started_monotonic_ms"].(int64) {
			return "settlement"
		}
	default:
		return "state"
	}
	return "valid"
}

// Claim: state-dependent absence sentinels and authoritative settlement members are checked independently of JSON closure, with a same-state valid record before every changed member.
func TestLabGatewayRecordPairs(test *testing.T) {
	var corpus struct {
		Cases []struct {
			Name   string         `json:"name"`
			Ledger map[string]any `json:"ledger"`
		} `json:"cases"`
	}
	decodeContract(test, "attempt-fixtures.json", &corpus)
	candidate, price, _, _, _ := gatewayFixture(test)
	limit := limitsFromPlan(test, candidate)
	for _, row := range corpus.Cases {
		ledger := normalizedBounded(test, row.Ledger)
		valid := ledger["attempts"].([]any)[0].(map[string]any)
		fields := []string{"reservation_cost_usd", "reservation_output_tokens", "usage_complete", "usage_sha256", "upstream_request_id", "settled_micro_usd"}
		if row.Name != "unknown" {
			fields = append(fields, "settled_monotonic_ms")
		}
		if row.Name != "settled" {
			for field := range gatewayZeroUsage() {
				fields = append(fields, "usage."+field)
			}
		}
		for _, field := range fields {
			test.Run(row.Name+"/"+field, func(test *testing.T) {
				if got := gatewayRecordAdmission(test, valid, price, limit); got != "valid" {
					test.Fatal("state valid control:", got)
				}
				changed := normalizedBounded(test, valid)
				want := "settlement"
				switch field {
				case "reservation_cost_usd":
					changed[field] = "10.560001"
					want = "reservation"
				case "reservation_output_tokens":
					changed[field] = int64(127999)
					want = "reservation"
				case "usage_complete":
					changed[field] = !valid[field].(bool)
					if row.Name != "settled" {
						want = "absence_metadata"
					}
				case "usage_sha256":
					changed[field] = "sha256:" + strings.Repeat("b", 64)
					if row.Name != "settled" {
						want = "absence_metadata"
					}
				case "upstream_request_id":
					if row.Name == "settled" {
						changed[field] = "not-observed"
					} else {
						changed[field] = "unproven-request"
						want = "absence_metadata"
					}
				case "settled_micro_usd":
					changed[field] = valid[field].(int64) + 1
					if row.Name == "reserved" {
						want = "reserved_metadata"
					}
					if row.Name == "unknown" {
						want = "unknown_charge"
					}
				case "settled_monotonic_ms":
					if row.Name == "reserved" {
						changed[field] = int64(1)
						want = "reserved_metadata"
					} else {
						changed[field] = int64(2099)
					}
				default:
					changed["usage"].(map[string]any)[strings.TrimPrefix(field, "usage.")] = int64(1)
					want = "absence_metadata"
				}
				if got := gatewayRecordAdmission(test, changed, price, limit); got != want {
					test.Fatalf("record refusal: %s want %s", got, want)
				}
			})
		}
	}
}

func gatewayPriceIdentity(test *testing.T, price map[string]any, model any) bool {
	expected := normalizedBounded(test, gatewayPublishedPrice(test))
	if model != price["model"] || len(price) != len(expected) {
		return false
	}
	for field, value := range expected {
		if !reflect.DeepEqual(price[field], value) {
			return false
		}
	}
	return true
}

// Claim: every applicable scalar catalogue operator also attacks the exact published price identity, independently of whether the altered spelling remains shape-valid.
func TestLabGatewayPriceCataloguePairs(test *testing.T) {
	set, _ := loadContracts(test)
	price := normalizedBounded(test, gatewayPublishedPrice(test))
	shape := boundedShape(set, gatewayPriceFormat)
	for _, field := range fixtureFields(price, shape, set) {
		if strings.HasPrefix(field.Type, "@") {
			continue
		}
		cases := scalarMutations(field.Type)
		if value, ok := field.Value.(string); ok {
			cases = append(cases, literalMutations(value)...)
		}
		cases = append(cases, wrongTypes(field.Value)...)
		for _, mutation := range cases {
			test.Run(fmt.Sprint(field.Path)+"/"+mutation.Name, func(test *testing.T) {
				if !gatewayPriceIdentity(test, price, price["model"]) {
					test.Fatal("price catalogue valid control")
				}
				changed := normalizedBounded(test, price)
				putPath(changed, field.Path, mutation.Value)
				if got, want := gatewayPriceIdentity(test, changed, price["model"]), reflect.DeepEqual(changed, price); got != want {
					test.Fatalf("price identity operator: %s got %v want %v", mutation.Name, got, want)
				}
			})
		}
	}
}

// Claim: the attempt array exercises empty, singleton and both sides of its 256-member ceiling in full canonical records below the independent byte ceiling.
func TestLabGatewayArrayPairs(test *testing.T) {
	set, fixtures := loadContracts(test)
	shape := boundedShape(set, gatewayLedgerFormat)
	var valid map[string]any
	for index, row := range set.Surfaces {
		if row.Format == gatewayLedgerFormat {
			valid = normalizedBounded(test, fixtures[index].Valid)
		}
	}
	for _, count := range []int{0, 1, 255, 256, 257} {
		test.Run(fmt.Sprint(count), func(test *testing.T) {
			record := normalizedBounded(test, valid)
			member := record["attempts"].([]any)[0]
			items := make([]any, count)
			for i := range items {
				items[i] = member
			}
			record["attempts"] = items
			data := canonicalObject(test, record)
			if len(data) > shape.MaxBytes {
				test.Fatal("array witness masked by size")
			}
			err := checkRecord(data, shape, set)
			if count <= 256 && err != nil {
				test.Fatal("array valid control:", err)
			}
			if count > 256 && (err == nil || !strings.Contains(err.Error(), "array")) {
				test.Fatalf("array refusal: %v", err)
			}
		})
	}
}

// Claim: the model argument is independent of the approved price identity, aggregate input/cache partition has its own bound, and ceiling rejection cannot be masked by a cache-sum mismatch.
func TestLabGatewayIndependentPricePairs(test *testing.T) {
	_, price, _, _, _ := gatewayFixture(test)
	test.Run("model", func(test *testing.T) {
		if !gatewayPriceIdentity(test, price, "claude-opus-5-5") || gatewayPriceIdentity(test, price, "other-model") {
			test.Fatal("independent model gate")
		}
	})
	test.Run("aggregate-input", func(test *testing.T) {
		usage := gatewayZeroUsage()
		usage["input_tokens"] = int64(999999)
		usage["cache_creation_5m_input_tokens"], usage["cache_creation_input_tokens"] = int64(1), int64(1)
		if _, ok := gatewayCharge(test, price, usage, 128000); !ok {
			test.Fatal("aggregate input valid control")
		}
		usage["input_tokens"] = int64(1000000)
		if _, ok := gatewayCharge(test, price, usage, 128000); ok {
			test.Fatal("aggregate input bound")
		}
	})
}

func gatewayReached(limit boundedLimits, output, charged, attemptMS, totalMS int64) bool {
	return output >= limit.Output || charged >= limit.Cost || attemptMS >= limit.PerMS || totalMS >= limit.TotalMS
}
