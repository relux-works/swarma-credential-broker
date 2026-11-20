package labcontractv0

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const recoveryFormat = "swarma-broker-lab-service-recovery/1"

func recoveryFixture(test *testing.T) (contractSet, recordShape, map[string]any) {
	test.Helper()
	set, fixtures := loadContracts(test)
	for position, shape := range set.Surfaces {
		if shape.Format == recoveryFormat {
			object, err := wire.Parse(canonicalObject(test, fixtures[position].Valid))
			if err != nil {
				test.Fatal(err)
			}
			return set, shape, object
		}
	}
	test.Fatal("missing private inventory")
	return contractSet{}, recordShape{}, nil
}

func recoveryPrivate(shape recordShape) bool {
	return shape.Format == recoveryFormat && shape.Writer == "B1" && slices.Equal(shape.Readers, []string{"B1"}) && shape.MaxBytes == 524288
}

// Claim: the additive recovery format is B1-only and cannot replace or modify any frozen external definition or fixture.
func TestLabRecoveryPrivateInventory(test *testing.T) {
	set, shape, _ := recoveryFixture(test)
	if !recoveryPrivate(shape) {
		test.Fatal("private control refused")
	}
	shape.Readers = append(shape.Readers, "G1")
	if recoveryPrivate(shape) {
		test.Fatal("external recovery reader admitted")
	}
	external, _ := loadExternalContracts(test)
	if len(set.Surfaces) != 31 || len(external.Surfaces) != 30 {
		test.Fatal("inventory size")
	}
	for _, candidate := range external.Surfaces {
		if candidate.Format == "swarma-broker-lab-service-journal/1" && !reflect.DeepEqual(candidate.Fields, set.Structures["RecoveryExternalJournal"].Fields) {
			test.Fatal("external journal changed")
		}
	}
	for name, digest := range map[string]string{"surfaces.json": "6c520459f15bf77a83fb0414d46cc65e777d2956292f8132154003129bd59c71", "fixtures.json": "73d0c9241d1a70a596fdb3b011f2bdeac5f95b90cdcd75bf99e405b93a049fcf"} {
		if hashContract(readContract(test, name)) != digest {
			test.Fatalf("external bytes changed: %s", name)
		}
	}
}

func recoveryJoin(object map[string]any) error {
	revision := object["revision"].(int64)
	state := object["state"].(map[string]any)
	external := object["external"].(map[string]any)
	context := external["context"].(map[string]any)
	if revision > 9007199254740990 || object["previous_revision"].(int64)+1 != revision || state["revision"].(int64) > revision || state["installation_id"] != object["installation_id"] || context["installation_id"] != object["installation_id"] {
		return fmt.Errorf("recovery_join")
	}
	observations := object["observation"].([]any)
	if len(observations) > 1 {
		return fmt.Errorf("recovery_observation")
	}
	if len(observations) == 1 {
		observation := observations[0].(map[string]any)
		baseline := observation["baseline"].(map[string]any)
		baselineBytes, baselineErr := wire.Encode(baseline)
		if baselineErr != nil || len(baselineBytes) > 65536 {
			return fmt.Errorf("recovery_observation")
		}
		if observation["seen"].(int64) < observation["floor"].(int64) || baseline["sequence"] != observation["floor"] || observation["store_generation"] != baseline["sequence_generation"] || observation["store_generation"] != baseline["store"].(map[string]any)["generation"] || observation["observed_monotonic_ms"].(int64) < baseline["observed_monotonic_ms"].(int64) || observation["observed_monotonic_ms"].(int64) > observation["receipt_monotonic_ms"].(int64) {
			return fmt.Errorf("recovery_observation")
		}
	}
	encoded, err := wire.Encode(external)
	if err != nil || object["external_sha256"] != "sha256:"+hashContract(encoded) {
		return fmt.Errorf("recovery_digest")
	}
	if !journalHeadValid(external) {
		return fmt.Errorf("recovery_head")
	}
	if len(state["operations"].([]any)) != len(external["entries"].([]any)) {
		return fmt.Errorf("recovery_operations")
	}
	limit, reserve := external["operation_limit"].(int64), external["narrowing_reserve"].(int64)
	if limit < 1 || limit > 256 || reserve < 1 || reserve >= limit {
		return fmt.Errorf("recovery_capacity")
	}
	return nil
}

// Claim: a whole joined snapshot admits while revision, installation, digest, head, operation-count and finite-capacity mismatches refuse.
func TestLabRecoveryJoinPairs(test *testing.T) {
	set, shape, control := recoveryFixture(test)
	if err := checkRecord(canonicalObject(test, control), shape, set); err != nil {
		test.Fatal(err)
	}
	if err := recoveryJoin(control); err != nil {
		test.Fatalf("valid join: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"revision":        func(object map[string]any) { object["previous_revision"] = int64(1) },
		"engine-revision": func(object map[string]any) { object["state"].(map[string]any)["revision"] = int64(2) },
		"installation":    func(object map[string]any) { object["installation_id"] = "foreign" },
		"digest":          func(object map[string]any) { object["external_sha256"] = "sha256:" + hashContract([]byte("changed")) },
		"head": func(object map[string]any) {
			object["external"].(map[string]any)["head"].(map[string]any)["sequence"] = int64(1)
		},
		"count": func(object map[string]any) {
			object["state"].(map[string]any)["operations"] = []any{grammarSample("@RecoveryOperation", set)}
		},
		"reserve": func(object map[string]any) { object["external"].(map[string]any)["narrowing_reserve"] = int64(32) },
	}
	for name, mutate := range mutations {
		test.Run(name, func(test *testing.T) {
			object, err := wire.Parse(canonicalObject(test, control))
			if err != nil {
				test.Fatal(err)
			}
			mutate(object)
			if name == "reserve" {
				resealClosure(test, object["external"].(map[string]any))
			}
			if name == "reserve" || name == "head" {
				encoded, _ := wire.Encode(object["external"])
				object["external_sha256"] = "sha256:" + hashContract(encoded)
			}
			expected := map[string]string{"revision": "recovery_join", "engine-revision": "recovery_join", "installation": "recovery_join", "digest": "recovery_digest", "head": "recovery_head", "count": "recovery_operations", "reserve": "recovery_capacity"}[name]
			if err := recoveryJoin(object); err == nil || err.Error() != expected {
				test.Fatalf("joined mismatch admitted or wrong gate: %v", err)
			}
		})
	}
}

func recoveryReplay(operation map[string]any) error {
	count := 0
	for _, name := range []string{"bind", "unbind", "request", "renew", "release", "hold", "lift", "event"} {
		variants := operation[name].([]any)
		count += len(variants)
		if len(variants) > 1 {
			return fmt.Errorf("recovery_variant")
		}
		if len(variants) == 1 {
			arguments := variants[0].(map[string]any)["arguments"].(map[string]any)
			if identity, present := arguments["operation_id"]; present && identity != operation["operation_id"] {
				return fmt.Errorf("recovery_operation_id")
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("recovery_variant")
	}
	return nil
}

// Claim: each typed replay preserves its canonical arguments/result and exactly one variant; absent, doubled and contradictory identities refuse.
func TestLabRecoveryReplayPairs(test *testing.T) {
	set, _, _ := recoveryFixture(test)
	for _, name := range []string{"bind", "unbind", "request", "renew", "release", "hold", "lift", "event"} {
		test.Run(name, func(test *testing.T) {
			operation := grammarSample("@RecoveryOperation", set).(map[string]any)
			for _, variant := range []string{"bind", "unbind", "request", "renew", "release", "hold", "lift", "event"} {
				operation[variant] = []any{}
			}
			replayType := set.Structures["RecoveryOperation"].Fields[name][2:]
			replay := grammarSample(replayType, set).(map[string]any)
			if identity, present := replay["arguments"].(map[string]any)["operation_id"]; present {
				operation["operation_id"] = identity
			}
			operation[name] = []any{replay}
			if err := recoveryReplay(operation); err != nil {
				test.Fatalf("valid replay: %v", err)
			}
			for _, member := range []string{"arguments", "result"} {
				encoded, err := wire.Encode(replay[member])
				if err != nil {
					test.Fatal(err)
				}
				parsed, err := wire.Parse(encoded)
				if err != nil {
					test.Fatal(err)
				}
				again, _ := wire.Encode(parsed)
				if string(encoded) != string(again) {
					test.Fatal("non-lossless bytes")
				}
			}
			operation[name] = []any{}
			if recoveryReplay(operation) == nil {
				test.Fatal("empty variant admitted")
			}
			operation[name] = []any{replay, replay}
			if recoveryReplay(operation) == nil {
				test.Fatal("double variant admitted")
			}
			operation[name] = []any{replay}
			other := "bind"
			if name == other {
				other = "unbind"
			}
			operation[other] = []any{grammarSample(set.Structures["RecoveryOperation"].Fields[other][2:], set)}
			if recoveryReplay(operation) == nil {
				test.Fatal("multiple variants admitted")
			}
			operation[other] = []any{}
			if _, present := replay["arguments"].(map[string]any)["operation_id"]; present {
				operation["operation_id"] = "22222222222222222222222222222222"
				if recoveryReplay(operation) == nil {
					test.Fatal("contradictory operation admitted")
				}
			}
		})
	}
}

// Claim: every private field grammar is exercised by the C0 scalar/type/array operators even when its optional fixture array is empty.
func TestLabRecoveryCataloguePairs(test *testing.T) {
	set, _, _ := recoveryFixture(test)
	var private contractSet
	decodeContract(test, "recovery-surfaces.json", &private)
	grammars := map[string]bool{}
	for _, shape := range private.Structures {
		for _, grammar := range shape.Fields {
			grammars[grammar] = true
			if strings.HasPrefix(grammar, "[]") {
				grammars[grammar[2:]] = true
			}
		}
	}
	for grammar := range grammars {
		test.Run(grammar, func(test *testing.T) {
			control := grammarSample(grammar, set)
			mutations := wrongTypes(control)
			if strings.HasPrefix(grammar, "[]") {
				for _, count := range []int{0, 1, 255, 256, 257} {
					items := make([]any, count)
					for position := range items {
						items[position] = grammarSample(grammar[2:], set)
					}
					mutations = append(mutations, grammarMutation{Name: fmt.Sprintf("count-%d", count), Value: items, Admit: count <= 256})
				}
			} else if !strings.HasPrefix(grammar, "@") {
				mutations = append(mutations, scalarMutations(grammar)...)
			}
			for _, mutation := range mutations {
				test.Run(mutation.Name, func(test *testing.T) {
					if err := checkValue(control, grammar, set); err != nil {
						test.Fatalf("valid control: %v", err)
					}
					if err := checkValue(mutation.Value, grammar, set); (err == nil) != mutation.Admit {
						test.Fatalf("catalogue verdict: %v", err)
					}
				})
			}
		})
	}
}
