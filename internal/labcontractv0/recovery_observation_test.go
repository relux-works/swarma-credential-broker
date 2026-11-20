package labcontractv0

import "testing"

// Claim: the private atomic join preserves a separate outer CAS revision and S>=F, exact generation/baseline and observed/receipt bounds; each mismatch refuses beside a complete joined control.
func TestLabRecoveryObservationJoinPairs(test *testing.T) {
	set, shape, control := recoveryFixture(test)
	var fixture struct {
		Valid map[string]any `json:"valid"`
	}
	decodeContract(test, "recovery-observation-fixtures.json", &fixture)
	control = normalizedBounded(test, fixture.Valid)
	mutations := map[string]func(map[string]any){
		"baseline-size": func(record map[string]any) {
			invalidation := observationControl(test).Invalidation
			items := make([]any, 256)
			for position := range items {
				items[position] = invalidation
			}
			baseline := record["baseline"].(map[string]any)
			baseline["invalidations"] = items
			receipts := make([]any, 256)
			for position := range receipts {
				receipts[position] = baseline["receipts"].([]any)[0]
			}
			baseline["receipts"] = receipts
			if len(canonicalObject(test, baseline)) <= 65536 {
				test.Fatal("oversize plant not applied")
			}
		},
		"seen": func(record map[string]any) { record["seen"] = record["floor"].(int64) - 1 },
		"floor": func(record map[string]any) {
			record["floor"] = record["floor"].(int64) + 1
			record["seen"] = record["floor"]
		},
		"generation": func(record map[string]any) { record["store_generation"] = "dddddddddddddddddddddddddddddddd" },
		"receipt":    func(record map[string]any) { record["receipt_monotonic_ms"] = int64(0) },
		"observed":   func(record map[string]any) { record["observed_monotonic_ms"] = int64(0) },
	}
	for name, mutate := range mutations {
		test.Run(name, func(test *testing.T) {
			if err := checkRecord(canonicalObject(test, control), shape, set); err != nil {
				test.Fatal("shape control", err)
			}
			if err := recoveryJoin(control); err != nil {
				test.Fatal("joined control", err)
			}
			bad := normalizedBounded(test, cloneObject(test, control))
			mutate(bad["observation"].([]any)[0].(map[string]any))
			if err := checkRecord(canonicalObject(test, bad), shape, set); err != nil {
				test.Fatal("semantic plant violated the shape", err)
			}
			if err := recoveryJoin(bad); err == nil || err.Error() != "recovery_observation" {
				test.Fatal("observation mismatch admitted", err)
			}
		})
	}
}
