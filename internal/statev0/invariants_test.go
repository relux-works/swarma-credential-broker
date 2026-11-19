package statev0

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: literal member/tag sets for the declared nonce, /2 and revocation structs match S:774-776,880-883,892-895; no optional verifier field is admitted.
func TestJournalSpecMemberSets(test *testing.T) {
	cases := []struct {
		value any
		tags  string
	}{
		{ConsumedNonce{}, "nonce boot_id peer_pid peer_start_ticks"},
		{NonceState{}, "format installation_id revision consumed"},
		{OperationReceipt{}, "nonce terminal_caller boot_id peer_pid peer_start_ticks freshness"},
		{ServiceOperationV2{}, "principal method operation_id arguments result at receipt"},
		{ServiceStateV2{}, "kind installation_id revision watermark bindings leases holds operations"},
		{BaselineRevocationState{}, "seq records"},
		{RevocationState{}, "format installation_id revision state"},
	}
	for _, entry := range cases {
		declared := reflect.TypeOf(entry.value)
		test.Run(declared.Name(), func(test *testing.T) {
			var tags []string
			for position := 0; position < declared.NumField(); position++ {
				tags = append(tags, declared.Field(position).Tag.Get("json"))
			}
			if strings.Join(tags, " ") != entry.tags {
				test.Fatal("journal spec member/tag set changed")
			}
		})
	}
}

func journalObjectLocations(value any, location []any) [][]any {
	var locations [][]any
	switch current := value.(type) {
	case map[string]any:
		locations = append(locations, append([]any{}, location...))
		for member, child := range current {
			if member == "arguments" || member == "result" {
				continue
			}
			locations = append(locations, journalObjectLocations(child, append(append([]any{}, location...), member))...)
		}
	case []any:
		for position, child := range current {
			locations = append(locations, journalObjectLocations(child, append(append([]any{}, location...), position))...)
		}
	}
	return locations
}

func journalObjectAt(root map[string]any, location []any) map[string]any {
	var current any = root
	for _, step := range location {
		switch position := step.(type) {
		case string:
			current = current.(map[string]any)[position]
		case int:
			current = current.([]any)[position]
		}
	}
	return current.(map[string]any)
}

// Claim: non-empty receipt/freshness and signed revocation/target objects reject unknown, missing and forbidden-null members beside unchanged valid controls. Method arguments/results remain their existing owners contract.
func TestJournalNestedSchemaControls(test *testing.T) {
	for name, control := range journalControls(test) {
		test.Run(name, func(test *testing.T) {
			encoded, err := wire.Encode(control)
			if err != nil {
				test.Fatal(err)
			}
			root, err := wire.Parse(encoded)
			if err != nil {
				test.Fatal(err)
			}
			for _, location := range journalObjectLocations(root, nil) {
				object := journalObjectAt(root, location)
				for member, original := range object {
					for _, mutation := range []string{"missing", "null"} {
						if mutation == "missing" && member == "reason" {
							continue
						}
						nullable := len(location) == 2 && location[0] == "operations" && (member == "at" || member == "receipt" || member == "arguments" || member == "result")
						if mutation == "null" && (original == nil || nullable) {
							continue
						}
						modified, _ := wire.Parse(encoded)
						if mutation == "missing" {
							delete(journalObjectAt(modified, location), member)
						} else {
							journalObjectAt(modified, location)[member] = nil
						}
						assertJournalRefusal(test, control, encoded, modified)
					}
				}
				modified, _ := wire.Parse(encoded)
				journalObjectAt(modified, location)["unpublished_member"] = true
				assertJournalRefusal(test, control, encoded, modified)
			}
		})
	}
}

func assertJournalRefusal(test *testing.T, control any, valid []byte, modified map[string]any) {
	test.Helper()
	target := reflect.New(reflect.TypeOf(control)).Interface()
	if wire.Decode(valid, target) != nil {
		test.Fatal("non-empty valid adjacent control refused")
	}
	invalid, err := wire.Encode(modified)
	if err != nil || !errors.Is(wire.Decode(invalid, reflect.New(reflect.TypeOf(control)).Interface()), wire.ErrMalformed) {
		test.Fatal("nested invalid neighbor accepted")
	}
	after, err := wire.Encode(modified)
	if err != nil || !bytes.Equal(invalid, after) {
		test.Fatal("refusal changed input bytes")
	}
}

// Claim: neither unknown/mixed freshness nor empty/mixed revocation targets can pass the same decoder as the non-empty positive controls.
func TestJournalSumRefusals(test *testing.T) {
	controls := journalControls(test)
	cases := []struct {
		name     string
		control  string
		location []any
		member   string
		value    any
	}{
		{"unknown-freshness", "service-utc", []any{"operations", 0, "receipt", "freshness"}, "kind", "other"},
		{"utc-cannot-mix-boottime", "service-utc", []any{"operations", 0, "receipt", "freshness"}, "boot_id", "11111111-2222-4333-8444-555555555555"},
		{"boottime-cannot-mix-utc", "service-boottime", []any{"operations", 0, "receipt", "freshness"}, "expires_at", "2030-01-01T00:05:00Z"},
		{"empty-target", "revocations-nonempty", []any{"state", "records", 0, "body"}, "revokes", map[string]any{}},
		{"unknown-target", "revocations-nonempty", []any{"state", "records", 0, "body"}, "revokes", map[string]any{"other": "synthetic-target"}},
		{"grant-target-wrong-type", "revocations-nonempty", []any{"state", "records", 0, "body", "revokes"}, "grant", int64(1)},
		{"null-signed-record", "revocations-nonempty", []any{"state"}, "records", []any{nil}},
		{"grant-cannot-mix-key", "revocations-nonempty", []any{"state", "records", 0, "body", "revokes"}, "key", "synthetic-key"},
		{"key-cannot-mix-grant", "revocations-nonempty", []any{"state", "records", 1, "body", "revokes"}, "grant", "synthetic-grant"},
		{"reason-null", "revocations-nonempty", []any{"state", "records", 1, "body"}, "reason", nil},
	}
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			control := controls[entry.control]
			valid, err := wire.Encode(control)
			if err != nil {
				test.Fatal(err)
			}
			modified, _ := wire.Parse(valid)
			journalObjectAt(modified, entry.location)[entry.member] = entry.value
			assertJournalRefusal(test, control, valid, modified)
		})
	}
}

// Claim: plain decoding still refuses assembly sealed sums, while the state adapters decode both receipt and revocation variants without pre-seeding an interface.
func TestJournalSumDecoding(test *testing.T) {
	controls := journalControls(test)
	for _, name := range []string{"service-utc", "service-boottime", "revocations-nonempty"} {
		control := controls[name]
		encoded, err := wire.Encode(control)
		if err != nil {
			test.Fatal(err)
		}
		target := reflect.New(reflect.TypeOf(control)).Interface()
		if wire.Decode(encoded, target) != nil {
			test.Fatal("declared sum adapter refused adjacent control")
		}
		switch current := control.(type) {
		case ServiceStateV2:
			data, err := wire.Encode(current.Operations[0].Receipt.Freshness)
			var plain assemblyv0.Freshness
			if err != nil || !errors.Is(wire.Decode(data, &plain), wire.ErrMalformed) {
				test.Fatal("raw assembly freshness limitation changed")
			}
		case RevocationState:
			for _, record := range current.State.Records {
				data, err := wire.Encode(record)
				var plain assemblyv0.RevocationEnvelope
				if err != nil || !errors.Is(wire.Decode(data, &plain), wire.ErrMalformed) {
					test.Fatal("raw assembly revocation limitation changed")
				}
			}
		}
	}
}

// Claim: the two new sum adapters publish their receiver only after all nested fields decode; malformed neighboring sums leave an existing receiver unchanged.
func TestJournalSumFailurePreservesReceiver(test *testing.T) {
	controls := journalControls(test)
	cases := []struct {
		name     string
		control  any
		location []any
		member   string
	}{
		{"receipt", *controls["service-utc"].(ServiceStateV2).Operations[0].Receipt, nil, "freshness"},
		{"revocations", controls["revocations-nonempty"].(RevocationState).State, []any{"records", 1, "body"}, "revokes"},
	}
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			valid, err := wire.Encode(entry.control)
			target := reflect.New(reflect.TypeOf(entry.control)).Interface()
			if err != nil || wire.Decode(valid, target) != nil {
				test.Fatal("valid sum receiver control refused")
			}
			modified, _ := wire.Parse(valid)
			journalObjectAt(modified, entry.location)[entry.member] = nil
			invalid, err := wire.Encode(modified)
			if err != nil || !errors.Is(wire.Decode(invalid, target), wire.ErrMalformed) {
				test.Fatal("malformed sum did not refuse")
			}
			after, err := wire.Encode(target)
			if err != nil || !bytes.Equal(valid, after) {
				test.Fatal("failed sum decode published partial receiver")
			}
		})
	}
}
