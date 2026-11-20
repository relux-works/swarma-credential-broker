//go:build linux && broker_lab

package labv0

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const recoveryFormat = "swarma-broker-lab-service-recovery/1"
const stateFormat = "swarma-broker-lab-service-state/1"
const journalFormat = "swarma-broker-lab-service-journal/1"
const stateName = "owner-lab-service.json"

var variants = map[string]string{
	"service.bind": "bind", "service.unbind": "unbind", "service.lease.request": "request", "service.lease.renew": "renew", "service.lease.release": "release", "account.hold": "hold", "account.hold.lift": "lift", "event.report": "event",
}

func digest(value any) string {
	raw, err := wire.Encode(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func object(value any) (map[string]any, error) {
	raw, err := wire.Encode(value)
	if err != nil {
		return nil, err
	}
	return wire.Parse(raw)
}

func stateObject(state wire.ServiceState) (map[string]any, error) {
	state.Kind = stateFormat
	encoded, err := object(state)
	if err != nil {
		return nil, err
	}
	for _, family := range []string{"bindings", "leases", "holds"} {
		if encoded[family] == nil {
			encoded[family] = []any{}
		}
		for _, value := range encoded[family].([]any) {
			record := value.(map[string]any)
			fields := map[string][]string{"bindings": {"removed_operation_id", "removed_at"}, "leases": {"last_renewal_operation_id"}, "holds": {"lifted_by", "lift_operation_id", "lifted_at"}}[family]
			for _, name := range fields {
				if record[name] == nil {
					record[name] = []any{}
				} else {
					record[name] = []any{record[name]}
				}
			}
		}
	}
	operations := []any{}
	for _, operation := range state.Operations {
		variant, exists := variants[operation.Method]
		if !exists {
			return nil, fmt.Errorf("recovery_method")
		}
		arguments, err := wire.Parse(operation.Arguments)
		if err != nil {
			return nil, err
		}
		result, err := wire.Parse(operation.Result)
		if err != nil {
			return nil, err
		}
		record := map[string]any{"principal": operation.Principal, "operation_id": operation.ID, "at": operation.At}
		for _, name := range variants {
			record[name] = []any{}
		}
		record[variant] = []any{map[string]any{"method": operation.Method, "arguments": arguments, "result": result}}
		operations = append(operations, record)
	}
	encoded["operations"] = operations
	return encoded, nil
}

func decodeState(encoded map[string]any) (wire.ServiceState, error) {
	state := wire.ServiceState{}
	copy, err := object(encoded)
	if err != nil {
		return state, err
	}
	for _, family := range []string{"bindings", "leases", "holds"} {
		for _, value := range copy[family].([]any) {
			record := value.(map[string]any)
			fields := map[string][]string{"bindings": {"removed_operation_id", "removed_at"}, "leases": {"last_renewal_operation_id"}, "holds": {"lifted_by", "lift_operation_id", "lifted_at"}}[family]
			for _, name := range fields {
				items := record[name].([]any)
				if len(items) > 1 {
					return state, fmt.Errorf("recovery_optional")
				}
				record[name] = nil
				if len(items) == 1 {
					record[name] = items[0]
				}
			}
			if family == "bindings" {
				present := 0
				for _, name := range fields {
					if record[name] != nil {
						present++
					}
				}
				if record["state"] == "active" && present != 0 || record["state"] == "removed" && present != 2 {
					return state, fmt.Errorf("recovery_removal")
				}
			}
			if family == "holds" {
				present := 0
				for _, name := range fields {
					if record[name] != nil {
						present++
					}
				}
				if record["state"] == "active" && present != 0 || record["state"] == "lifted" && present != 3 {
					return state, fmt.Errorf("recovery_lift")
				}
			}
		}
	}
	operations := []any{}
	for _, value := range copy["operations"].([]any) {
		record := value.(map[string]any)
		count := 0
		var replay map[string]any
		for _, name := range variants {
			items := record[name].([]any)
			count += len(items)
			if len(items) == 1 {
				replay = items[0].(map[string]any)
			}
		}
		if count != 1 {
			return state, fmt.Errorf("recovery_variant")
		}
		arguments := replay["arguments"].(map[string]any)
		if identity, present := arguments["operation_id"]; present && identity != record["operation_id"] {
			return state, fmt.Errorf("recovery_operation_id")
		}
		operations = append(operations, map[string]any{"principal": record["principal"], "operation_id": record["operation_id"], "at": record["at"], "method": replay["method"], "arguments": arguments, "result": replay["result"]})
	}
	copy["operations"] = operations
	raw, err := wire.Encode(copy)
	if err != nil || json.Unmarshal(raw, &state) != nil {
		return wire.ServiceState{}, fmt.Errorf("recovery_state")
	}
	return state, nil
}

func sealJournal(journal map[string]any) {
	preimage := map[string]any{}
	for name, value := range journal {
		if name != "head" {
			preimage[name] = value
		}
	}
	journal["head"] = map[string]any{"sequence": len(journal["entries"].([]any)), "sha256": digest(map[string]any{"domain": "swarma-broker-lab-journal-head/1", "record": preimage})}
}

func encodeRecovery(state wire.ServiceState, external map[string]any) ([]byte, error) {
	encoded, err := stateObject(state)
	if err != nil {
		return nil, err
	}
	return wire.Encode(map[string]any{"format": recoveryFormat, "installation_id": state.Installation, "revision": state.Revision, "previous_revision": state.Revision - 1, "external": external, "external_sha256": digest(external), "state": encoded, "observation": []any{}})
}

func readRecovery(raw []byte, installation string) (wire.ServiceState, map[string]any, error) {
	state := wire.ServiceState{}
	envelope, err := labcontract.ReadRecovery(raw)
	if err != nil {
		return state, nil, err
	}
	revision := envelope["revision"].(int64)
	external := envelope["external"].(map[string]any)
	encoded := envelope["state"].(map[string]any)
	if !validObservationRecovery(envelope["observation"].([]any)) {
		return state, nil, fmt.Errorf("recovery_observation")
	}
	if revision > 9007199254740990 || envelope["previous_revision"].(int64)+1 != revision || encoded["revision"].(int64) > revision || envelope["installation_id"] != installation || encoded["installation_id"] != installation || external["context"].(map[string]any)["installation_id"] != installation || digest(external) != envelope["external_sha256"] {
		return state, nil, fmt.Errorf("recovery_join")
	}
	public, err := wire.Encode(external)
	if err != nil {
		return state, nil, err
	}
	if _, err = labcontract.Read(journalFormat, public); err != nil {
		return state, nil, err
	}
	copy, err := object(external)
	if err != nil {
		return state, nil, err
	}
	sealJournal(copy)
	if !labcontract.Equal(copy["head"], external["head"]) {
		return state, nil, fmt.Errorf("recovery_head")
	}
	state, err = decodeState(encoded)
	if err != nil {
		return wire.ServiceState{}, nil, err
	}
	if err = joinState(state, external); err != nil {
		return wire.ServiceState{}, nil, err
	}
	return state, external, nil
}

func joinState(state wire.ServiceState, external map[string]any) error {
	entries := external["entries"].([]any)
	limit, reserve := external["operation_limit"].(int64), external["narrowing_reserve"].(int64)
	if limit < 1 || limit > 256 || reserve < 1 || reserve >= limit || len(entries) > int(limit) || len(entries) != len(state.Operations) {
		return fmt.Errorf("recovery_capacity")
	}
	seen := map[string]bool{}
	for position, operation := range state.Operations {
		entry := entries[position].(map[string]any)
		arguments, err := wire.Parse(operation.Arguments)
		if err != nil || seen[operation.ID] || entry["operation_id"] != operation.ID || entry["request_sha256"] != digest(arguments) || entry["result"] != "committed" || entry["sequence"] != int64(position+1) || entry["previous"].(map[string]any)["sequence"] != int64(position) {
			return fmt.Errorf("recovery_operation_join")
		}
		seen[operation.ID] = true
	}
	active := false
	for _, hold := range state.Holds {
		if hold.State == "active" {
			active = true
		}
	}
	if external["held"] != active {
		return fmt.Errorf("recovery_hold_join")
	}
	for _, group := range []struct {
		records []any
		ids     []string
	}{
		{external["bindings"].([]any), bindingIDs(state)}, {external["leases"].([]any), leaseIDs(state)},
	} {
		if len(group.records) != len(group.ids) || !sort.StringsAreSorted(group.ids) {
			return fmt.Errorf("recovery_record_join")
		}
		for position, value := range group.records {
			record := value.(map[string]any)
			identity := record["lease_id"]
			if identity == nil {
				identity = record["binding_id"]
			}
			if identity != group.ids[position] || position > 0 && group.ids[position] == group.ids[position-1] {
				return fmt.Errorf("recovery_record_join")
			}
		}
	}
	for position, binding := range state.Bindings {
		record := external["bindings"].([]any)[position].(map[string]any)
		gateway := record["gateway"].(map[string]any)
		if gateway["uid"] != int64(binding.UID) || gateway["generation"] != binding.Generation || record["revoked"] != (binding.State == "removed") {
			return fmt.Errorf("recovery_binding_join")
		}
	}
	for position, lease := range state.Leases {
		record := external["leases"].([]any)[position].(map[string]any)
		status := "ended"
		if lease.State == "active" || lease.State == "revoked" {
			status = lease.State
		}
		if record["binding_id"] != lease.BindingID || record["issue_operation_id"] != lease.OperationID || record["status"] != status || record["bounds"].(map[string]any)["authorized_until"] != lease.Until.UTC().Format("2006-01-02T15:04:05.999999999Z07:00") || active && lease.State == "active" {
			return fmt.Errorf("recovery_lease_join")
		}
		var binding map[string]any
		for _, value := range external["bindings"].([]any) {
			candidate := value.(map[string]any)
			if candidate["binding_id"] == lease.BindingID {
				binding = candidate
			}
		}
		if binding == nil {
			return fmt.Errorf("recovery_binding_join")
		}
		caller := binding["caller"].(map[string]any)
		if caller["uid"] != int64(lease.AgentUID) || caller["generation"] != lease.AgentGeneration || caller["execution_id"] != lease.LaunchID {
			return fmt.Errorf("recovery_caller_join")
		}
		renewals := []any{}
		issueFound := false
		for _, operation := range state.Operations {
			if operation.Method != "service.lease.request" && operation.Method != "service.lease.renew" {
				continue
			}
			result, err := wire.Parse(operation.Result)
			if err != nil {
				return fmt.Errorf("recovery_result_join")
			}
			if result["service_lease_id"] != lease.ID {
				continue
			}
			if operation.Method == "service.lease.request" {
				if operation.ID != lease.OperationID || issueFound {
					return fmt.Errorf("recovery_issue_join")
				}
				issueFound = true
			} else {
				renewals = append(renewals, operation.ID)
			}
		}
		if !issueFound || !labcontract.Equal(record["renew_operation_ids"], renewals) {
			return fmt.Errorf("recovery_renew_join")
		}
		if len(renewals) == 0 && lease.LastRenewalOperationID != nil || len(renewals) > 0 && (lease.LastRenewalOperationID == nil || *lease.LastRenewalOperationID != renewals[len(renewals)-1]) {
			return fmt.Errorf("recovery_renew_join")
		}
	}
	return nil
}

func bindingIDs(state wire.ServiceState) []string {
	ids := make([]string, len(state.Bindings))
	for position, binding := range state.Bindings {
		ids[position] = binding.ID
	}
	return ids
}

func leaseIDs(state wire.ServiceState) []string {
	ids := make([]string, len(state.Leases))
	for position, lease := range state.Leases {
		ids[position] = lease.ID
	}
	return ids
}

func terminalMethod(method string) bool {
	return method == "account.hold" || method == "service.unbind" || method == "service.lease.release"
}
