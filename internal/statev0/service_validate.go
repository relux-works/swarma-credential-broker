package statev0

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func absoluteHome(home string) bool {
	return strings.HasPrefix(home, "/") && path.Clean(home) == home && !strings.ContainsRune(home, 0)
}

func hexID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

func policyDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32 && "sha256:"+hex.EncodeToString(decoded) == value
}

func utc(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1 && value.Year() <= 9999
}

func principalRole(principal string) string {
	parts := strings.Split(principal, ":")
	if len(parts) != 4 || !wire.ASCII(principal, 512) {
		return ""
	}
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != parts[0] || len(parts[1]) > 128 {
		return ""
	}
	switch parts[2] {
	case "operator", "owner":
		if parts[3] == "" {
			return parts[2]
		}
	case "service":
		if wire.ASCII(parts[1], 128) && parts[3] == "credential-gateway" {
			return "service"
		}
	}
	return ""
}

func closed(raw []byte, target any, keys ...string) bool {
	object, err := wire.Parse(raw)
	if err != nil || len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if value, present := object[key]; !present || value == nil {
			return false
		}
	}
	canonical, err := wire.Encode(object)
	return err == nil && bytes.Equal(raw, canonical) && json.Unmarshal(raw, target) == nil
}

func (journal *Journal) valid(account string, state ServiceStateV2) error {
	if state.Kind != ServiceJournalKind || state.InstallationID != journal.installation || state.Revision == 0 || state.Revision > assemblyv0.MaxSafeInteger || !utc(state.Watermark) || state.Bindings == nil || state.Leases == nil || state.Holds == nil || state.Operations == nil {
		return ErrUnavailable
	}
	bindings := map[string]bool{}
	active := map[wire.ServiceBinding]bool{}
	for _, binding := range state.Bindings {
		if bindings[binding.ID] || !wire.ASCII(binding.ID, 128) || binding.Account != account || binding.Service != "credential-gateway" || binding.Kind != "claude-oauth-token" || !wire.ASCII(binding.Generation, 128) || !policyDigest(binding.PolicyDigest) || !wire.ASCII(binding.CreatedBy, 512) || !wire.ASCII(binding.OperationID, 128) || !utc(binding.CreatedAt) {
			return ErrUnavailable
		}
		bindings[binding.ID] = true
		switch binding.State {
		case "active":
			if active[binding.Binding()] || binding.RemovedAt != nil || binding.RemovedOperationID != nil {
				return ErrUnavailable
			}
			active[binding.Binding()] = true
		case "removed":
			if binding.RemovedOperationID == nil || !hexID(*binding.RemovedOperationID) || binding.RemovedAt == nil || !utc(*binding.RemovedAt) {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
	}
	leases := map[string]bool{}
	for _, lease := range state.Leases {
		if leases[lease.ID] || !wire.ASCII(lease.ID, 128) || lease.Account != account || !bindings[lease.BindingID] || lease.Service != "credential-gateway" || lease.Kind != "claude-oauth-token" || lease.Harness != "claude_code" || !utc(lease.Until) {
			return ErrUnavailable
		}
		for _, value := range []string{lease.Generation, lease.AgentGeneration, lease.AgentBindingID, lease.LaunchID, lease.OperationID} {
			if !wire.ASCII(value, 128) {
				return ErrUnavailable
			}
		}
		if lease.State != "active" && lease.State != "released" && lease.State != "expired" && lease.State != "revoked" || lease.LastRenewalOperationID != nil && !wire.ASCII(*lease.LastRenewalOperationID, 128) {
			return ErrUnavailable
		}
		leases[lease.ID] = true
	}
	holds := map[string]bool{}
	activeHolds := 0
	for _, hold := range state.Holds {
		if holds[hold.ID] || !wire.ASCII(hold.ID, 128) || hold.Account != account || hold.Reason != "leak_match" || hold.Service != "credential-gateway" || !wire.ASCII(hold.Generation, 128) || !bindings[hold.BindingID] || !leases[hold.LeaseID] || !wire.ASCII(hold.OperationID, 128) || !utc(hold.PlacedAt) {
			return ErrUnavailable
		}
		switch hold.State {
		case "active":
			activeHolds++
			if hold.LiftedBy != nil || hold.LiftOperationID != nil || hold.LiftedAt != nil {
				return ErrUnavailable
			}
		case "lifted":
			if hold.LiftedBy == nil || !wire.ASCII(*hold.LiftedBy, 512) || hold.LiftOperationID == nil || !hexID(*hold.LiftOperationID) || hold.LiftedAt == nil || !utc(*hold.LiftedAt) {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
		holds[hold.ID] = true
	}
	if activeHolds > 1 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, operation := range state.Operations {
		key := operation.Principal + "\n" + operation.Method + "\n" + string(operation.OperationID)
		if seen[key] || journal.validOperation(account, operation) != nil {
			return ErrUnavailable
		}
		seen[key] = true
	}
	return validServiceLinks(state)
}

func (journal *Journal) validReceipt(receipt *OperationReceipt, narrowing bool) bool {
	if receipt == nil || !hexID(string(receipt.Nonce)) || !bootID(receipt.BootID) || receipt.PeerPID == 0 || receipt.PeerPID > assemblyv0.MaxSafeInteger || receipt.PeerStartTicks == 0 || receipt.PeerStartTicks > assemblyv0.MaxSafeInteger {
		return false
	}
	if receipt.TerminalCaller.Name == "" || !absoluteHome(receipt.TerminalCaller.Home) {
		return false
	}
	switch freshness := receipt.Freshness.(type) {
	case assemblyv0.UTCFreshness:
		begin, beginErr := time.Parse(time.RFC3339Nano, string(freshness.NotBefore))
		end, endErr := time.Parse(time.RFC3339Nano, string(freshness.ExpiresAt))
		return !narrowing && freshness.Kind == "utc" && beginErr == nil && endErr == nil && utc(begin) && utc(end) && end.After(begin) && end.Sub(begin) <= 300*time.Second
	case assemblyv0.BoottimeFreshness:
		return narrowing && freshness.Kind == "boottime" && freshness.BootID == receipt.BootID && freshness.ExpiresAtMS <= assemblyv0.MaxSafeInteger && freshness.ExpiresAtMS > freshness.NotBeforeMS && freshness.ExpiresAtMS-freshness.NotBeforeMS <= 300000
	}
	return false
}

func (journal *Journal) validOperation(account string, operation ServiceOperationV2) error {
	role := principalRole(operation.Principal)
	if role == "" || !hexID(string(operation.OperationID)) || operation.At != nil && !utc(*operation.At) {
		return ErrUnavailable
	}
	operator := role == "operator"
	if operator && operation.Method != "service.bind" && operation.Method != "service.unbind" && operation.Method != "account.hold.lift" {
		return ErrUnavailable
	}
	if operator != (operation.Receipt != nil) || operator && !journal.validReceipt(operation.Receipt, operation.Method == "service.unbind") {
		return ErrUnavailable
	}
	if operation.At == nil && operation.Method != "service.unbind" && operation.Method != "service.lease.release" && operation.Method != "account.hold" {
		return ErrUnavailable
	}
	var arguments, result map[string]any
	var argumentKeys, resultKeys []string
	switch operation.Method {
	case "service.bind":
		if !operator {
			return ErrUnavailable
		}
		argumentKeys = []string{"operation_id", "service_name", "uid", "service_generation", "account", "kind", "installation_policy_digest"}
		resultKeys = []string{"service_binding_id", "service_name", "uid", "service_generation", "account", "kind", "installation_policy_digest", "state"}
	case "service.unbind":
		if !operator {
			return ErrUnavailable
		}
		argumentKeys = []string{"operation_id", "service_binding_id"}
		resultKeys = []string{"service_binding_id", "state"}
	case "account.hold.lift":
		if role != "operator" && role != "owner" {
			return ErrUnavailable
		}
		argumentKeys = []string{"operation_id", "hold_id", "account"}
		resultKeys = []string{"hold_id", "account", "state"}
	case "account.hold":
		argumentKeys = []string{"operation_id", "service_lease_id", "account", "reason_code"}
		resultKeys = []string{"hold_id", "account", "reason_code", "placed_at", "state"}
	case "service.lease.request":
		argumentKeys = []string{"operation_id", "account", "agent_uid", "agent_generation", "launch_id"}
		resultKeys = []string{"service_lease_id", "authorized_until"}
	case "service.lease.renew":
		argumentKeys = []string{"operation_id", "service_lease_id"}
		resultKeys = []string{"service_lease_id", "authorized_until"}
	case "service.lease.release", "event.report":
		argumentKeys = []string{"service_lease_id"}
		if operation.Method == "event.report" {
			argumentKeys = append(argumentKeys, "event")
		}
		resultKeys = []string{"service_lease_id", "state"}
	default:
		return ErrUnavailable
	}
	if !closed(operation.Arguments, &arguments, argumentKeys...) || !closed(operation.Result, &result, resultKeys...) {
		return ErrUnavailable
	}
	if inner, present := arguments["operation_id"]; present && inner != string(operation.OperationID) {
		return ErrUnavailable
	}
	for _, object := range []map[string]any{arguments, result} {
		if label, present := object["account"]; present && label != account {
			return ErrUnavailable
		}
		if !methodValues(object) {
			return ErrUnavailable
		}
	}
	wantedState := map[string]string{"service.bind": "active", "service.unbind": "removed", "account.hold.lift": "lifted", "account.hold": "active", "service.lease.release": "released", "event.report": "active"}
	if expected, present := wantedState[operation.Method]; present && result["state"] != expected {
		return ErrUnavailable
	}
	for _, key := range []string{"service_binding_id", "service_lease_id", "hold_id"} {
		if left, present := arguments[key]; present {
			if right, present := result[key]; present && left != right {
				return ErrUnavailable
			}
		}
	}
	if operation.Method == "service.bind" {
		for _, key := range []string{"service_name", "uid", "service_generation", "account", "kind", "installation_policy_digest"} {
			if arguments[key] != result[key] {
				return ErrUnavailable
			}
		}
	}
	if role != "service" && !operator && operation.Method != "account.hold.lift" {
		return ErrUnavailable
	}
	return nil
}

func bootID(value string) bool {
	return len(value) == 36 && value[8] == 45 && value[13] == 45 && value[18] == 45 && value[23] == 45 && hexID(strings.ReplaceAll(value, "-", ""))
}

func methodValues(object map[string]any) bool {
	for key, value := range object {
		switch key {
		case "uid", "agent_uid":
			number, valid := value.(float64)
			if !valid || number < 0 || number > float64(^uint32(0)) || number != float64(uint32(number)) {
				return false
			}
		case "authorized_until", "placed_at":
			text, valid := value.(string)
			parsed, err := time.Parse(time.RFC3339Nano, text)
			if !valid || err != nil || !utc(parsed) {
				return false
			}
		case "event":
			event, valid := value.(map[string]any)
			if !valid {
				return false
			}
			switch event["kind"] {
			case "lease_expiring", "lease_expired", "reauth_required":
				if len(event) != 1 {
					return false
				}
			case "error":
				if len(event) != 2 || event["class"] != "auth" && event["class"] != "permission" && event["class"] != "quota" && event["class"] != "unknown" {
					return false
				}
			default:
				return false
			}
		default:
			text, valid := value.(string)
			if !valid || !wire.ASCII(text, 128) {
				return false
			}
			switch key {
			case "service_name":
				if text != "credential-gateway" {
					return false
				}
			case "kind":
				if text != "claude-oauth-token" {
					return false
				}
			case "reason_code":
				if text != "leak_match" {
					return false
				}
			case "installation_policy_digest":
				if !policyDigest(text) {
					return false
				}
			}
		}
	}
	return true
}

func same(left, right any) bool {
	return reflect.DeepEqual(left, right)
}

func retained(prior, next ServiceStateV2) (bool, error) {
	if next.Watermark.Before(prior.Watermark) || len(next.Operations) < len(prior.Operations) || len(next.Bindings) < len(prior.Bindings) || len(next.Leases) < len(prior.Leases) || len(next.Holds) < len(prior.Holds) {
		return false, ErrConflict
	}
	for index, operation := range prior.Operations {
		if !same(operation, next.Operations[index]) {
			return false, ErrConflict
		}
	}
	widening := false
	for _, operation := range next.Operations[len(prior.Operations):] {
		if operation.At == nil && !next.Watermark.Equal(prior.Watermark) {
			return false, ErrConflict
		}
		switch operation.Method {
		case "service.bind", "service.lease.request", "service.lease.renew", "account.hold.lift":
			widening = true
		}
	}
	bindings := map[string]wire.ServiceBindingRecord{}
	for _, binding := range next.Bindings {
		bindings[binding.ID] = binding
	}
	for _, old := range prior.Bindings {
		current, present := bindings[old.ID]
		if !present {
			return false, ErrConflict
		}
		if old.State == "active" && current.State == "removed" {
			operation := transitionOutcome(next.Operations[len(prior.Operations):], "service.unbind", "service_binding_id", old.ID, *current.RemovedOperationID)
			if operation == nil {
				return false, ErrConflict
			}
			current.State, current.RemovedAt, current.RemovedOperationID = old.State, old.RemovedAt, old.RemovedOperationID
		}
		if !same(old, current) {
			return false, ErrConflict
		}
	}
	leases := map[string]wire.ServiceLeaseRecord{}
	for _, lease := range next.Leases {
		leases[lease.ID] = lease
	}
	for _, old := range prior.Leases {
		current, present := leases[old.ID]
		if !present {
			return false, ErrConflict
		}
		if old.State == "active" && current.State != "active" {
			current.State = old.State
		}
		if old.State == "active" && current.State == "active" && (!old.Until.Equal(current.Until) || !same(old.LastRenewalOperationID, current.LastRenewalOperationID)) {
			widening = true
			current.Until, current.LastRenewalOperationID = old.Until, old.LastRenewalOperationID
		}
		if !same(old, current) {
			return false, ErrConflict
		}
	}
	holds := map[string]wire.AccountHoldRecord{}
	for _, hold := range next.Holds {
		holds[hold.ID] = hold
	}
	for _, old := range prior.Holds {
		current, present := holds[old.ID]
		if !present {
			return false, ErrConflict
		}
		if old.State == "active" && current.State == "lifted" {
			operation := transitionOutcome(next.Operations[len(prior.Operations):], "account.hold.lift", "hold_id", old.ID, *current.LiftOperationID)
			if operation == nil || operation.Principal != *current.LiftedBy {
				return false, ErrConflict
			}
			widening = true
			current.State, current.LiftedBy, current.LiftedAt, current.LiftOperationID = old.State, old.LiftedBy, old.LiftedAt, old.LiftOperationID
		}
		if !same(old, current) {
			return false, ErrConflict
		}
	}
	return widening || len(next.Bindings) > len(prior.Bindings) || len(next.Leases) > len(prior.Leases), nil
}

func servicePrincipal(uid uint32, generation string) string {
	return strconv.FormatUint(uint64(uid), 10) + ":" + generation + ":service:credential-gateway"
}

func validServiceLinks(state ServiceStateV2) error {
	bindings := map[string]wire.ServiceBindingRecord{}
	leases := map[string]wire.ServiceLeaseRecord{}
	holds := map[string]wire.AccountHoldRecord{}
	outcomes := map[string]bool{}
	effects := map[string]bool{}
	for _, binding := range state.Bindings {
		bindings[binding.ID] = binding
	}
	for _, lease := range state.Leases {
		leases[lease.ID] = lease
	}
	for _, hold := range state.Holds {
		holds[hold.ID] = hold
	}
	for _, operation := range state.Operations {
		arguments, argumentErr := wire.Parse(operation.Arguments)
		result, resultErr := wire.Parse(operation.Result)
		if argumentErr != nil || resultErr != nil {
			return ErrUnavailable
		}
		id := string(operation.OperationID)
		target := ""
		for _, member := range []string{"service_binding_id", "service_lease_id", "hold_id"} {
			if value, present := result[member].(string); present {
				target = value
			}
		}
		outcomes[operation.Principal+"\n"+operation.Method+"\n"+id+"\n"+target] = true
		effects[operation.Method+"\n"+id+"\n"+target] = true
		switch operation.Method {
		case "service.bind", "service.unbind":
			bindingID, _ := result["service_binding_id"].(string)
			binding, present := bindings[bindingID]
			if !present {
				return ErrUnavailable
			}
			if operation.Method == "service.bind" && (binding.OperationID != id || binding.CreatedBy != operation.Principal) {
				return ErrUnavailable
			}
			if operation.Method == "service.unbind" && (binding.State != "removed" || binding.RemovedOperationID == nil || *binding.RemovedOperationID != id) {
				return ErrUnavailable
			}
		case "service.lease.request", "service.lease.renew", "service.lease.release", "event.report":
			leaseID, _ := result["service_lease_id"].(string)
			lease, present := leases[leaseID]
			if !present || servicePrincipal(lease.UID, lease.Generation) != operation.Principal || operation.Method == "service.lease.request" && lease.OperationID != id {
				return ErrUnavailable
			}
		case "account.hold":
			holdID, _ := result["hold_id"].(string)
			leaseID, _ := arguments["service_lease_id"].(string)
			_, present := holds[holdID]
			lease, leasePresent := leases[leaseID]
			if !present || !leasePresent || servicePrincipal(lease.UID, lease.Generation) != operation.Principal {
				return ErrUnavailable
			}
		case "account.hold.lift":
			holdID, _ := result["hold_id"].(string)
			hold, present := holds[holdID]
			if !present || hold.State != "lifted" || hold.LiftOperationID == nil || *hold.LiftOperationID != id || hold.LiftedBy == nil || *hold.LiftedBy != operation.Principal {
				return ErrUnavailable
			}
		}
	}
	for _, binding := range state.Bindings {
		if !outcomes[binding.CreatedBy+"\nservice.bind\n"+binding.OperationID+"\n"+binding.ID] || binding.State == "removed" && !effects["service.unbind\n"+*binding.RemovedOperationID+"\n"+binding.ID] {
			return ErrUnavailable
		}
	}
	for _, lease := range state.Leases {
		binding := bindings[lease.BindingID]
		if binding.UID != lease.UID || binding.Generation != lease.Generation || !outcomes[servicePrincipal(lease.UID, lease.Generation)+"\nservice.lease.request\n"+lease.OperationID+"\n"+lease.ID] || lease.LastRenewalOperationID != nil && !outcomes[servicePrincipal(lease.UID, lease.Generation)+"\nservice.lease.renew\n"+*lease.LastRenewalOperationID+"\n"+lease.ID] {
			return ErrUnavailable
		}
	}
	for _, hold := range state.Holds {
		lease := leases[hold.LeaseID]
		if hold.BindingID != lease.BindingID || hold.UID != lease.UID || hold.Generation != lease.Generation || !outcomes[servicePrincipal(hold.UID, hold.Generation)+"\naccount.hold\n"+hold.OperationID+"\n"+hold.ID] || hold.State == "lifted" && !outcomes[*hold.LiftedBy+"\naccount.hold.lift\n"+*hold.LiftOperationID+"\n"+hold.ID] {
			return ErrUnavailable
		}
	}
	return nil
}

func transitionOutcome(operations []ServiceOperationV2, method, member, target, id string) *ServiceOperationV2 {
	for _, operation := range operations {
		if operation.Method != method || string(operation.OperationID) != id {
			continue
		}
		arguments, argumentErr := wire.Parse(operation.Arguments)
		result, resultErr := wire.Parse(operation.Result)
		if argumentErr == nil && resultErr == nil && arguments[member] == target && result[member] == target {
			return &operation
		}
	}
	return nil
}
