//go:build linux && broker_lab

package labv0

import (
	"fmt"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type projectionFacts struct {
	gateway            map[string]any
	caller             map[string]any
	authorityUntil     time.Time
	callerUntil        time.Time
	timeUntil          time.Time
	qualificationUntil time.Time
	lifetime           time.Duration
	version            string
}

func (facts projectionFacts) project(state wire.ServiceState, previous map[string]any) (map[string]any, error) {
	journal, err := object(previous)
	if err != nil || facts.lifetime < time.Second || facts.lifetime > 900*time.Second || facts.lifetime%time.Second != 0 {
		return nil, ErrUnknown
	}
	entries := journal["entries"].([]any)
	if len(entries)+1 != len(state.Operations) {
		return nil, ErrUnknown
	}
	operation := state.Operations[len(entries)]
	arguments, err := wire.Parse(operation.Arguments)
	if err != nil {
		return nil, ErrUnknown
	}
	journal["entries"] = append(entries, map[string]any{"operation_id": operation.ID, "previous": journal["head"], "request_sha256": digest(arguments), "result": "committed", "sequence": len(entries) + 1})
	bindings := []any{}
	for _, binding := range state.Bindings {
		if facts.gateway["uid"] != int64(binding.UID) || facts.gateway["generation"] != binding.Generation {
			return nil, ErrUnknown
		}
		leases := []string{}
		for _, lease := range state.Leases {
			if lease.BindingID == binding.ID {
				leases = append(leases, lease.ID)
			}
		}
		bindings = append(bindings, map[string]any{"binding_id": binding.ID, "bound_until": facts.authorityUntil.UTC().Format(time.RFC3339Nano), "caller": facts.caller, "epoch": facts.caller["execution_epoch"], "gateway": facts.gateway, "lease_ids": sortedStrings(leases), "revoked": binding.State == "removed"})
	}
	journal["bindings"] = bindings
	held := false
	for _, hold := range state.Holds {
		if hold.State == "active" {
			held = true
		}
	}
	journal["held"] = held
	leases := []any{}
	for _, lease := range state.Leases {
		if facts.caller["uid"] != int64(lease.AgentUID) || facts.caller["generation"] != lease.AgentGeneration || facts.caller["execution_id"] != lease.LaunchID {
			return nil, ErrUnknown
		}
		var old map[string]any
		for _, value := range previous["leases"].([]any) {
			candidate := value.(map[string]any)
			if candidate["lease_id"] == lease.ID {
				old = candidate
			}
		}
		renewals := []string{}
		var latest wire.ServiceOperation
		for _, candidate := range state.Operations {
			if candidate.Method != "service.lease.request" && candidate.Method != "service.lease.renew" {
				continue
			}
			result, err := wire.Parse(candidate.Result)
			if err != nil {
				return nil, ErrUnknown
			}
			if result["service_lease_id"] == lease.ID {
				latest = candidate
				if candidate.Method == "service.lease.renew" {
					renewals = append(renewals, candidate.ID)
				}
			}
		}
		if latest.At.IsZero() {
			return nil, ErrUnknown
		}
		var bounds any
		if old != nil && latest.ID != operation.ID {
			bounds = old["bounds"]
		} else {
			until := latest.At.Add(facts.lifetime)
			for _, deadline := range []time.Time{facts.authorityUntil, facts.callerUntil, facts.timeUntil, facts.qualificationUntil} {
				if deadline.Before(until) {
					until = deadline
				}
			}
			if !until.Equal(lease.Until) {
				return nil, fmt.Errorf("lease_deadline_join")
			}
			bounds = map[string]any{"authority_until": facts.authorityUntil.UTC().Format(time.RFC3339Nano), "authorized_until": until.UTC().Format(time.RFC3339Nano), "caller_until": facts.callerUntil.UTC().Format(time.RFC3339Nano), "issued_at": latest.At.UTC().Format(time.RFC3339Nano), "lifetime_seconds": int64(facts.lifetime / time.Second), "qualification_until": facts.qualificationUntil.UTC().Format(time.RFC3339Nano), "time_until": facts.timeUntil.UTC().Format(time.RFC3339Nano)}
		}
		status := "ended"
		if lease.State == "active" || lease.State == "revoked" {
			status = lease.State
		}
		sequence := int64(0)
		if old != nil {
			sequence = old["revocation_sequence"].(int64)
		}
		if status == "revoked" && (old == nil || old["status"] != "revoked") {
			sequence++
		}
		leases = append(leases, map[string]any{"binding_id": lease.BindingID, "bounds": bounds, "issue_operation_id": lease.OperationID, "lease_id": lease.ID, "renew_operation_ids": stringsInOrder(renewals), "revocation_sequence": sequence, "status": status, "version_id": facts.version})
	}
	journal["leases"] = leases
	sealJournal(journal)
	raw, err := wire.Encode(journal)
	if err != nil {
		return nil, err
	}
	return labcontract.Read(journalFormat, raw)
}

func stringsInOrder(values []string) []any {
	result := make([]any, len(values))
	for position, value := range values {
		result[position] = value
	}
	return result
}
