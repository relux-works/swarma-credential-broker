package statev0

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func (journal *Journal) reserve(state ServiceStateV2) error {
	data, err := journal.reservedState(state)
	if err != nil || len(data) > MaxServiceJournalBytes {
		return ErrCapacity
	}
	return nil
}

func (journal *Journal) reservedState(state ServiceStateV2) ([]byte, error) {
	maximumTime := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	maximumID := strings.Repeat("f", 32)
	maximumText := strings.Repeat("\x01", 128)
	operator := "4294967295:" + maximumText + ":operator:"
	service := "4294967295:" + maximumText + ":service:credential-gateway"
	var largestPin assemblyv0.PrincipalPin
	largestSize := 0
	for _, pin := range journal.callers {
		encoded, err := wire.Encode(pin)
		if err != nil {
			return nil, err
		}
		if len(encoded) > largestSize {
			largestPin, largestSize = pin, len(encoded)
		}
	}
	receipt := &OperationReceipt{
		Nonce: assemblyv0.Nonce(maximumID), TerminalCaller: largestPin,
		BootID: "ffffffff-ffff-ffff-ffff-ffffffffffff", PeerPID: assemblyv0.MaxSafeInteger, PeerStartTicks: assemblyv0.MaxSafeInteger,
		Freshness: assemblyv0.BoottimeFreshness{Kind: "boottime", BootID: "ffffffff-ffff-ffff-ffff-ffffffffffff", NotBeforeMS: assemblyv0.MaxSafeInteger - 300000, ExpiresAtMS: assemblyv0.MaxSafeInteger},
	}
	reserved := state
	reserved.Revision, reserved.Watermark = assemblyv0.MaxSafeInteger, maximumTime
	reserved.Bindings = append([]wire.ServiceBindingRecord{}, state.Bindings...)
	reserved.Leases = append([]wire.ServiceLeaseRecord{}, state.Leases...)
	reserved.Holds = append([]wire.AccountHoldRecord{}, state.Holds...)
	reserved.Operations = append([]ServiceOperationV2{}, state.Operations...)
	for index, binding := range reserved.Bindings {
		if binding.State != "active" {
			continue
		}
		binding.State, binding.RemovedOperationID, binding.RemovedAt = "removed", &maximumID, &maximumTime
		reserved.Bindings[index] = binding
		arguments, err := wire.Encode(wire.ServiceUnbind{OperationID: maximumID, BindingID: binding.ID})
		if err != nil {
			return nil, err
		}
		result, err := wire.Encode(map[string]any{"service_binding_id": binding.ID, "state": "removed"})
		if err != nil {
			return nil, err
		}
		reserved.Operations = append(reserved.Operations, ServiceOperationV2{Principal: operator, Method: "service.unbind", OperationID: assemblyv0.OperationID(maximumID), Arguments: arguments, Result: result, At: &maximumTime, Receipt: receipt})
	}
	for index := range reserved.Leases {
		if reserved.Leases[index].State == "active" {
			reserved.Leases[index].State = "released"
		}
	}
	for _, hold := range state.Holds {
		if hold.State == "active" {
			return wire.Encode(reserved)
		}
	}
	account := ""
	if len(state.Bindings) != 0 {
		account = state.Bindings[0].Account
	} else {
		account = maximumText
	}
	hold := wire.AccountHoldRecord{
		ID: maximumText, Account: account, Reason: "leak_match", Service: "credential-gateway", UID: ^uint32(0), Generation: maximumText,
		BindingID: maximumText, LeaseID: maximumText, OperationID: maximumID, PlacedAt: maximumTime, State: "active",
	}
	reserved.Holds = append(reserved.Holds, hold)
	arguments, err := wire.Encode(wire.ServiceHold{OperationID: maximumID, LeaseID: maximumText, Account: account, Reason: "leak_match"})
	if err != nil {
		return nil, err
	}
	result, err := wire.Encode(hold.Metadata())
	if err != nil {
		return nil, err
	}
	reserved.Operations = append(reserved.Operations, ServiceOperationV2{Principal: service, Method: "account.hold", OperationID: assemblyv0.OperationID(maximumID), Arguments: json.RawMessage(arguments), Result: json.RawMessage(result), At: &maximumTime})
	return wire.Encode(reserved)
}
