// Package statev0 declares inactive records and ports; it implements no store or gate.
package statev0

import (
	"encoding/json"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type ConsumedNonce struct {
	Nonce          assemblyv0.Nonce `json:"nonce"`
	BootID         string           `json:"boot_id"`
	PeerPID        uint64           `json:"peer_pid"`
	PeerStartTicks uint64           `json:"peer_start_ticks"`
}

type NonceState struct {
	Format         string          `json:"format"`
	InstallationID string          `json:"installation_id"`
	Revision       uint64          `json:"revision"`
	Consumed       []ConsumedNonce `json:"consumed"`
}

type OperationReceipt struct {
	Nonce          assemblyv0.Nonce        `json:"nonce"`
	TerminalCaller assemblyv0.PrincipalPin `json:"terminal_caller"`
	BootID         string                  `json:"boot_id"`
	PeerPID        uint64                  `json:"peer_pid"`
	PeerStartTicks uint64                  `json:"peer_start_ticks"`
	Freshness      assemblyv0.Freshness    `json:"freshness"`
}

type ServiceOperationV2 struct {
	Principal   string                 `json:"principal"`
	Method      string                 `json:"method"`
	OperationID assemblyv0.OperationID `json:"operation_id"`
	Arguments   json.RawMessage        `json:"arguments"`
	Result      json.RawMessage        `json:"result"`
	At          *time.Time             `json:"at"`
	Receipt     *OperationReceipt      `json:"receipt"`
}

type ServiceStateV2 struct {
	Kind           string                      `json:"kind"`
	InstallationID string                      `json:"installation_id"`
	Revision       uint64                      `json:"revision"`
	Watermark      time.Time                   `json:"watermark"`
	Bindings       []wire.ServiceBindingRecord `json:"bindings"`
	Leases         []wire.ServiceLeaseRecord   `json:"leases"`
	Holds          []wire.AccountHoldRecord    `json:"holds"`
	Operations     []ServiceOperationV2        `json:"operations"`
}

type BaselineRevocationState struct {
	Seq     uint64                          `json:"seq"`
	Records []assemblyv0.RevocationEnvelope `json:"records"`
}

type RevocationState struct {
	Format         string                  `json:"format"`
	InstallationID string                  `json:"installation_id"`
	Revision       uint64                  `json:"revision"`
	State          BaselineRevocationState `json:"state"`
}
