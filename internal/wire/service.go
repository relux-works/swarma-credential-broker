package wire

import (
	"encoding/json"
	"time"
)

// ServiceProfile selects the inactive secret-free-service-v0 dialect on broker/1.
const ServiceProfile = "broker/1"

type ServiceBinding struct {
	Service      string `json:"service_name"`
	UID          uint32 `json:"uid"`
	Generation   string `json:"service_generation"`
	Account      string `json:"account"`
	Kind         string `json:"kind"`
	PolicyDigest string `json:"installation_policy_digest"`
}
type ServiceBind struct {
	OperationID string `json:"operation_id"`
	ServiceBinding
}
type ServiceUnbind struct {
	OperationID string `json:"operation_id"`
	BindingID   string `json:"service_binding_id"`
}
type ServiceCaller struct {
	Account    string `json:"account"`
	UID        uint32 `json:"agent_uid"`
	Generation string `json:"agent_generation"`
	LaunchID   string `json:"launch_id"`
}
type ServiceRequest struct {
	OperationID string `json:"operation_id"`
	ServiceCaller
}
type ServiceLeaseID struct {
	LeaseID string `json:"service_lease_id"`
}
type ServiceRenew struct {
	OperationID string `json:"operation_id"`
	ServiceLeaseID
}
type ServiceHold struct {
	OperationID string `json:"operation_id"`
	LeaseID     string `json:"service_lease_id"`
	Account     string `json:"account"`
	Reason      string `json:"reason_code"`
}
type ServiceLift struct {
	OperationID string `json:"operation_id"`
	HoldID      string `json:"hold_id"`
	Account     string `json:"account"`
}
type ServicePayload struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type ServiceLease struct {
	LeaseID         string         `json:"service_lease_id"`
	Account         string         `json:"account"`
	Harness         string         `json:"harness"`
	Kind            string         `json:"kind"`
	Payload         ServicePayload `json:"payload"`
	TokenExpiresAt  *time.Time     `json:"token_expires_at"`
	AuthorizedUntil string         `json:"authorized_until"`
	Renewable       bool           `json:"renewable"`
}

// The following are the closed records of accepted service dialect section 6.
// The protected journal envelope supplies atomic revision and installation pins.
type ServiceBindingRecord struct {
	ID                 string     `json:"service_binding_id"`
	Service            string     `json:"service_name"`
	UID                uint32     `json:"service_uid"`
	Generation         string     `json:"service_generation"`
	Account            string     `json:"account"`
	Kind               string     `json:"kind"`
	PolicyDigest       string     `json:"installation_policy_digest"`
	CreatedBy          string     `json:"created_by"`
	OperationID        string     `json:"operation_id"`
	CreatedAt          time.Time  `json:"created_at"`
	State              string     `json:"state"`
	RemovedOperationID *string    `json:"removed_operation_id"`
	RemovedAt          *time.Time `json:"removed_at"`
}

func (r ServiceBindingRecord) Binding() ServiceBinding {
	return ServiceBinding{r.Service, r.UID, r.Generation, r.Account, r.Kind, r.PolicyDigest}
}

type ServiceLeaseRecord struct {
	ID                     string    `json:"service_lease_id"`
	BindingID              string    `json:"service_binding_id"`
	Service                string    `json:"service_name"`
	UID                    uint32    `json:"service_uid"`
	Generation             string    `json:"service_generation"`
	Account                string    `json:"account"`
	Harness                string    `json:"harness"`
	Kind                   string    `json:"kind"`
	AgentUID               uint32    `json:"agent_uid"`
	AgentGeneration        string    `json:"agent_generation"`
	AgentBindingID         string    `json:"binding_id"`
	LaunchID               string    `json:"launch_id"`
	OperationID            string    `json:"operation_id"`
	Until                  time.Time `json:"authorized_until"`
	LastRenewalOperationID *string   `json:"last_renewal_operation_id"`
	State                  string    `json:"state"`
}

func (r ServiceLeaseRecord) Caller() ServiceCaller {
	return ServiceCaller{r.Account, r.AgentUID, r.AgentGeneration, r.LaunchID}
}

type AccountHoldRecord struct {
	ID              string     `json:"hold_id"`
	Account         string     `json:"account"`
	Reason          string     `json:"reason_code"`
	Service         string     `json:"service_name"`
	UID             uint32     `json:"service_uid"`
	Generation      string     `json:"service_generation"`
	BindingID       string     `json:"service_binding_id"`
	LeaseID         string     `json:"service_lease_id"`
	OperationID     string     `json:"operation_id"`
	PlacedAt        time.Time  `json:"placed_at"`
	State           string     `json:"state"`
	LiftedBy        *string    `json:"lifted_by"`
	LiftOperationID *string    `json:"lift_operation_id"`
	LiftedAt        *time.Time `json:"lifted_at"`
}

func (h AccountHoldRecord) Metadata() map[string]any {
	return map[string]any{"hold_id": h.ID, "account": h.Account, "reason_code": h.Reason, "placed_at": h.PlacedAt, "state": h.State}
}

// ServiceOperation retains canonical nonsecret arguments and metadata outcomes.
// At is also the durable end-time evidence for released leases.
type ServiceOperation struct {
	Principal string          `json:"principal"`
	Method    string          `json:"method"`
	ID        string          `json:"operation_id"`
	Arguments json.RawMessage `json:"arguments"`
	Result    json.RawMessage `json:"result"`
	At        time.Time       `json:"at"`
}
type ServiceState struct {
	Kind         string                 `json:"kind"`
	Installation string                 `json:"installation_id"`
	Revision     uint64                 `json:"revision"`
	Watermark    time.Time              `json:"watermark"`
	Bindings     []ServiceBindingRecord `json:"bindings"`
	Leases       []ServiceLeaseRecord   `json:"leases"`
	Holds        []AccountHoldRecord    `json:"holds"`
	Operations   []ServiceOperation     `json:"operations"`
}

// ServiceAccount is the custody reader's material-free account metadata.
type ServiceAccount struct {
	Account   string
	Harness   string
	Kind      string
	State     string
	ExpiresAt *time.Time
}
