package wire

// SPEC-PENDING: broker/1 is Core's selected dialect; this hello profile spelling,
// JSON field layout, response payload and auxiliary renewal/lift names await
// spec/secret-free-service-v0.md. Framing remains the existing length-prefixed JSON.
const ServiceProfile = "broker/1"

type ServiceBinding struct {
	Service      string `json:"service"`
	UID          uint32 `json:"uid"`
	Generation   string `json:"service_generation"`
	Account      string `json:"account"`
	Kind         string `json:"kind"`
	PolicyDigest string `json:"policy_digest"`
}

type ServiceCaller struct {
	Account    string `json:"account"`
	UID        uint32 `json:"agent_uid"`
	Generation string `json:"agent_generation"`
	LaunchID   string `json:"launch_id"`
}

type ServiceRequest struct {
	Caller       ServiceCaller `json:"caller"`
	Kind         string        `json:"kind"`
	PolicyDigest string        `json:"policy_digest"`
}

type ServiceLeaseID struct {
	LeaseID string `json:"lease_id"`
}
type ServiceHold struct {
	LeaseID string `json:"lease_id"`
	Reason  string `json:"reason"`
}
type ServiceLift struct {
	Account string `json:"account"`
}
type ServiceLease struct {
	LeaseID         string `json:"lease_id"`
	Account         string `json:"account"`
	Kind            string `json:"kind"`
	AuthorizedUntil string `json:"authorized_until"`
	Token           string `json:"token"`
}

// SPEC-PENDING: local protected binding/tombstone record schema and revision
// semantics. No lease material or placeholder is persisted here.
type ServiceBindingState struct {
	Kind         string         `json:"kind"`
	Installation string         `json:"installation_id"`
	Revision     uint64         `json:"revision"`
	Bound        bool           `json:"bound"`
	Binding      ServiceBinding `json:"binding"`
}
