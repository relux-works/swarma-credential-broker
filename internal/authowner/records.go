package authowner

import (
	"bytes"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"time"
)

type Binding struct {
	Installation string `json:"installation_id"`
	Account      string `json:"account"`
	Attempt      string `json:"attempt_id"`
	Sequence     uint64 `json:"attempt_sequence"`
	Revision     uint64 `json:"revision"`
	Operation    string `json:"operation"`
	Daemon       string `json:"daemon_instance_id"`
	Policy       uint64 `json:"policy_generation"`
	Identity
	Unit        string    `json:"unit_name"`
	Executable  string    `json:"executable_sha256"`
	Home        string    `json:"vendor_home_id"`
	StoreBefore uint64    `json:"store_generation_before"`
	TokenBefore uint64    `json:"token_generation_before"`
	Created     time.Time `json:"created_at"`
	Deadline    time.Time `json:"deadline"`
}
type Intent struct {
	Kind string `json:"kind"`
	Binding
	Phase string `json:"phase"`
}
type Evidence struct {
	Kind string `json:"kind"`
	Binding
	Phase       string      `json:"phase"`
	Observation Observation `json:"observation"`
	Absence     string      `json:"absence"`
	Outcome     Disposition `json:"outcome"`
	RPC         Disposition `json:"rpc_outcome"`
	Plan        string      `json:"plan_type"`
	StoreAfter  uint64      `json:"store_generation_after"`
}
type Checkpoint struct {
	Kind             string    `json:"kind"`
	Installation     string    `json:"installation_id"`
	Revision         uint64    `json:"revision"`
	Account          string    `json:"account"`
	VendorID         string    `json:"vendor_account_id"`
	HomeID           string    `json:"vendor_home_id"`
	State            string    `json:"state"`
	PendingAttempt   string    `json:"pending_attempt"`
	RetainedAttempts uint64    `json:"retained_attempts"`
	LastAttempt      string    `json:"last_resolved_attempt"`
	StoreGeneration  uint64    `json:"store_generation"`
	TokenGeneration  uint64    `json:"token_generation"`
	Policy           uint64    `json:"policy_generation"`
	Watermark        time.Time `json:"watermark"`
	// The whole protected vendor-file digest reconciles the local snapshot; it
	// is not independent freshness evidence and never appears in status.
	StoreDigest   string    `json:"vendor_store_digest"`
	Plan          string    `json:"plan_type"`
	TokenDigest   string    `json:"current_token_digest"`
	NextProactive time.Time `json:"next_proactive"`
	RetryAt       time.Time `json:"retry_at"`
	Failures      uint64    `json:"safe_failures"`
}

// decodeRecord also requires every encoded field, including flattened binding
// fields. Re-encoding rejects typed null, omitted members and alternate time
// encodings; Parse enforces canonical JSON and rejects duplicate members.
func decodeRecord(raw []byte, v any) error {
	if _, e := wire.Parse(raw); e != nil {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrUnavailable
	}
	b, e := wire.Encode(v)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrUnavailable
	}
	return nil
}
