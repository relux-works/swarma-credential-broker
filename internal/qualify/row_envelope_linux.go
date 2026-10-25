//go:build linux

package qualify

import (
	"os"
	"reflect"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type rowHello struct {
	Version   int    `json:"version"`
	Profile   string `json:"profile"`
	Principal struct {
		UID uint32 `json:"uid"`
	} `json:"principal"`
	Generation uint64 `json:"policy_generation"`
}

type rowError struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details struct{} `json:"details"`
}

// Only validated, closed metadata is retained, never raw response frames.
// One fact is recorded per exchange, including both malformed/hello variants.
type rowEnvelope struct {
	Lease        *rowLease `json:"lease,omitempty"`
	Kind         string    `json:"kind"`
	RequestID    *string   `json:"request_id"`
	PayloadBytes int       `json:"payload_bytes"`
	Hello        *rowHello `json:"hello"`
	Refusal      *rowError `json:"refusal"`
}

func decodeRowEnvelope(b []byte, id, side string, generation uint64) (rowEnvelope, error) {
	f := rowEnvelope{PayloadBytes: len(b)}
	// Profile §7: spec/v0-codex-refresher.md lines 582-598 require disjoint
	// response shapes, exact correlation, closed details and bounded terminals.
	// Lines 602-605 specify the successful hello and unsupported negotiation.
	if side == "positive" {
		var reply struct {
			ID     string   `json:"request_id"`
			Result rowHello `json:"result"`
		}
		if wire.Decode(b, &reply) != nil {
			return rowEnvelope{}, qualification.ErrUnavailable
		}
		f.Kind, f.RequestID, f.Hello = "hello", &reply.ID, &reply.Result
	} else {
		var reply struct {
			ID    *string  `json:"request_id"`
			Error rowError `json:"error"`
		}
		if len(b) > 512 || wire.Decode(b, &reply) != nil {
			return rowEnvelope{}, qualification.ErrUnavailable
		}
		f.Kind, f.RequestID, f.Refusal = "error", reply.ID, &reply.Error
	}
	if !validRowEnvelope(f, id, side, generation) {
		return rowEnvelope{}, qualification.ErrUnavailable
	}
	return f, nil
}

func validRowEnvelope(f rowEnvelope, id, side string, generation uint64) bool {
	want := rowEnvelope{}
	requestID := "fixture-hello"
	var payload any
	if side == "positive" {
		if generation == 0 {
			return false
		}
		hello := rowHello{Version: 1, Profile: wire.Profile, Generation: generation}
		hello.Principal.UID = uint32(os.Geteuid())
		want.Kind, want.RequestID, want.Hello = "hello", &requestID, &hello
		payload = map[string]any{"request_id": requestID, "result": hello}
	} else if side == "negative" {
		if rowRefusal(id) == "closed" {
			return reflect.DeepEqual(f, rowEnvelope{Kind: "closed"})
		}
		if id == "profile-unsupported" {
			want.RequestID = &requestID
		}
		refusal := wire.Refuse(rowRefusal(id))
		want.Kind = "error"
		want.Refusal = &rowError{Code: refusal.Code, Message: refusal.Message}
		payload = map[string]any{"request_id": want.RequestID, "error": want.Refusal}
	} else {
		return false
	}
	b, e := wire.Encode(payload)
	if e != nil || want.Kind == "error" && len(b) > 512 {
		return false
	}
	want.PayloadBytes = len(b)
	return reflect.DeepEqual(f, want)
}

func validRowEnvelopes(o rowObservation, generation uint64) bool {
	if lifecycleRow(o.ID) || ownerRow(o.ID) {
		return validOwnerEffects(o)
	}
	if leaseProtocolRow(o.ID) {
		return validLeaseProtocolEnvelopes(o, generation)
	}
	if runnerRow(o.ID) {
		return len(o.Envelopes) == 0 && validRunnerEffects(o)
	}
	if o.ID == "peer-denied" {
		return validPeerEnvelopes(o, generation)
	}
	if admissionRow(o.ID) {
		return validAdmissionEnvelopes(o, generation)
	}
	n := 1
	if o.Side == "negative" && (o.ID == "profile-unsupported" || o.ID == "frame-malformed-first") {
		n = 2
	}
	if len(o.Envelopes) != n {
		return false
	}
	for _, f := range o.Envelopes {
		if !validRowEnvelope(f, o.ID, o.Side, generation) {
			return false
		}
	}
	return true
}
