//go:build linux

package qualify

import (
	"reflect"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Sanitized lease metadata. No token, token digest or raw response is retained.
type rowLease struct {
	ID      string `json:"lease_id"`
	Until   string `json:"authorized_until"`
	Expires string `json:"token_expires_at"`
}

func decodeAdmissionError(b []byte, id, requestID string) (rowEnvelope, error) {
	var reply struct {
		ID    string   `json:"request_id"`
		Error rowError `json:"error"`
	}
	if len(b) > 512 || wire.Decode(b, &reply) != nil || reply.ID != requestID {
		return rowEnvelope{}, qualification.ErrUnavailable
	}
	f := rowEnvelope{Kind: "error", RequestID: &reply.ID, PayloadBytes: len(b), Refusal: &reply.Error}
	if !validAdmissionError(f, id, requestID) {
		return rowEnvelope{}, qualification.ErrUnavailable
	}
	return f, nil
}
func validAdmissionError(f rowEnvelope, id, requestID string) bool {
	refusal := wire.Refuse(rowRefusal(id))
	want := rowEnvelope{Kind: "error", RequestID: &requestID, Refusal: &rowError{Code: refusal.Code, Message: refusal.Message}}
	b, e := wire.Encode(map[string]any{"request_id": requestID, "error": want.Refusal})
	want.PayloadBytes = len(b)
	return e == nil && len(b) <= 512 && reflect.DeepEqual(f, want)
}
func decodeAdmissionGrant(b []byte, id string, in rowInput) (wire.LeaseResult, rowEnvelope, error) {
	var reply struct {
		ID     string           `json:"request_id"`
		Result wire.LeaseResult `json:"result"`
	}
	if wire.Decode(b, &reply) != nil || reply.ID != id {
		return wire.LeaseResult{}, rowEnvelope{}, qualification.ErrUnavailable
	}
	r := reply.Result
	if r.Account != in.Policy.Accounts[0].Label || r.Harness != "codex_cli" || r.Channel != "external-token" || r.Payload.Channel != "external-token" || r.Payload.AccountID != in.Policy.Accounts[0].VendorID || r.Payload.PlanType != "" || !r.Renewable || !policy.Hash(r.Payload.AccessToken) {
		return wire.LeaseResult{}, rowEnvelope{}, qualification.ErrUnavailable
	}
	f := rowEnvelope{Kind: "lease", RequestID: &reply.ID, PayloadBytes: len(b), Lease: &rowLease{r.LeaseID, r.AuthorizedUntil, r.TokenExpiresAt}}
	if !validAdmissionGrant(f, id) {
		return wire.LeaseResult{}, rowEnvelope{}, qualification.ErrUnavailable
	}
	return r, f, nil
}
func validAdmissionGrant(f rowEnvelope, id string) bool {
	if f.Lease == nil || (len(f.Lease.ID) != 32 || !policy.Hash(f.Lease.ID+f.Lease.ID)) {
		return false
	}
	until, e := time.Parse(time.RFC3339, f.Lease.Until)
	expires, ee := time.Parse(time.RFC3339, f.Lease.Expires)
	if e != nil || ee != nil || !expires.After(until) || until.Format(time.RFC3339) != f.Lease.Until || expires.Format(time.RFC3339) != f.Lease.Expires {
		return false
	}
	// Synthetic material has a fixed encoded length. Reconstruct only the
	// public response shape/size; this constant is never a real material hash.
	r := wire.LeaseResult{LeaseID: f.Lease.ID, Account: "synthetic-subject", Harness: "codex_cli", Channel: "external-token", Payload: wire.Payload{Channel: "external-token", AccessToken: strings.Repeat("x", 64), AccountID: "synthetic-vendor"}, TokenExpiresAt: f.Lease.Expires, AuthorizedUntil: f.Lease.Until, Renewable: true}
	b, e := wire.Encode(map[string]any{"request_id": id, "result": r})
	want := rowEnvelope{Kind: "lease", RequestID: &id, PayloadBytes: len(b), Lease: f.Lease}
	return e == nil && reflect.DeepEqual(f, want)
}
func decodeAdmissionRelease(b []byte, id, leaseID string) (rowEnvelope, error) {
	var reply struct {
		ID     string             `json:"request_id"`
		Result wire.ReleaseResult `json:"result"`
	}
	if wire.Decode(b, &reply) != nil || reply.ID != id || reply.Result != (wire.ReleaseResult{LeaseID: leaseID, State: "released"}) {
		return rowEnvelope{}, qualification.ErrUnavailable
	}
	return rowEnvelope{Kind: "released", RequestID: &reply.ID, PayloadBytes: len(b), Lease: &rowLease{ID: leaseID}}, nil
}
func validAdmissionRelease(f rowEnvelope, id, leaseID string) bool {
	b, e := wire.Encode(map[string]any{"request_id": id, "result": wire.ReleaseResult{LeaseID: leaseID, State: "released"}})
	want := rowEnvelope{Kind: "released", RequestID: &id, PayloadBytes: len(b), Lease: &rowLease{ID: leaseID}}
	return e == nil && reflect.DeepEqual(f, want)
}
func validAdmissionEnvelopes(o rowObservation, generation uint64) bool {
	n := 2
	if o.ID == "lease-ended" {
		n = 4
		if o.Side == "positive" {
			n = 5
		}
	}
	if len(o.Envelopes) != n || !validRowEnvelope(o.Envelopes[0], o.ID, "positive", generation) {
		return false
	}
	if o.ID != "lease-ended" && o.Side == "negative" {
		return validAdmissionError(o.Envelopes[1], o.ID, "fixture-request")
	}
	grant := o.Envelopes[1]
	if !validAdmissionGrant(grant, "fixture-request") {
		return false
	}
	if o.ID != "lease-ended" {
		return true
	}
	if o.Side == "negative" {
		return validAdmissionRelease(o.Envelopes[2], "fixture-release", grant.Lease.ID) && validAdmissionError(o.Envelopes[3], o.ID, "fixture-renew")
	}
	return validAdmissionGrant(o.Envelopes[2], "fixture-renew") && reflect.DeepEqual(o.Envelopes[2].Lease, grant.Lease) && validAdmissionRelease(o.Envelopes[3], "fixture-release", grant.Lease.ID) && validAdmissionRelease(o.Envelopes[4], "fixture-release-again", grant.Lease.ID)
}

// Only the parent fills counters after joining the worker and server.
type admissionEffects struct {
	QualificationRefused bool   `json:"qualification_refused"`
	StartedAt            string `json:"started_at"`
	Records              int    `json:"records"`
	Snapshots            int    `json:"snapshots"`
	Refreshes            int    `json:"refreshes"`
	StateVerified        bool   `json:"state_verified"`
	FaultEstablished     bool   `json:"fault_established"`
}

func validAdmissionEffects(o rowObservation) bool {
	if !admissionRow(o.ID) {
		return o.Admission == nil
	}
	f := o.Admission
	if f == nil || f.QualificationRefused != (o.ID == "release-unqualified" && o.Side == "negative") || f.Refreshes != 0 || !f.StateVerified || f.FaultEstablished != (o.Side == "negative") {
		return false
	}
	records, calls := 1, 2
	if o.Side == "negative" && o.ID != "lease-ended" {
		records, calls = 0, 0
	}
	if o.Side == "positive" && o.ID == "lease-ended" {
		calls = 4
	}
	if f.Records != records || f.Snapshots != calls {
		return false
	}
	start, e := time.Parse(time.RFC3339Nano, f.StartedAt)
	if e != nil {
		return false
	}
	for _, fact := range o.Envelopes {
		if fact.Kind == "lease" && (fact.Lease == nil || fact.Lease.Until != start.Add(5*time.Second).Truncate(time.Second).Format(time.RFC3339) || fact.Lease.Expires != start.Add(time.Minute).Truncate(time.Second).Format(time.RFC3339)) {
			return false
		}
	}
	return true
}
