//go:build linux

package timeconf

import (
	"context"
	"time"
)

// OriginalRequest holds independently retained expectations, never values chosen
// by the bytes being loaded. Deadline is the enclosing operation's original
// deadline; Checkpoint comes from a fresh authenticated RollbackWitness.Read.
// Expected.Scope.OperationDigest remains empty, as in ConsumptionRequest.
type OriginalRequest struct {
	Deadline        time.Time
	Expected        Enrollment
	OperationDigest string
	Challenge       string
	Boot            string
	ReceiptDigest   string
	Checkpoint      WitnessHead
}

// RetainedOriginal is an exact owning-codec object. Bytes is a caller-owned copy,
// Size is its exact byte length, and Digest binds all those bytes. These exported
// values are data, not provenance capabilities or authentication proofs.
type RetainedOriginal struct {
	Digest string
	Size   uint64
	Bytes  []byte
}

// OriginalDescriptor identifies the protected descriptor actually checked for
// an object, including the receipt. Digest associates it with exact copied
// bytes. These Linux stat identities are audit data, never authority by value;
// the qualified reader retains the live custody/invalidation guard separately.
type OriginalDescriptor struct {
	Digest string
	Device uint64
	Inode  uint64
	Owner  uint32
	Mode   uint32
}

// OriginalProvenance records the installed reader qualification, exact enrolled
// validator closure and checked descriptor identities. Digests must match
// independently protected installation, not select a validator from the bundle.
// Descriptors is a disjoint owned copy with one entry per closure object.
type OriginalProvenance struct {
	ReaderQualificationDigest string
	ValidatorDigest           string
	Descriptors               []OriginalDescriptor
}

// OriginalBundle contains the exact receipt and its complete bounded original
// closure, including settlement ancestry and source evidence. Objects excludes
// the receipt itself. Checkpoint must equal the independently requested head.
// All byte slices must be disjoint owned copies, with no lazy reads or alias to
// backend/caller storage. No wire representation is defined by these types.
type OriginalBundle struct {
	Receipt    []byte
	Objects    []RetainedOriginal
	Checkpoint WitnessHead
	Provenance OriginalProvenance
}

// OriginalReader is a future protected retained-original reader/validator. It
// runs before terminal consumer time-use locks and within the original deadline.
// Permitted outer exclusions may remain held as specified by the consumer; see
// docs/time-contract.md, Final issuance, enrollment and registration windows.
// A qualified implementation authenticates descriptor ownership, path/executable
// provenance, protected enrollment and codec/validator versions; validates exact
// receipt bindings, original source/record bytes, settlement acknowledgment and
// complete ancestry against the independently current Checkpoint; and returns
// only a complete owned snapshot. The entire closure, including receipt and
// witness material, is limited to 64 objects, 8 MiB total and depth 16, without
// cycles; the receipt is at most 65536 bytes. Excessive ancestry or originals
// must refuse with no bundle; never truncate the closure to fit. Backend-specific
// witness material requires its own reviewed closed validator, not a hash or
// placeholder proof.
//
// Missing, substituted, restored, held, in-flight or unauthenticated material
// must return no bundle and a ConsumptionRefusal (originals, binding, continuity
// or deadline). Unavailable provenance/validator/platform qualification returns
// ActivationRefusal{Reason:"originals_unavailable"}. Both wrap ErrUnavailable;
// error strings must not include source bytes, paths or identities. A nil error
// is permitted only after all validations and original-deadline completion.
//
// Installation and continuing authority/retention invalidation must be qualified
// separately. Implementing this interface or constructing OriginalBundle grants
// no authority and activates no path. See docs/time-handoff.md for custody and
// currentness obligations. This exported interface may be implemented by callers;
// ClosedOriginalReader is its only shipped implementation, and no production
// code accepts or consumes an injected OriginalReader.
type OriginalReader interface {
	ReadOriginals(context.Context, OriginalRequest) (OriginalBundle, error)
}

// ClosedOriginalReader is the only shipped original-reader implementation. Its
// zero value refuses without reading storage, clocks, callbacks or credentials.
type ClosedOriginalReader struct{}

func (ClosedOriginalReader) ReadOriginals(context.Context, OriginalRequest) (OriginalBundle, error) {
	return OriginalBundle{}, &ActivationRefusal{Reason: "originals_unavailable"}
}

var _ OriginalReader = ClosedOriginalReader{}
