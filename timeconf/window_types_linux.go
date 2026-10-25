//go:build linux

package timeconf

// WindowExpected comes from protected original intent and installed enrollment,
// never from a decoded envelope. Native stricter capture/H retention rules win.
// Operation binds every protected native field through the owning codec without
// provider-wire additions. These structs neither prove admission nor select
// current state; the admitted owning transaction retains the full native read set.
type WindowExpected struct {
	Enrollment        Enrollment
	Operation         string
	Challenge         string
	Run               string // Private per-attempt nonce bound to preparation.
	Epoch             string // Independently enrolled live-writer/instance fence.
	Window            WindowIdentity
	TransitionVersion string
	Deadline          HandoffDeadline
	Budget            HandoffBudget
	JournalFloorNS    int64
	UncertaintyCapNS  int64
}

// LockedWindowState is independently selected before m under every initial
// persistence/use exclusion. These data are not self-authenticating claims;
// only the consumer's qualified currentness/custody protocol can supply them.
type LockedWindowState struct {
	Intent WindowExpected
	// Revision is the uint64 generation of unused v, never a cast/truncation of
	// a composite native StateID. Bind the exact predecessor and protected read
	// set in Intent.Operation, re-derived under admission before m; retain both
	// for the owning transaction's atomic full-predecessor and unused-v CAS.
	Revision Generation
	Epoch    string
	Unused   bool
	Current  bool
	FloorNS  int64
	ExpiryNS int64
}

// FinalCapture is one local suspend-aware read passed as data, outside the check.
// It is never a receipt timestamp or a callback. Clock names include their domain.
type FinalCapture struct {
	Boot, Clock string
	NS          int64
}

// UseKey deliberately excludes H, run, challenge and native format version.
// Operation binds exact
// native owner/arguments; profile/sequence map the authorized phase/action/slot.
type UseKey struct {
	Consumer, Store, Operation string
	Window                     WindowIdentity
}

// WindowCandidate is inert data for a serialized owning transition. Copies do
// not authorize duplicate acts. Discard it on lock release or epoch invalidation.
type WindowCandidate struct {
	key               UseKey
	commitment        string
	revision          Generation
	epoch             string
	transitionVersion string
	run               string
}

func (c WindowCandidate) TransitionVersion() string { return c.transitionVersion }

func (c WindowCandidate) Use() (UseKey, string, Generation, string) {
	return c.key, c.commitment, c.revision, c.epoch
}

// ConsumeIfUnused belongs to the consumer's reviewed native transition version.
// Implementations compare exact revision/current logical key/live epoch/unused
// together under retained serialization. Every H for a burned key refuses.
// Ambiguous persistence means no act; lost replies never authorize redispatch.
// The burn-before-Act ordering describes separable effects. A native atomic
// act/use profile supplies its own admitted transaction implementation and
// commits the use state atomically with the act. It compares full predecessor,
// unused v, H and exact outcome together, not via an independently committing
// reference burn and Act. Recovery is a native outcome/status path, never a new
// successful consume or dispatch grant. No production adapter is supplied.
type ConsumeIfUnused interface {
	ConsumeIfUnused(WindowCandidate, LockedWindowState, ActProtocol) error
}

// ActProtocol describes a separable authoritative effect, not a callback used by
// VerifyWindow. A consumer must durably burn before Act, enforce live epoch and
// original deadline through completion, and retain outcome/cleanup under its own
// transaction. Atomic act/use profiles own their admitted atomic implementation.
type ActProtocol interface{ Act() error }
