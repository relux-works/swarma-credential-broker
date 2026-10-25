//go:build linux && swarma_timeconf_fixture

package timeconf

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// NewFixtureHandoffProvider selects only the synthetic fixture trust domain.
// Its 500 ms original reserve plus 500 ms source uncertainty match the published
// arithmetic controls. Neither the in-memory witness nor these bounds qualify a
// production provider, native act, original reader or retention mechanism.
func NewFixtureHandoffProvider(root string) (*FixtureConsumer, error) {
	f, err := NewFixtureConsumer(root)
	if err != nil {
		return nil, err
	}
	f.consumer.timePath = &pathQualification{reserve: 500 * time.Millisecond, budget: 300 * time.Millisecond, handoff: time.Millisecond, reboot: true}
	f.clock.uncertainty = 1500 * time.Millisecond
	return f, nil
}

// SetHandoffSample retains the same source/reserve assumptions as construction.
func (f *FixtureConsumer) SetHandoffSample(o time.Time) error {
	if f == nil || f.consumer == nil || f.consumer.timePath.reserve != 500*time.Millisecond {
		return &ActivationRefusal{Reason: "fixture_unselected"}
	}
	return f.SetNextSample(o, 1500*time.Millisecond)
}

// FixtureHandoff exposes independent mutable test copies. Prepared's immutable
// private anchor never aliases Raw, Originals, Expected or their decoded data.
type FixtureHandoff struct {
	Raw       []byte
	Originals [][]byte
	Prepared  PreparedHandoff
	Expected  WindowExpected
	Local     LockedWindowState
	Capture   FinalCapture
}

// CollectHandoff uses real fixture settlement and loads its complete bounded
// history. Caller-selected IDs are deterministic test identities, not randomness
// or a production preparation API. The placeholder is never authenticated:
// only this tagged synthetic trust domain bypasses backend authentication.
func (f *FixtureConsumer) CollectHandoff(ctx context.Context, r ConsumptionRequest, window WindowIdentity, run, id string) (FixtureHandoff, error) {
	if f == nil || f.consumer == nil || f.consumer.timePath.reserve != 500*time.Millisecond {
		return FixtureHandoff{}, &ActivationRefusal{Reason: "fixture_unselected"}
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	raw, err := f.ConsumeBeforePin(ctx, r)
	if err != nil {
		return FixtureHandoff{}, err
	}
	receipt, err := VerifyFixtureReceipt(raw, f.Enrollment())
	if err != nil {
		return FixtureHandoff{}, err
	}
	s, err := f.consumer.store.open()
	if err != nil {
		return FixtureHandoff{}, err
	}
	defer s.close()
	head, err := s.witness.Read(ctx)
	if err != nil {
		return FixtureHandoff{}, handoffRefusal("continuity")
	}
	record, err := s.record(head)
	if err != nil {
		return FixtureHandoff{}, handoffRefusal("continuity")
	}
	stored, err := s.read(objectName("record-", head.RecordDigest), handoffClosureLimit)
	if err != nil {
		return FixtureHandoff{}, err
	}
	manifest, _ := canonical(record.Originals)
	witness, _ := canonical(WitnessMaterial{WitnessPlaceholderVersion})
	originals := [][]byte{raw, stored, manifest, witness}
	roles := []string{"receipt", "settlement", "evidence-manifest", "witness"}
	seen := map[string]bool{}
	total := 0
	for _, b := range originals {
		seen[sum(b)] = true
		total += len(b)
	}
	add := func(role string, b []byte) error {
		if seen[sum(b)] {
			return nil
		}
		if len(originals) >= 63 || len(b) > handoffClosureLimit || total > handoffClosureLimit-len(b) {
			return handoffRefusal("limit")
		}
		originals = append(originals, b)
		roles = append(roles, role)
		seen[sum(b)] = true
		total += len(b)
		return nil
	}
	walk, g := record, head.Generation
	for depth := 0; ; depth++ {
		if depth >= 16 || ctx.Err() != nil {
			return FixtureHandoff{}, handoffRefusal("limit")
		}
		for _, ref := range walk.Originals {
			n, e := generation(ref.Size)
			if e != nil || n > handoffClosureLimit {
				return FixtureHandoff{}, handoffRefusal("limit")
			}
			if seen[ref.Digest] {
				continue
			}
			if len(originals) >= 63 || n > uint64(handoffClosureLimit-total) {
				return FixtureHandoff{}, handoffRefusal("limit")
			}
			b, e := s.read(objectName("evidence-", ref.Digest), int(n))
			if e != nil {
				return FixtureHandoff{}, handoffRefusal("original_missing")
			}
			role := "history-source"
			if g == head.Generation {
				role = "source"
			}
			if e = add(role, b); e != nil {
				return FixtureHandoff{}, e
			}
		}
		if g == 0 {
			break
		}
		if depth == 15 || len(originals) >= 63 {
			return FixtureHandoff{}, handoffRefusal("limit")
		}
		previous := walk.Previous
		b, e := s.read(objectName("record-", previous), handoffClosureLimit-total)
		if e != nil {
			return FixtureHandoff{}, handoffRefusal("continuity")
		}
		if e = add("history-settlement", b); e != nil {
			return FixtureHandoff{}, e
		}
		g--
		walk, e = s.record(WitnessHead{g, previous})
		if e != nil {
			return FixtureHandoff{}, handoffRefusal("continuity")
		}
		if walk.Facts != nil {
			rr, e := settledReceipt(walk, WitnessHead{g, previous})
			if e != nil {
				return FixtureHandoff{}, e
			}
			bb, _ := EncodeReceipt(rr)
			if len(originals) >= 63 || len(bb) > handoffClosureLimit-total {
				return FixtureHandoff{}, handoffRefusal("limit")
			}
			retained, e := s.read(objectName("receipt-", sum(bb)), receiptLimit)
			if e != nil || !bytes.Equal(retained, bb) {
				return FixtureHandoff{}, handoffRefusal("original_missing")
			}
			if e = add("history-receipt", retained); e != nil {
				return FixtureHandoff{}, e
			}
		}
	}
	refs := make([]HandoffObject, len(originals))
	for i, b := range originals {
		refs[i] = HandoffObject{roles[i], sum(b), gen(uint64(len(b)))}
	}
	sample, _ := integer(receipt.Facts.Clock.ObservedNS)
	digest := fixtureRootDigest
	deadline := HandoffDeadline{receipt.Facts.Clock.Boot, "CLOCK_BOOTTIME", ns(sample), ns(sample + 250000000), ns(r.Deadline.UnixNano()), "250000000", digest}
	budget := HandoffBudget{digest, "300000000", "20000000", "1000000", "500000000"}
	refbytes, _ := canonical(refs)
	meta := HandoffMetadata{HandoffProfile, id, run, window, "fixture-use:1", deadline, budget, HandoffReference{sum(raw), gen(uint64(len(raw)))}, sum(refbytes), digest, WitnessMaterial{WitnessPlaceholderVersion}}
	h := Handoff{HandoffVersion, receipt, meta, refs}
	encoded, err := EncodeHandoff(h)
	if err != nil {
		return FixtureHandoff{}, err
	}
	expected := WindowExpected{
		Enrollment: f.Enrollment(), Operation: r.OperationDigest, Challenge: r.Challenge,
		Run: run, Epoch: "writer:deployment-7:epoch-42", Window: window,
		TransitionVersion: meta.TransitionVersion, Deadline: deadline, Budget: budget,
		JournalFloorNS: r.JournalFloor, UncertaintyCapNS: int64(PlatformMaxUncertainty),
	}
	p, err := PrepareFixtureHandoff(encoded, originals, expected, sample+100000000)
	if err != nil {
		return FixtureHandoff{}, err
	}
	local := LockedWindowState{expected, "0", expected.Epoch, true, true, r.JournalFloor, 300000000000}
	if ctx.Err() != nil {
		return FixtureHandoff{}, handoffRefusal("deadline")
	}
	return FixtureHandoff{encoded, originals, p, expected, local, FinalCapture{deadline.Boot, deadline.Clock, sample + 110000000}}, nil
}

// PrepareFixtureHandoff authenticates only the selected public synthetic root.
// It exercises exact reconstruction but never treats the witness placeholder as
// production proof. Unknown/missing originals and nonfixture enrollment refuse.
func PrepareFixtureHandoff(raw []byte, originals [][]byte, e WindowExpected, p int64) (PreparedHandoff, error) {
	if e.Enrollment.Authority.ID != fixtureAuthorityID || e.Enrollment.Authority.TrustRootDigest != fixtureRootDigest {
		return PreparedHandoff{}, &ActivationRefusal{Reason: "fixture_unselected"}
	}
	h, err := DecodeHandoff(raw)
	if err != nil {
		return PreparedHandoff{}, err
	}
	if err = CheckHandoffOriginals(h, originals); err != nil {
		return PreparedHandoff{}, err
	}
	if _, err = VerifyFixtureReceipt(originals[0], e.Enrollment); err != nil {
		return PreparedHandoff{}, handoffRefusal("consumer")
	}
	m := h.Handoff
	if e.Operation != h.Receipt.Facts.Scope.OperationDigest {
		return PreparedHandoff{}, handoffRefusal("operation")
	}
	if e.Challenge != h.Receipt.Facts.Sample.Challenge || e.Run != m.ConsumerRun || e.Window != m.Window || e.TransitionVersion != m.TransitionVersion {
		return PreparedHandoff{}, handoffRefusal("binding")
	}
	if e.Deadline != m.Deadline || e.Budget != m.Budget || e.Deadline.Boot != h.Receipt.Facts.Clock.Boot {
		return PreparedHandoff{}, handoffRefusal("deadline_binding")
	}
	commitment, _ := HandoffCommitment(raw)
	// Count public fixture copies plus private immutable copies before copying.
	total := 3 * len(raw)
	for _, b := range originals {
		total += 2 * len(b)
		if total > handoffClosureLimit {
			return PreparedHandoff{}, handoffRefusal("limit")
		}
	}
	owned := make([]string, len(originals))
	for i, b := range originals {
		owned[i] = string(b)
	}
	return PreparedHandoff{&handoffAnchor{m, h.Receipt.Facts, commitment, e, p, owned}}, nil
}

// ReferenceUseStore is test-only serialized memory, not durable/rollback-safe
// storage. This separable-effect model stores only a generation, not H or
// outcomes, and has no native status recovery. Faults model only the documented
// reference cuts; they do not qualify a native atomic act/use protocol.
type ReferenceUseStore struct {
	mu            sync.Mutex
	entries       map[UseKey]Generation
	unused        map[UseKey]Generation
	current       string
	unknown       bool
	AmbiguousBurn bool
	LoseReply     bool
	Events        []string
}

// Genesis names the originally authorized slots before checking, never from H.
func NewReferenceUseStore(epoch string, windows ...UseKey) *ReferenceUseStore {
	s := &ReferenceUseStore{entries: map[UseKey]Generation{}, unused: map[UseKey]Generation{}, current: epoch}
	for _, key := range windows {
		s.unused[key] = "0"
	}
	return s
}
func (s *ReferenceUseStore) Fence(epoch string) { s.mu.Lock(); defer s.mu.Unlock(); s.current = epoch }
func (s *ReferenceUseStore) ConsumeIfUnused(c WindowCandidate, local LockedWindowState, act ActProtocol) error {
	if s == nil {
		return handoffRefusal("continuity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumeLocked(c, local, act)
}

func (s *ReferenceUseStore) consumeLocked(c WindowCandidate, local LockedWindowState, act ActProtocol) error {
	key, h, revision, epoch := c.Use()
	if s.entries == nil || s.unknown || !local.Current {
		return handoffRefusal("continuity")
	}
	if h == "" || c.run != local.Intent.Run {
		return handoffRefusal("run")
	}
	if epoch == "" || epoch != s.current || epoch != local.Epoch || local.Intent.Epoch != epoch {
		return handoffRefusal("epoch")
	}
	want := UseKey{local.Intent.Enrollment.Scope.Consumer, local.Intent.Enrollment.Store, local.Intent.Operation, local.Intent.Window}
	if key != want || c.TransitionVersion() != local.Intent.TransitionVersion {
		return handoffRefusal("binding")
	}
	if _, burned := s.entries[key]; burned || !local.Unused || revision != local.Revision {
		return handoffRefusal("replay")
	}
	if want, known := s.unused[key]; !known || want != revision {
		return handoffRefusal("continuity")
	}
	if act == nil {
		return handoffRefusal("binding")
	}
	s.entries[key] = revision
	delete(s.unused, key)
	s.Events = append(s.Events, "burn")
	if s.AmbiguousBurn {
		s.unknown = true
		return handoffRefusal("continuity")
	}
	s.Events = append(s.Events, "act")
	if err := act.Act(); err != nil {
		return err
	}
	s.Events = append(s.Events, "committed")
	if s.LoseReply {
		return handoffRefusal("reply_lost")
	}
	return nil
}

var _ ConsumeIfUnused = (*ReferenceUseStore)(nil)

// ReferenceAdmission retains the initial map exclusion through read/check/use.
// One owning goroutine releases it. It models no native deadline or durability.
type ReferenceAdmission struct {
	store  *ReferenceUseStore
	local  LockedWindowState
	active bool
}

func (s *ReferenceUseStore) Admit(local LockedWindowState) (*ReferenceAdmission, error) {
	if s == nil {
		return nil, handoffRefusal("continuity")
	}
	s.mu.Lock()
	key := UseKey{local.Intent.Enrollment.Scope.Consumer, local.Intent.Enrollment.Store, local.Intent.Operation, local.Intent.Window}
	revision, known := s.unused[key]
	if !known || s.unknown || !local.Current || !local.Unused || revision != local.Revision {
		s.mu.Unlock()
		return nil, handoffRefusal("continuity")
	}
	if local.Epoch == "" || s.current != local.Epoch || local.Intent.Epoch != local.Epoch {
		s.mu.Unlock()
		return nil, handoffRefusal("epoch")
	}
	return &ReferenceAdmission{s, local, true}, nil
}
func (a *ReferenceAdmission) Release() {
	if a != nil && a.active {
		a.active = false
		a.store.mu.Unlock()
	}
}
func (a *ReferenceAdmission) ConsumeIfUnused(c WindowCandidate, local LockedWindowState, act ActProtocol) error {
	if a == nil || !a.active || a.store == nil || local != a.local {
		return handoffRefusal("binding")
	}
	return a.store.consumeLocked(c, local, act)
}
