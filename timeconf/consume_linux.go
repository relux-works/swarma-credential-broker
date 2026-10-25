//go:build linux

package timeconf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"sync/atomic"
	"time"
)

// ActivationRefusal distinguishes an unavailable/unqualified installed path
// from a rejected time predicate. It remains an ErrUnavailable for old callers.
type ActivationRefusal struct{ Reason string }

func (e *ActivationRefusal) Error() string { return "qualified_time_inactive: " + e.Reason }
func (e *ActivationRefusal) Unwrap() error { return ErrUnavailable }

// ConsumptionRefusal carries fixed codes only, never source output or identities.
type ConsumptionRefusal struct{ Code string }

func (e *ConsumptionRefusal) Error() string { return "qualified_time_refused: " + e.Code }
func (e *ConsumptionRefusal) Unwrap() error { return ErrUnavailable }
func refusal(code string) error             { return &ConsumptionRefusal{code} }

// Enrollment is an already protected binding. Scope.OperationDigest must be
// empty here: each operation supplies its digest without selecting a new store.
// Store is a public enrolled identifier, never the filesystem path.
type Enrollment struct {
	Authority AuthorityFact `json:"authority"`
	Adapter   AdapterFact   `json:"adapter"`
	Policy    PolicyFact    `json:"policy"`
	Scope     ScopeFact     `json:"scope"`
	Store     string        `json:"store"`
}

// ConsumptionRequest must be derived independently from the current operation.
// Deadline is the original caller deadline; collection never renews it. No
// call belongs under a consumer's final issuance/store/journal locks.
type ConsumptionRequest struct {
	Deadline        time.Time
	Expected        Enrollment
	OperationDigest string
	Challenge       string
	JournalFloor    int64
}

// Consumer has a private nonwaiting leaf. It has no stop entry or incident
// callback. Stop dispatch must remain independent in each integrating consumer.
// The zero value, like NewConsumer, refuses activation.
type Consumer struct {
	enrollment Enrollment
	policy     Policy
	store      settlementStore
	timePath   *pathQualification
	clock      Clock
	collector  localCollectorPath
	busy       atomic.Bool
}

// pathQualification has no production constructor. Test-only construction
// exercises settlement; it cannot establish native platform qualification.
type pathQualification struct {
	reserve time.Duration
	budget  time.Duration
	handoff time.Duration
	reboot  bool
}
type localCollection struct {
	evidence  Evidence
	originals [][]byte
	terminal  bool
	drained   bool
}
type localCollectorPath interface {
	collect(context.Context, Policy) (localCollection, error)
}

// NewConsumer selects only the fail-closed witness. It neither creates storage
// nor enrolls, resets or activates a provider. Backend provisioning and complete
// native call/fence qualification remain prerequisites to a production factory.
func NewConsumer(e Enrollment, p Policy, storeRoot string) (*Consumer, error) {
	if e.validate() != nil || p.Validate() != nil || p.Source == Off || !cleanPath(storeRoot) {
		return nil, ErrUnavailable
	}
	expected, err := EffectivePolicyDigest(p, e.Policy.SharedDigest, e.Policy.ServiceDigest)
	if err != nil || expected != e.Policy.EffectiveDigest {
		return nil, ErrUnavailable
	}
	b, _ := canonical(e)
	p.SourceFiles = append([]string(nil), p.SourceFiles...)
	return &Consumer{enrollment: e, policy: p, store: settlementStore{root: storeRoot, binding: sum(b), witness: ClosedWitness{}}, clock: SystemClock{}}, nil
}
func (e Enrollment) validate() error {
	for _, id := range []string{e.Authority.ID, e.Authority.Version, e.Scope.Machine, e.Scope.Consumer, e.Scope.Purpose, e.Scope.ContinuityScope, e.Store} {
		if !idPattern.MatchString(id) {
			return ErrUnavailable
		}
	}
	if len(e.Authority.Version) > 32 || e.Scope.OperationDigest != "" || !revisionPattern.MatchString(e.Adapter.Revision) || e.Adapter.CollectorEntry != "timeconf.CollectorEntry" {
		return ErrUnavailable
	}
	for _, d := range []string{e.Authority.TrustRootDigest, e.Authority.QualificationDigest, e.Adapter.ImageDigest, e.Adapter.ChronycDigest, e.Adapter.ClosureDigest, e.Policy.SharedDigest, e.Policy.EffectiveDigest} {
		if !digestPattern.MatchString(d) {
			return ErrUnavailable
		}
	}
	if e.Policy.ServiceDigest != "none" && !digestPattern.MatchString(e.Policy.ServiceDigest) {
		return ErrUnavailable
	}
	return nil
}

// EffectivePolicyDigest publishes the versioned canonical manifest binding all
// protected policy inputs and the exact applied policy. It is not enrollment.
func EffectivePolicyDigest(p Policy, shared, service string) (string, error) {
	if p.Validate() != nil || !digestPattern.MatchString(shared) || service != "none" && !digestPattern.MatchString(service) {
		return "", ErrUnavailable
	}
	b, e := canonical(struct {
		Version   string `json:"version"`
		Shared    string `json:"shared_digest"`
		Service   string `json:"service_digest"`
		Effective Policy `json:"effective"`
	}{"qualified-time/policy/1", shared, service, p})
	if e != nil {
		return "", ErrUnavailable
	}
	return sum(b), nil
}

// ConsumeBeforePin returns exact retained canonical bytes only after durable
// settlement and terminal/drain evidence. Its deadline covers admission, all
// commands, storage, witness, retention and cleanup. An unresolved worker keeps
// this instance fenced; a later worker result can never turn a timeout into pass.
func (c *Consumer) ConsumeBeforePin(ctx context.Context, r ConsumptionRequest) ([]byte, error) {
	if c == nil || c.timePath == nil {
		return nil, &ActivationRefusal{Reason: "path_unqualified"}
	}
	q := c.timePath
	if q.budget <= 0 || q.budget > 10*time.Second || q.handoff < 0 || q.reserve < q.budget || q.handoff > q.reserve-q.budget || c.collector == nil || c.clock == nil {
		return nil, &ActivationRefusal{Reason: "path_unqualified"}
	}
	if r.Expected != c.enrollment || !digestPattern.MatchString(r.OperationDigest) || !randomPattern.MatchString(r.Challenge) {
		return nil, refusal("binding")
	}
	deadline := r.Deadline
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if d := time.Now().Add(min(q.budget, c.policy.Timeout)); d.Before(deadline) {
		deadline = d
	}
	if deadline.IsZero() || !time.Now().Before(deadline) || ctx.Err() != nil {
		return nil, refusal("deadline")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if !c.busy.CompareAndSwap(false, true) {
		return nil, refusal("busy")
	}
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, err, released := c.consume(ctx, r)
		if released {
			c.busy.Store(false)
		}
		done <- result{raw, err}
	}()
	select {
	case v := <-done:
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, refusal("deadline")
		}
		return v.raw, v.err
	case <-ctx.Done():
		return nil, refusal("deadline")
	}
}
func point(v ClockPoint) (savedClock, error) {
	n := v.Now.UnixNano()
	if !bootValid(v.Boot) || v.Elapsed < 0 || !time.Unix(0, n).Equal(v.Now) {
		return savedClock{}, ErrUnavailable
	}
	return savedClock{v.Boot, ns(n), ns(int64(v.Elapsed)), ns(0)}, nil
}
func stepped(a, b savedClock, p Policy) bool {
	if a.Boot != b.Boot {
		return false
	}
	aw, _ := integer(a.Wall)
	bw, _ := integer(b.Wall)
	am, _ := integer(a.Elapsed)
	bm, _ := integer(b.Elapsed)
	if bm < am {
		return true
	}
	// Exact signed arithmetic also covers observations near int64 boundaries.
	d := new(big.Int).Sub(big.NewInt(bw), big.NewInt(aw))
	d.Sub(d, new(big.Int).Sub(big.NewInt(bm), big.NewInt(am)))
	return d.Cmp(big.NewInt(-int64(p.BackwardTolerance))) < 0 || d.Cmp(big.NewInt(int64(p.StepTolerance))) > 0
}
func (c *Consumer) consume(ctx context.Context, request ConsumptionRequest) ([]byte, error, bool) {
	s, e := c.store.open()
	if e != nil {
		return nil, refusal("store"), false
	}
	defer s.close()
	r, h, e := s.load(ctx)
	if e != nil {
		var inactive *ActivationRefusal
		if errors.As(e, &inactive) {
			return nil, e, false
		}
		return nil, refusal("continuity"), false
	}
	if r.InFlight || r.Held {
		return nil, refusal("held"), true
	}
	// Every prior begin burns its challenge, including refused observations.
	usedIDs := map[string]bool{}
	walk, head := r, h
	for head.Generation > 0 {
		if ctx.Err() != nil {
			return nil, refusal("deadline"), false
		}
		if walk.Facts != nil {
			usedIDs[walk.Facts.Sample.ID] = true
		}
		if walk.Challenge == request.Challenge {
			return nil, refusal("challenge_reused"), true
		}
		head = WitnessHead{head.Generation - 1, walk.Previous}
		walk, e = s.record(head)
		if e != nil {
			return nil, refusal("continuity"), false
		}
	}
	prior := r
	r.InFlight = true
	r.Facts = nil
	r.Originals = nil
	r.Operation = request.OperationDigest
	r.Challenge = request.Challenge
	// No clock read or collector callback precedes this durable marker.
	h, e = s.commit(ctx, h, r)
	if e != nil {
		return nil, refusal("begin"), false
	}
	r.Generation = gen(h.Generation)
	before, be := c.clock.Read(ctx)
	b, bpe := point(before)
	if be != nil || bpe != nil {
		return nil, refusal("clock"), false
	}
	if prior.Last.Boot != b.Boot && !c.timePath.reboot {
		return nil, refusal("boot_unqualified"), false
	}
	observation, ce := c.collector.collect(ctx, c.policy)
	after, ae := c.clock.Read(ctx)
	a, ape := point(after)
	if ae != nil || ape != nil || ctx.Err() != nil || !observation.terminal || !observation.drained {
		return nil, refusal("completion"), false
	}
	r.InFlight = false
	r.Last = a
	r.Last.Reference = prior.Last.Reference
	if stepped(prior.Last, b, c.policy) || stepped(b, a, c.policy) || b.Boot != a.Boot {
		r.Held = true
		r.Hold = a
		pw, _ := integer(prior.Last.Wall)
		bw, _ := integer(b.Wall)
		aw, _ := integer(a.Wall)
		r.Hold.Wall = ns(max(pw, bw, aw))
		r.Hold.Reference = prior.Last.Reference
	}
	code := "evidence"
	trusted := !r.Held && ce == nil && (prior.Last.Boot == a.Boot || c.timePath.reboot) && b.Boot == a.Boot && (&Provider{policy: c.policy}).trackingValid(observation.evidence, after.Now)
	if trusted {
		delta, de := uncertainty(observation.evidence.Tracking, after.Now, c.policy.MaxUncertainty)
		if de == nil && delta <= c.policy.MaxUncertainty-c.timePath.reserve {
			delta += c.timePath.reserve
			until := min(after.Now.Add(c.policy.AuthorityWindow).UnixNano(), observation.evidence.Tracking.Reference.Add(c.policy.MaxSyncAge).UnixNano())
			o := after.Now.UnixNano()
			w, _ := integer(prior.HighWater)
			if o <= math.MaxInt64-int64(delta) && o >= math.MinInt64+int64(delta) && o-int64(delta) > max(w, request.JournalFloor) && o+int64(delta) < until {
				f := Facts{Authority: c.enrollment.Authority, Adapter: c.enrollment.Adapter, Policy: c.enrollment.Policy, Scope: c.enrollment.Scope,
					Sample: SampleFact{Challenge: request.Challenge, Fresh: true}, Clock: ClockFact{a.Boot, "CLOCK_REALTIME/UTC", "CLOCK_BOOTTIME", b.Elapsed, a.Elapsed}, Observed: ns(o), Uncertainty: ns(int64(delta)), AuthorityUntil: ns(until),
					Continuity: ContinuityFact{Store: c.enrollment.Store, PriorHighWater: prior.HighWater, HighWater: ns(o + int64(delta)), JournalFloor: ns(request.JournalFloor), PriorBoot: prior.Last.Boot, Transition: "same-boot"}}
				if a.Boot != prior.Last.Boot {
					f.Continuity.Transition = "qualified-reboot"
				}
				f.Scope.OperationDigest = request.OperationDigest
				f.Sample.ID, e = observationID(rand.Reader, usedIDs)
				if e != nil {
					return nil, refusal("random"), false
				}
				association := "unproven"
				if c.policy.Source == NTSAuthData {
					association = "verified"
				}
				originals := observation.originals
				if len(originals) == 0 || len(originals) > 60 {
					return nil, refusal("originals"), false
				}
				total := 0
				for _, raw := range originals {
					total += len(raw)
					if len(raw) == 0 || len(raw) > 8<<20 || total > (8<<20)-4*receiptLimit {
						return nil, refusal("originals"), false
					}
					if s.retain(ctx, "evidence-", raw, "evidence") != nil {
						return nil, refusal("retention"), false
					}
					r.Originals = append(r.Originals, retainedObject{sum(raw), gen(uint64(len(raw)))})
				}
				manifest, _ := canonical(r.Originals)
				f.Evidence = EvidenceFact{true, c.policy.Source, true, association, ns(observation.evidence.Tracking.Reference.UnixNano()), sum(manifest)}
				r.Last.Reference = f.Evidence.Reference
				r.HighWater = f.Continuity.HighWater
				r.Facts = &f
				code = ""
			} else {
				code = "interval"
			}
		}
	}
	h, e = s.commit(ctx, h, r)
	if e != nil {
		return nil, refusal("settlement"), false
	}
	if code != "" {
		return nil, refusal(code), true
	}
	receipt, e := settledReceipt(r, h)
	if e != nil {
		return nil, refusal("receipt"), false
	}
	raw, e := EncodeReceipt(receipt)
	if e != nil {
		return nil, refusal("receipt"), false
	}
	if s.retain(ctx, "receipt-", raw, "receipt") != nil || ctx.Err() != nil {
		return nil, refusal("retention"), false
	}
	return raw, nil, true
}

func observationID(source io.Reader, used map[string]bool) (string, error) {
	var id [16]byte
	if _, e := io.ReadFull(source, id[:]); e != nil {
		return "", ErrUnavailable
	}
	value := hex.EncodeToString(id[:])
	if used[value] {
		return "", ErrUnavailable
	}
	return value, nil
}
