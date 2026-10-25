//go:build linux && swarma_timeconf_fixture

package timeconf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const fixtureAuthorityID = "timeconf-fixture-only"

var fixtureRootDigest = sum([]byte("qualified-time/fixture-trust-domain/1"))

// FixtureConsumer exercises the unchanged consumption engine under a synthetic
// authority. It never exposes its Consumer, witness or qualification object.
// This entire implementation is excluded from default builds.
type FixtureConsumer struct {
	consumer *Consumer
	clock    fixtureClock
	lost     atomic.Bool
}

type fixtureClock struct {
	mu          sync.Mutex
	point       ClockPoint
	uncertainty time.Duration
	sample      uint64
}

func (c *fixtureClock) Read(ctx context.Context) (ClockPoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.point, ctx.Err()
}
func (c *fixtureClock) collect(ctx context.Context, _ Policy) (localCollection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.point, ctx.Err()
	e := Evidence{Tracking: Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: p.Now.Add(-time.Second), Leap: "Normal", UpdateInterval: 10}, Sources: Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}
	numbers, _ := e.Tracking.numbers()
	numbers[rootDispersion] = durationSeconds(c.uncertainty - time.Second)
	e.Tracking.RootDispersion, _ = numbers[rootDispersion].Float64()
	e.Tracking.exact = &numbers
	return localCollection{e, [][]byte{[]byte("synthetic fixture clock report")}, true, true}, err
}

type taggedFixtureWitness struct {
	mu   sync.Mutex
	head WitnessHead
}

func (w *taggedFixtureWitness) Read(ctx context.Context) (WitnessHead, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, ctx.Err()
}
func (w *taggedFixtureWitness) CompareAndSwap(ctx context.Context, old, next WitnessHead) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil || w.head != old || next.Generation <= old.Generation || next.Generation-old.Generation != 1 {
		return ErrUnavailable
	}
	w.head = next
	return nil
}

// NewFixtureConsumer provisions only an empty protected test-owned directory.
// Its in-memory witness is not a durable backend and cannot qualify production.
func NewFixtureConsumer(root string) (*FixtureConsumer, error) {
	if pathProtected(root, uint32(os.Geteuid())) != nil {
		return nil, ErrUnavailable
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		return nil, ErrUnavailable
	}
	p := Policy{Source: NTSConfig, Chronyc: filepath.Join(root, "collector"), SourceFiles: []string{filepath.Join(root, "source.conf")}, MaxSyncAge: time.Minute, MaxUncertainty: PlatformMaxUncertainty, MaxOffset: time.Millisecond, MaxRootDistance: PlatformMaxRootDistance, AuthorityWindow: 30 * time.Second, StepTolerance: time.Millisecond, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	d := fixtureRootDigest
	e := Enrollment{Authority: AuthorityFact{fixtureAuthorityID, "1", d, d}, Adapter: AdapterFact{strings.Repeat("a", 40), "timeconf.CollectorEntry", d, d, d}, Policy: PolicyFact{d, "none", ""}, Scope: ScopeFact{Machine: "fixture-machine", Consumer: "fixture-consumer", Purpose: "fixture", ContinuityScope: "fixture-clock"}, Store: "fixture-store"}
	e.Policy.EffectiveDigest, _ = EffectivePolicyDigest(p, d, "none")
	c, err := NewConsumer(e, p, root)
	if err != nil {
		return nil, err
	}
	f := &FixtureConsumer{consumer: c}
	f.clock.uncertainty = time.Second
	f.clock.point = ClockPoint{time.Unix(211, 0).UTC(), 211 * time.Second, "11111111-1111-4111-8111-111111111111"}
	w := &taggedFixtureWitness{}
	c.store.witness = w
	c.timePath = &pathQualification{reserve: time.Second, budget: 500 * time.Millisecond, handoff: time.Millisecond, reboot: true}
	c.clock, c.collector = &f.clock, &f.clock
	r := settlement{Version: "qualified-time/settlement/1", Binding: c.store.binding, Generation: "0", Previous: "none", HighWater: "140000000000", Last: savedClock{f.clock.point.Boot, "140000000000", "140000000000", "139000000000"}, Hold: savedClock{Wall: "0", Elapsed: "0", Reference: "0"}}
	b, _ := canonical(r)
	w.head = WitnessHead{0, sum(b)}
	s, err := c.store.open()
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err = s.write(context.Background(), objectName("record-", w.head.RecordDigest), b, "fixture-genesis"); err == nil {
		err = s.write(context.Background(), "current", witnessBytes(w.head), "fixture-pointer")
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (f *FixtureConsumer) Enrollment() Enrollment {
	if f == nil || f.consumer == nil {
		return Enrollment{}
	}
	return f.consumer.enrollment
}
func (f *FixtureConsumer) Policy() Policy {
	if f == nil || f.consumer == nil {
		return Policy{}
	}
	p := f.consumer.policy
	p.SourceFiles = append([]string(nil), p.SourceFiles...)
	return p
}

// Advance moves only the synthetic observation and elapsed clock together.
func (f *FixtureConsumer) Advance(d time.Duration) error {
	if f == nil || f.consumer == nil {
		return &ActivationRefusal{Reason: "fixture_unselected"}
	}
	if d <= 0 || d > time.Hour {
		return ErrUnavailable
	}
	f.clock.mu.Lock()
	defer f.clock.mu.Unlock()
	f.clock.point.Now = f.clock.point.Now.Add(d)
	f.clock.point.Elapsed += d
	return nil
}

// SetNextSample selects O and total uncertainty, including the one-second
// reservation. Each explicit sample uses a distinct qualified synthetic boot:
// backward O can exercise the interval gate without creating a clock-step hold.
// It never changes journal input, settlement, witness, or an existing hold.
func (f *FixtureConsumer) SetNextSample(observed time.Time, delta time.Duration) error {
	if f == nil || f.consumer == nil {
		return &ActivationRefusal{Reason: "fixture_unselected"}
	}
	n := observed.UnixNano()
	if n < 0 || !time.Unix(0, n).Equal(observed) || delta < time.Second || delta > PlatformMaxUncertainty {
		return ErrUnavailable
	}
	f.clock.mu.Lock()
	defer f.clock.mu.Unlock()
	if f.clock.sample == (1<<48)-1 {
		return ErrUnavailable
	}
	f.clock.sample++
	f.clock.point = ClockPoint{observed.UTC(), time.Duration(n), fmt.Sprintf("22222222-2222-4222-8222-%012x", f.clock.sample)}
	f.clock.uncertainty = delta
	return nil
}

// LoseNextReply suppresses one successful reply after real durable settlement.
func (f *FixtureConsumer) LoseNextReply() {
	if f == nil || f.consumer == nil {
		return
	}
	f.lost.Store(true)
}
func (f *FixtureConsumer) ConsumeBeforePin(ctx context.Context, r ConsumptionRequest) ([]byte, error) {
	if f == nil || f.consumer == nil {
		return nil, &ActivationRefusal{Reason: "fixture_unselected"}
	}
	b, err := f.consumer.ConsumeBeforePin(ctx, r)
	if err == nil && f.lost.Swap(false) {
		return nil, refusal("fixture_reply_lost")
	}
	return b, err
}
func (f *FixtureConsumer) HighWater() (Nanoseconds, error) {
	if f == nil || f.consumer == nil {
		return "", &ActivationRefusal{Reason: "fixture_unselected"}
	}
	s, err := f.consumer.store.open()
	if err != nil {
		return "", err
	}
	defer s.close()
	r, _, err := s.load(context.Background())
	return r.HighWater, err
}

// VerifyFixtureReceipt checks only the real codec and exact fixture enrollment.
// It is not an authenticator, retained-original validator or one-use handoff.
func VerifyFixtureReceipt(raw []byte, expected Enrollment) (Receipt, error) {
	r, err := DecodeReceipt(raw)
	if err != nil {
		return Receipt{}, err
	}
	f := r.Facts
	scope := f.Scope
	scope.OperationDigest = ""
	got := Enrollment{f.Authority, f.Adapter, f.Policy, scope, f.Continuity.Store}
	if expected.Authority.ID != fixtureAuthorityID || expected.Authority.TrustRootDigest != fixtureRootDigest || got != expected {
		return Receipt{}, refusal("fixture_binding")
	}
	return r, nil
}
