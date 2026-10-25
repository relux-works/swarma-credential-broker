//go:build linux

package timeconf

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This witness is deliberately compiled only into tests. Keeping its head
// outside the checkpoint tree models an independent restore domain, not a
// qualified production backend or durability guarantee.
type fixtureWitness struct {
	mu          sync.Mutex
	head        WitnessHead
	unavailable bool
	beforeCAS   func(WitnessHead) error
	afterCAS    func(WitnessHead) error
}

func (w *fixtureWitness) Read(ctx context.Context) (WitnessHead, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil || w.unavailable {
		return WitnessHead{}, ErrUnavailable
	}
	return w.head, nil
}
func (w *fixtureWitness) CompareAndSwap(ctx context.Context, old, next WitnessHead) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil || w.unavailable || w.head != old || old.Generation == math.MaxUint64 || next.Generation != old.Generation+1 || !digestPattern.MatchString(next.RecordDigest) {
		return ErrUnavailable
	}
	if w.beforeCAS != nil {
		if e := w.beforeCAS(next); e != nil {
			return e
		}
	}
	w.head = next
	if w.afterCAS != nil {
		return w.afterCAS(next)
	}
	return nil
}

type fixtureLocal struct {
	collectFn func(context.Context, Policy) (localCollection, error)
}

func (f fixtureLocal) collect(ctx context.Context, p Policy) (localCollection, error) {
	return f.collectFn(ctx, p)
}

type settlementFixture struct {
	consumer   *Consumer
	witness    *fixtureWitness
	enrollment Enrollment
	policy     Policy
	root       string
	now        time.Time
	boot       string
	collection localCollection
	collectErr error
	collected  int
	before     ClockPoint
	after      ClockPoint
	readCount  int
}

const fixtureBoot = "11111111-1111-4111-8111-111111111111"
const secondBoot = "22222222-2222-4222-8222-222222222222"

func newSettlementFixture(t *testing.T) *settlementFixture {
	t.Helper()
	f := &settlementFixture{root: protectedTemp(t), now: time.Unix(211, 0).UTC(), boot: fixtureBoot}
	f.policy = testPolicy()
	f.policy.MaxUncertainty = PlatformMaxUncertainty
	f.policy.Timeout = time.Second
	d := sum([]byte("fixture-enrollment"))
	f.enrollment = Enrollment{Authority: AuthorityFact{"time-owner", "1", d, d}, Adapter: AdapterFact{strings.Repeat("a", 40), "timeconf.CollectorEntry", d, d, d}, Policy: PolicyFact{d, "none", ""}, Scope: ScopeFact{Machine: "machine", Consumer: "consumer", Purpose: "test", ContinuityScope: "clock", OperationDigest: ""}, Store: "continuity"}
	f.enrollment.Policy.EffectiveDigest, _ = EffectivePolicyDigest(f.policy, d, "none")
	c, e := NewConsumer(f.enrollment, f.policy, f.root)
	if e != nil {
		t.Fatal(e)
	}
	f.consumer = c
	f.witness = &fixtureWitness{}
	c.store.witness = f.witness
	c.timePath = &pathQualification{reserve: time.Second, budget: 500 * time.Millisecond, handoff: time.Millisecond, reboot: true}
	c.clock = f
	c.collector = fixtureLocal{func(context.Context, Policy) (localCollection, error) {
		f.collected++
		return f.collection, f.collectErr
	}}
	f.setTime(211, fixtureBoot)
	f.seed(t, 140, 140, fixtureBoot)
	return f
}
func (f *settlementFixture) Read(context.Context) (ClockPoint, error) {
	f.readCount++
	if f.readCount%2 == 1 {
		return f.before, nil
	}
	return f.after, nil
}
func (f *settlementFixture) setTime(seconds int64, boot string) {
	f.now = time.Unix(seconds, 0).UTC()
	f.boot = boot
	f.before = ClockPoint{f.now, time.Duration(seconds) * time.Second, boot}
	f.after = f.before
	e := evidenceAt(f.now)
	e.Tracking.SystemOffset = 0
	e.Tracking.LastOffset = 0
	e.Tracking.RMSOffset = 0
	e.Tracking.RootDelay = 0
	e.Tracking.RootDispersion = 0
	e.Tracking.Skew = 0
	f.collection = localCollection{evidence: e, originals: [][]byte{[]byte("fixture original source report")}, terminal: true, drained: true}
}
func (f *settlementFixture) seed(t *testing.T, w, wall int64, boot string) {
	t.Helper()
	r := settlement{Version: "qualified-time/settlement/1", Binding: f.consumer.store.binding, Generation: "0", Previous: "none", HighWater: ns(w * int64(time.Second)), Last: savedClock{boot, ns(wall * int64(time.Second)), ns(wall * int64(time.Second)), ns((wall - 1) * int64(time.Second))}, Hold: savedClock{Wall: "0", Elapsed: "0", Reference: "0"}}
	b, _ := canonical(r)
	h := WitnessHead{0, sum(b)}
	if e := os.WriteFile(filepath.Join(f.root, objectName("record-", h.RecordDigest)), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(f.root, "current"), witnessBytes(h), 0600); e != nil {
		t.Fatal(e)
	}
	f.witness.head = h
}
func (f *settlementFixture) request(challenge string) ConsumptionRequest {
	return ConsumptionRequest{Deadline: time.Now().Add(400 * time.Millisecond), Expected: f.enrollment, OperationDigest: sum([]byte("operation")), Challenge: challenge, JournalFloor: 140 * int64(time.Second)}
}
func (f *settlementFixture) call(challenge string) ([]byte, error) {
	return f.consumer.ConsumeBeforePin(context.Background(), f.request(challenge))
}
func fixturePass(t *testing.T, f *settlementFixture, challenge string) Receipt {
	t.Helper()
	raw, e := f.call(challenge)
	if e != nil {
		t.Fatal("fixture path refused", e)
	}
	r, e := DecodeReceipt(raw)
	if e != nil {
		t.Fatal("invalid returned receipt", e)
	}
	return r
}
func requireRefusal(t *testing.T, raw []byte, e error) {
	t.Helper()
	if !errors.Is(e, ErrUnavailable) || len(raw) != 0 {
		t.Fatal("expected refusal with no receipt", e)
	}
}
func currentSettlement(t *testing.T, f *settlementFixture) (settlement, WitnessHead) {
	t.Helper()
	s, e := f.consumer.store.open()
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	r, h, e := s.load(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return r, h
}
func restartFixture(f *settlementFixture) {
	c := &Consumer{enrollment: f.enrollment, policy: f.policy, store: f.consumer.store, timePath: f.consumer.timePath, clock: f, collector: f.consumer.collector}
	f.consumer = c
}

// Claim: the fixture admits a fresh bound receipt; a failed later operation
// cannot undo U=201 even with an unchanged consumer floor of 140. Reboot keeps W.
func TestSettlementConsumedBoundAfterFailure(t *testing.T) {
	f := newSettlementFixture(t)
	f.setTime(200, fixtureBoot)
	first := fixturePass(t, f, strings.Repeat("1", 32))
	if first.Facts.Continuity.HighWater != "201000000000" || first.Facts.Continuity.PriorHighWater != "140000000000" {
		t.Fatal("wrong consumed bounds")
	}
	r, _ := currentSettlement(t, f)
	if r.Operation != sum([]byte("operation")) || r.Challenge != strings.Repeat("1", 32) || r.Facts.Sample.ID != first.Facts.Sample.ID {
		t.Fatal("association not retained")
	}
	restartFixture(f)
	f.setTime(171, secondBoot)
	raw, e := f.call(strings.Repeat("2", 32))
	requireRefusal(t, raw, e)
	r, _ = currentSettlement(t, f)
	if r.HighWater != "201000000000" || r.Held {
		t.Fatal("refused interval changed consumed bound or invented a step across boots")
	}
	f.setTime(211, secondBoot)
	next := fixturePass(t, f, strings.Repeat("3", 32))
	if next.Facts.Continuity.PriorHighWater != "201000000000" || next.Facts.Continuity.HighWater != "212000000000" {
		t.Fatal("history lost across failed operation")
	}
}

// Claim: equality to either provider W or imported J refuses; one nanosecond
// above that same floor passes. The receipt codec independently rejects equality.
func TestSettlementStrictFloor(t *testing.T) {
	for _, floor := range []string{"provider", "journal"} {
		t.Run(floor, func(t *testing.T) {
			f := newSettlementFixture(t)
			f.seed(t, 200, 140, fixtureBoot)
			f.setTime(201, fixtureBoot)
			if floor == "journal" {
				f.setTime(211, fixtureBoot)
			}
			request := f.request(strings.Repeat("4", 32))
			if floor == "journal" {
				request.JournalFloor = 210 * int64(time.Second)
			}
			raw, e := f.consumer.ConsumeBeforePin(context.Background(), request)
			requireRefusal(t, raw, e)
			request.Challenge = strings.Repeat("5", 32)
			request.Deadline = time.Now().Add(400 * time.Millisecond)
			f.before.Now = f.before.Now.Add(time.Nanosecond)
			f.before.Elapsed++
			f.after = f.before
			raw, e = f.consumer.ConsumeBeforePin(context.Background(), request)
			if e != nil {
				t.Fatal("strict positive control refused", e)
			}
			if _, e = DecodeReceipt(raw); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Claim: collection sees the independently committed in-flight marker before
// any source is queried. Recovery of that prefix is held, not an empty baseline.
func TestSettlementBeginPrecedesCollection(t *testing.T) {
	f := newSettlementFixture(t)
	events := []string{}
	f.consumer.store.syncFault = func(point string) error { events = append(events, point); return nil }
	f.witness.beforeCAS = func(next WitnessHead) error {
		if next.Generation == 1 {
			if strings.Join(events, ",") != "record-file,record-directory" {
				t.Error("witness begin preceded durable record file/directory", events)
			}
			events = append(events, "begin-cas")
		}
		return nil
	}
	f.consumer.collector = fixtureLocal{func(ctx context.Context, _ Policy) (localCollection, error) {
		if strings.Join(events, ",") != "record-file,record-directory,begin-cas,pointer-file,pointer-directory,current-directory" {
			t.Error("collection preceded complete begin publication", events)
		}
		h, e := f.witness.Read(ctx)
		if e != nil || h.Generation != 1 {
			t.Error("collection began without durable witness begin")
		}
		b, e := os.ReadFile(filepath.Join(f.root, objectName("record-", h.RecordDigest)))
		var r settlement
		if e != nil || strictRecord(b, &r, receiptLimit) != nil || !r.InFlight {
			t.Error("collection began without durable in-flight record")
		}
		return f.collection, nil
	}}
	fixturePass(t, f, strings.Repeat("6", 32))
}

// Claim: missing provider history refuses without writing or consulting a
// collector, even when the imported consumer journal remains intact.
func TestSettlementMissingNeverReset(t *testing.T) {
	for _, missing := range []string{"current", "record", "witness"} {
		t.Run(missing, func(t *testing.T) {
			f := newSettlementFixture(t)
			if missing == "witness" {
				f.witness.unavailable = true
			} else {
				name := "current"
				if missing == "record" {
					name = objectName("record-", f.witness.head.RecordDigest)
				}
				if e := os.Remove(filepath.Join(f.root, name)); e != nil {
					t.Fatal(e)
				}
			}
			before, _ := os.ReadDir(f.root)
			raw, e := f.call(strings.Repeat("7", 32))
			requireRefusal(t, raw, e)
			after, _ := os.ReadDir(f.root)
			if f.collected != 0 || len(before) != len(after) {
				t.Fatal("missing history was reset or collected against")
			}
		})
	}
}

// Claim: a restored coherent old checkpoint mismatches the independent witness.
// Permission/corruption/link ambiguity refuses without changing either head.
func TestSettlementUntrustedStore(t *testing.T) {
	for _, defect := range []string{"rollback", "corrupt", "unreadable", "special-mode", "hardlink", "symlink", "directory-mode", "missing-original", "missing-receipt"} {
		t.Run(defect, func(t *testing.T) {
			f := newSettlementFixture(t)
			old, _ := os.ReadFile(filepath.Join(f.root, "current"))
			receipt := fixturePass(t, f, strings.Repeat("8", 32))
			h := f.witness.head
			current := filepath.Join(f.root, "current")
			switch defect {
			case "rollback":
				_ = os.WriteFile(current, old, 0600)
			case "corrupt":
				_ = os.WriteFile(current, []byte("{}"), 0600)
			case "unreadable":
				_ = os.Chmod(current, 0000)
			case "special-mode":
				if e := os.Chmod(current, os.ModeSetuid|0600); e != nil {
					t.Fatal(e)
				}
				info, e := os.Lstat(current)
				if e != nil || info.Mode()&os.ModeSetuid == 0 {
					t.Fatal("special-mode fixture was not applied", e)
				}
			case "hardlink":
				if e := os.Link(current, filepath.Join(f.root, "linked")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				_ = os.Rename(current, filepath.Join(f.root, "moved"))
				if e := os.Symlink("moved", current); e != nil {
					t.Fatal(e)
				}
			case "directory-mode":
				_ = os.Chmod(f.root, 0755)
			case "missing-original":
				_ = os.Remove(filepath.Join(f.root, objectName("evidence-", sum(f.collection.originals[0]))))
			case "missing-receipt":
				b, _ := EncodeReceipt(receipt)
				_ = os.Remove(filepath.Join(f.root, objectName("receipt-", sum(b))))
			}
			restartFixture(f)
			raw, e := f.call(strings.Repeat("9", 32))
			requireRefusal(t, raw, e)
			if f.witness.head != h || f.collected != 1 {
				t.Fatal("untrusted history mutated or recollected")
			}
		})
	}
}

// Claim: a known step latches complete incident bounds despite a collector
// failure. Process restart, reboot and an ordinary later report cannot clear it.
func TestSettlementStickyHold(t *testing.T) {
	f := newSettlementFixture(t)
	f.before.Elapsed += time.Second
	f.after = f.before
	f.collectErr = ErrUnavailable
	raw, e := f.call(strings.Repeat("a", 32))
	requireRefusal(t, raw, e)
	r, _ := currentSettlement(t, f)
	if !r.Held || r.InFlight || r.Hold.Reference != "139000000000" || r.HighWater != "140000000000" {
		t.Fatal("step not durably held with bounds")
	}
	restartFixture(f)
	f.collectErr = nil
	f.setTime(300, secondBoot)
	raw, e = f.call(strings.Repeat("b", 32))
	requireRefusal(t, raw, e)
	if f.collected != 1 {
		t.Fatal("ordinary report attempted to clear durable hold")
	}
}

// Claim: a completed, consistent failed query may settle with unchanged W;
// incomplete clocks instead leave an unresolved begin, held after restart.
func TestSettlementFailedCollectionAndClock(t *testing.T) {
	f := newSettlementFixture(t)
	f.collectErr = ErrUnavailable
	raw, e := f.call(strings.Repeat("c", 32))
	requireRefusal(t, raw, e)
	r, _ := currentSettlement(t, f)
	if r.InFlight || r.Held || r.Last.Wall != "211000000000" || r.HighWater != "140000000000" {
		t.Fatal("failed query settlement lost baseline")
	}
	f.collectErr = nil
	f.setTime(212, fixtureBoot)
	fixturePass(t, f, strings.Repeat("d", 32))
	bad := newSettlementFixture(t)
	bad.after.Boot = "unknown"
	raw, e = bad.call(strings.Repeat("e", 32))
	requireRefusal(t, raw, e)
	restartFixture(bad)
	raw, e = bad.call(strings.Repeat("f", 32))
	requireRefusal(t, raw, e)
	if bad.collected != 1 {
		t.Fatal("incomplete incident prefix was silently settled")
	}
}

// Claim: the current operation/challenge cannot select another binding or reuse
// a consumed challenge. A genuinely new bound challenge causes new collection.
func TestSettlementAssociation(t *testing.T) {
	f := newSettlementFixture(t)
	r := fixturePass(t, f, strings.Repeat("1", 32))
	raw, e := f.call(strings.Repeat("1", 32))
	requireRefusal(t, raw, e)
	request := f.request(strings.Repeat("2", 32))
	request.Expected.Scope.Consumer = "other"
	raw, e = f.consumer.ConsumeBeforePin(context.Background(), request)
	requireRefusal(t, raw, e)
	if f.collected != 1 {
		t.Fatal("replay or identity mismatch collected")
	}
	f.setTime(215, fixtureBoot)
	next := fixturePass(t, f, strings.Repeat("3", 32))
	if f.collected != 2 || r.Facts.Sample.ID == next.Facts.Sample.ID || r.Facts.Sample.Generation == next.Facts.Sample.Generation {
		t.Fatal("cached observation returned")
	}
}

// Claim: every actual fsync boundary refuses on a lost acknowledgment, with no
// receipt. The witness never rewinds; committed U remains burned. A prefix after
// begin cannot collect again after restart. These are filesystem fault fixtures,
// not proof of storage hardware or power-loss durability.
func TestSettlementFsyncCrashPrefixes(t *testing.T) {
	points := []string{}
	f := newSettlementFixture(t)
	f.consumer.store.syncFault = func(point string) error { points = append(points, point); return nil }
	fixturePass(t, f, strings.Repeat("4", 32))
	counts := map[string]int{}
	for _, point := range points {
		counts[point]++
		number := counts[point]
		t.Run(fmt.Sprintf("%s-%d", point, number), func(t *testing.T) {
			f := newSettlementFixture(t)
			seen := 0
			applied := false
			f.consumer.store.syncFault = func(p string) error {
				if p == point {
					seen++
					if seen == number {
						applied = true
						return ErrUnavailable
					}
				}
				return nil
			}
			raw, e := f.call(strings.Repeat("5", 32))
			requireRefusal(t, raw, e)
			if !applied {
				t.Fatal("fsync fault not reached")
			}
			committed := f.witness.head
			f.consumer.store.syncFault = nil
			restartFixture(f)
			s, oe := f.consumer.store.open()
			if oe != nil {
				t.Fatal(oe)
			}
			r, re := s.record(committed)
			s.close()
			if re != nil {
				t.Fatal("witness lost its prepared record", re)
			}
			if committed.Generation == 1 && !r.InFlight {
				t.Fatal("committed begin not held")
			}
			if committed.Generation == 2 && r.HighWater != "212000000000" {
				t.Fatal("lost reply erased consumed U")
			}
			raw, e = f.call(strings.Repeat("6", 32))
			if committed.Generation == 0 {
				if e != nil {
					t.Fatal("unused prepared prefix prevented fresh observation", e)
				}
			} else {
				requireRefusal(t, raw, e)
			}
			if f.witness.head.Generation < committed.Generation {
				t.Fatal("witness rewound")
			}
		})
	}
	expected := "record-file,record-directory,pointer-file,pointer-directory,current-directory,evidence-file,evidence-directory,record-file,record-directory,pointer-file,pointer-directory,current-directory,receipt-file,receipt-directory"
	if strings.Join(points, ",") != expected {
		t.Fatal("write-order boundary inventory changed", points)
	}
}

// Claim: CAS failures before/after acknowledgment cannot silently reset state;
// losing the final acknowledgment still burns the candidate upper bound.
func TestSettlementCASCrashPrefixes(t *testing.T) {
	for _, phase := range []string{"before-begin", "after-begin", "before-final", "after-final"} {
		t.Run(phase, func(t *testing.T) {
			f := newSettlementFixture(t)
			target := uint64(1)
			if strings.HasSuffix(phase, "final") {
				target = 2
			}
			hook := func(h WitnessHead) error {
				if h.Generation == target {
					return ErrUnavailable
				}
				return nil
			}
			if strings.HasPrefix(phase, "before") {
				f.witness.beforeCAS = hook
			} else {
				f.witness.afterCAS = hook
			}
			raw, e := f.call(strings.Repeat("7", 32))
			requireRefusal(t, raw, e)
			f.witness.beforeCAS = nil
			f.witness.afterCAS = nil
			restartFixture(f)
			committed := f.witness.head
			s, oe := f.consumer.store.open()
			if oe != nil {
				t.Fatal(oe)
			}
			r, re := s.record(committed)
			s.close()
			if re != nil {
				t.Fatal(re)
			}
			if phase == "after-final" && r.HighWater != "212000000000" {
				t.Fatal("final CAS lost U")
			}
			if phase == "before-begin" && f.collected != 0 {
				t.Fatal("collection preceded witness begin")
			}
			if phase != "before-begin" {
				raw, e = f.call(strings.Repeat("8", 32))
				requireRefusal(t, raw, e)
			}
		})
	}
}

// Claim: the test-only witness rejects stale CAS and generation wrap. The
// production witness refuses both operations with a typed activation error.
func TestRollbackWitness(t *testing.T) {
	ctx := context.Background()
	d := sum([]byte("record"))
	w := &fixtureWitness{head: WitnessHead{3, d}}
	if w.CompareAndSwap(ctx, WitnessHead{2, d}, WitnessHead{3, d}) == nil {
		t.Fatal("stale CAS accepted")
	}
	next := WitnessHead{4, sum([]byte("next"))}
	if w.CompareAndSwap(ctx, w.head, next) != nil {
		t.Fatal("valid fixture CAS refused")
	}
	w.head = WitnessHead{math.MaxUint64, d}
	if w.CompareAndSwap(ctx, w.head, WitnessHead{0, d}) == nil {
		t.Fatal("generation wrapped")
	}
	closed := ClosedWitness{}
	_, e := closed.Read(ctx)
	var a *ActivationRefusal
	if !errors.As(e, &a) || !errors.Is(e, ErrUnavailable) {
		t.Fatal("closed read not typed")
	}
	if e = closed.CompareAndSwap(ctx, WitnessHead{}, next); !errors.As(e, &a) {
		t.Fatal("closed CAS not typed")
	}
}

func (f *settlementFixture) applyPolicy(t *testing.T, p Policy) {
	t.Helper()
	f.policy = p
	f.consumer.policy = p
	f.enrollment.Policy.EffectiveDigest, _ = EffectivePolicyDigest(p, f.enrollment.Policy.SharedDigest, f.enrollment.Policy.ServiceDigest)
	f.consumer.enrollment = f.enrollment
	b, _ := canonical(f.enrollment)
	f.consumer.store.binding = sum(b)
	f.seed(t, 140, 140, fixtureBoot)
}

// Claim: U=A refuses at the provider boundary; one nanosecond of exclusive
// authority passes without changing the observation or uncertainty.
func TestSettlementExclusiveAuthority(t *testing.T) {
	for _, extra := range []time.Duration{0, time.Nanosecond} {
		t.Run(extra.String(), func(t *testing.T) {
			f := newSettlementFixture(t)
			p := f.policy
			p.AuthorityWindow = time.Second + extra
			f.applyPolicy(t, p)
			raw, e := f.call(strings.Repeat("f", 32))
			if extra == 0 {
				requireRefusal(t, raw, e)
			} else if e != nil {
				t.Fatal("exclusive positive control refused", e)
			}
		})
	}
}

// Claim: original nanosecond floors survive storage. Rounding W down or L up
// would admit the first interval; the second genuinely exceeds the same floor.
func TestSettlementSubsecondFloor(t *testing.T) {
	f := newSettlementFixture(t)
	s, e := f.consumer.store.open()
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.record(f.witness.head)
	s.close()
	if e != nil {
		t.Fatal(e)
	}
	r.HighWater = "200200000000"
	b, _ := canonical(r)
	h := WitnessHead{0, sum(b)}
	if e = os.WriteFile(filepath.Join(f.root, objectName("record-", h.RecordDigest)), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.root, "current"), witnessBytes(h), 0600); e != nil {
		t.Fatal(e)
	}
	f.witness.head = h
	f.consumer.timePath.reserve = 100 * time.Millisecond
	f.consumer.timePath.budget = 50 * time.Millisecond
	f.setTime(200, fixtureBoot)
	f.before.Now = f.before.Now.Add(200 * time.Millisecond)
	f.before.Elapsed += 200 * time.Millisecond
	f.after = f.before
	raw, e := f.call(strings.Repeat("1", 32))
	requireRefusal(t, raw, e)
	f.setTime(202, fixtureBoot)
	f.before.Now = f.before.Now.Add(200 * time.Millisecond)
	f.before.Elapsed += 200 * time.Millisecond
	f.after = f.before
	receipt := fixturePass(t, f, strings.Repeat("2", 32))
	if receipt.Facts.Continuity.PriorHighWater != "200200000000" || receipt.Facts.Observed != "202200000000" || receipt.Facts.Uncertainty != "100000000" {
		t.Fatal("coarse conversion replaced exact facts")
	}
}

// Claim: an unqualified reboot cannot establish a new baseline through a refused
// first call and then pass. Its unresolved begin stays held even after restart.
// A separately qualified fresh fixture transition is the positive control.
func TestSettlementUnqualifiedReboot(t *testing.T) {
	f := newSettlementFixture(t)
	f.setTime(211, secondBoot)
	f.consumer.timePath.reboot = false
	raw, e := f.call(strings.Repeat("3", 32))
	requireRefusal(t, raw, e)
	restartFixture(f)
	f.consumer.timePath.reboot = true
	raw, e = f.call(strings.Repeat("4", 32))
	requireRefusal(t, raw, e)
	if f.collected != 0 {
		t.Fatal("unqualified reboot established an ordinary baseline")
	}
	good := newSettlementFixture(t)
	good.setTime(211, secondBoot)
	r := fixturePass(t, good, strings.Repeat("5", 32))
	if r.Facts.Continuity.Transition != "qualified-reboot" || r.Facts.Continuity.PriorBoot != fixtureBoot {
		t.Fatal("qualified fixture transition lost")
	}
}
