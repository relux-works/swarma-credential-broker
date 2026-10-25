//go:build linux && swarma_timeconf_fixture

package timeconf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func handoffPacket(t *testing.T) (*FixtureConsumer, FixtureHandoff) {
	t.Helper()
	f, err := NewFixtureHandoffProvider(protectedTemp(t))
	if err != nil {
		t.Fatal(err)
	}
	return f, collectPacket(t, f, "1", "1", WindowIdentity{"fixture-window", "1"})
}
func collectPacket(t *testing.T, f *FixtureConsumer, challenge, id string, w WindowIdentity, original ...time.Time) FixtureHandoff {
	t.Helper()
	op, _ := NativeOperationDigest("fixture-operation", []byte("exact original identity"))
	r := ConsumptionRequest{time.Now().Add(400 * time.Millisecond), f.Enrollment(), op, strings.Repeat(challenge, 32), 140000000000}
	if len(original) > 0 {
		r.Deadline = original[0]
	}
	p, err := f.CollectHandoff(context.Background(), r, w, strings.Repeat("a", 32), strings.Repeat(id, 32))
	if err != nil {
		t.Fatal(err)
	}
	if p.Expected.Deadline.OriginalUTCNS != ns(r.Deadline.UnixNano()) {
		t.Fatal("original caller deadline identity changed")
	}
	return p
}
func checked(t *testing.T, p FixtureHandoff) WindowCandidate {
	t.Helper()
	c, err := VerifyWindow(p.Prepared, p.Expected, p.Local, p.Capture)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func handoffCode(t *testing.T, err error, code string) {
	t.Helper()
	var r *HandoffRefusal
	if !errors.As(err, &r) || r.Code != code || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func expectedUseKey(e WindowExpected) UseKey {
	return UseKey{e.Enrollment.Scope.Consumer, e.Enrollment.Store, e.Operation, e.Window}
}

type handoffAct func() error

func (a handoffAct) Act() error { return a() }

// Claim: the real closed codec round trips an unchanged provider receipt and its
// complete originals, rejects canonical violations and substitution, and cannot
// mutate private preparation through the fixture's exported byte copies.
func TestHandoffCodec(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		h, err := DecodeHandoff(p.Raw)
		if err != nil {
			t.Fatal(err)
		}
		b, err := EncodeHandoff(h)
		if err != nil || !bytes.Equal(b, p.Raw) {
			t.Fatal("round trip", err)
		}
		r, _ := EncodeReceipt(h.Receipt)
		if !bytes.Equal(r, p.Originals[0]) {
			t.Fatal("receipt changed")
		}
		if err = CheckHandoffOriginals(h, p.Originals); err != nil {
			t.Fatal(err)
		}
		var root map[string]json.RawMessage
		_ = json.Unmarshal(p.Raw, &root)
		for name, raw := range map[string][]byte{"trailing": append(append([]byte{}, p.Raw...), '\n'), "extra": append(append([]byte{}, p.Raw...), []byte(`{}`)...), "duplicate": bytes.Replace(p.Raw, []byte(`"version":"qualified-time/handoff/1"`), []byte(`"version":"qualified-time/handoff/1","version":"qualified-time/handoff/1"`), 1)} {
			if _, err = DecodeHandoff(raw); err == nil {
				t.Fatal(name)
			}
		}
		for _, key := range []string{"unknown", "objects", "receipt", "version"} {
			copyRoot := map[string]json.RawMessage{}
			for k, v := range root {
				copyRoot[k] = v
			}
			copyRoot[key] = json.RawMessage(`null`)
			raw, _ := json.Marshal(copyRoot)
			if _, err = DecodeHandoff(raw); err == nil {
				t.Fatal("null/unknown", key)
			}
		}
		bounded, _ := DecodeHandoff(p.Raw)
		for len(bounded.Objects) < 63 {
			bounded.Objects = append(bounded.Objects, HandoffObject{"history-source", sum([]byte{byte(len(bounded.Objects))}), "1"})
		}
		manifest, _ := canonical(bounded.Objects)
		bounded.Handoff.ClosureDigest = sum(manifest)
		accepted, err := EncodeHandoff(bounded)
		if err != nil {
			t.Fatal("63-descriptor structural control", err)
		}
		if _, err = DecodeHandoff(accepted); err != nil {
			t.Fatal(err)
		}
		bounded.Objects = append(bounded.Objects, HandoffObject{"history-source", sum([]byte("extra")), "1"})
		oversize, _ := canonical(bounded)
		_, err = DecodeHandoff(oversize)
		handoffCode(t, err, "limit")
		copyOriginals := append([][]byte{}, p.Originals...)
		copyOriginals[4] = []byte("substituted source")
		handoffCode(t, CheckHandoffOriginals(h, copyOriginals), "original_mismatch")
		copyOriginals[4] = append([]byte{}, p.Originals[4]...)
		copyOriginals[4][0] ^= 1
		handoffCode(t, CheckHandoffOriginals(h, copyOriginals), "original_mismatch")
		copyOriginals[4] = nil
		handoffCode(t, CheckHandoffOriginals(h, copyOriginals), "original_missing")
		handoffCode(t, CheckHandoffOriginals(h, p.Originals[:len(p.Originals)-1]), "original_missing")
		for _, mutate := range []func(*Handoff){func(h *Handoff) { h.Receipt.Facts.AuthorityUntil = h.Receipt.Facts.Continuity.HighWater }, func(h *Handoff) { h.Version = "unknown" }, func(h *Handoff) { h.Handoff.Witness.Version = "accepting/1" }, func(h *Handoff) { h.Objects = append(h.Objects, h.Objects[4]) }, func(h *Handoff) { h.Objects[4].Size = "18446744073709551616" }, func(h *Handoff) { h.Objects[4].Role = "unknown" }, func(h *Handoff) {
			for len(h.Objects) < 64 {
				h.Objects = append(h.Objects, h.Objects[4])
			}
		}} {
			x, _ := DecodeHandoff(p.Raw)
			mutate(&x)
			if _, err = EncodeHandoff(x); err == nil {
				t.Fatal("invalid structure accepted")
			}
		}
		p.Raw[0] = '!'
		p.Originals[0][0] = '!'
		_ = checked(t, p)
	})
}

// Claim: same-qualification paired cases enforce exact independent binding and
// checked exclusive arithmetic. Positive 110 ms and D-1 ns endpoints match the
// Python table; an actual supplied late m refuses. No native pause is simulated.
func TestHandoffWindowVectors(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*FixtureHandoff)
	}{
		{"HandoffTimelyRun", "", func(*FixtureHandoff) {}},
		{"DeadlineNeighbour", "", func(p *FixtureHandoff) { p.Capture.NS += 118999999 }},
		{"HandoffDeadlineEquality", "deadline", func(p *FixtureHandoff) { p.Capture.NS += 119000000 }},
		{"HandoffLateRun", "deadline", func(p *FixtureHandoff) { p.Capture.NS += 1390000000 }},
		{"Operation", "operation", func(p *FixtureHandoff) {
			p.Expected.Operation = sum([]byte("another operation"))
			p.Local.Intent = p.Expected
		}},
		{"Consumer", "consumer", func(p *FixtureHandoff) {
			p.Expected.Enrollment.Scope.Consumer = "another-consumer"
			p.Local.Intent = p.Expected
		}},
		{"Boot", "boot", func(p *FixtureHandoff) { p.Capture.Boot = "22222222-2222-4222-8222-222222222222" }},
		{"DeadlineBinding", "deadline_binding", func(p *FixtureHandoff) {
			p.Expected.Deadline.OriginalUTCNS = "301000000000"
			p.Local.Intent = p.Expected
		}},
		{"ReserveBinding", "reserve", func(p *FixtureHandoff) {
			p.Expected.Budget.ReservedUncertaintyNS = "600000000"
			p.Local.Intent = p.Expected
		}},
		{"HandoffLockedStateRace", "operation", func(p *FixtureHandoff) { p.Local.Intent.Operation = sum([]byte("changed locked head")) }},
		{"Window", "window", func(p *FixtureHandoff) { p.Expected.Window.Sequence = "2"; p.Local.Intent = p.Expected }},
		{"TransitionVersion", "window", func(p *FixtureHandoff) { p.Local.Intent.TransitionVersion = "fixture-use:2" }},
		{"Run", "run", func(p *FixtureHandoff) { p.Local.Epoch = strings.Repeat("b", 32) }},
		{"Replay", "replay", func(p *FixtureHandoff) { p.Local.Unused = false }},
		{"Continuity", "continuity", func(p *FixtureHandoff) { p.Local.Current = false }},
		{"LockedFloor", "interval", func(p *FixtureHandoff) { p.Local.FloorNS = 210000000000 }},
		{"AuthorityEquality", "authority", func(p *FixtureHandoff) { p.Local.ExpiryNS = 212000000000 }},
		{"Overflow", "overflow", func(p *FixtureHandoff) { p.Capture.NS = 1<<63 - 1 }},
		{"HandoffMacParity", "boot", func(p *FixtureHandoff) { p.Capture.Clock = "MACH_CONTINUOUS_TIME/ns" }},
		{"AwakeOnlyClock", "boot", func(p *FixtureHandoff) { p.Capture.Clock = "CLOCK_UPTIME_RAW" }},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, p := handoffPacket(t)
				_ = checked(t, p)
				before, _ := f.HighWater()
				v.change(&p)
				c, err := VerifyWindow(p.Prepared, p.Expected, p.Local, p.Capture)
				if v.code == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					handoffCode(t, err, v.code)
					if c != (WindowCandidate{}) {
						t.Fatal("partial candidate")
					}
				}
				after, _ := f.HighWater()
				if before != after {
					t.Fatal("pure check mutated provider")
				}
			})
		})
	}
}

// Claim: two pure checks return inert candidates. Exact serialized use accepts
// once and burns before the separable act; all H values for that key refuse.
// This store is volatile fixture memory, not native durability qualification.
func TestHandoffDoubleCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		a, b := checked(t, p), checked(t, p)
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		acts := 0
		act := handoffAct(func() error { acts++; return nil })
		if err := s.ConsumeIfUnused(a, p.Local, act); err != nil {
			t.Fatal(err)
		}
		h, _ := DecodeHandoff(p.Raw)
		h.Handoff.ID = strings.Repeat("f", 32)
		raw, _ := EncodeHandoff(h)
		p.Prepared, _ = PrepareFixtureHandoff(raw, p.Originals, p.Expected, p.Capture.NS-10000000)
		fresh := checked(t, p)
		if fresh.commitment == a.commitment || fresh.key != a.key {
			t.Fatal("H allocated a logical key")
		}
		err := s.ConsumeIfUnused(fresh, p.Local, act)
		if err == nil {
			t.Fatal("fresh H accepted for burned window")
		}
		handoffCode(t, err, "replay")
		handoffCode(t, s.ConsumeIfUnused(b, p.Local, act), "replay")
		if acts != 1 || len(s.entries) != 1 {
			t.Fatal("duplicate act or burn")
		}
	})
}

// Claim: initial reference admission is retained before the synthetic read,
// and the map contains its burn before act. Missing/changed admission refuses.
func TestHandoffUseAdmissionOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		c := checked(t, p)
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		bad := p.Local
		bad.Revision = "1"
		acts := 0
		act := handoffAct(func() error {
			acts++
			if _, ok := s.entries[c.key]; !ok {
				t.Error("act before burn")
			}
			return nil
		})
		handoffCode(t, s.ConsumeIfUnused(c, bad, act), "replay")
		handoffCode(t, (&ReferenceAdmission{}).ConsumeIfUnused(c, p.Local, act), "binding")
		admission, err := s.Admit(p.Local)
		if err != nil {
			t.Fatal(err)
		}
		defer admission.Release()
		// This synthetic read is placed after initial admission. TryLock proves
		// the reference exclusion is already held; it does not qualify a clock.
		capture := func() FinalCapture {
			if s.mu.TryLock() {
				s.mu.Unlock()
				t.Error("read before initial admission")
			}
			return p.Capture
		}
		c, err = VerifyWindow(p.Prepared, p.Expected, p.Local, capture())
		if err != nil {
			t.Fatal(err)
		}
		if err = admission.ConsumeIfUnused(c, p.Local, act); err != nil {
			t.Fatal(err)
		}
		if acts != 1 || !reflect.DeepEqual(s.Events, []string{"burn", "act", "committed"}) {
			t.Fatal("wrong transition order", s.Events)
		}
	})
}

// Claim: ambiguous burn prevents act, a lost reply keeps its exact burn, and a
// missing store does not reconstruct unused. These are in-memory fault controls.
func TestHandoffUseRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		c := checked(t, p)
		acts := 0
		act := handoffAct(func() error { acts++; return nil })
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		s.AmbiguousBurn = true
		handoffCode(t, s.ConsumeIfUnused(c, p.Local, act), "continuity")
		s.AmbiguousBurn = false
		handoffCode(t, s.ConsumeIfUnused(c, p.Local, act), "continuity")
		if acts != 0 || len(s.entries) != 1 {
			t.Fatal("ambiguous burn authorized act")
		}
		s = NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		s.LoseReply = true
		handoffCode(t, s.ConsumeIfUnused(c, p.Local, act), "reply_lost")
		s.LoseReply = false
		handoffCode(t, s.ConsumeIfUnused(c, p.Local, act), "replay")
		if acts != 1 || len(s.entries) != 1 {
			t.Fatal("lost reply authorized replay")
		}
		handoffCode(t, (&ReferenceUseStore{}).ConsumeIfUnused(c, p.Local, act), "continuity")
		handoffCode(t, NewReferenceUseStore(p.Expected.Run).ConsumeIfUnused(c, p.Local, act), "continuity")
	})
}

// Claim: fixture preparation refuses nonfixture enrollment or unavailable exact
// originals; ordinary Consumer and witness remain inactive under the tag.
func TestHandoffProvenanceAndPurity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, p := handoffPacket(t)
		_ = checked(t, p)
		for _, unselected := range []*FixtureConsumer{nil, {}} {
			var inactive *ActivationRefusal
			if err := unselected.SetHandoffSample(time.Unix(211, 0)); !errors.As(err, &inactive) || inactive.Reason != "fixture_unselected" {
				t.Fatal("unselected sample setter", err)
			}
			_, err := unselected.CollectHandoff(context.Background(), ConsumptionRequest{}, WindowIdentity{}, "", "")
			if !errors.As(err, &inactive) || inactive.Reason != "fixture_unselected" {
				t.Fatal("unselected collector", err)
			}
		}
		e := p.Expected
		e.Enrollment.Authority.ID = "production-authority"
		_, err := PrepareFixtureHandoff(p.Raw, p.Originals, e, p.Capture.NS)
		var a *ActivationRefusal
		if !errors.As(err, &a) {
			t.Fatal("nonfixture preparation activated", err)
		}
		_, err = PrepareFixtureHandoff(p.Raw, nil, p.Expected, p.Capture.NS)
		handoffCode(t, err, "original_missing")
		ordinary, _ := NewConsumer(f.Enrollment(), f.Policy(), f.consumer.store.root)
		raw, err := ordinary.ConsumeBeforePin(context.Background(), ConsumptionRequest{})
		if len(raw) != 0 || !errors.As(err, &a) {
			t.Fatal("ordinary consumer activated", err)
		}
		if err = ValidateHandoffWitness(WitnessMaterial{WitnessPlaceholderVersion}); !errors.As(err, &a) {
			t.Fatal("placeholder accepted", err)
		}
	})
}

// N1 uses a separately declared long original operation, not the illustrative
// 250 ms window deadline. Its original UTC/deadline/budget never grow across the
// synthetic reboot mapping; T=300 ms remains per fresh observation. No native
// restart mapping, retention, power-loss or elapsed-time qualification is claimed.
func originalN1Window(t *testing.T, p FixtureHandoff) FixtureHandoff {
	t.Helper()
	h, _ := DecodeHandoff(p.Raw)
	d := h.Handoff.Deadline
	d.StartNS = "0"
	d.AbsoluteNS = "280000000000"
	d.OriginalBudgetNS = "280000000000"
	h.Handoff.Deadline = d
	p.Expected.Deadline = d
	p.Local.Intent = p.Expected
	p.Raw, _ = EncodeHandoff(h)
	var err error
	p.Prepared, err = PrepareFixtureHandoff(p.Raw, p.Originals, p.Expected, p.Capture.NS-10000000)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Claim: real provider J=140,O=200,delta=1 settles W=201. Intact lower
// [170,172] refuses interval with W unchanged. Fresh [210,212] can prepare/use an
// unused logical window; an earlier burn instead refuses every fresh H.
func TestHandoffN1(t *testing.T) {
	for _, burned := range []bool{false, true} {
		name := "HandoffN1BeforeBurn"
		if burned {
			name = "HandoffN1AfterBurn"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, err := NewFixtureHandoffProvider(protectedTemp(t))
				if err != nil {
					t.Fatal(err)
				}
				if err = f.SetHandoffSample(time.Unix(200, 0)); err != nil {
					t.Fatal(err)
				}
				originalDeadline := time.Now().Add(80 * time.Second)
				first := originalN1Window(t, collectPacket(t, f, "1", "1", WindowIdentity{"fixture-window", "1"}, originalDeadline))
				c := checked(t, first)
				if w, _ := f.HighWater(); w != "201000000000" {
					t.Fatal(w)
				}
				s := NewReferenceUseStore(first.Expected.Run, expectedUseKey(first.Expected))
				acts := 0
				act := handoffAct(func() error { acts++; return nil })
				if burned {
					if err = s.ConsumeIfUnused(c, first.Local, handoffAct(func() error { return ErrUnavailable })); !errors.Is(err, ErrUnavailable) {
						t.Fatal(err)
					}
				}
				_ = f.SetHandoffSample(time.Unix(171, 0))
				op := first.Expected.Operation
				raw, err := f.ConsumeBeforePin(context.Background(), ConsumptionRequest{originalDeadline, f.Enrollment(), op, strings.Repeat("2", 32), 140000000000})
				var refused *ConsumptionRefusal
				if len(raw) != 0 || !errors.As(err, &refused) || refused.Code != "interval" {
					t.Fatal("N1 lower interval accepted", err)
				}
				if w, _ := f.HighWater(); w != "201000000000" {
					t.Fatal("N1 reset W", w)
				}
				_ = f.SetHandoffSample(time.Unix(211, 0))
				next := originalN1Window(t, collectPacket(t, f, "3", "3", first.Expected.Window, originalDeadline))
				fresh := checked(t, next)
				if next.Expected.Deadline.AbsoluteNS != first.Expected.Deadline.AbsoluteNS || next.Expected.Deadline.OriginalUTCNS != first.Expected.Deadline.OriginalUTCNS {
					t.Fatal("original deadline renewed")
				}
				err = s.ConsumeIfUnused(fresh, next.Local, act)
				if burned {
					handoffCode(t, err, "replay")
					if acts != 0 {
						t.Fatal("burn refunded")
					}
				} else if err != nil || acts != 1 {
					t.Fatal("unused window refused", err)
				}
				if w, _ := f.HighWater(); w != "212000000000" {
					t.Fatal(w)
				}
			})
		})
	}
}

// Claim: missing/restored provider pointers cannot use intact in-memory witness
// state as unused genesis. A nearby full-history receipt passes before each cut.
func TestHandoffN1Continuity(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "missing"}[missing], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, err := NewFixtureHandoffProvider(protectedTemp(t))
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(f.consumer.store.root, "current")
				genesis, _ := os.ReadFile(path)
				p := collectPacket(t, f, "1", "1", WindowIdentity{"fixture-window", "1"})
				_ = checked(t, p)
				if missing {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, genesis, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Advance(3 * time.Second)
				_, err = f.CollectHandoff(context.Background(), ConsumptionRequest{time.Now().Add(400 * time.Millisecond), f.Enrollment(), p.Expected.Operation, strings.Repeat("2", 32), 140000000000}, p.Expected.Window, p.Expected.Run, strings.Repeat("2", 32))
				var r *ConsumptionRefusal
				if !errors.As(err, &r) || r.Code != "continuity" {
					t.Fatal("missing/restored history accepted", err)
				}
				head, _ := f.consumer.store.witness.Read(context.Background())
				if head.Generation != 2 {
					t.Fatal("witness reset")
				}
			})
		})
	}
}

// Claim: reference consumption rejects a candidate after replacement epoch.
// This is a pre-dispatch check only: the native after-burn/paused-effect fence
// remains a documented requirement, never a claimed in-memory-store guarantee.
func TestHandoffEpochAfterBurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		c := checked(t, p)
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		_ = s.ConsumeIfUnused(c, p.Local, handoffAct(func() error { return ErrUnavailable }))
		s.Fence(strings.Repeat("b", 32))
		acts := 0
		handoffCode(t, s.ConsumeIfUnused(c, p.Local, handoffAct(func() error { acts++; return nil })), "run")
		if acts != 0 || len(s.entries) != 1 {
			t.Fatal("old epoch dispatched/refunded")
		}
	})
}

// Claim: the normative document explicitly declares the two pause limitations
// and missing native parity. Identical pure inputs cannot reveal a real pause;
// no fake scheduling, storage, macOS or late-effect execution is asserted here.
func TestHandoffStaleCapture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "docs", "time-handoff.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Pure input alone cannot distinguish them", "An arbitrary pause after it still", "post-write check cannot retract", "also fence a process paused or restored"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatal("missing infeasibility declaration", s)
		}
	}
	b, err = os.ReadFile(filepath.Join("..", "docs", "time-handoff-macos.md"))
	if err != nil || !bytes.Contains(b, []byte("unimplemented and unqualified")) {
		t.Fatal("native parity misrepresented", err)
	}
}

// Claim: fixture receipt/budget values and the executable Go deadline vectors
// retain the published Python table's exact source/reserve/cap and nanoseconds.
func TestHandoffPublishedVectorAlignment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		h, _ := DecodeHandoff(p.Raw)
		if h.Receipt.Facts.Uncertainty != "1000000000" || h.Handoff.Budget.ReservedUncertaintyNS != "500000000" || h.Handoff.Budget.TotalDelayNS != "300000000" || h.Handoff.Budget.FinalWorkMaxNS != "20000000" || h.Handoff.Budget.ErrorNS != "1000000" {
			t.Fatal("fixture drifted from published qualification assumptions")
		}
		b, err := os.ReadFile(filepath.Join("..", "docs", "time-handoff.md"))
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range []string{"| source_uncertainty_ns | 500000000 |", "| cap_ns | 1500000000 |", "| timely | 110000000 | 300000000 | 500000000 |", "| deadline-neighbour | 228999999 | 300000000 | 500000000 |", "| deadline-equality | 229000000 | 300000000 | 500000000 |"} {
			if !bytes.Contains(b, []byte(row)) {
				t.Fatal("published arithmetic drift", row)
			}
		}
		for _, n := range []struct{ allowance, reserve, code string }{{"2000000000", "500000000", "reserve"}, {"2000000000", "2000000000", "reserve"}} {
			x := h
			x.Handoff.Budget.TotalDelayNS = Nanoseconds(n.allowance)
			x.Handoff.Budget.ReservedUncertaintyNS = Nanoseconds(n.reserve)
			raw, err := EncodeHandoff(x)
			if err != nil {
				t.Fatal(err)
			}
			expected := p.Expected
			expected.Budget = x.Handoff.Budget
			prepared, err := PrepareFixtureHandoff(raw, p.Originals, expected, p.Capture.NS-10000000)
			if err != nil {
				t.Fatal(err)
			}
			local := p.Local
			local.Intent = expected
			c, err := VerifyWindow(prepared, expected, local, p.Capture)
			handoffCode(t, err, n.code)
			if c != (WindowCandidate{}) {
				t.Fatal("unfunded allowance admitted")
			}
		}
	})
}

// Claim: two genuinely concurrent reference consumes of separately checked
// candidates yield exactly one burn/act; the loser receives replay, not success.
func TestHandoffConcurrentUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		a, b := checked(t, p), checked(t, p)
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		acts := 0
		act := handoffAct(func() error { acts++; return nil })
		results := make(chan error, 2)
		go func() { results <- s.ConsumeIfUnused(a, p.Local, act) }()
		go func() { results <- s.ConsumeIfUnused(b, p.Local, act) }()
		successes := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err == nil {
				successes++
			} else {
				handoffCode(t, err, "replay")
			}
		}
		if successes != 1 || acts != 1 || len(s.entries) != 1 {
			t.Fatal("concurrent consume duplicated effect")
		}
	})
}

// Claim: a native use-format migration cannot allocate a new logical slot or
// refund an existing burn; the version remains a separately checked binding.
func TestHandoffTransitionVersionDoesNotRefund(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p := handoffPacket(t)
		c := checked(t, p)
		s := NewReferenceUseStore(p.Expected.Run, expectedUseKey(p.Expected))
		act := handoffAct(func() error { return nil })
		if err := s.ConsumeIfUnused(c, p.Local, act); err != nil {
			t.Fatal(err)
		}
		h, _ := DecodeHandoff(p.Raw)
		h.Handoff.TransitionVersion = "fixture-use:2"
		p.Expected.TransitionVersion = h.Handoff.TransitionVersion
		p.Local.Intent = p.Expected
		raw, _ := EncodeHandoff(h)
		var err error
		p.Prepared, err = PrepareFixtureHandoff(raw, p.Originals, p.Expected, p.Capture.NS-10000000)
		if err != nil {
			t.Fatal(err)
		}
		next := checked(t, p)
		if next.key != c.key {
			t.Fatal("transition version allocated another slot")
		}
		handoffCode(t, s.ConsumeIfUnused(next, p.Local, act), "replay")
	})
}
