//go:build linux

package authowner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// The oracle consumes only externally supplied evidence and persisted records.
// It does not call the implementation's sample/floor/decision helpers.
type sequenceConfidence struct {
	mu        sync.Mutex
	value     TimeEvidence
	effective time.Time
	calls     int
	atCall    int
	onCall    func(TimeEvidence) TimeEvidence
}

func (s *sequenceConfidence) Validate(_ context.Context, _ string, _ string, _ uint64, watermark time.Time) (TimeEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == s.atCall && s.onCall != nil {
		s.value = s.onCall(s.value)
	}
	if watermark.After(s.effective) {
		s.effective = watermark
	}
	if s.value.Trusted && !s.value.Now.IsZero() && s.value.Now.After(s.effective) {
		s.effective = s.value.Now
	}
	return s.value, nil
}
func (s *sequenceConfidence) state() (TimeEvidence, time.Time, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, s.effective, s.calls
}
func (s *sequenceConfidence) set(v TimeEvidence) {
	s.mu.Lock()
	s.value = v
	s.mu.Unlock()
}
func (s *sequenceConfidence) allowed() bool {
	v, effective, _ := s.state()
	return v.Trusted && v.Fresh && !v.Now.IsZero() && effective.Before(v.AuthorityUntil)
}

type sequenceManager struct {
	Manager
	source *sequenceConfidence
	t      *testing.T
}

func (m sequenceManager) Start(ctx context.Context, spec UnitSpec) error {
	if !m.source.allowed() {
		m.t.Error("protected writer start outside independent authority")
	}
	return m.Manager.Start(ctx, spec)
}

func sequenceCheckpoint(t *testing.T, f *fixture) Checkpoint {
	t.Helper()
	records, err := f.disk.Records()
	var c Checkpoint
	if err != nil || json.Unmarshal(records["owner-checkpoint.json"], &c) != nil {
		t.Fatal("sequence checkpoint")
	}
	return c
}

func sequenceReplace(t *testing.T, f *fixture, current *Engine, source *sequenceConfidence) *Engine {
	t.Helper()
	current.Close()
	c := f.c
	c.DaemonInstance = id()
	// A new process observes its durable floor only after valid restoration.
	// An invalid prefix stays closed before sampling; unacted observations belong
	// to the prior process. Durable non-revival is checked across this reset.
	source.mu.Lock()
	source.effective = time.Time{}
	source.mu.Unlock()
	next, err := New(context.Background(), c, sequenceManager{f.m, source, t}, source, fakeClassifier{})
	if err != nil {
		t.Fatal("sequence replacement", err)
	}
	t.Cleanup(next.Close)
	return next
}

func sequenceEvent(rng *rand.Rand, kind string, base, expires, floor time.Time) TimeEvidence {
	v := TimeEvidence{Now: expires.Add(-time.Second), AuthorityUntil: base.Add(8 * time.Hour), Trusted: true, Fresh: true}
	switch kind {
	case "forward":
		v.Now = floor.Add(time.Duration(1+rng.Intn(250)) * time.Millisecond)
	case "backward":
		v.Now = floor.Add(-time.Duration(1+rng.Intn(250)) * time.Millisecond)
	case "missing":
		v.Now = time.Time{}
	case "expiry":
		v.Now = expires.Add(time.Duration(1+rng.Intn(250)) * time.Millisecond)
	case "authority-end":
		v.Now, v.AuthorityUntil = floor, floor
	case "stale":
		v.Fresh = false
	}
	return v
}

// Claim: fixed-seed generated source sequences exercise each of the eight
// owner-record completions, watermark completion and material-flush postcheck,
// then every admission (snapshot, fresh-home, writer, Due, recovery). The oracle
// requires process effective time and persisted decision time to be monotone,
// no revival after a durable expiry refusal, progress on stable valid time, and
// no protected write/start/admission outside the exclusive authority bound.
// Replacement resets only unacted process observations; durable decision time
// and expired-material evidence must survive. Pending prefixes recover only
// with their existing conclusive RPC proof. This is bounded sequence coverage,
// not a claim about arbitrary schedules or atomic concurrent revocation.
func TestTimeAuthoritySequences(t *testing.T) {
	seeds := []int64{1, 7, 42, 20261023}
	t.Logf("reproduction seeds: %v", seeds)
	targets := []string{"watermark", "material-flush", "pending-checkpoint", "intent", "submitted", "running", "stopping", "absence", "resolved", "final-checkpoint"}
	for _, seed := range seeds {
		for index, target := range targets {
			modes := []string{"live", "replacement"}
			if index >= 2 {
				modes = append(modes, "pending-recovery")
			}
			for _, mode := range modes {
				t.Run(fmt.Sprintf("seed-%d/%s/%s", seed, target, mode), func(t *testing.T) {
					rng := rand.New(rand.NewSource(seed + int64(index)*101))
					var f *fixture
					var source *sequenceConfidence
					armed, auditing, triggered := false, false, false
					writes := 0
					var event TimeEvidence
					hook := func(stage string) error {
						if auditing && stage == "write" && !source.allowed() {
							t.Error("protected persistence outside independent authority")
						}
						if armed && stage == "directory-sync" {
							writes++
							at := index - 1
							if index == 0 {
								at = 1
							}
							if writes == at && !triggered {
								triggered = true
								source.set(event)
							}
						}
						return nil
					}
					f = fixtureHook(t, "safe", hook)
					base := f.t.now
					expires := base.Add(4 * time.Hour)
					good := TimeEvidence{Now: expires.Add(-time.Second), AuthorityUntil: base.Add(8 * time.Hour), Trusted: true, Fresh: true}
					source = &sequenceConfidence{value: good, effective: sequenceCheckpoint(t, f).Watermark}
					current := f.e
					current.confidence = source
					current.manager = sequenceManager{f.m, source, t}
					label := f.c.Accounts[0].Label
					if s, err := current.Snapshot(context.Background(), label); err != nil || s.AccessToken != f.token {
						t.Fatal("stable pre-expiry positive control", err)
					}
					kinds := []string{"forward", "backward", "missing", "expiry", "authority-end", "stale"}
					event = sequenceEvent(rng, kinds[(int(seed)+index)%len(kinds)], base, expires, good.Now)
					if mode == "pending-recovery" {
						event = sequenceEvent(rng, "missing", base, expires, good.Now)
					}
					auditing = true
					switch target {
					case "watermark":
						good.Now = good.Now.Add(time.Millisecond)
						source.set(good)
						armed = true
						current.Snapshot(context.Background(), label)
					case "material-flush":
						source.mu.Lock()
						source.atCall = source.calls + 2
						source.onCall = func(TimeEvidence) TimeEvidence { triggered = true; return event }
						source.mu.Unlock()
						current.durableMaterial(context.Background(), current.accounts[label])
					default:
						armed = true
						current.Refresh(context.Background(), label, 1)
					}
					armed = false
					if !triggered {
						t.Fatal("requested completed boundary not exercised")
					}
					durable := sequenceCheckpoint(t, f).Watermark
					_, previous, _ := source.state()
					expired := !durable.Before(expires)
					if mode != "live" {
						source.set(good)
						current = sequenceReplace(t, f, current, source)
						_, previous, _ = source.state()
					}
					// Every sequence includes each behavior; random values and orders
					// explore neighboring corrections and admission interleavings.
					behaviors := append([]string{"stable"}, kinds...)
					for _, at := range rng.Perm(len(behaviors)) {
						kind := behaviors[at]
						_, model, _ := source.state()
						v := sequenceEvent(rng, kind, base, expires, model)
						source.set(v)
						if mode == "replacement" || mode == "pending-recovery" && rng.Intn(2) == 0 {
							current = sequenceReplace(t, f, current, source)
							_, previous, _ = source.state()
						}
						for _, entry := range rng.Perm(5) {
							before := sequenceCheckpoint(t, f)
							_, expectedFloor, calls := source.state()
							var snapshot owner.Snapshot
							var due bool
							var err error
							switch entry {
							case 0:
								snapshot, err = current.Snapshot(context.Background(), label)
							case 1:
								err = current.AdmitFreshHome(context.Background(), label)
							case 2:
								snapshot, err = current.Refresh(context.Background(), label, 1)
							case 3:
								due, err = current.Due(context.Background(), label)
							case 4:
								err = recoverTimeFixture(current, label)
							}
							after := sequenceCheckpoint(t, f)
							_, effective, afterCalls := source.state()
							current.clock.mu.Lock()
							actual := current.clock.observed
							current.clock.mu.Unlock()
							if actual.Before(previous) || actual.Before(effective) || after.Watermark.Before(durable) {
								t.Fatal("effective or durable time moved backwards")
							}
							previous, durable = actual, after.Watermark
							if !source.allowed() && (err == nil || snapshot.AccessToken != "" || due) {
								t.Fatal("admission outside independent authority")
							}
							if snapshot.AccessToken != "" {
								if expired || !after.Watermark.Before(expires) {
									t.Fatal("expired material revived")
								}
							}
							if entry == 0 && errors.Is(err, ErrUnavailable) && !after.Watermark.Before(expires) {
								expired = true
							}
							// Stable valid source observations must actually raise the
							// durable floor on a usable non-recovery admission.
							if entry != 4 && afterCalls > calls && source.allowed() && !current.accounts[label].blocked && before.PendingAttempt == "" {
								if v.Now.After(expectedFloor) {
									expectedFloor = v.Now
								}
								if after.Watermark.Before(expectedFloor) {
									t.Fatal("stable trusted sample not made durable")
								}
							}
						}
					}
				})
			}
		}
	}
}

// Claim: even a source advancing at both watermark completions costs at most
// two writes. An unpersisted final sample cannot itself expire material. On the
// next admission its sticky process floor is persisted, and that durable expiry
// cannot revive after a covered correction or public replacement restart.
func TestTimeAuthorityCompletionSequences(t *testing.T) {
	seeds := []int64{1, 7, 42, 20261023}
	t.Logf("reproduction seeds: %v", seeds)
	for _, seed := range seeds {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			var f *fixture
			armed := false
			writes := 0
			hook := func(stage string) error {
				if armed && stage == "directory-sync" {
					writes++
					if writes == 1 {
						f.t.advance(time.Duration(1+rng.Intn(250)) * time.Millisecond)
					} else {
						f.t.advance(2 * time.Second)
					}
				}
				return nil
			}
			f = fixtureHook(t, "safe", hook)
			f.t.advance(4*time.Hour - time.Second)
			corrected := f.t.now
			armed = true
			first, err := f.snapshot()
			cp := sequenceCheckpoint(t, f)
			if writes != 2 || err != nil || first.AccessToken != f.token || !cp.Watermark.Before(corrected.Add(time.Second)) {
				t.Fatal("decision used unpersisted postcheck time or exceeded bounded writes", writes, err)
			}
			armed = false
			f.t.mu.Lock()
			f.t.now = corrected
			f.t.mu.Unlock()
			if s, err := f.snapshot(); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || sequenceCheckpoint(t, f).Watermark.Before(corrected.Add(time.Second)) {
				t.Fatal("observed expiry floor lost before durable decision")
			}
			r := f.replacement(t)
			if s, err := r.Snapshot(context.Background(), f.c.Accounts[0].Label); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
				t.Fatal("durable expiry revived after replacement")
			}
		})
	}
}

// Claim: the process floor is shared across accounts, includes trusted samples
// even when their authority is insufficient, and cannot fall on correction or
// missing evidence. Per-account durable floors remain independent lower bounds.
func TestTimeAuthorityProcessFloor(t *testing.T) {
	base := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	e := &Engine{}
	first, second := &account{}, &account{}
	check := func(a *account, now, until, expected time.Time, valid bool) {
		t.Helper()
		e.confidence = fixedTimeProbe{TimeEvidence{Now: now, AuthorityUntil: until, Trusted: true, Fresh: true}}
		v, err := e.admissionTime(context.Background(), a, Checkpoint{Watermark: base})
		if valid {
			if err != nil || !v.Now.Equal(expected) {
				t.Fatal("shared process floor lost", err)
			}
		} else if !errors.Is(err, ErrUnavailable) {
			t.Fatal("missing or uncovered source admitted")
		}
	}
	future := base.Add(time.Hour)
	check(first, future, future.Add(time.Hour), future, true)
	check(second, base, future.Add(time.Hour), future, true)
	check(first, time.Time{}, future.Add(time.Hour), time.Time{}, false)
	check(second, future.Add(time.Minute), future, time.Time{}, false)
	check(first, base, future, time.Time{}, false)
	check(second, base, future.Add(time.Hour), future.Add(time.Minute), true)
}
