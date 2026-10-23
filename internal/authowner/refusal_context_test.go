//go:build linux

package authowner

import (
	"context"
	"errors"
	"testing"
	"time"
)

type resolutionGenerationConfidence struct {
	source     *sequenceConfidence
	t          *testing.T
	generation uint64
}

func (s resolutionGenerationConfidence) Validate(ctx context.Context, label, home string, generation uint64, floor time.Time) (TimeEvidence, error) {
	if generation != s.generation {
		s.t.Errorf("refusal raise validated generation %d, want prospective %d", generation, s.generation)
		return TimeEvidence{}, ErrUnavailable
	}
	return s.source.Validate(ctx, label, home, generation, floor)
}

// Claim: a committed resolution's refusal raise validates its prospective
// generation while persisting only a watermark, and its covered neighbor stamps
// D rather than the newer final E. This tests the resolution boundary with a
// synthetic prospective checkpoint, not a native vendor transaction.
func TestResolutionRefusalContext(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		name := "covered"
		if crossed {
			name = "expiry"
		}
		t.Run(name, func(t *testing.T) {
			var source *sequenceConfidence
			armed, writes := false, 0
			hook := func(stage string) error {
				if armed && stage == "directory-sync" {
					writes++
					v, _, _ := source.state()
					if writes == 1 {
						v.Now = v.Now.Add(100 * time.Millisecond)
					}
					if writes == 2 {
						step := 100 * time.Millisecond
						if crossed {
							step = 2 * time.Second
						}
						v.Now = v.Now.Add(step)
					}
					source.set(v)
				}
				return nil
			}
			f := fixtureHook(t, "safe", hook)
			a := f.e.accounts[f.c.Accounts[0].Label]
			expiry := f.t.now.Add(4 * time.Hour)
			source = &sequenceConfidence{value: TimeEvidence{Now: expiry.Add(-time.Second), AuthorityUntil: expiry.Add(time.Hour), Trusted: true, Fresh: true}}
			c := a.checkpoint
			c.StoreGeneration++
			f.e.confidence = resolutionGenerationConfidence{source, t, c.StoreGeneration}
			armed = true
			stamp, err := f.e.clock.resolution(context.Background(), f.e, a, &c, time.Time{}, expiry, Committed, 0)
			armed = false
			cp := sequenceCheckpoint(t, f)
			_, effective, _ := source.state()
			if cp.StoreGeneration != 1 {
				t.Fatal("refusal raise published prospective generation")
			}
			if crossed {
				if !errors.Is(err, ErrUnavailable) || writes != 3 || cp.Watermark.Before(effective) {
					t.Fatal("prospective expiry refusal not durable", writes, err)
				}
			} else if err != nil || writes != 2 || !stamp.Equal(cp.Watermark) || !stamp.Before(effective) {
				t.Fatal("covered resolution did not stamp durable time", writes, err)
			}
		})
	}
}

// Claim: a trusted sample from another account between admission and material
// decision narrows that decision. Expiry persists refusal; an uncovered shared
// floor refuses without writing; a covered pre-expiry neighbor still grants.
func TestMaterialDecisionProcessFloor(t *testing.T) {
	for _, mode := range []string{"covered", "expiry", "authority-end"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "safe")
			a := f.e.accounts[f.c.Accounts[0].Label]
			expiry := f.t.now.Add(4 * time.Hour)
			v := TimeEvidence{Now: f.t.now, AuthorityUntil: expiry.Add(time.Hour), Trusted: true, Fresh: true}
			other := v
			other.Now = expiry.Add(-time.Second)
			if mode == "expiry" {
				other.Now = expiry.Add(time.Second)
			}
			if mode == "authority-end" {
				other.Now = v.AuthorityUntil
				other.AuthorityUntil = other.Now.Add(time.Hour)
			}
			f.e.confidence = fixedTimeProbe{other}
			if _, err := f.e.admissionTime(context.Background(), &account{}, Checkpoint{}); err != nil {
				t.Fatal("other account sample", err)
			}
			before := sequenceCheckpoint(t, f)
			err := f.e.clock.materialAvailable(context.Background(), f.e, a, a.checkpoint, v, expiry)
			after := sequenceCheckpoint(t, f)
			if mode == "covered" {
				if err != nil {
					t.Fatal("covered shared-floor control refused", err)
				}
			} else if !errors.Is(err, ErrUnavailable) {
				t.Fatal("material decision ignored shared effective time")
			}
			if mode == "expiry" && after.Watermark.Before(other.Now) {
				t.Fatal("shared-floor expiry not durable")
			}
			if mode == "authority-end" && after.Revision != before.Revision {
				t.Fatal("uncovered shared floor authorized write")
			}
		})
	}
}
