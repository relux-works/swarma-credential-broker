//go:build linux

package authowner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// Claim: generated initial/first/final catch-up crossings never serve expired
// material. Covered neighbors grant, authority-end neighbors refuse without a
// further effect, and durable expiry survives correction and replacement.
// These finite seeds do not model asynchronous revocation between instructions.
func TestExpiryCatchupSequences(t *testing.T) {
	for _, seed := range []int64{1, 7, 42, 20261023} {
		for position := 0; position <= 2; position++ {
			for _, mode := range []string{"covered", "expiry", "authority-end"} {
				t.Run(fmt.Sprintf("seed-%d/position-%d/%s", seed, position, mode), func(t *testing.T) {
					rng := rand.New(rand.NewSource(seed + int64(position)))
					var source *sequenceConfidence
					armed, writes := false, 0
					var crossing time.Time
					hook := func(stage string) error {
						if armed && stage == "write" && !source.allowed() {
							t.Error("write outside exclusive authority")
						}
						if armed && stage == "directory-sync" {
							writes++
							v, _, _ := source.state()
							if writes == position {
								v.Now = crossing
							} else if writes < position {
								v.Now = v.Now.Add(time.Duration(1+rng.Intn(100)) * time.Millisecond)
							}
							source.set(v)
						}
						return nil
					}
					f := fixtureHook(t, "safe", hook)
					expiry := f.t.now.Add(4 * time.Hour)
					crossing = expiry.Add(time.Duration(1+rng.Intn(250)) * time.Millisecond)
					if mode == "covered" {
						crossing = expiry.Add(-time.Duration(1+rng.Intn(250)) * time.Millisecond)
					}
					v := TimeEvidence{Now: expiry.Add(-time.Second), AuthorityUntil: expiry.Add(time.Hour), Trusted: true, Fresh: true}
					if mode == "authority-end" {
						v.AuthorityUntil = crossing
					}
					if position == 0 {
						v.Now = crossing
					}
					source = &sequenceConfidence{value: v}
					f.e.confidence = source
					before := sequenceCheckpoint(t, f).Watermark
					armed = true
					got, err := f.snapshot()
					armed = false
					cp := sequenceCheckpoint(t, f)
					_, effective, _ := source.state()
					if cp.Watermark.Before(before) || effective.Before(cp.Watermark) {
						t.Fatal("time floors decreased or durable time exceeds effective time")
					}
					if mode == "covered" {
						if err != nil || got.AccessToken != f.token || !effective.Before(expiry) {
							t.Fatal("covered control refused", err)
						}
					} else {
						if !errors.Is(err, ErrUnavailable) || got.AccessToken != "" {
							t.Fatal("invalid material served at effective time")
						}
						if mode == "expiry" && cp.Watermark.Before(effective) {
							t.Fatal("expiry refusal not durable at refusing effective time")
						}
					}
					bound := 2
					if mode == "expiry" && position == 2 {
						bound = 3
					}
					if writes > bound {
						t.Fatal("bounded admission/refusal write cost exceeded", writes)
					}
					if mode == "expiry" {
						v.Now = expiry.Add(-2 * time.Second)
						source.set(v)
						oldWrites := writes
						armed = true
						second, secondErr := f.snapshot()
						armed = false
						if !errors.Is(secondErr, ErrUnavailable) || second.AccessToken != "" || writes != oldWrites {
							t.Fatal("correction revived material or repeated refusal write")
						}
						r := sequenceReplace(t, f, f.e, source)
						if s, err := r.Snapshot(context.Background(), f.c.Accounts[0].Label); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
							t.Fatal("replacement revived material")
						}
					}
					if f.m.count() != 0 {
						t.Fatal("snapshot started writer")
					}
				})
			}
		}
	}
}

// Claim: failure before publication or at completion of the extra refusal
// raise closes live admission. A completed watermark also closes replacement;
// pre-publication failure cannot itself persist evidence across replacement.
func TestExpiryRefusalRaiseFailure(t *testing.T) {
	for _, stage := range []string{"write", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			var f *fixture
			armed, writes := false, 0
			hook := func(at string) error {
				if !armed {
					return nil
				}
				if at == "write" {
					writes++
				}
				if at == "directory-sync" && writes <= 2 {
					f.t.advance(2 * time.Second)
				}
				if writes == 3 && at == stage {
					return errors.New("fixture refusal raise interruption")
				}
				return nil
			}
			f = fixtureHook(t, "safe", hook)
			// First completion stays covered, second crosses expiry.
			f.t.advance(4*time.Hour - 3*time.Second)
			corrected := f.t.now
			armed = true
			s, err := f.snapshot()
			armed = false
			if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || !f.e.accounts[f.c.Accounts[0].Label].blocked || writes != 3 {
				t.Fatal("failed refusal raise did not close account", writes, err)
			}
			f.t.mu.Lock()
			f.t.now = corrected
			f.t.mu.Unlock()
			if s, err := f.snapshot(); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
				t.Fatal("failed refusal raise released material on correction")
			}
			if stage == "directory-sync" {
				r := f.replacement(t)
				if s, err := r.Snapshot(context.Background(), f.c.Accounts[0].Label); !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
					t.Fatal("completed refusal raise revived after replacement")
				}
			}
		})
	}
}

// Claim: generated retry-not-ready returns use their second admission's E;
// covered neighbors still grant and exclusive-authority neighbors refuse. No
// case starts a second writer inside the safe interval.
func TestRetryExpirySequences(t *testing.T) {
	for _, seed := range []int64{1, 7, 42, 20261023} {
		for _, mode := range []string{"covered", "expiry", "authority-end"} {
			t.Run(fmt.Sprintf("seed-%d/%s", seed, mode), func(t *testing.T) {
				rng := rand.New(rand.NewSource(seed))
				f := newFixture(t, "safe")
				expiry := f.t.now.Add(4 * time.Hour)
				f.t.advance(4*time.Hour - 500*time.Millisecond)
				if s, err := f.refresh(); err != nil || s.AccessToken != f.token {
					t.Fatal("safe retry setup", err)
				}
				next := expiry.Add(time.Duration(1+rng.Intn(250)) * time.Millisecond)
				if mode == "covered" {
					next = expiry.Add(-time.Duration(1+rng.Intn(250)) * time.Millisecond)
				}
				source := &sequenceConfidence{value: TimeEvidence{Now: f.t.now, AuthorityUntil: expiry.Add(time.Hour), Trusted: true, Fresh: true}, atCall: 2}
				source.onCall = func(v TimeEvidence) TimeEvidence {
					v.Now = next
					if mode == "authority-end" {
						v.AuthorityUntil = next
					}
					return v
				}
				f.e.confidence = source
				s, err := f.e.Refresh(context.Background(), f.c.Accounts[0].Label, 1)
				_, effective, _ := source.state()
				cp := sequenceCheckpoint(t, f)
				if mode == "covered" {
					if err != nil || s.AccessToken != f.token || !effective.Before(s.ExpiresAt) {
						t.Fatal("covered retry refused", err)
					}
				} else if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" {
					t.Fatal("retry served material invalid at latest effective time")
				}
				if mode == "expiry" && cp.Watermark.Before(effective) {
					t.Fatal("retry expiry refusal not durable")
				}
				if f.m.count() != 1 || !cp.Watermark.Before(cp.RetryAt) {
					t.Fatal("safe interval not preserved")
				}
			})
		}
	}
}
