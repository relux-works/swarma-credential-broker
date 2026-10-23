//go:build linux

package authowner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Claim: public material release must obey max(trusted now, durable watermark).
// A trusted expiry crossing at the second watermark completion cannot authorize
// material, even when a bounded persistence policy declines another write.
// Adjacent covered and exclusive-authority controls distinguish expiry from
// confidence refusal. No real clock or account state is changed.
func TestFinalCompletionExpiryProbe(t *testing.T) {
	for _, mode := range []string{"covered-control", "expiry-crossing", "authority-end"} {
		t.Run(mode, func(t *testing.T) {
			var f *fixture
			armed := false
			writes := 0
			hook := func(stage string) error {
				if armed && stage == "directory-sync" {
					writes++
					if writes == 1 {
						f.t.advance(100 * time.Millisecond)
					}
					if writes == 2 {
						step := 100 * time.Millisecond
						if mode == "expiry-crossing" {
							step = 2 * time.Second
						}
						f.t.advance(step)
					}
				}
				return nil
			}
			f = fixtureHook(t, "safe", hook)
			expiry := f.t.now.Add(4 * time.Hour)
			f.t.advance(4*time.Hour - time.Second)
			if mode == "authority-end" {
				source := &sequenceConfidence{value: TimeEvidence{Now: f.t.now, AuthorityUntil: f.t.now.Add(200 * time.Millisecond), Trusted: true, Fresh: true}}
				// Each write has a precheck and postcheck, after the initial sample.
				source.atCall = 5
				source.onCall = func(v TimeEvidence) TimeEvidence { v.Now = v.AuthorityUntil; return v }
				f.e.confidence = source
				// Source's first completion must advance to require the catch-up.
				source.atCall = 3
				source.onCall = func(v TimeEvidence) TimeEvidence {
					v.Now = v.Now.Add(100 * time.Millisecond)
					source.atCall = 5
					source.onCall = func(v TimeEvidence) TimeEvidence { v.Now = v.AuthorityUntil; return v }
					return v
				}
			}
			armed = true
			got, err := f.snapshot()
			armed = false
			cp := sequenceCheckpoint(t, f)
			t.Logf("writes=%d persisted_before_expiry=%t observed_at_or_after_expiry=%t material=%t unavailable=%t", writes, cp.Watermark.Before(expiry), !f.t.now.Before(expiry), got.AccessToken != "", errors.Is(err, ErrUnavailable))
			wantWrites := 2
			if mode == "expiry-crossing" {
				wantWrites = 3
			}
			if writes != wantWrites {
				t.Fatal("second completion not reached", writes)
			}
			if mode == "covered-control" {
				if err != nil || got.AccessToken != f.token {
					t.Fatal("covered control refused", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || got.AccessToken != "" {
				t.Error("material released after trusted expiry or exclusive authority end")
			}
			if mode == "expiry-crossing" {
				if cp.Watermark.Before(f.t.now) {
					t.Fatal("refusal time not durable")
				}
				armed = true
				second, secondErr := f.snapshot()
				armed = false
				if !errors.Is(secondErr, ErrUnavailable) || second.AccessToken != "" || writes != wantWrites {
					t.Fatal("durable expiry repeated a refusal write or revived material")
				}
			}
			if f.m.count() != 0 {
				t.Fatal("snapshot started writer")
			}
		})
	}
}

// Claim: returning an existing snapshot during safe retry must revalidate that
// snapshot against the latest durable time observed by the same Refresh call.
// The public safe resolution establishes retry_at just beyond token expiry;
// the next confidence sample crosses expiry while still before retry_at.
func TestRefreshRetryExpiryProbe(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		name := "covered-control"
		if crossed {
			name = "expiry-crossing"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "safe")
			expiry := f.t.now.Add(4 * time.Hour)
			f.t.advance(4*time.Hour - 500*time.Millisecond)
			if s, err := f.refresh(); err != nil || s.AccessToken != f.token {
				t.Fatal("safe resolution control", err)
			}
			cp := sequenceCheckpoint(t, f)
			if !cp.RetryAt.After(expiry) || f.m.count() != 1 {
				t.Fatal("retry boundary not established")
			}
			next := expiry.Add(-250 * time.Millisecond)
			if crossed {
				next = expiry.Add(100 * time.Millisecond)
			}
			source := &sequenceConfidence{value: TimeEvidence{Now: f.t.now, AuthorityUntil: expiry.Add(time.Hour), Trusted: true, Fresh: true}, atCall: 2}
			source.onCall = func(v TimeEvidence) TimeEvidence { v.Now = next; return v }
			f.e.confidence = source
			got, err := f.e.Refresh(context.Background(), f.c.Accounts[0].Label, 1)
			after := sequenceCheckpoint(t, f)
			t.Logf("persisted_at_or_after_expiry=%t before_retry=%t material=%t unavailable=%t", !after.Watermark.Before(expiry), after.Watermark.Before(after.RetryAt), got.AccessToken != "", errors.Is(err, ErrUnavailable))
			if crossed {
				if after.Watermark.Before(expiry) {
					t.Fatal("expiry crossing not durable")
				}
				if !errors.Is(err, ErrUnavailable) || got.AccessToken != "" {
					t.Error("retry path returned snapshot expired by its own durable time")
				}
			} else if err != nil || got.AccessToken != f.token {
				t.Fatal("covered retry control refused", err)
			}
			if f.m.count() != 1 {
				t.Fatal("retry interval started another writer")
			}
		})
	}
}
