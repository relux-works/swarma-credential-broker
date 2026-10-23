//go:build linux

package authowner

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Claim: every admission requires trusted time to cover the durable watermark.
// A future canonical watermark at or beyond AuthorityUntil cannot permit fresh
// home admission. An earlier sticky watermark within authority remains valid.
func TestFreshHomeWatermarkCoverageProbe(t *testing.T) {
	for _, history := range []string{"initial", "committed", "safe", "rejected"} {
		t.Run(history, func(t *testing.T) {
			for _, reopen := range []bool{false, true} {
				name := "live"
				if reopen {
					name = "replacement"
				}
				t.Run(name, func(t *testing.T) {
					for _, tc := range []struct {
						name   string
						offset time.Duration
						valid  bool
					}{{"unchanged-control", 0, true}, {"covered-sticky-control", 30 * time.Minute, true}, {"authority-end", time.Hour, false}, {"beyond-authority", 2 * time.Hour, false}} {
						t.Run(tc.name, func(t *testing.T) {
							mode := "rotate"
							if history == "safe" || history == "rejected" {
								mode = history
							}
							f := newFixture(t, mode)
							label := f.c.Accounts[0].Label
							if history != "initial" {
								if _, err := f.refresh(); err != nil {
									t.Fatal("history control", err)
								}
							}
							records, err := f.disk.Records()
							if err != nil {
								t.Fatal(err)
							}
							var cp Checkpoint
							if json.Unmarshal(records["owner-checkpoint.json"], &cp) != nil {
								t.Fatal("checkpoint")
							}
							cp.Watermark = f.t.now.Add(tc.offset)
							authorityPut(t, f, "owner-checkpoint.json", cp)
							e := f.e
							if reopen {
								e = f.replacement(t)
							}
							starts := f.m.count()
							s, readErr := e.Snapshot(context.Background(), label)
							freshErr := e.AdmitFreshHome(context.Background(), label)
							if tc.valid {
								if readErr != nil || freshErr != nil {
									t.Fatal("covered watermark refused", readErr, freshErr)
								}
								return
							}
							if !errors.Is(readErr, ErrUnavailable) || s.AccessToken != "" {
								t.Error("watermark outside authority admitted material")
							}
							if !errors.Is(freshErr, ErrUnavailable) {
								t.Errorf("watermark outside authority admitted fresh home: history=%s snapshot_unavailable=%t fresh_home_unavailable=%t", history, errors.Is(readErr, ErrUnavailable), errors.Is(freshErr, ErrUnavailable))
							}
							if f.m.count() != starts {
								t.Error("time fault started writer")
							}
						})
					}
				})
			}
		})
	}
}

// Claim: clock correction can expose the same boundary without changing any
// retained record. The sticky watermark must fit within fresh authority on both
// admission paths; a smaller correction that still covers it remains valid.
func TestFreshHomeClockCorrectionProbe(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		name := "live"
		if reopen {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				step  time.Duration
				valid bool
			}{{"covered-control", -30 * time.Minute, true}, {"authority-end", -time.Hour, false}, {"outside-authority", -2 * time.Hour, false}} {
				t.Run(tc.name, func(t *testing.T) {
					f := newFixture(t, "rotate")
					label := f.c.Accounts[0].Label
					if _, err := f.refresh(); err != nil {
						t.Fatal(err)
					}
					f.t.advance(tc.step)
					e := f.e
					if reopen {
						e = f.replacement(t)
					}
					s, readErr := e.Snapshot(context.Background(), label)
					freshErr := e.AdmitFreshHome(context.Background(), label)
					if tc.valid {
						if readErr != nil || freshErr != nil {
							t.Fatal("covered correction refused", readErr, freshErr)
						}
						return
					}
					if !errors.Is(readErr, ErrUnavailable) || s.AccessToken != "" {
						t.Error("uncovered correction admitted material")
					}
					if !errors.Is(freshErr, ErrUnavailable) {
						t.Errorf("uncovered correction admitted fresh home: snapshot_unavailable=%t fresh_home_unavailable=%t", errors.Is(readErr, ErrUnavailable), errors.Is(freshErr, ErrUnavailable))
					}
				})
			}
		})
	}
}

type fixedTimeProbe struct{ evidence TimeEvidence }

func (p fixedTimeProbe) Validate(context.Context, string, string, uint64, time.Time) (TimeEvidence, error) {
	return p.evidence, nil
}

// Claim: a freshness flag without a nonzero trusted instant is not authority.
// Both public admission paths reject missing time while normal evidence works.
func TestFreshHomeMissingTimeProbe(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		name := "live"
		if reopen {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			for _, missing := range []bool{false, true} {
				name := "time-control"
				if missing {
					name = "missing-instant"
				}
				t.Run(name, func(t *testing.T) {
					f := newFixture(t, "rotate")
					label := f.c.Accounts[0].Label
					evidence := TimeEvidence{Now: f.t.now, AuthorityUntil: f.t.now.Add(time.Hour), Trusted: true, Fresh: true}
					if missing {
						evidence.Now = time.Time{}
					}
					provider := fixedTimeProbe{evidence}
					e := f.e
					if reopen {
						f.e.Close()
						var err error
						e, err = New(context.Background(), f.c, f.m, provider, fakeClassifier{})
						if err != nil {
							t.Fatal(err)
						}
						defer e.Close()
					} else {
						e.confidence = provider
					}
					s, readErr := e.Snapshot(context.Background(), label)
					freshErr := e.AdmitFreshHome(context.Background(), label)
					if !missing {
						if readErr != nil || freshErr != nil {
							t.Fatal("valid time refused", readErr, freshErr)
						}
						return
					}
					if !errors.Is(readErr, ErrUnavailable) || s.AccessToken != "" {
						t.Error("missing time admitted material")
					}
					if !errors.Is(freshErr, ErrUnavailable) {
						t.Errorf("missing time admitted fresh home: snapshot_unavailable=%t fresh_home_unavailable=%t", errors.Is(readErr, ErrUnavailable), errors.Is(freshErr, ErrUnavailable))
					}
				})
			}
		})
	}
}
