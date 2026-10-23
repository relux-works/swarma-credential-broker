//go:build linux

package authowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// Claim: the reflected watermark field is tested below its retained-history
// bound and at/beyond its independent authority bound on every admission path.
// Valid unchanged and covered sticky watermarks prevent reject-all behavior.
// Pending live cases explicitly restore/recover before ordinary admission;
// replacement cases use New. This is a finite boundary set, not arbitrary time.
func testWatermarkAdmissions(t *testing.T, history string, field retainedField) {
	t.Helper()
	if field.path != "watermark" {
		t.Fatal("watermark schema field required")
	}
	for _, boundary := range []string{"unchanged-control", "covered-sticky-control", "below-history", "authority-end", "beyond-authority"} {
		t.Run(boundary, func(t *testing.T) {
			for _, mode := range []string{"live", "replacement"} {
				t.Run(mode, func(t *testing.T) {
					for _, entry := range []string{"snapshot", "fresh-home", "writer", "due", "recovery"} {
						t.Run(entry, func(t *testing.T) {
							f := newFixture(t, "rotate")
							label := f.c.Accounts[0].Label
							if _, err := f.refresh(); err != nil {
								t.Fatal(err)
							}
							prefix := f.e.accounts[label].checkpoint
							if history != "committed" {
								scenario := strings.TrimPrefix(history, "pending-")
								if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte(scenario), 0600); err != nil {
									t.Fatal(err)
								}
								if _, err := f.e.Refresh(context.Background(), label, 2); err != nil {
									t.Fatal(err)
								}
							}
							cp := f.e.accounts[label].checkpoint
							pending := strings.HasPrefix(history, "pending-")
							if pending {
								settled := cp
								cp = prefix
								cp.Revision = settled.Revision - 1
								cp.State, cp.PendingAttempt = owner.Unavailable, settled.LastAttempt
							}
							// A valid writer control must reach a real fixture RPC, rather than
							// coalescing on a stale generation or returning before a safe retry.
							if entry == "writer" {
								f.t.advance(time.Second)
								if err := os.WriteFile(filepath.Join(f.home, "next-token"), []byte(jwt(f.t.now.Add(6*time.Hour), "synthetic-later-generation")), 0600); err != nil {
									t.Fatal(err)
								}
							}
							evidence, err := f.t.Validate(context.Background(), label, f.c.Accounts[0].HomeID, cp.StoreGeneration, cp.Watermark)
							if err != nil {
								t.Fatal(err)
							}
							var changed map[string]any
							raw, err := json.Marshal(cp)
							if err != nil || json.Unmarshal(raw, &changed) != nil {
								t.Fatal("checkpoint fixture")
							}
							valid := boundary == "unchanged-control" || boundary == "covered-sticky-control"
							switch boundary {
							case "covered-sticky-control":
								changed[field.path] = evidence.Now.Add(30 * time.Minute)
							case "below-history":
								substituteField(changed, field, "checkpoint", prefix.Watermark)
							case "authority-end":
								changed[field.path] = evidence.AuthorityUntil
							case "beyond-authority":
								changed[field.path] = evidence.AuthorityUntil.Add(time.Hour)
							}
							authorityPut(t, f, "owner-checkpoint.json", changed)
							before, err := f.disk.Records()
							if err != nil {
								t.Fatal(err)
							}
							starts := f.m.count()
							e := f.e
							if mode == "replacement" {
								e = f.replacement(t)
							}
							if mode == "live" && pending && entry != "recovery" {
								err := recoverTimeFixture(e, label)
								if valid && err != nil {
									t.Fatal("valid pending recovery refused", err)
								}
								if !valid && !errors.Is(err, ErrUnavailable) {
									t.Fatal("invalid pending recovery admitted", err)
								}
							}
							var result owner.Snapshot
							var due bool
							switch entry {
							case "snapshot":
								result, err = e.Snapshot(context.Background(), label)
							case "fresh-home":
								err = e.AdmitFreshHome(context.Background(), label)
							case "writer":
								result, err = e.Refresh(context.Background(), label, 2)
							case "due":
								due, err = e.Due(context.Background(), label)
							case "recovery":
								err = recoverTimeFixture(e, label)
							}
							if valid {
								if err != nil {
									t.Fatal("valid watermark refused", err)
								}
								if entry == "writer" {
									want := starts + 1
									if strings.Contains(history, "rejected") {
										want = starts
									}
									if f.m.count() != want {
										t.Fatal("valid writer control did not exercise expected transition")
									}
								}
								return
							}
							if !errors.Is(err, ErrUnavailable) || result.AccessToken != "" || due {
								t.Fatalf("watermark admitted by %s: %v", entry, err)
							}
							if f.m.count() != starts {
								t.Fatal("invalid time started writer")
							}
							after, err := f.disk.Records()
							if err != nil || len(before) != len(after) {
								t.Fatal("invalid time changed protected records")
							}
							for name, value := range before {
								if !bytes.Equal(value, after[name]) {
									t.Fatal("invalid time changed protected record", name)
								}
							}
						})
					}
				})
			}
		})
	}
}

func recoverTimeFixture(e *Engine, label string) error {
	a, err := e.enter(context.Background(), label, true)
	if err != nil {
		return err
	}
	defer e.leave(a)
	if err = e.restore(a); err != nil {
		return err
	}
	return e.recover(context.Background(), a)
}

type revokingTimeProbe struct {
	good, bad      TimeEvidence
	allowed, calls int
}

func (p *revokingTimeProbe) Validate(context.Context, string, string, uint64, time.Time) (TimeEvidence, error) {
	p.calls++
	if p.calls <= p.allowed {
		return p.good, nil
	}
	return p.bad, nil
}

// Claim: valid time for Snapshot and retry scheduling cannot authorize a writer
// after authority disappears. The writer rechecks before any intent/unit effect;
// the neighboring valid control commits actual replacement fixture material.
func TestWriterTimeRevalidation(t *testing.T) {
	for _, fault := range []string{"valid-control", "missing-instant", "uncovered-watermark"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, "rotate")
			good := TimeEvidence{Now: f.t.now, AuthorityUntil: f.t.now.Add(time.Hour), Trusted: true, Fresh: true}
			bad := good
			if fault == "missing-instant" {
				bad.Now = time.Time{}
			}
			if fault == "uncovered-watermark" {
				bad.Now, bad.AuthorityUntil = f.t.now.Add(-time.Hour), f.t.now
			}
			clock := &revokingTimeProbe{good: good, bad: bad, allowed: 2}
			f.e.confidence = clock
			before, err := f.disk.Records()
			if err != nil {
				t.Fatal(err)
			}
			s, err := f.refresh()
			if fault == "valid-control" {
				if err != nil || s.Generation != 2 || s.AccessToken != f.next || f.m.count() != 1 {
					t.Fatal("valid writer refused", err)
				}
				return
			}
			if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || f.m.count() != 0 || clock.calls != 3 {
				t.Fatal("time revoked before writer admitted", err, clock.calls)
			}
			after, err := f.disk.Records()
			if err != nil || len(before) != len(after) {
				t.Fatal("refused writer changed records")
			}
			for name, raw := range before {
				if !bytes.Equal(raw, after[name]) {
					t.Fatal("refused writer published records")
				}
			}
		})
	}
}

type timeRevokingClassifier struct {
	engine   *Engine
	evidence TimeEvidence
}

func (p timeRevokingClassifier) Classify(err RPCError) Disposition {
	p.engine.confidence = fixedTimeProbe{p.evidence}
	return (fakeClassifier{}).Classify(err)
}

// Claim: independently revoked time after vendor I/O cannot publish resolution
// or reopen admission. The already-started contained writer is stopped, but its
// pending history stays unresolved; valid time resolves the neighboring control.
func TestResolutionTimeRevalidation(t *testing.T) {
	for _, fault := range []string{"valid-control", "missing-instant", "uncovered-watermark"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, "safe")
			evidence := TimeEvidence{Now: f.t.now, AuthorityUntil: f.t.now.Add(time.Hour), Trusted: true, Fresh: true}
			if fault == "missing-instant" {
				evidence.Now = time.Time{}
			}
			if fault == "uncovered-watermark" {
				evidence.Now, evidence.AuthorityUntil = f.t.now.Add(-time.Hour), f.t.now
			}
			f.e.classifier = timeRevokingClassifier{f.e, evidence}
			s, err := f.refresh()
			a := f.e.accounts[f.c.Accounts[0].Label]
			if fault == "valid-control" {
				if err != nil || s.State != owner.Transient || a.checkpoint.PendingAttempt != "" {
					t.Fatal("valid resolution refused", err)
				}
				return
			}
			if !errors.Is(err, ErrUnavailable) || s.AccessToken != "" || a.checkpoint.PendingAttempt == "" || a.checkpoint.RetainedAttempts != 0 || f.m.count() != 1 {
				t.Fatal("invalid time published resolution", err)
			}
			records, err := f.disk.Records()
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range records {
				var v Evidence
				if json.Unmarshal(raw, &v) == nil && v.Phase == "resolved" {
					t.Fatal("invalid time appended resolved evidence")
				}
			}
			if _, err = f.snapshot(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unresolved time admitted snapshot")
			}
			if err = f.e.AdmitFreshHome(context.Background(), a.config.Label); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unresolved time admitted fresh home")
			}
			if _, err = f.refresh(); !errors.Is(err, ErrUnavailable) || f.m.count() != 1 {
				t.Fatal("unresolved time admitted another writer")
			}
		})
	}
}

// Claim: the one time rule requires independent trusted/fresh evidence and a
// nonzero instant, with an exclusive upper bound on max(Now, Watermark).
// Both covered clock directions are valid; provider errors never create time.
func TestAdmissionTimeAuthorityBounds(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, name := range []string{"current-control", "covered-sticky-control", "advanced-control", "untrusted", "stale", "missing-instant", "missing-authority", "now-at-limit", "now-beyond-limit", "watermark-at-limit", "watermark-beyond-limit", "provider-error"} {
		t.Run(name, func(t *testing.T) {
			evidence := TimeEvidence{Now: now, AuthorityUntil: now.Add(time.Hour), Trusted: true, Fresh: true}
			cp := Checkpoint{Watermark: now}
			valid := strings.HasSuffix(name, "-control")
			switch name {
			case "covered-sticky-control":
				cp.Watermark = now.Add(30 * time.Minute)
			case "advanced-control":
				cp.Watermark = now.Add(-30 * time.Minute)
			case "untrusted":
				evidence.Trusted = false
			case "stale":
				evidence.Fresh = false
			case "missing-instant":
				evidence.Now = time.Time{}
			case "missing-authority":
				evidence.AuthorityUntil = time.Time{}
			case "now-at-limit":
				evidence.Now = evidence.AuthorityUntil
			case "now-beyond-limit":
				evidence.Now = evidence.AuthorityUntil.Add(time.Second)
			case "watermark-at-limit":
				cp.Watermark = evidence.AuthorityUntil
			case "watermark-beyond-limit":
				cp.Watermark = evidence.AuthorityUntil.Add(time.Second)
			}
			provider := failingTimeProbe{evidence: evidence, fail: name == "provider-error"}
			e := &Engine{confidence: provider}
			result, err := e.admissionTime(context.Background(), &account{}, cp)
			if valid {
				want := now
				if cp.Watermark.After(want) {
					want = cp.Watermark
				}
				if err != nil || !result.Now.Equal(want) || !result.AuthorityUntil.Equal(evidence.AuthorityUntil) {
					t.Fatal("covered time refused", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || !result.Now.IsZero() {
				t.Fatal("invalid time supplied authority", err)
			}
		})
	}
}

type failingTimeProbe struct {
	evidence TimeEvidence
	fail     bool
}

func (p failingTimeProbe) Validate(context.Context, string, string, uint64, time.Time) (TimeEvidence, error) {
	if p.fail {
		return p.evidence, errors.New("synthetic independent time failure")
	}
	return p.evidence, nil
}
