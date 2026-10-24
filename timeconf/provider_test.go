package timeconf

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func testPolicy() Policy {
	return Policy{Source: NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: time.Minute, MaxUncertainty: 20 * time.Millisecond, MaxOffset: 10 * time.Millisecond, MaxRootDistance: 20 * time.Millisecond, AuthorityWindow: 30 * time.Second, StepTolerance: 100 * time.Millisecond, Timeout: 100 * time.Millisecond, MaxOutputBytes: 4096, Resync: "new-authenticated-sync"}
}
func evidenceAt(now time.Time) Evidence {
	return Evidence{Tracking: Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: now.Add(-time.Second), Leap: "Normal", SystemOffset: 0.001, LastOffset: 0.001, RMSOffset: 0.001, RootDelay: 0.002, RootDispersion: 0.001, UpdateInterval: 10, Skew: 0.1}, Sources: Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}, Authentication: Authentication{Addresses: map[string]bool{"192.0.2.1": true}}}
}

type fakeCollector struct {
	evidence Evidence
	err      error
	calls    int
}

func (f *fakeCollector) Collect(context.Context, Policy) (Evidence, error) {
	f.calls++
	return f.evidence, f.err
}

type fakeClock struct {
	point ClockPoint
	err   error
}

func (f *fakeClock) Read(context.Context) (ClockPoint, error) { return f.point, f.err }
func providerFixture(t *testing.T) (*Provider, *fakeCollector, *fakeClock) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	c := &fakeCollector{evidence: evidenceAt(now)}
	clock := &fakeClock{point: ClockPoint{Now: now, Elapsed: time.Hour, Boot: "fixture-boot"}}
	p, err := New(testPolicy(), c, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, c, clock
}
func refused(t *testing.T, p *Provider) {
	t.Helper()
	v, err := p.Sample(context.Background())
	if !errors.Is(err, ErrUnavailable) || v.Trusted || v.Fresh || !v.Now.IsZero() || !v.AuthorityUntil.IsZero() {
		t.Fatal("untrusted evidence supplied authority")
	}
}
func trusted(t *testing.T, p *Provider) Sample {
	t.Helper()
	v, err := p.Sample(context.Background())
	if err != nil || !v.Trusted || !v.Fresh || v.Now.IsZero() || !v.Now.Before(v.AuthorityUntil) {
		t.Fatal("valid evidence refused", err)
	}
	return v
}

// Claim: a collector error refuses even a well-formed, in-tolerance evidence
// prefix; clearing that error permits the adjacent positive control.
func TestCollectorErrorsNeverTrust(t *testing.T) {
	p, c, _ := providerFixture(t)
	c.err = errors.New("fixture collector failure")
	refused(t, p)
	c.err = nil
	trusted(t, p)
}

// Claim: each configured tolerance, missing authority field and invalid leap
// refuses with no authority; the same provider admits the nearby valid evidence.
func TestEvidenceBounds(t *testing.T) {
	cases := map[string]func(*Evidence, time.Time){
		"unconfigured-selected": func(e *Evidence, _ time.Time) { e.Sources.Entries = []string{"192.0.2.2"} },
		"non-nts":               func(e *Evidence, _ time.Time) { e.Sources.AllNTS = false },
		"no-sources":            func(e *Evidence, _ time.Time) { e.Sources.Count = 0 },
		"leap-insert":           func(e *Evidence, _ time.Time) { e.Tracking.Leap = "Insert second" },
		"leap-delete":           func(e *Evidence, _ time.Time) { e.Tracking.Leap = "Delete second" },
		"unsynchronized":        func(e *Evidence, _ time.Time) { e.Tracking.Leap = "Not synchronised" },
		"system-offset":         func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = 0.011 },
		"negative-offset":       func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = -0.011 },
		"last-offset":           func(e *Evidence, _ time.Time) { e.Tracking.LastOffset = 0.011 },
		"rms-offset":            func(e *Evidence, _ time.Time) { e.Tracking.RMSOffset = 0.011 },
		"root-delay":            func(e *Evidence, _ time.Time) { e.Tracking.RootDelay = 0.041 },
		"root-dispersion":       func(e *Evidence, _ time.Time) { e.Tracking.RootDispersion = 0.021 },
		"stale":                 func(e *Evidence, n time.Time) { e.Tracking.Reference = n.Add(-time.Minute) },
		"future":                func(e *Evidence, n time.Time) { e.Tracking.Reference = n.Add(time.Nanosecond) },
		"missing-reference":     func(e *Evidence, _ time.Time) { e.Tracking.Reference = time.Time{} },
		"stratum":               func(e *Evidence, _ time.Time) { e.Tracking.Stratum = 16 },
		"frequency":             func(e *Evidence, _ time.Time) { e.Tracking.Frequency = 1e7 },
		"residual":              func(e *Evidence, _ time.Time) { e.Tracking.ResidualFrequency = -1e7 },
		"skew":                  func(e *Evidence, _ time.Time) { e.Tracking.Skew = -1 },
		"update-interval":       func(e *Evidence, _ time.Time) { e.Tracking.UpdateInterval = math.NaN() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, c, clock := providerFixture(t)
			good := c.evidence
			change(&c.evidence, clock.point.Now)
			refused(t, p)
			c.evidence = good
			trusted(t, p)
		})
	}
}

// Claim: both negative wall/elapsed deltas and excessive positive steps hold
// across valid repeated samples; only a later new authenticated sync clears it.
// Ordinary collection failure cannot erase the hold. State is provider-local.
func TestClockStepHold(t *testing.T) {
	for _, name := range []string{"backward", "relative-backward", "forward"} {
		t.Run(name, func(t *testing.T) {
			p, c, clock := providerFixture(t)
			trusted(t, p)
			base := clock.point.Now
			clock.point.Elapsed += 2 * time.Second
			if name == "backward" {
				clock.point.Now = base.Add(-time.Second)
				c.evidence.Tracking.Reference = base.Add(-2 * time.Second)
			} else if name == "relative-backward" {
				clock.point.Now = base.Add(time.Second)
			} else {
				clock.point.Now = base.Add(4 * time.Second)
			}
			refused(t, p)
			refused(t, p)
			c.err = errors.New("fixture loss")
			refused(t, p)
			c.err = nil
			refused(t, p)
			clock.point.Now = base.Add(10 * time.Second)
			clock.point.Elapsed += clock.point.Now.Sub(p.last.Now)
			// This matching delta preserves the hold until a new sync is observed.
			refused(t, p)
			c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Nanosecond)
			trusted(t, p)
		})
	}
}

// Claim: operator-only recovery never clears through tracking alone; a changed
// boot discards the comparison but cannot authorize stale or failed evidence.
func TestBootAndOperatorHold(t *testing.T) {
	p, c, clock := providerFixture(t)
	p.policy.Resync = "operator"
	trusted(t, p)
	clock.point.Now = clock.point.Now.Add(-time.Second)
	clock.point.Elapsed += time.Second
	c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Second)
	refused(t, p)
	clock.point.Now = clock.point.Now.Add(10 * time.Second)
	clock.point.Elapsed += 10 * time.Second
	c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Nanosecond)
	refused(t, p)
	clock.point.Boot = "next-fixture-boot"
	clock.point.Elapsed = time.Second
	c.err = errors.New("no new evidence")
	refused(t, p)
	c.err = nil
	c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Minute)
	refused(t, p)
	c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Second)
	trusted(t, p)
}

// Claim: a hold is detected even while the collector fails, and fresh authdata
// must cover the selected source and every reported association for option B.
func TestFailedCollectorClockAndAuthentication(t *testing.T) {
	p, c, clock := providerFixture(t)
	trusted(t, p)
	clock.point.Now = clock.point.Now.Add(-time.Second)
	clock.point.Elapsed += time.Second
	c.err = errors.New("fixture failure")
	refused(t, p)
	c.err = nil
	c.evidence.Tracking.Reference = clock.point.Now.Add(-time.Second)
	refused(t, p)
	p, c, _ = providerFixture(t)
	p.policy.Source = NTSAuthData
	c.evidence.Authentication.Addresses = map[string]bool{"192.0.2.2": true}
	refused(t, p)
	c.evidence.Authentication.Addresses = map[string]bool{"192.0.2.1": true, "192.0.2.2": false}
	refused(t, p)
	c.evidence.Authentication.Addresses = map[string]bool{"192.0.2.1": true}
	trusted(t, p)
}

// Claim: the exclusive grant endpoint is the earlier of window and evidence
// expiry. Invalid clocks refuse without a synthetic timestamp or trusted flags.
func TestAuthorityWindowAndClockFailure(t *testing.T) {
	p, c, clock := providerFixture(t)
	c.evidence.Tracking.Reference = clock.point.Now.Add(-59 * time.Second)
	v := trusted(t, p)
	if !v.AuthorityUntil.Equal(clock.point.Now.Add(time.Second)) {
		t.Fatal("window extended evidence freshness")
	}
	clock.err = errors.New("clock failed")
	refused(t, p)
	clock.err = nil
	clock.point.Boot = ""
	refused(t, p)
}

// Claim: missing production policy selects no source even when environment
// hints request one; the provider neither samples clocks nor invokes collectors.
func TestProductionDefaultOff(t *testing.T) {
	t.Setenv("TIME_CONFIDENCE_SOURCE", string(NTSConfig))
	p, err := Production(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, p)
}

// Claim: one provider serializes simultaneous consumers without data races or
// losing independent authority checks. These fixed samples do not model I/O.
func TestConcurrentSamples(t *testing.T) {
	p, _, _ := providerFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := p.Sample(context.Background())
			if err != nil || !v.Trusted {
				t.Error("concurrent sample refused")
			}
		}()
	}
	wg.Wait()
}

// Claim: delta includes measured correction plus root distance, grows with each
// correction/delay/dispersion/skew component and age, and is rounded upward.
func TestUncertaintyBoundAndMonotonicity(t *testing.T) {
	changes := map[string]func(*Tracking){
		"system":     func(v *Tracking) { v.SystemOffset = -0.002 },
		"last":       func(v *Tracking) { v.LastOffset = 0.002 },
		"rms":        func(v *Tracking) { v.RMSOffset = 0.002 },
		"delay":      func(v *Tracking) { v.RootDelay += 0.001 },
		"dispersion": func(v *Tracking) { v.RootDispersion += 0.001 },
		"skew":       func(v *Tracking) { v.Skew += 0.1 },
		"age":        func(v *Tracking) { v.Reference = v.Reference.Add(-time.Second) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p, c, clock := providerFixture(t)
			base := trusted(t, p)
			change(&c.evidence.Tracking)
			got := trusted(t, p)
			if got.Uncertainty <= base.Uncertainty {
				t.Fatal("uncertainty did not grow")
			}
			x := c.evidence.Tracking
			min := time.Duration((math.Abs(x.SystemOffset) + x.RootDelay/2 + x.RootDispersion) * float64(time.Second))
			if got.Uncertainty < min || got.Boot != clock.point.Boot {
				t.Fatal("uncertainty/boot bound missing")
			}
		})
	}
}

// Claim: process-start sampling collects again, includes uncertainty and boot,
// and cannot reuse a previously trusted sample after evidence loss.
func TestStartSampleFreshEvidence(t *testing.T) {
	p, c, clock := providerFixture(t)
	trusted(t, p)
	c.err = errors.New("lost evidence")
	got, err := p.StartSample(context.Background())
	if !errors.Is(err, ErrUnavailable) || got != (Sample{}) {
		t.Fatal("cached start authority")
	}
	c.err = nil
	got, err = p.StartSample(context.Background())
	if err != nil || got.Uncertainty <= 0 || got.Boot != clock.point.Boot || c.calls != 3 {
		t.Fatal("start sample incomplete")
	}
}

// Claim: zero backward tolerance holds on even one nanosecond of relative
// backward motion, alongside an equal wall/elapsed advance that stays trusted.
func TestZeroBackwardThreshold(t *testing.T) {
	for _, backward := range []bool{false, true} {
		p, _, clock := providerFixture(t)
		trusted(t, p)
		clock.point.Now = clock.point.Now.Add(time.Second)
		clock.point.Elapsed += time.Second
		if backward {
			clock.point.Now = clock.point.Now.Add(-time.Nanosecond)
			refused(t, p)
		} else {
			trusted(t, p)
		}
	}
}

func platformTestPolicy() Policy {
	p := testPolicy()
	p.MaxSyncAge = PlatformMaxSyncAge
	p.MaxUncertainty = PlatformMaxUncertainty
	p.MaxOffset = PlatformMaxOffset
	p.MaxRootDistance = PlatformMaxRootDistance
	p.AuthorityWindow = PlatformAuthorityWindow
	p.BackwardTolerance = PlatformBackwardTolerance
	p.StepTolerance = time.Second
	return p
}

// Claim: the shared age/offset/root-distance ceilings admit the exact permitted
// numeric bound and its tighter neighbor; freshness's exclusive endpoint refuses
// exactly 2048s, while 2048s-1ns retains a one-nanosecond authority interval.
func TestPlatformEvidenceBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Evidence, time.Time)
		ok     bool
	}{
		{"age-before", func(e *Evidence, n time.Time) { e.Tracking.Reference = n.Add(-2048*time.Second + time.Nanosecond) }, true},
		{"age-at", func(e *Evidence, n time.Time) { e.Tracking.Reference = n.Add(-2048 * time.Second) }, false},
		{"age-after", func(e *Evidence, n time.Time) { e.Tracking.Reference = n.Add(-2048*time.Second - time.Nanosecond) }, false},
		{"offset-below", func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = 0.5 - 1e-9 }, true},
		{"offset-at", func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = 0.5 }, true},
		{"offset-above", func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = 0.5 + 1e-9 }, false},
		{"negative-offset-at", func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = -0.5 }, true},
		{"negative-offset-beyond", func(e *Evidence, _ time.Time) { e.Tracking.SystemOffset = -0.5 - 1e-9 }, false},
		{"distance-below", func(e *Evidence, _ time.Time) { e.Tracking.RootDelay = 0; e.Tracking.RootDispersion = 1 - 1e-9 }, true},
		{"distance-at", func(e *Evidence, _ time.Time) { e.Tracking.RootDelay = 0; e.Tracking.RootDispersion = 1 }, true},
		{"distance-above", func(e *Evidence, _ time.Time) { e.Tracking.RootDelay = 0; e.Tracking.RootDispersion = 1 + 1e-9 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c, clock := providerFixture(t)
			tc.change(&c.evidence, clock.point.Now)
			p, err := New(platformTestPolicy(), c, clock, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ok {
				v := trusted(t, p)
				if tc.name == "age-before" && v.AuthorityUntil.Sub(v.Now) != time.Nanosecond {
					t.Fatal("freshness cap lost")
				}
			} else {
				refused(t, p)
			}
		})
	}
	p, c, clock := providerFixture(t)
	p.policy = platformTestPolicy()
	c.evidence.Tracking.Reference = clock.point.Now
	if v := trusted(t, p); v.AuthorityUntil.Sub(v.Now) != 5*time.Minute {
		t.Fatal("shared five minute window changed")
	}
}

// Claim: a relative backward step at/below the shared one-second bound remains
// usable, while its adjacent larger value holds; the broker's stricter zero
// threshold is covered separately. Forward tolerance also has an exact boundary.
func TestPlatformStepBoundaries(t *testing.T) {
	for _, direction := range []string{"backward", "forward"} {
		for _, delta := range []time.Duration{time.Second - time.Nanosecond, time.Second, time.Second + time.Nanosecond} {
			t.Run(direction+"/"+delta.String(), func(t *testing.T) {
				p, _, clock := providerFixture(t)
				p.policy = platformTestPolicy()
				trusted(t, p)
				clock.point.Elapsed += 2 * time.Second
				wallDelta := 2*time.Second - delta
				if direction == "forward" {
					wallDelta = 2*time.Second + delta
				}
				clock.point.Now = clock.point.Now.Add(wallDelta)
				if delta > time.Second {
					refused(t, p)
				} else {
					trusted(t, p)
				}
			})
		}
	}
}

// Claim: all loaded policies are bounded by the platform ceilings, independent
// of the embedding service's own shared-policy comparison.
func TestPlatformPolicyCeilings(t *testing.T) {
	for _, field := range []string{"MaxSyncAge", "MaxUncertainty", "MaxOffset", "MaxRootDistance", "AuthorityWindow", "BackwardTolerance"} {
		q := platformTestPolicy()
		v := reflect.ValueOf(&q).Elem().FieldByName(field)
		v.SetInt(v.Int() + 1)
		if q.Validate() == nil {
			t.Fatal("platform ceiling exceeded", field)
		}
	}
	if platformTestPolicy().Validate() != nil {
		t.Fatal("shared policy control refused")
	}
}

// Claim: a detected step records exactly one fixed hold incident while the hold
// persists; authenticated recovery records a distinct fixed resync incident.
func TestClockIncidentCodes(t *testing.T) {
	_, c, clock := providerFixture(t)
	var codes []string
	p, err := New(testPolicy(), c, clock, func(v Incident) { codes = append(codes, v.Code) })
	if err != nil {
		t.Fatal(err)
	}
	trusted(t, p)
	base := clock.point.Now
	clock.point.Now = base.Add(-time.Second)
	clock.point.Elapsed += time.Second
	c.evidence.Tracking.Reference = base.Add(-2 * time.Second)
	refused(t, p)
	refused(t, p)
	if !reflect.DeepEqual(codes, []string{"clock_step_hold"}) {
		t.Fatal("hold incident missing or repeated")
	}
	clock.point.Now = base.Add(3 * time.Second)
	clock.point.Elapsed += 4 * time.Second
	c.evidence.Tracking.Reference = base.Add(2 * time.Second)
	trusted(t, p)
	if !reflect.DeepEqual(codes, []string{"clock_step_hold", "clock_resync"}) {
		t.Fatal("resync incident missing")
	}
}

// Claim: field 4 of one parsed tracking report determines sync age and the
// exclusive authority cap; field 13 is diagnostic only. The stricter service
// control catches an interval gate even when 1040s is below the shared ceiling.
func TestReferenceAgeIndependentOfUpdateInterval(t *testing.T) {
	for _, tc := range []struct {
		name        string
		maxAge, age time.Duration
		interval    float64
		ok          bool
	}{
		{"interval-1040-age-134-stricter", 1024 * time.Second, 134 * time.Second, 1040, true},
		{"interval-1040-age-134-shared", 2048 * time.Second, 134 * time.Second, 1040, true},
		{"interval-above-shared", 2048 * time.Second, 134 * time.Second, 4096, true},
		{"interval-zero", 2048 * time.Second, 134 * time.Second, 0, true},
		{"interval-negative", 2048 * time.Second, 134 * time.Second, -1, true},
		{"reference-before-limit", 2048 * time.Second, 2048*time.Second - time.Nanosecond, 1040, true},
		{"reference-at-limit", 2048 * time.Second, 2048 * time.Second, 1040, false},
		{"reference-after-limit", 2048 * time.Second, 2048*time.Second + time.Nanosecond, 1040, false},
		{"future-reference", 2048 * time.Second, -time.Nanosecond, 1040, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c, clock := providerFixture(t)
			q := platformTestPolicy()
			q.MaxSyncAge = tc.maxAge
			ref := clock.point.Now.Add(-tc.age)
			report := fmt.Sprintf("C0000201,192.0.2.1,3,%d.%09d,0.001,0.001,0.001,1,0.1,0.1,0.002,0.001,%g,Normal\n", ref.Unix(), ref.Nanosecond(), tc.interval)
			tracking, err := ParseTracking([]byte(report))
			if err != nil || !tracking.Reference.Equal(ref) || tracking.UpdateInterval != tc.interval {
				t.Fatal("tracking report did not retain reference and diagnostic interval", err)
			}
			c.evidence.Tracking = tracking
			p, err := New(q, c, clock, nil)
			if err != nil {
				t.Fatal("service policy refused", err)
			}
			if !tc.ok {
				refused(t, p)
				return
			}
			v := trusted(t, p)
			wantUntil := ref.Add(tc.maxAge)
			if window := clock.point.Now.Add(q.AuthorityWindow); window.Before(wantUntil) {
				wantUntil = window
			}
			if !v.Now.Equal(clock.point.Now) || !v.AuthorityUntil.Equal(wantUntil) {
				t.Fatal("authority did not use this report's reference and trusted sample time")
			}
		})
	}
}

// Claim: returned conservative uncertainty, including age times skew, has its
// own inclusive cap even when measured offsets and root distance pass. These
// samples also exercise a service's smaller cap with adjacent valid controls.
func TestReturnedUncertaintyCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		cap  time.Duration
		age  time.Duration
		skew float64
		ok   bool
	}{
		{"below-shared", 1500 * time.Millisecond, 1000*time.Second - time.Nanosecond, 1000, true},
		{"at-shared", 1500 * time.Millisecond, 1000 * time.Second, 1000, true},
		{"above-shared-age", 1500 * time.Millisecond, 1000*time.Second + time.Nanosecond, 1000, false},
		{"above-shared-skew", 1500 * time.Millisecond, 1000 * time.Second, 1001, false},
		{"at-stricter", time.Second, 1000 * time.Second, 500, true},
		{"above-stricter", time.Second, 1000 * time.Second, 1000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c, clock := providerFixture(t)
			q := platformTestPolicy()
			q.MaxUncertainty = tc.cap
			c.evidence.Tracking.Reference = clock.point.Now.Add(-tc.age)
			c.evidence.Tracking.SystemOffset = 0.25
			c.evidence.Tracking.RootDelay = 0
			c.evidence.Tracking.RootDispersion = 0.25
			c.evidence.Tracking.Skew = tc.skew
			p, err := New(q, c, clock, nil)
			if err != nil {
				t.Fatal("valid capped policy refused", err)
			}
			if !tc.ok {
				refused(t, p)
				return
			}
			v := trusted(t, p)
			if v.Uncertainty != tc.cap {
				t.Fatal("returned uncertainty did not respect the inclusive cap", v.Uncertainty)
			}
		})
	}
}
