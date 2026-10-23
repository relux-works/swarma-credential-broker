package timeconf

import (
	"context"
	"log"
	"math"
	"sync"
	"time"
)

type Sample struct {
	Now, AuthorityUntil time.Time
	Trusted, Fresh      bool
	Uncertainty         time.Duration
	Boot                string
}
type ClockPoint struct {
	Now     time.Time
	Elapsed time.Duration
	Boot    string
}
type Clock interface {
	Read(context.Context) (ClockPoint, error)
}
type Tracking struct {
	ReferenceID, Address, Leap, Name                                                                                   string
	Stratum                                                                                                            int
	Reference                                                                                                          time.Time
	SystemOffset, LastOffset, RMSOffset, Frequency, ResidualFrequency, Skew, RootDelay, RootDispersion, UpdateInterval float64
}
type Sources struct {
	Count   int
	AllNTS  bool
	Entries []string
}
type Authentication struct{ Addresses map[string]bool }
type Evidence struct {
	Tracking       Tracking
	Sources        Sources
	Authentication Authentication
}
type Collector interface {
	Collect(context.Context, Policy) (Evidence, error)
}

// Incident contains fixed codes only, never collector output or source names.
type Incident struct{ Code string }

type Provider struct {
	mu                      sync.Mutex
	policy                  Policy
	collector               Collector
	clock                   Clock
	incident                func(Incident)
	last                    ClockPoint
	held                    bool
	holdWall, holdReference time.Time
	holdElapsed             time.Duration
	lastReference           time.Time
}

func New(p Policy, collector Collector, clock Clock, incident func(Incident)) (*Provider, error) {
	if p.Validate() != nil || p.Source != Off && (collector == nil || clock == nil) {
		return nil, ErrUnavailable
	}
	if incident == nil {
		incident = func(v Incident) { log.Print("time_confidence: ", v.Code) }
	}
	p.SourceFiles = append([]string(nil), p.SourceFiles...)
	return &Provider{policy: p, collector: collector, clock: clock, incident: incident}, nil
}
func (p *Provider) emit(code string) {
	if p.incident != nil {
		p.incident(Incident{Code: code})
	}
}

// compare runs even when the evidence collector fails. Bad evidence cannot hide
// a clock step or clear a hold. Comparison state is never shared across boots.
func (p *Provider) compare(v ClockPoint) (changed, step bool) {
	if p.last.Boot != "" && p.last.Boot != v.Boot {
		p.held = false
		p.holdWall = time.Time{}
		p.holdReference = time.Time{}
		p.lastReference = time.Time{}
		changed = true
	}
	if p.last.Boot == v.Boot && !p.last.Now.IsZero() {
		dw, dm := v.Now.Sub(p.last.Now), v.Elapsed-p.last.Elapsed
		if dm < 0 || dw-dm < -p.policy.BackwardTolerance || dw-dm > p.policy.StepTolerance {
			step = true
			if !p.held {
				p.holdReference = p.lastReference
				p.emit("clock_step_hold")
			}
			p.held = true
			p.holdElapsed = v.Elapsed
			if v.Now.After(p.holdWall) {
				p.holdWall = v.Now
			}
			if p.last.Now.After(p.holdWall) {
				p.holdWall = p.last.Now
			}
		}
	}
	p.last = v
	return
}
func validPoint(v ClockPoint) bool { return !v.Now.IsZero() && v.Boot != "" && v.Elapsed >= 0 }
func finite(v float64) bool        { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func (p *Provider) trackingValid(e Evidence, now time.Time) bool {
	t := e.Tracking
	// Sync age comes from this report's reference, never its averaged update interval.
	age := now.Sub(t.Reference)
	if !e.Sources.AllNTS || e.Sources.Count < 1 || !selectedConfigured(e.Sources, t) || t.Leap != "Normal" || t.Stratum < 1 || t.Stratum > 15 || t.Reference.IsZero() || age < 0 || age >= p.policy.MaxSyncAge {
		return false
	}
	for _, v := range []float64{t.SystemOffset, t.LastOffset, t.RMSOffset, t.Frequency, t.ResidualFrequency, t.Skew, t.RootDelay, t.RootDispersion, t.UpdateInterval} {
		if !finite(v) {
			return false
		}
	}
	bound := p.policy.MaxOffset.Seconds()
	if math.Abs(t.SystemOffset) > bound || math.Abs(t.LastOffset) > bound || t.RMSOffset < 0 || t.RMSOffset > bound || t.RootDelay < 0 || t.RootDispersion < 0 || t.Skew < 0 || math.Abs(t.Frequency) > 1e6 || math.Abs(t.ResidualFrequency) > 1e6 || t.Skew > 1e6 || t.RootDelay/2+t.RootDispersion > p.policy.MaxRootDistance.Seconds() {
		return false
	}
	if p.policy.Source == NTSAuthData {
		if !e.Authentication.Addresses[t.Address] {
			return false
		}
		for _, authenticated := range e.Authentication.Addresses {
			if !authenticated {
				return false
			}
		}
	}
	return true
}

// Sample serializes observations so concurrent consumers cannot reorder the
// within-boot baseline. The authority window is exclusive at sync freshness.
func (p *Provider) Sample(ctx context.Context) (Sample, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || p.policy.Source == Off {
		return Sample{}, ErrUnavailable
	}
	before, err := p.clock.Read(ctx)
	if err != nil || !validPoint(before) {
		p.emit("clock_unavailable")
		return Sample{}, ErrUnavailable
	}
	changed, step := p.compare(before)
	evidence, collectErr := p.collector.Collect(ctx, p.policy)
	after, clockErr := p.clock.Read(ctx)
	if clockErr != nil || !validPoint(after) {
		p.emit("clock_unavailable")
		return Sample{}, ErrUnavailable
	}
	changedAfter, stepAfter := p.compare(after)
	if collectErr != nil || ctx.Err() != nil || changed || changedAfter || before.Boot != after.Boot || !p.trackingValid(evidence, after.Now) {
		p.emit("evidence_unavailable")
		return Sample{}, ErrUnavailable
	}
	delta := uncertainty(evidence.Tracking, after.Now)
	if delta > p.policy.MaxUncertainty {
		p.emit("evidence_unavailable")
		return Sample{}, ErrUnavailable
	}
	if p.held {
		if p.policy.Resync != "new-authenticated-sync" || step || stepAfter || after.Elapsed <= p.holdElapsed || !evidence.Tracking.Reference.After(p.holdReference) || !evidence.Tracking.Reference.After(p.holdWall) {
			return Sample{}, ErrUnavailable
		}
		p.held = false
		p.emit("clock_resync")
	}
	p.lastReference = evidence.Tracking.Reference
	until := after.Now.Add(p.policy.AuthorityWindow)
	freshUntil := evidence.Tracking.Reference.Add(p.policy.MaxSyncAge)
	if freshUntil.Before(until) {
		until = freshUntil
	}
	if !after.Now.Before(until) {
		return Sample{}, ErrUnavailable
	}
	return Sample{Now: after.Now, AuthorityUntil: until, Trusted: true, Fresh: true, Uncertainty: delta, Boot: after.Boot}, nil
}

// StartSample performs a new observation before any process time decision. It
// never reuses a cached sample. Cross-process ordering also needs the previous
// decision bound; see the consumer protocol in docs/time-confidence.md.
func (p *Provider) StartSample(ctx context.Context) (Sample, error) { return p.Sample(ctx) }

func uncertainty(t Tracking, now time.Time) time.Duration {
	// The observed correction plus root distance bounds the sample under the NTP
	// error model. Include last/RMS correction conservatively and grow dispersion
	// since the reference by the measured frequency uncertainty (ppm).
	offset := math.Max(math.Abs(t.SystemOffset), math.Max(math.Abs(t.LastOffset), t.RMSOffset))
	seconds := offset + t.RootDelay/2 + t.RootDispersion + now.Sub(t.Reference).Seconds()*t.Skew/1e6
	// Ceil rounds fractional nanoseconds upward without adding a nanosecond to
	// an exact bound, which must remain valid at the inclusive uncertainty cap.
	return time.Duration(math.Ceil(seconds * float64(time.Second)))
}

func selectedConfigured(s Sources, t Tracking) bool {
	for _, entry := range s.Entries {
		if entry == t.Address || t.Name != "" && entry == t.Name {
			return true
		}
	}
	return false
}
