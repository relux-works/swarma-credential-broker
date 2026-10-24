//go:build linux && timeconf_smoke

package timeconf

import (
	"context"
	"testing"
	"time"
)

// Claim: this opt-in read-only diagnostic exercises installed collectors; it is
// evidence only and supplies no activation, source-selection or account gate.
// Every printed field is a fixed verdict or parsed numeric/enum aggregate.
func TestHostTimeConfidenceSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := testPolicy()
	p.Timeout = 2 * time.Second
	p.MaxSyncAge = PlatformMaxSyncAge
	p.MaxUncertainty = PlatformMaxUncertainty
	p.MaxOffset = PlatformMaxOffset
	p.MaxRootDistance = PlatformMaxRootDistance
	p.AuthorityWindow = PlatformAuthorityWindow
	p.BackwardTolerance = PlatformBackwardTolerance
	p.MaxOutputBytes = 65536
	runner := SystemRunner{}
	b, err := runner.Run(ctx, p.Chronyc, []string{"-c", "tracking"}, p.Timeout, p.MaxOutputBytes)
	if err == nil {
		v, parseErr := ParseTracking(b)
		if parseErr == nil {
			t.Logf("tracking parsed: leap=%s stratum=%d age_seconds=%.3f update_interval_seconds=%.3f absolute_offset_seconds=%.9f root_distance_seconds=%.9f dispersion_seconds=%.9f", v.Leap, v.Stratum, time.Since(v.Reference).Seconds(), v.UpdateInterval, abs(v.SystemOffset), v.RootDelay/2+v.RootDispersion, v.RootDispersion)
		} else {
			t.Log("tracking: evidence_unavailable")
		}
	} else {
		t.Log("tracking: evidence_unavailable")
	}
	sources, sourceErr := collectSources(ctx, p)
	if sourceErr != nil {
		t.Log("source configuration: evidence_unavailable")
	} else {
		t.Logf("source configuration parsed: count=%d all_nts=%t", sources.Count, sources.AllNTS)
	}
	b, err = runner.Run(ctx, p.Chronyc, []string{"-c", "authdata", "-a"}, p.Timeout, p.MaxOutputBytes)
	if err == nil {
		v, parseErr := ParseAuthData(b)
		if parseErr == nil {
			t.Logf("authentication parsed: associations=%d", len(v.Addresses))
		} else {
			t.Log("authentication: evidence_unavailable")
		}
	} else {
		t.Log("authentication: evidence_unavailable")
	}
	for _, source := range []Source{NTSConfig, NTSAuthData} {
		p.Source = source
		_, err := (SystemCollector{}).Collect(ctx, p)
		if err != nil {
			t.Logf("source mode %s: evidence_unavailable", source)
		} else {
			t.Logf("source mode %s: collection_available", source)
		}
		provider, providerErr := Production(&p, func(Incident) {})
		if providerErr != nil {
			t.Logf("source mode %s: provider_unavailable", source)
			continue
		}
		sample, sampleErr := provider.StartSample(ctx)
		if sampleErr != nil {
			t.Logf("source mode %s: provider_unavailable", source)
		} else {
			t.Logf("source mode %s: trusted=%t fresh=%t uncertainty_ns=%d authority_seconds=%.3f", source, sample.Trusted, sample.Fresh, sample.Uncertainty.Nanoseconds(), sample.AuthorityUntil.Sub(sample.Now).Seconds())
		}
	}
	if v, err := (SystemClock{}).Read(ctx); err != nil {
		t.Log("clock: evidence_unavailable")
	} else {
		t.Logf("clock: boot_present=%t elapsed_nonnegative=%t wall_present=%t", v.Boot != "", v.Elapsed >= 0, !v.Now.IsZero())
	}
}
func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
