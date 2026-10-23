//go:build linux

package authowner_test

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/ownerconfidence"
	"github.com/relux-works/swarma-credential-broker/internal/timeconf"
	"reflect"
	"sync"
	"testing"
	"time"
)

type confidenceInputs struct {
	mu      sync.Mutex
	now     time.Time
	elapsed time.Duration
	bad     bool
}

func (c *confidenceInputs) Read(context.Context) (timeconf.ClockPoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return timeconf.ClockPoint{Now: c.now, Elapsed: c.elapsed, Boot: "fixture-boot"}, nil
}
func (c *confidenceInputs) Collect(context.Context, timeconf.Policy) (timeconf.Evidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return timeconf.Evidence{Tracking: timeconf.Tracking{Address: "192.0.2.1", Leap: "Normal", Stratum: 3, Reference: c.now.Add(-time.Second), SystemOffset: 0.001, RootDelay: 0.002, RootDispersion: 0.001, UpdateInterval: 10}, Sources: timeconf.Sources{Count: 1, AllNTS: !c.bad, Entries: []string{"192.0.2.1"}}}, nil
}
func providerFor(t *testing.T, f *authowner.ConfidenceFixture) (*timeconf.Provider, *confidenceInputs) {
	t.Helper()
	v := &confidenceInputs{now: f.Now(), elapsed: time.Hour}
	p, err := timeconf.New(timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: time.Minute, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: time.Millisecond * 10, MaxRootDistance: time.Millisecond * 10, AuthorityWindow: time.Second * 30, StepTolerance: time.Millisecond, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}, v, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Use(ownerconfidence.Adapter{Source: p})
	return p, v
}

// Claim: the real adapter admits covered synthetic fresh-home state; non-NTS
// confidence returns the owner's exact refusal and changes no durable records.
func TestConfidenceAdmissionAndWatermark(t *testing.T) {
	f := authowner.NewConfidenceFixture(t)
	_, v := providerFor(t, f)
	if err := f.Admit(context.Background()); err != nil {
		t.Fatal("covered admission refused", err)
	}
	before, err := f.Records()
	if err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.bad = true
	v.now = v.now.Add(time.Second)
	v.elapsed += time.Second
	v.mu.Unlock()
	if err := f.Admit(context.Background()); !errors.Is(err, authowner.ErrUnavailable) || err.Error() != "lease_owner_unavailable" {
		t.Fatal("untrusted admission was not refused", err)
	}
	after, err := f.Records()
	if err != nil || !reflect.DeepEqual(before, after) || f.Starts() != 0 {
		t.Fatal("refusal changed watermark/records or started writer")
	}
	v.mu.Lock()
	v.bad = false
	v.mu.Unlock()
	if err := f.Admit(context.Background()); err != nil {
		t.Fatal("valid confidence recovery refused", err)
	}
}

// Claim: a backward hold closes renewal before any new writer; if time fails
// after an owned fixture writer starts, the owner still confirms its stop.
func TestConfidenceHoldRenewalAndStop(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-start", true: "after-start"}[during], func(t *testing.T) {
			f := authowner.NewConfidenceFixture(t)
			p, v := providerFor(t, f)
			if err := f.Admit(context.Background()); err != nil {
				t.Fatal(err)
			}
			step := func() {
				v.mu.Lock()
				v.now = v.now.Add(-time.Second)
				v.elapsed += time.Second
				v.mu.Unlock()
				if _, err := p.Sample(context.Background()); !errors.Is(err, timeconf.ErrUnavailable) {
					t.Error("backward sample trusted")
				}
			}
			if !during {
				step()
				if err := f.Renew(context.Background()); !errors.Is(err, authowner.ErrUnavailable) || f.Starts() != 0 {
					t.Fatal("hold started renewal")
				}
				return
			}
			started := make(chan struct{}, 1)
			gate := make(chan struct{})
			f.Gate(started, gate)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- f.Renew(ctx) }()
			select {
			case <-started:
			case <-ctx.Done():
				close(gate)
				t.Fatal("fixture writer did not start")
			}
			step()
			close(gate)
			select {
			case err := <-result:
				if !errors.Is(err, authowner.ErrUnavailable) || !f.Stopped() {
					t.Fatal("time loss prevented confirmed stop", err)
				}
			case <-ctx.Done():
				t.Fatal("renewal did not terminate")
			}
		})
	}
}
