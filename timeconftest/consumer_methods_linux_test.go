//go:build linux && swarma_timeconf_fixture

package timeconftest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-credential-broker/timeconftest"
)

func unselected(t *testing.T, err error) {
	t.Helper()
	var r *timeconf.ActivationRefusal
	if !errors.As(err, &r) || r.Reason != "fixture_unselected" {
		t.Fatalf("want fixture_unselected, got %v", err)
	}
}
func receivers(t *testing.T, call func(*testing.T, *timeconftest.FixtureConsumer)) {
	t.Helper()
	for name, f := range map[string]*timeconftest.FixtureConsumer{"nil": nil, "zero": new(timeconftest.FixtureConsumer)} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("unselected method panicked: %v", p)
				}
			}()
			call(t, f)
			if f != nil && !reflect.ValueOf(f).Elem().IsZero() {
				t.Error("unselected method changed zero receiver")
			}
		})
	}
}

// Claim: Enrollment is zero for both unselected receivers and populated after selection.
func TestFixtureUnselectedEnrollment(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) {
		if f.Enrollment() != (timeconf.Enrollment{}) {
			t.Fatal("nonzero enrollment")
		}
	})
	f, _ := fixture(t)
	if f.Enrollment().Authority.ID == "" {
		t.Fatal("selected enrollment missing")
	}
	positive(t, f, "1")
}

// Claim: Policy is zero for both unselected receivers and returns an independent selected copy.
func TestFixtureUnselectedPolicy(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) {
		if !reflect.DeepEqual(f.Policy(), timeconf.Policy{}) {
			t.Fatal("nonzero policy")
		}
	})
	f, _ := fixture(t)
	p := f.Policy()
	p.SourceFiles[0] = "changed"
	if f.Policy().SourceFiles[0] == "changed" {
		t.Fatal("policy alias")
	}
	positive(t, f, "1")
}

// Claim: Advance refuses both unselected receivers with the named type; selected advancement works.
func TestFixtureUnselectedAdvance(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) { unselected(t, f.Advance(time.Second)) })
	f, _ := fixture(t)
	if err := f.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	positive(t, f, "1")
}

// Claim: LoseNextReply is harmless on both unselected receivers and suppresses a selected success.
func TestFixtureUnselectedLoseNextReply(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) { f.LoseNextReply() })
	f, _ := fixture(t)
	f.LoseNextReply()
	raw, err := f.ConsumeBeforePin(context.Background(), request(f, "1"))
	refused(t, raw, err, "fixture_reply_lost")
	if w, e := f.HighWater(); e != nil || w != "212000000000" {
		t.Fatal(w, e)
	}
}

// Claim: ConsumeBeforePin refuses both unselected receivers without bytes; selection admits a receipt.
func TestFixtureUnselectedConsumeBeforePin(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) {
		raw, err := f.ConsumeBeforePin(context.Background(), timeconf.ConsumptionRequest{})
		unselected(t, err)
		if len(raw) != 0 {
			t.Fatal("unselected receipt")
		}
	})
	f, _ := fixture(t)
	positive(t, f, "1")
}

// Claim: HighWater returns zero plus typed refusal for both unselected receivers, and real W after selection.
func TestFixtureUnselectedHighWater(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) {
		w, err := f.HighWater()
		unselected(t, err)
		if w != "" {
			t.Fatal("unselected W")
		}
	})
	f, _ := fixture(t)
	if w, err := f.HighWater(); err != nil || w != "140000000000" {
		t.Fatal(w, err)
	}
	positive(t, f, "1")
}

// Claim: the tagged sample setter refuses both unselected receivers; a selected explicit sample settles normally.
func TestFixtureUnselectedSetNextSample(t *testing.T) {
	receivers(t, func(t *testing.T, f *timeconftest.FixtureConsumer) {
		unselected(t, f.SetNextSample(time.Unix(200, 0), time.Second))
	})
	f, _ := fixture(t)
	if err := f.SetNextSample(time.Unix(200, 0), time.Second); err != nil {
		t.Fatal(err)
	}
	positive(t, f, "1")
}

func storage(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			result[path] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Claim: J=140,O=200,delta=1 settles W=201. A subsequent [170,172]
// refuses at the real interval gate without a receipt or W change; [210,212]
// then passes. Selecting samples itself leaves every stored byte unchanged.
func TestFixtureExplicitIntervalBelowHighWater(t *testing.T) {
	f, root := fixture(t)
	sample := func(o int64, d time.Duration) {
		t.Helper()
		before := storage(t, root)
		if err := f.SetNextSample(time.Unix(o, 0), d); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, storage(t, root)) {
			t.Fatal("sample setter changed durable state")
		}
	}
	sample(200, time.Second)
	first, _ := timeconf.DecodeReceipt(positive(t, f, "1"))
	if first.Facts.Observed != "200000000000" || first.Facts.Uncertainty != "1000000000" || first.Facts.Continuity.JournalFloor != "140000000000" || first.Facts.Continuity.HighWater != "201000000000" {
		t.Fatal(first.Facts)
	}
	sample(171, time.Second)
	raw, err := f.ConsumeBeforePin(context.Background(), request(f, "2"))
	refused(t, raw, err, "interval")
	if w, e := f.HighWater(); e != nil || w != "201000000000" {
		t.Fatal("refusal changed W", w, e)
	}
	sample(211, time.Second)
	last, _ := timeconf.DecodeReceipt(positive(t, f, "3"))
	if last.Facts.Continuity.PriorHighWater != "201000000000" || last.Facts.Continuity.HighWater != "212000000000" {
		t.Fatal(last.Facts)
	}
}

// Claim: explicit uncertainty includes reservation exactly, rejects out-of-range
// samples without writes, and keeps the last valid observation usable.
func TestFixtureSampleUncertaintyAndInvalidInputs(t *testing.T) {
	f, root := fixture(t)
	before := storage(t, root)
	for _, v := range []struct {
		o time.Time
		d time.Duration
	}{{time.Unix(-1, 0), time.Second}, {time.Unix(211, 0), time.Second - time.Nanosecond}, {time.Unix(211, 0), timeconf.PlatformMaxUncertainty + time.Nanosecond}} {
		if err := f.SetNextSample(v.o, v.d); !errors.Is(err, timeconf.ErrUnavailable) {
			t.Fatal("invalid sample accepted", err)
		}
	}
	if !reflect.DeepEqual(before, storage(t, root)) {
		t.Fatal("invalid sample wrote state")
	}
	if err := f.SetNextSample(time.Unix(211, 0), 1250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r, _ := timeconf.DecodeReceipt(positive(t, f, "1"))
	if r.Facts.Uncertainty != "1250000000" || r.Facts.Continuity.HighWater != "212250000000" {
		t.Fatal(r.Facts)
	}
}

// Claim: expired original context cannot be extended. Replacing both an unused
// deadline and context is accepted; extending a consumed challenge is replay.
func TestFixtureDeadlineReplacementBoundaries(t *testing.T) {
	f, _ := fixture(t)
	r := request(f, "1")
	r.Deadline = time.Now().Add(-time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), r.Deadline)
	defer cancel()
	raw, err := f.ConsumeBeforePin(ctx, r)
	refused(t, raw, err, "deadline")
	r.Deadline = time.Now().Add(400 * time.Millisecond)
	raw, err = f.ConsumeBeforePin(ctx, r)
	refused(t, raw, err, "deadline")
	if w, e := f.HighWater(); e != nil || w != "140000000000" {
		t.Fatal(w, e)
	}
	raw, err = f.ConsumeBeforePin(context.Background(), r)
	if err != nil {
		t.Fatal("replacement of unused request refused", err)
	}
	if _, err = timeconftest.VerifyReceipt(raw, f.Enrollment()); err != nil {
		t.Fatal(err)
	}
	r.Deadline = time.Now().Add(time.Second)
	raw, err = f.ConsumeBeforePin(context.Background(), r)
	refused(t, raw, err, "challenge_reused")
	if w, e := f.HighWater(); e != nil || w != "212000000000" {
		t.Fatal("replay changed W", w, e)
	}
}
