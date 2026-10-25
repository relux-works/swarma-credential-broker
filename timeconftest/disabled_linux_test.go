//go:build linux && !swarma_timeconf_fixture

package timeconftest_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-credential-broker/timeconftest"
)

// Claim: importing the default package cannot select any fixture or write
// storage. Explicit and zero-value selection both return typed activation refusal.
// The same import's accepting control runs only in the separate tagged suite.
func TestFixtureDefaultImportRefused(t *testing.T) {
	root := t.TempDir()
	f, err := timeconftest.New(root)
	var inactive *timeconf.ActivationRefusal
	if f != nil || !errors.As(err, &inactive) {
		t.Fatal("untagged fixture activated", err)
	}
	var zero timeconftest.FixtureConsumer
	raw, err := zero.ConsumeBeforePin(context.Background(), timeconf.ConsumptionRequest{})
	if len(raw) != 0 || !errors.As(err, &inactive) {
		t.Fatal("zero fixture activated", err)
	}
	if _, err = timeconftest.VerifyReceipt([]byte("{}"), timeconf.Enrollment{}); !errors.As(err, &inactive) {
		t.Fatal("untagged verification activated", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("inactive fixture wrote state", err)
	}
}

// Claim: every default-mode method is safe on nil and zero receivers; no method
// selects a fixture. Accepting method controls run in the tagged regression tests.
func TestFixtureDefaultMethodsUnselected(t *testing.T) {
	for name, f := range map[string]*timeconftest.FixtureConsumer{"nil": nil, "zero": new(timeconftest.FixtureConsumer)} {
		t.Run(name, func(t *testing.T) {
			if f.Enrollment() != (timeconf.Enrollment{}) || !reflect.DeepEqual(f.Policy(), timeconf.Policy{}) {
				t.Fatal("unselected binding")
			}
			f.LoseNextReply()
			w, err := f.HighWater()
			if w != "" {
				t.Fatal("unselected W")
			}
			_, consumeErr := f.ConsumeBeforePin(context.Background(), timeconf.ConsumptionRequest{})
			for _, e := range []error{err, consumeErr, f.Advance(time.Second)} {
				var r *timeconf.ActivationRefusal
				if !errors.As(e, &r) || r.Reason != "fixture_unselected" {
					t.Fatal("untyped or wrong refusal", e)
				}
			}
		})
	}
}
