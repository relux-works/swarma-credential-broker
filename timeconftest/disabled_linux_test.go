//go:build linux && !timeconf_fixture

package timeconftest_test

import (
	"context"
	"errors"
	"os"
	"testing"

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
