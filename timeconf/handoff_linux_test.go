//go:build linux

package timeconf

import (
	"errors"
	"testing"
)

// Claim: default public zero values cannot create preparation or a candidate,
// and the closed witness placeholder never authenticates, including unknown
// versions. Tagged tests supply the separate synthetic positive domain.
func TestHandoffProductionInactive(t *testing.T) {
	c, err := VerifyWindow(PreparedHandoff{}, WindowExpected{}, LockedWindowState{}, FinalCapture{})
	var a *ActivationRefusal
	if c != (WindowCandidate{}) || !errors.As(err, &a) || a.Reason != "handoff_unqualified" {
		t.Fatal("production window activated", err)
	}
	for _, v := range []string{WitnessPlaceholderVersion, "unknown", ""} {
		err = ValidateHandoffWitness(WitnessMaterial{v})
		if !errors.As(err, &a) || a.Reason != "witness_unavailable" {
			t.Fatal("witness placeholder accepted", err)
		}
	}
}

// Claim: the verifier's scalar arithmetic preserves signed/unsigned endpoints,
// canonical decimals and overflow rejection without importing a general parser.
func TestHandoffScalarBoundaries(t *testing.T) {
	for _, s := range []string{"0", "1", "-1", "9223372036854775807", "-9223372036854775808"} {
		if _, ok := windowInteger(s); !ok {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "-0", "00", "+1", "01", "9223372036854775808", "-9223372036854775809", "1e3"} {
		if _, ok := windowInteger(s); ok {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"0", "18446744073709551615"} {
		if !windowUnsigned(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"-1", "18446744073709551616", "00"} {
		if windowUnsigned(s) {
			t.Fatal(s)
		}
	}
	if _, ok := windowAdd(1<<63-1, 1); ok {
		t.Fatal("upper overflow")
	}
	if _, ok := windowAdd(-1<<63, -1); ok {
		t.Fatal("lower overflow")
	}
	if n, ok := windowAdd(-1<<63, 1); !ok || n != -1<<63+1 {
		t.Fatal("valid neighbor")
	}
}
