//go:build linux && swarma_timeconf_fixture

package timeconftest_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-credential-broker/timeconftest"
)

func fixture(t *testing.T) (*timeconftest.FixtureConsumer, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := timeconftest.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return f, root
}
func request(f *timeconftest.FixtureConsumer, digit string) timeconf.ConsumptionRequest {
	d, _ := timeconf.NativeOperationDigest("fixture-operation", []byte("public operation"))
	return timeconf.ConsumptionRequest{Deadline: time.Now().Add(400 * time.Millisecond), Expected: f.Enrollment(), OperationDigest: d, Challenge: strings.Repeat(digit, 32), JournalFloor: 140000000000}
}
func positive(t *testing.T, f *timeconftest.FixtureConsumer, digit string) []byte {
	t.Helper()
	raw, err := f.ConsumeBeforePin(context.Background(), request(f, digit))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = timeconftest.VerifyReceipt(raw, f.Enrollment()); err != nil {
		t.Fatal(err)
	}
	return raw
}
func refused(t *testing.T, raw []byte, err error, code string) {
	t.Helper()
	var r *timeconf.ConsumptionRefusal
	if len(raw) != 0 || !errors.As(err, &r) || r.Code != code {
		t.Fatalf("want %s refusal without receipt, got %v", code, err)
	}
}
func activation(t *testing.T, raw []byte, err error) {
	t.Helper()
	var r *timeconf.ActivationRefusal
	if len(raw) != 0 || !errors.As(err, &r) {
		t.Fatal("production accepted fixture domain or untyped refusal", err)
	}
}

// Claim: a settled positive control uses the production encoder and decoder;
// matching a fixture enrollment conveys only codec/domain agreement, not trust.
func TestFixtureReceiptCodecPositive(t *testing.T) {
	f, _ := fixture(t)
	raw := positive(t, f, "1")
	r, err := timeconf.DecodeReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := timeconf.EncodeReceipt(r)
	if err != nil || !bytes.Equal(raw, again) || r.Facts.Continuity.HighWater != "212000000000" {
		t.Fatal("codec round trip or settlement mismatch", err)
	}
}

// Claim: replay of a settled challenge refuses without another advancement;
// a later observation with a distinct challenge remains admissible.
func TestFixtureReplayRefused(t *testing.T) {
	f, _ := fixture(t)
	positive(t, f, "1")
	raw, err := f.ConsumeBeforePin(context.Background(), request(f, "1"))
	refused(t, raw, err, "challenge_reused")
	if w, e := f.HighWater(); e != nil || w != "212000000000" {
		t.Fatal("replay changed W", w, e)
	}
	if err = f.Advance(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	positive(t, f, "2")
}

// Claim: an expired original deadline refuses before consumption and cannot
// publish a receipt; a new, live request is the nearby positive control.
func TestFixtureDeadlineRefused(t *testing.T) {
	f, _ := fixture(t)
	r := request(f, "1")
	r.Deadline = time.Now().Add(-time.Second)
	raw, err := f.ConsumeBeforePin(context.Background(), r)
	refused(t, raw, err, "deadline")
	if w, e := f.HighWater(); e != nil || w != "140000000000" {
		t.Fatal("expired request changed W", w, e)
	}
	positive(t, f, "2")
}

// Claim: losing a successful reply preserves consumed U and its challenge.
// Equality to that U still refuses; one nanosecond above it passes.
func TestFixtureLostReplyBurnsUpperBound(t *testing.T) {
	f, _ := fixture(t)
	f.LoseNextReply()
	raw, err := f.ConsumeBeforePin(context.Background(), request(f, "1"))
	refused(t, raw, err, "fixture_reply_lost")
	if w, e := f.HighWater(); e != nil || w != "212000000000" {
		t.Fatal("lost reply undid U", w, e)
	}
	raw, err = f.ConsumeBeforePin(context.Background(), request(f, "1"))
	refused(t, raw, err, "challenge_reused")
	if err = f.Advance(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	raw, err = f.ConsumeBeforePin(context.Background(), request(f, "2"))
	refused(t, raw, err, "interval")
	if err = f.Advance(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	positive(t, f, "3")
}

// Claim: the real fixture enrollment cannot activate an ordinary Consumer,
// including when the explicit fixture tag is present. The fixture itself passes.
func TestFixtureRootProductionConsumerRefused(t *testing.T) {
	f, root := fixture(t)
	c, err := timeconf.NewConsumer(f.Enrollment(), f.Policy(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, ordinary := range []*timeconf.Consumer{nil, new(timeconf.Consumer), c} {
		raw, err := ordinary.ConsumeBeforePin(context.Background(), request(f, "1"))
		activation(t, raw, err)
	}
	positive(t, f, "2")
	var zero timeconftest.FixtureConsumer
	raw, err := zero.ConsumeBeforePin(context.Background(), request(f, "3"))
	activation(t, raw, err)
}

// Claim: ClosedWitness cannot acknowledge or load a fixture checkpoint, even
// though the same fixture produces a valid settled receipt under its own root.
func TestFixtureRootClosedWitnessRefused(t *testing.T) {
	f, _ := fixture(t)
	raw := positive(t, f, "1")
	r, _ := timeconf.DecodeReceipt(raw)
	w := timeconf.ClosedWitness{}
	_, err := w.Read(context.Background())
	activation(t, nil, err)
	err = w.CompareAndSwap(context.Background(), timeconf.WitnessHead{}, timeconf.WitnessHead{Generation: 1, RecordDigest: r.Facts.Continuity.RecordDigest})
	activation(t, nil, err)
}

// Claim: structural decoding alone succeeds, but enrollment verification refuses
// an independently selected non-fixture authority/root and every changed binding.
// This is a consumer codec/domain check, not a production evidence authenticator.
func TestFixtureReceiptProductionEnrollmentRefused(t *testing.T) {
	f, _ := fixture(t)
	raw := positive(t, f, "1")
	if _, err := timeconf.DecodeReceipt(raw); err != nil {
		t.Fatal(err)
	}
	production := f.Enrollment()
	production.Authority.ID = "enrolled-time-authority"
	production.Authority.TrustRootDigest = "sha256:" + strings.Repeat("b", 64)
	_, err := timeconftest.VerifyReceipt(raw, production)
	var r *timeconf.ConsumptionRefusal
	if !errors.As(err, &r) || r.Code != "fixture_binding" {
		t.Fatal("fixture root accepted under production enrollment", err)
	}
	changed := f.Enrollment()
	changed.Scope.Consumer = "another-consumer"
	if _, err = timeconftest.VerifyReceipt(raw, changed); !errors.As(err, &r) || r.Code != "fixture_binding" {
		t.Fatal("changed enrollment accepted", err)
	}
	if _, err = timeconftest.VerifyReceipt(raw, f.Enrollment()); err != nil {
		t.Fatal(err)
	}
}

// Claim: enabling the test tag adds no witness argument to production
// construction; the ordinary three-argument constructor still builds/refuses.
func TestProductionConstructorNoWitnessInjection(t *testing.T) {
	constructor := reflect.TypeOf(timeconf.NewConsumer)
	if constructor.NumIn() != 3 || constructor.IsVariadic() {
		t.Fatal("production NewConsumer accepts injected witness")
	}
	f, root := fixture(t)
	c, err := timeconf.NewConsumer(f.Enrollment(), f.Policy(), root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.ConsumeBeforePin(context.Background(), request(f, "1"))
	activation(t, raw, err)
	positive(t, f, "2")
}

// Claim: construction never resets a nonempty root or follows a writable root;
// rejection preserves existing bytes. Fresh protected construction still passes.
func TestFixtureConstructionRefused(t *testing.T) {
	f, root := fixture(t)
	before, err := os.ReadFile(root + "/current")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = timeconftest.New(root); !errors.Is(err, timeconf.ErrUnavailable) {
		t.Fatal("existing root reset", err)
	}
	after, err := os.ReadFile(root + "/current")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("root changed", err)
	}
	bad := t.TempDir()
	if err = os.Chmod(bad, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = timeconftest.New(bad); !errors.Is(err, timeconf.ErrUnavailable) {
		t.Fatal("writable root accepted", err)
	}
	entries, err := os.ReadDir(bad)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejection wrote files", err)
	}
	positive(t, f, "1")
}
