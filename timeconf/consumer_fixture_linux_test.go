//go:build linux && swarma_timeconf_fixture

package timeconf

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Claim: choosing another synthetic sample cannot clear an existing persisted
// hold or move its W/witness head; the real engine continues to refuse held state.
func TestFixtureSampleCannotClearHold(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := NewFixtureConsumer(root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.consumer.store.open()
	if err != nil {
		t.Fatal(err)
	}
	r, h, err := s.load(context.Background())
	if err != nil {
		s.close()
		t.Fatal(err)
	}
	r.Held = true
	r.Hold = r.Last
	r.Operation = sum([]byte("held fixture"))
	r.Challenge = strings.Repeat("1", 32)
	_, err = s.commit(context.Background(), h, r)
	s.close()
	if err != nil {
		t.Fatal(err)
	}
	read := func() (settlement, WitnessHead) {
		t.Helper()
		s, e := f.consumer.store.open()
		if e != nil {
			t.Fatal(e)
		}
		defer s.close()
		r, h, e := s.load(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		return r, h
	}
	before, head := read()
	if err = f.SetNextSample(time.Unix(211, 0), time.Second); err != nil {
		t.Fatal(err)
	}
	after, next := read()
	if !reflect.DeepEqual(before, after) || head != next {
		t.Fatal("sample changed hold or witness")
	}
	digest, err := NativeOperationDigest("held-fixture", []byte("operation"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.ConsumeBeforePin(context.Background(), ConsumptionRequest{Deadline: time.Now().Add(400 * time.Millisecond), Expected: f.Enrollment(), OperationDigest: digest, Challenge: strings.Repeat("2", 32), JournalFloor: 140000000000})
	var refusal *ConsumptionRefusal
	if len(raw) != 0 || !errors.As(err, &refusal) || refusal.Code != "held" {
		t.Fatal("held fixture admitted sample", err)
	}
	after, next = read()
	if !reflect.DeepEqual(before, after) || head != next {
		t.Fatal("held refusal changed settlement")
	}
}
