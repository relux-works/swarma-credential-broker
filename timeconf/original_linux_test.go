//go:build linux

package timeconf

import (
	"context"
	"errors"
	"testing"
)

// The shipped reader returns a typed closed refusal and no bytes for both an
// empty request and a structurally bound request; these are not provenance or
// native qualification tests. A canceled or absent context cannot open it.
func TestClosedOriginalReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requests := []OriginalRequest{{}, {
		OperationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Challenge:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Boot:            "11111111-1111-4111-8111-111111111111",
		Checkpoint:      WitnessHead{Generation: 1, RecordDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}}
	for _, req := range requests {
		for _, c := range []context.Context{nil, context.Background(), ctx} {
			var reader OriginalReader = ClosedOriginalReader{}
			bundle, err := reader.ReadOriginals(c, req)
			var refusal *ActivationRefusal
			if !errors.As(err, &refusal) || refusal.Reason != "originals_unavailable" || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("expected closed activation refusal, got %v", err)
			}
			if bundle.Receipt != nil || bundle.Objects != nil || bundle.Checkpoint != (WitnessHead{}) ||
				bundle.Provenance.ReaderQualificationDigest != "" || bundle.Provenance.ValidatorDigest != "" || bundle.Provenance.Descriptors != nil {
				t.Fatal("closed reader returned material")
			}
		}
	}
}
