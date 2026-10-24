package ownerconfidence

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/timeconf"
	"testing"
	"time"
)

type sourceFixture struct {
	sample timeconf.Sample
	err    error
}

func (s sourceFixture) Sample(context.Context) (timeconf.Sample, error) { return s.sample, s.err }

// Claim: missing sources and collector errors discard even a trusted prefix;
// a valid sample maps the owner fields without inventing time or a watermark.
func TestAdapterRefusalAndControl(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sample := timeconf.Sample{Now: now, AuthorityUntil: now.Add(time.Minute), Trusted: true, Fresh: true, Uncertainty: time.Millisecond, Boot: "fixture-boot"}
	for _, a := range []Adapter{{}, {Source: sourceFixture{sample, timeconf.ErrUnavailable}}} {
		got, err := a.Validate(context.Background(), "", "", 0, time.Time{})
		if !errors.Is(err, authowner.ErrUnavailable) || got != (authowner.TimeEvidence{}) {
			t.Fatal("failed source supplied authority")
		}
	}
	got, err := (Adapter{Source: sourceFixture{sample, nil}}).Validate(context.Background(), "", "", 0, now.Add(time.Hour))
	if err != nil || got.Now != now || got.AuthorityUntil != sample.AuthorityUntil || !got.Trusted || !got.Fresh {
		t.Fatal("valid source changed owner evidence")
	}
}
