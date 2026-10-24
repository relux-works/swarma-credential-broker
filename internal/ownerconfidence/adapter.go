// Package ownerconfidence adapts shared clock evidence to the contained owner.
package ownerconfidence

import (
	"context"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/timeconf"
)

type Source interface {
	Sample(context.Context) (timeconf.Sample, error)
}
type Adapter struct{ Source Source }

var _ authowner.Confidence = Adapter{}

func (a Adapter) Validate(ctx context.Context, _ string, _ string, _ uint64, _ time.Time) (authowner.TimeEvidence, error) {
	if a.Source == nil {
		return authowner.TimeEvidence{}, authowner.ErrUnavailable
	}
	v, err := a.Source.Sample(ctx)
	if err != nil {
		return authowner.TimeEvidence{}, authowner.ErrUnavailable
	}
	return authowner.TimeEvidence{Now: v.Now, AuthorityUntil: v.AuthorityUntil, Trusted: v.Trusted, Fresh: v.Fresh}, nil
}
