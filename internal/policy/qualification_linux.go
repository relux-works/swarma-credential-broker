//go:build linux

package policy

import (
	"context"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Qualified is the common daemon/runner reader. The observer measures current
// inputs; neither policy references nor historical digests authorize a tuple.
func (c Config) Qualified(ctx context.Context, path string, observer qualification.IdentityObserver) (qualification.Record, qualification.Catalog, error) {
	b, e := wire.Encode(c)
	if e != nil {
		return qualification.Record{}, qualification.Catalog{}, qualification.ErrUnavailable
	}
	if observer == nil {
		observer = qualification.NativeObserver{ExecutablePath: c.Policy.Executable, StaticPolicy: b}
	}
	r, catalog, e := (qualification.Repository{Path: qualification.Directory(path), UID: c.Policy.BrokerUID, Observer: observer}).Read(ctx)
	if e != nil || r.Identity.Executable.SHA256 != c.Policy.ExecutableSHA256 {
		return qualification.Record{}, qualification.Catalog{}, qualification.ErrUnavailable
	}
	return r, catalog, nil
}
