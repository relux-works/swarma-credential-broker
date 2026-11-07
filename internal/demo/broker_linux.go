//go:build linux

package demo

import (
	"context"
	"reflect"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
)

// ManagedAccountReference installs the protected human account/read reference
// lookup in the existing contained owner. It grants neither enrolment nor time
// confidence. The caller must still supply admitted manager, confidence and
// durable owner state to authowner.New; none is fabricated by the demo.
func ManagedAccountReference(c authowner.Config) (authowner.Config, error) {
	q, e := ReadQualification()
	if e != nil {
		return authowner.Config{}, e
	}
	p, e := ReadProjection()
	if e != nil {
		return authowner.Config{}, e
	}
	if len(c.Accounts) != 1 || c.Accounts[0].Label != p.Binding.Account || c.Accounts[0].VendorID != q.ChatGPTAccountID || c.PolicyGeneration != p.Binding.PolicyGeneration || c.Executable != q.Executable || c.ExecutableSHA256 != p.Binding.ExecutableSHA256 {
		return authowner.Config{}, ErrRefused
	}
	c.AccountReference = func(ctx context.Context, label string) (string, error) {
		if ctx.Err() != nil || label != p.Binding.Account {
			return "", ErrRefused
		}
		next, e := ReadQualification()
		if e != nil || !reflect.DeepEqual(q, next) {
			return "", ErrRefused
		}
		return next.AccountReference, nil
	}
	return c, nil
}

// BrokerOptions composes the source-only demo gates with the existing manager.
// Callers retain the private static-policy observer and an independently admitted
// authowner.Engine. The ordinary daemon remains stopped until that ceremony and
// its native prerequisites have been supplied; this is not an enrolment CLI.
func BrokerOptions(base lease.Options) lease.Options {
	previous := base.Qualification
	var mu sync.Mutex
	var originalProjection *Projection
	var originalQualification *Qualification
	failed := false
	base.DemoAdmission = NewAdmission()
	base.Qualification = func(ctx context.Context, p policy.Policy) error {
		if ctx.Err() != nil || p.BrokerUID != 1102 {
			return ErrRefused
		}
		if previous != nil {
			if e := previous(ctx, p); e != nil {
				return e
			}
		}
		projection, e := ReadProjection()
		if e != nil {
			return e
		}
		q, e := ReadQualification()
		if e != nil {
			return e
		}
		mu.Lock()
		if failed || originalProjection != nil && (!reflect.DeepEqual(*originalProjection, projection) || !reflect.DeepEqual(*originalQualification, q)) {
			failed = true
			mu.Unlock()
			return ErrRefused
		}
		if originalProjection == nil {
			originalProjection = &projection
			originalQualification = &q
		}
		mu.Unlock()
		if q.Executable != p.Executable || projection.Binding.ExecutableSHA256 != p.ExecutableSHA256 || projection.Binding.PolicyGeneration != p.Generation || q.Evidence.Identity.Executable.SHA256 != p.ExecutableSHA256 {
			return ErrRefused
		}
		// The projected binding is for one worker UID; static policy recomputes it
		// per admitted peer. Projection never widens account/profile authority.
		matched := false
		for _, a := range p.Accounts {
			if a.Label == projection.Binding.Account && a.VendorID == q.ChatGPTAccountID && a.Enabled && a.ReleaseVersion == "0.163.0" && a.QualificationID != "" && a.Endpoint == projection.Binding.Endpoint {
				for _, profile := range a.Profiles {
					if profile == projection.Binding.Profile {
						matched = true
					}
				}
			}
		}
		if !matched {
			return ErrRefused
		}
		return nil
	}
	return base
}
