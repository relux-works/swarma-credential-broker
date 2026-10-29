package lease

import (
	"context"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// allowlist never reads material, creates lease records or invokes a refresher.
func (m *Manager) allowlist(ctx context.Context, p policy.Policy, uid uint32, params any) Outcome {
	refuse := func(code string) Outcome { return Outcome{Err: wire.Refuse(code), Generation: p.Generation} }
	if ctx.Err() != nil || m.ctx.Err() != nil {
		return refuse("allowlist_unavailable")
	}
	if !p.Observer(uid) {
		return refuse("allowlist_not_authorised")
	}
	r, ok := params.(wire.AllowlistRequest)
	if !ok {
		return refuse("allowlist_tuple_mismatch")
	}
	if r.ExpectedGeneration != p.Generation {
		return refuse("allowlist_generation_mismatch")
	}
	a, err := p.Admit(r.TargetUID, r.Account, r.Profile)
	if err != nil || r.Harness != "codex_cli" || r.Channel != "external-token" || r.Binding != p.Binding(r.TargetUID, a, r.Profile) {
		return refuse("allowlist_tuple_mismatch")
	}
	if a.ReleaseVersion != "0.163.0" || a.QualificationID == "" || a.NetworkRequired {
		return refuse("allowlist_unavailable")
	}
	if m.options.ObservePolicy != nil && m.options.ObservePolicy(ctx, p) != nil {
		return refuse("allowlist_unavailable")
	}
	if ctx.Err() != nil {
		return refuse("request_deadline_exceeded")
	}
	// Also fence direct callers against a replacement during protected-source I/O.
	err = m.WithGenerationContext(ctx, p.Generation, func(context.Context) error { return nil })
	if err != nil {
		return refuse("allowlist_unavailable")
	}
	return Outcome{Result: wire.AllowlistResult{Tuple: r, Generation: p.Generation, Decision: "allow"}, Generation: p.Generation}
}
