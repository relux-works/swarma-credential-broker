//go:build linux

package authowner

import (
	"encoding/hex"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

// validateChain implements the retained-chain table in docs/auth-owner.md.
// It accepts incomplete recovery prefixes, never contradictory history. A prefix
// is not admission authority: callers also require a settled checkpoint.
func (e *Engine) validateChain(a *account) error {
	c := a.checkpoint
	if c.Kind != "account-checkpoint/1" || c.Installation != e.config.Installation || c.Account != a.config.Label || c.VendorID != a.config.VendorID || c.HomeID != a.config.HomeID || c.Revision == 0 || c.Policy != e.config.PolicyGeneration || c.StoreGeneration == 0 || c.TokenGeneration == 0 || c.StoreDigest == "" || c.TokenDigest == "" || !validPlan(c.Plan) || c.Watermark.IsZero() {
		return ErrUnavailable
	}
	if c.State != owner.Active && c.State != owner.Transient && c.State != owner.Reauth && !(c.State == owner.Unavailable && c.PendingAttempt != "") {
		return ErrUnavailable
	}
	count := uint64(len(a.intents))
	if c.RetainedAttempts > count || count-c.RetainedAttempts > 1 || c.RetainedAttempts > (^uint64(0)-2)/2 {
		return ErrUnavailable
	}
	minimum := 1 + 2*c.RetainedAttempts
	if c.PendingAttempt != "" {
		minimum++
		if c.State != owner.Unavailable || count != c.RetainedAttempts+1 || a.intents[c.PendingAttempt].Sequence != count {
			return ErrUnavailable
		}
	} else if count != c.RetainedAttempts {
		return ErrUnavailable
	}
	if c.Revision < minimum {
		return ErrUnavailable
	}
	ordered := make([]Intent, len(a.intents))
	for key, v := range a.intents {
		if v.Kind != "attempt-intent/1" || v.Phase != "intent" || v.Revision != 1 || key != v.Attempt || !e.binding(a, v.Binding) || v.Identity != e.identity || v.Sequence > count || ordered[v.Sequence-1].Kind != "" {
			return ErrUnavailable
		}
		ordered[v.Sequence-1] = v
	}
	for key := range a.attempts {
		if _, ok := a.intents[key]; !ok {
			return ErrUnavailable
		}
	}
	sg, tg := uint64(1), uint64(1)
	var failures uint64
	var retryAt, nextProactive, resolvedAt, expires time.Time
	storeDigest, tokenDigest, generationPlan := c.StoreDigest, c.TokenDigest, c.Plan
	if len(ordered) > 0 {
		first := ordered[0]
		storeDigest, tokenDigest, generationPlan, expires = first.StoreDigestBefore, first.TokenDigestBefore, first.PlanBefore, first.TokenExpiresBefore
	}
	prefixStore, prefixToken, prefixPlan := storeDigest, tokenDigest, generationPlan
	latestPhase := ""
	for _, intent := range ordered {
		if intent.StoreBefore != sg || intent.TokenBefore != tg || intent.StoreDigestBefore != storeDigest || intent.TokenDigestBefore != tokenDigest || intent.PlanBefore != generationPlan || !intent.TokenExpiresBefore.Equal(expires) || !validDigest(storeDigest) || !validDigest(tokenDigest) || !validPlan(generationPlan) || expires.IsZero() {
			return ErrUnavailable
		}
		list := a.attempts[intent.Attempt]
		previous := "intent"
		var observed Observation
		var rpc Disposition = Unknown
		plan := ""
		for i, v := range list {
			b := v.Binding
			b.Revision = 1
			if v.Kind != "attempt-evidence/1" || b != intent.Binding || v.Revision != uint64(i)+2 {
				return ErrUnavailable
			}
			// The only skipped phase is recovery without durable response proof.
			allowed := previous == "intent" && v.Phase == "submitted" || previous == "submitted" && v.Phase == "running" || previous == "running" && (v.Phase == "stopping" || v.Phase == "absent") || previous == "stopping" && v.Phase == "absent" || previous == "absent" && v.Phase == "resolved"
			if !allowed {
				return ErrUnavailable
			}
			if v.Phase != "resolved" && (!v.ResolvedAt.IsZero() || !v.TokenExpires.IsZero() || v.StoreDigestAfter != "" || v.TokenDigestAfter != "") {
				return ErrUnavailable
			}
			o := v.Observation
			terminal := v.Phase == "absent" || v.Phase == "resolved"
			if v.Phase != "submitted" || suppliedObservation(o) {
				if !validRunning(intent.Binding, o) || !filepath.IsAbs(o.Cgroup) || filepath.Clean(o.Cgroup) != o.Cgroup || o.Cgroup == "/" || observed.Complete && !sameWriter(observed, o) {
					return ErrUnavailable
				}
				if terminal {
					if !confirmed(intent.Binding, observed, o) || previous == "absent" && o.Active != observed.Active {
						return ErrUnavailable
					}
				} else if observed.Complete && observed.Active == "active" && (o.MainPID != observed.MainPID || o.ProcessStart != observed.ProcessStart) {
					return ErrUnavailable
				} else if o.Active != "active" || o.Substate != "running" || o.MainPID == 0 || o.ProcessStart == 0 || o.StopCompleted || o.Empty || o.PopulatedZero || o.CgroupRemoved {
					return ErrUnavailable
				}
				observed = o
			}
			if terminal && v.Absence != "confirmed" || !terminal && v.Absence != "unknown" || v.Phase != "resolved" && (v.Outcome != Unknown || v.StoreAfter != 0) {
				return ErrUnavailable
			}
			switch v.Phase {
			case "submitted", "running":
				if v.RPC != Unknown || v.Plan != "" {
					return ErrUnavailable
				}
			case "stopping":
				if !validDisposition(v.RPC) || v.RPC == Committed && !validPlan(v.Plan) || v.RPC != Committed && v.Plan != "" {
					return ErrUnavailable
				}
				rpc, plan = v.RPC, v.Plan
			case "absent", "resolved":
				if v.RPC != rpc || v.Plan != plan {
					return ErrUnavailable
				}
				if v.Phase == "resolved" {
					if rpc == Unknown || v.Outcome != rpc {
						return ErrUnavailable
					}
					if v.ResolvedAt.IsZero() || v.ResolvedAt.Before(intent.Created) || v.ResolvedAt.Before(resolvedAt) || v.TokenExpires.IsZero() || rpc == Committed && !v.ResolvedAt.Before(v.TokenExpires) || rpc != Committed && !expires.IsZero() && !v.TokenExpires.Equal(expires) {
						return ErrUnavailable
					}
					if !validDigest(v.StoreDigestAfter) || !validDigest(v.TokenDigestAfter) || rpc == Committed && (v.StoreDigestAfter == storeDigest || v.TokenDigestAfter == tokenDigest) || rpc != Committed && (v.StoreDigestAfter != storeDigest || v.TokenDigestAfter != tokenDigest) {
						return ErrUnavailable
					}
					storeDigest, tokenDigest = v.StoreDigestAfter, v.TokenDigestAfter
					if rpc == Committed {
						generationPlan = v.Plan
					}
					resolvedAt, expires = v.ResolvedAt, v.TokenExpires
					// Only the checkpointed prefix determines checkpoint scheduling;
					// a durable pending resolution is replayed by recovery.
					if intent.Sequence <= c.RetainedAttempts {
						prefixStore, prefixToken, prefixPlan = storeDigest, tokenDigest, generationPlan
						switch rpc {
						case Committed:
							failures, retryAt = 0, time.Time{}
							nextProactive = proactiveAt(resolvedAt, expires, e.config.ProactiveWindow)
						case Safe:
							if failures == ^uint64(0) {
								return ErrUnavailable
							}
							failures++
							retryAt = resolvedAt.Add(safeBackoff(failures))
						}
						if c.Watermark.Before(resolvedAt) {
							return ErrUnavailable
						}
					}
					if rpc == Committed {
						if sg == ^uint64(0) || tg == ^uint64(0) {
							return ErrUnavailable
						}
						sg++
						tg++
					}
					if v.StoreAfter != sg {
						return ErrUnavailable
					}
				}
			}
			previous = v.Phase
		}
		latestPhase = previous
		if intent.Sequence <= c.RetainedAttempts && previous != "resolved" {
			return ErrUnavailable
		}
		if intent.Sequence == c.RetainedAttempts {
			if c.LastAttempt != intent.Attempt || c.StoreGeneration != sg || c.TokenGeneration != tg {
				return ErrUnavailable
			}
			if c.PendingAttempt == "" {
				want := map[Disposition]string{Committed: owner.Active, Safe: owner.Transient, Rejected: owner.Reauth}[rpc]
				if c.State != want {
					return ErrUnavailable
				}
			}
		}
	}
	if c.RetainedAttempts == 0 && (c.LastAttempt != "" || c.StoreGeneration != 1 || c.TokenGeneration != 1) {
		return ErrUnavailable
	}
	if c.Plan != prefixPlan { // The checkpointed generation survives non-commit and pending outcomes.
		return ErrUnavailable
	}
	if c.StoreDigest != prefixStore || c.TokenDigest != prefixToken {
		return ErrUnavailable
	}
	if c.Failures != failures {
		return ErrUnavailable
	}
	if retryAt.IsZero() && !c.RetryAt.IsZero() || !retryAt.IsZero() && c.RetryAt.Before(retryAt) {
		return ErrUnavailable
	}
	if !c.NextProactive.Equal(nextProactive) {
		return ErrUnavailable
	}
	if c.PendingAttempt == "" || latestPhase == "resolved" {
		material, err := load(a.config, false)
		if err != nil || material.Digest != storeDigest || digestToken(material.Token) != tokenDigest || !expires.IsZero() && !material.Expires.Equal(expires) {
			return ErrUnavailable
		}
	}
	return nil
}

// Diagnostics alone never turn an unobserved submitted record into authority.
func suppliedObservation(o Observation) bool {
	o.Result, o.ExitStatus, o.Observed = "", 0, time.Time{}
	return o != (Observation{})
}

func validDigest(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == 32 && v == hex.EncodeToString(b)
}

func safeBackoff(failures uint64) time.Duration {
	delay := time.Second
	for i := uint64(1); i < failures && delay < 60*time.Second; i++ {
		delay *= 2
	}
	if delay > 60*time.Second {
		return 60 * time.Second
	}
	return delay
}

func proactiveAt(resolvedAt, expires time.Time, window time.Duration) time.Time {
	next := resolvedAt.Add(expires.Sub(resolvedAt) / 2)
	if start := expires.Add(-window); start.After(next) {
		next = start
	}
	return next
}

func validDisposition(v Disposition) bool {
	return v == Unknown || v == Committed || v == Safe || v == Rejected
}

// Reload on every admission boundary; a previous successful restore does not
// authorize later use of protected records that have since become inconsistent.
func (e *Engine) retained(a *account) error {
	if !a.historyValid || e.restore(a) != nil {
		a.historyValid = false
		a.blocked = true
		return ErrUnavailable
	}
	if a.checkpoint.PendingAttempt != "" {
		return ErrUnavailable
	}
	return nil
}
