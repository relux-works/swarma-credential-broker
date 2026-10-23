//go:build linux

package authowner

import (
	"context"
	"sync"
	"time"
)

// timeAuthority owns the process-wide observed floor and the per-account
// durable decision floor. Its mutex protects only sample merging, never I/O.
// Account checkpoints remain serialized by the engine's existing account gate.
type timeAuthority struct {
	mu       sync.Mutex
	observed time.Time
}

func (t *timeAuthority) floor(lower time.Time) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if lower.After(t.observed) {
		t.observed = lower
	}
	return t.observed
}

// sample checks independent confidence against every trusted instant already
// observed in this process. The result is not yet a durable decision time.
func (t *timeAuthority) sample(ctx context.Context, e *Engine, a *account, c Checkpoint) (TimeEvidence, error) {
	lower := t.floor(c.Watermark)
	lower = t.floor(a.checkpoint.Watermark)
	v, err := e.confidence.Validate(ctx, a.config.Label, a.config.HomeID, c.StoreGeneration, lower)
	if err == nil && v.Trusted && !v.Now.IsZero() {
		t.floor(v.Now)
	}
	if err != nil || !v.Trusted || !v.Fresh || v.Now.IsZero() {
		return TimeEvidence{}, ErrUnavailable
	}
	v.Now = t.floor(lower)
	if !v.Now.Before(v.AuthorityUntil) {
		return TimeEvidence{}, ErrUnavailable
	}
	return v, nil
}

// commit keeps completed writes even when the postcheck refuses their successor.
// Only this type consumes its observed-time result; numeric actions use durable.
func (t *timeAuthority) commit(ctx context.Context, e *Engine, a *account, c Checkpoint, write func() error) (TimeEvidence, error) {
	if _, err := t.sample(ctx, e, a, c); err != nil {
		return TimeEvidence{}, timeAdmissionRefusal{}
	}
	if err := write(); err != nil {
		return TimeEvidence{}, ErrUnavailable
	}
	v, err := t.sample(ctx, e, a, c)
	if err != nil {
		return TimeEvidence{}, timeAdmissionRefusal{}
	}
	return v, nil
}

func (t *timeAuthority) checkpoint(ctx context.Context, e *Engine, a *account, c Checkpoint) (TimeEvidence, error) {
	return t.commit(ctx, e, a, c, func() error {
		c.Watermark = t.floor(c.Watermark).UTC()
		if err := e.checkpoint(a, c); err != nil {
			return err
		}
		if c.PendingAttempt != "" {
			a.blocked = true
		}
		return nil
	})
}

// durable admits at most two watermark writes. The final completion sample
// still fences freshness and authority, but cannot decide expiry or scheduling.
func (t *timeAuthority) durable(ctx context.Context, e *Engine, a *account, c Checkpoint, v TimeEvidence) (TimeEvidence, error) {
	for writes := 0; writes < 2 && v.Now.After(a.checkpoint.Watermark); writes++ {
		proposal := a.checkpoint
		proposal.Watermark = v.Now.UTC()
		var err error
		v, err = t.commit(ctx, e, a, c, func() error {
			proposal.Watermark = t.floor(proposal.Watermark).UTC()
			if err := e.checkpoint(a, proposal); err != nil {
				return err
			}
			if proposal.PendingAttempt != "" {
				a.blocked = true
			}
			return nil
		})
		if err != nil {
			return TimeEvidence{}, err
		}
	}
	// This is the rule of action: the last postcheck's newer Now is observed,
	// but only the persisted floor can affect a numeric authority decision.
	v.Now = a.checkpoint.Watermark
	return v, nil
}

func (t *timeAuthority) admission(ctx context.Context, e *Engine, a *account) (TimeEvidence, error) {
	if a.blocked || e.retained(a) != nil || a.config.Disk.Healthy() != nil {
		return TimeEvidence{}, ErrUnavailable
	}
	v, err := t.sample(ctx, e, a, a.checkpoint)
	if err != nil {
		return TimeEvidence{}, ErrUnavailable
	}
	identity, err := e.manager.Identity(ctx)
	if err != nil || identity != e.identity {
		return TimeEvidence{}, ErrUnavailable
	}
	return t.durable(ctx, e, a, a.checkpoint, v)
}

func (t *timeAuthority) materialValid(v TimeEvidence, expires time.Time) bool {
	return !v.Now.IsZero() && v.Now.Before(expires)
}

func (t *timeAuthority) retryReady(v TimeEvidence, c Checkpoint) bool {
	return !v.Now.Before(c.RetryAt)
}

func (t *timeAuthority) due(v TimeEvidence, c Checkpoint, expires time.Time, window time.Duration) bool {
	return !v.Now.Before(c.NextProactive) && t.retryReady(v, c) && !v.Now.Before(expires.Add(-window))
}

func (t *timeAuthority) stamp(v TimeEvidence, b *Binding, runtime time.Duration) {
	b.Created = v.Now.UTC()
	b.Deadline = v.Now.Add(runtime).UTC()
}

func (t *timeAuthority) resolution(ctx context.Context, e *Engine, a *account, c *Checkpoint, recorded, expires time.Time, outcome Disposition, backoff time.Duration) (time.Time, error) {
	v, err := t.sample(ctx, e, a, *c)
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	v, err = t.durable(ctx, e, a, *c, v)
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	c.Watermark = v.Now.UTC()
	resolved := c.Watermark
	if !recorded.IsZero() {
		resolved = recorded
	}
	if outcome == Safe {
		c.RetryAt = resolved.Add(backoff)
	}
	if outcome == Committed {
		if !t.materialValid(v, expires) {
			return time.Time{}, ErrUnavailable
		}
		c.NextProactive = proactiveAt(resolved, expires, e.config.ProactiveWindow)
	}
	return resolved, nil
}
