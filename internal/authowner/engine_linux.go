//go:build linux

package authowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type account struct {
	config       AccountConfig
	gate         chan struct{}
	lock         *os.File
	checkpoint   Checkpoint
	attempts     map[string][]Evidence
	intents      map[string]Intent
	blocked      bool
	historyValid bool
}

// Engine holds the per-home locks until Close has joined all admitted work.
// The caller owns the store's singleton lifetime lock for at least this long.
// Per-account channels serialize lifecycle work, never a state mutex over I/O.
type Engine struct {
	config     Config
	manager    Manager
	confidence Confidence // Injection slot; only timeAuthority reads this provider.
	clock      timeAuthority
	classifier Classifier
	identity   Identity
	accounts   map[string]*account
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

func New(ctx context.Context, c Config, m Manager, t Confidence, classifier Classifier) (*Engine, error) {
	if m == nil || t == nil || c.Installation == "" || c.DaemonInstance == "" || c.PolicyGeneration == 0 || c.QualificationID == "" || !prefixPattern.MatchString(c.WriterPrefix) || !unitPattern.MatchString(c.DaemonUnit) || len(c.Accounts) == 0 {
		return nil, ErrUnavailable
	}
	if c.Runtime == 0 {
		c.Runtime = 120 * time.Second
	}
	if c.Runtime <= 0 || c.Runtime > 120*time.Second {
		return nil, ErrUnavailable
	}
	if c.ProactiveWindow == 0 {
		c.ProactiveWindow = 48 * time.Hour
	}
	if c.ProactiveWindow < 0 {
		return nil, ErrUnavailable
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 1024
	}
	if c.MaxAttempts < 1 {
		return nil, ErrUnavailable
	}
	if !filepath.IsAbs(c.Executable) {
		return nil, ErrUnavailable
	}
	f, err := os.Open(c.Executable)
	if err != nil {
		return nil, ErrUnavailable
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil || hex.EncodeToString(h.Sum(nil)) != c.ExecutableSHA256 {
		return nil, ErrUnavailable
	}
	if m.Ready(ctx) != nil || m.Owned(ctx) != nil {
		return nil, ErrUnavailable
	}
	identity, err := m.Identity(ctx)
	if err != nil || identity.Boot == "" || identity.Epoch == "" || identity.UID != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	e := &Engine{config: c, manager: m, confidence: t, classifier: classifier, identity: identity, accounts: map[string]*account{}}
	fail := func() (*Engine, error) { e.Close(); return nil, ErrUnavailable }
	vendors := map[string]bool{}
	for _, ac := range c.Accounts {
		if ac.Label == "" || ac.VendorID == "" || ac.Disk == nil || ac.Disk.Healthy() != nil || e.accounts[ac.Label] != nil || vendors[ac.VendorID] {
			return fail()
		}
		vendors[ac.VendorID] = true
		home, err := HomeIdentity(ac.Home)
		if err != nil || home != ac.HomeID {
			return fail()
		}
		parent := filepath.Dir(ac.Home)
		if _, err = HomeIdentity(parent); err != nil {
			return fail()
		}
		lock, err := os.OpenFile(filepath.Join(parent, "."+filepath.Base(ac.Home)+"-owner.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return fail()
		}
		st, err := lock.Stat()
		if err != nil || st.Mode() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			lock.Close()
			return fail()
		}
		if lock.Sync() != nil {
			lock.Close()
			return fail()
		}
		parentDir, err := os.Open(parent)
		if err != nil {
			lock.Close()
			return fail()
		}
		err = parentDir.Sync()
		parentDir.Close()
		if err != nil {
			lock.Close()
			return fail()
		}
		a := &account{config: ac, gate: make(chan struct{}, 1), lock: lock, intents: map[string]Intent{}, attempts: map[string][]Evidence{}}
		a.gate <- struct{}{}
		e.accounts[ac.Label] = a
		if e.restore(a) != nil {
			a.blocked = true
			continue
		}
		a.historyValid = true
		// The replacement fence starts closed. Recovery uses only retained names;
		// changed epochs and missing/contradictory history never become absence.
		if e.recover(ctx, a) != nil {
			a.blocked = true
		}
	}
	return e, nil
}
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		e.wg.Wait()
		for _, a := range e.accounts {
			if a.lock != nil {
				a.lock.Close()
				a.lock = nil
			}
		}
	})
}
func (e *Engine) enter(ctx context.Context, label string, wait bool) (*account, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ErrUnavailable
	}
	a := e.accounts[label]
	if a == nil {
		e.mu.Unlock()
		return nil, ErrUnavailable
	}
	e.wg.Add(1)
	e.mu.Unlock()
	if wait {
		select {
		case <-a.gate:
		case <-ctx.Done():
			e.wg.Done()
			return nil, ErrUnavailable
		}
	} else {
		select {
		case <-a.gate:
		default:
			e.wg.Done()
			return nil, ErrUnavailable
		}
	}
	return a, nil
}
func (e *Engine) leave(a *account) { a.gate <- struct{}{}; e.wg.Done() }
func (e *Engine) checkpoint(a *account, c Checkpoint) error {
	prior := a.checkpoint.Revision
	c.Revision = prior + 1
	if a.config.Disk.Healthy() != nil || a.config.Disk.Put("owner-checkpoint.json", prior, c) != nil {
		a.blocked = true
		return ErrUnavailable
	}
	a.checkpoint = c
	return nil
}

// timeAdmissionRefusal distinguishes withdrawn authority from a failed or
// interrupted durable operation. Both remain the same public unavailable error,
// but only the former authorizes this call's additional containment cleanup.
type timeAdmissionRefusal struct{}

func (timeAdmissionRefusal) Error() string { return ErrUnavailable.Error() }
func (timeAdmissionRefusal) Unwrap() error { return ErrUnavailable }

// commitThenRevalidate encloses one durable operation. A successful write is
// retained even if the independent authority check after completion refuses the
// next effect. In-memory publication belongs to commit, before the recheck.
func (e *Engine) commitThenRevalidate(ctx context.Context, a *account, c Checkpoint, commit func() error) (TimeEvidence, error) {
	return e.clock.commit(ctx, e, a, c, commit)
}

func (e *Engine) commitCheckpoint(ctx context.Context, a *account, c Checkpoint) (TimeEvidence, error) {
	return e.clock.checkpoint(ctx, e, a, c)
}

func (e *Engine) durableMaterial(ctx context.Context, a *account) (material, error) {
	var m material
	_, err := e.commitThenRevalidate(ctx, a, a.checkpoint, func() error {
		var err error
		m, err = load(a.config, true)
		return err
	})
	if err != nil {
		return material{}, err
	}
	return m, nil
}

func (e *Engine) appendIntent(ctx context.Context, a *account, v Intent) error {
	_, err := e.commitThenRevalidate(ctx, a, a.checkpoint, func() error {
		if a.config.Disk.Healthy() != nil || a.config.Disk.Append(evidenceName(v.Attempt, v.Revision), v) != nil {
			a.blocked = true
			return ErrUnavailable
		}
		a.intents[v.Attempt] = v
		a.blocked = true
		return nil
	})
	return err
}

// Compatibility adapters keep fixture callers on the same time authority.
func (e *Engine) admissionTime(ctx context.Context, a *account, c Checkpoint) (TimeEvidence, error) {
	return e.clock.sample(ctx, e, a, c)
}

func (e *Engine) confidenceAt(ctx context.Context, a *account) (TimeEvidence, error) {
	authorized, err := e.clock.admission(ctx, e, a)
	return authorized.evidence, err
}

func (e *Engine) snapshot(ctx context.Context, a *account) (owner.Snapshot, error) {
	v := owner.Snapshot{State: owner.Unavailable}
	t, err := e.confidenceAt(ctx, a)
	if err != nil {
		return v, ErrUnavailable
	}
	c := a.checkpoint
	if c.State == owner.Reauth {
		return owner.Snapshot{State: owner.Reauth}, nil
	}
	if c.State != owner.Active && c.State != owner.Transient {
		return v, ErrUnavailable
	}
	material, err := load(a.config, false)
	if err != nil || material.Digest != c.StoreDigest || digestToken(material.Token) != c.TokenDigest {
		return v, ErrUnavailable
	}
	if err := e.clock.materialAvailable(ctx, e, a, a.checkpoint, t, material.Expires); err != nil {
		return v, err
	}
	return owner.Snapshot{State: c.State, AccessToken: material.Token, AccountID: material.Account, PlanType: c.Plan, ExpiresAt: material.Expires, AuthorityUntil: t.AuthorityUntil, Generation: c.TokenGeneration, Trusted: true, Fresh: true, Qualified: true, PolicyGeneration: c.Policy, QualificationID: e.config.QualificationID, ExecutableSHA256: e.config.ExecutableSHA256}, nil
}
func (e *Engine) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	a, err := e.enter(ctx, label, false)
	if err != nil {
		return owner.Snapshot{State: owner.Unavailable}, err
	}
	defer e.leave(a)
	return e.snapshot(ctx, a)
}
func (e *Engine) Refresh(ctx context.Context, label string, generation uint64) (owner.Snapshot, error) {
	a, err := e.enter(ctx, label, true)
	if err != nil {
		return owner.Snapshot{State: owner.Unavailable}, err
	}
	defer e.leave(a)
	current, err := e.snapshot(ctx, a)
	if err != nil || current.State == owner.Reauth {
		return current, err
	}
	if current.Generation != generation {
		return current, nil
	}
	now, err := e.confidenceAt(ctx, a)
	if err != nil {
		return owner.Snapshot{State: owner.Unavailable}, err
	}
	if !e.clock.retryReady(now, a.checkpoint) {
		if err := e.clock.materialAvailable(ctx, e, a, a.checkpoint, now, current.ExpiresAt); err != nil {
			return owner.Snapshot{State: owner.Unavailable}, err
		}
		current.AuthorityUntil = now.AuthorityUntil
		return current, nil
	}
	if err = e.attempt(ctx, a); err != nil {
		if _, refused := err.(timeAdmissionRefusal); refused {
			err = ErrUnavailable
		}
		return owner.Snapshot{State: owner.Unavailable}, err
	}
	return e.snapshot(ctx, a)
}

// Due bounds proactive work by both the configured window and a durable
// half-remaining-lifetime interval after each success. Short vendor lifetimes
// therefore cannot produce an immediate refresh loop. Calls still use Refresh.
func (e *Engine) Due(ctx context.Context, label string) (bool, error) {
	a, err := e.enter(ctx, label, false)
	if err != nil {
		return false, err
	}
	defer e.leave(a)
	s, err := e.snapshot(ctx, a)
	if err != nil {
		return false, err
	}
	t, err := e.confidenceAt(ctx, a)
	if err != nil {
		return false, err
	}
	if s.State == owner.Reauth {
		return false, nil
	}
	if err := e.clock.materialAvailable(ctx, e, a, a.checkpoint, t, s.ExpiresAt); err != nil {
		return false, err
	}
	return e.clock.due(t, a.checkpoint, s.ExpiresAt, e.config.ProactiveWindow), nil
}

// AdmitFreshHome checks only the lifecycle prerequisite for the separate
// administrative enrolment ceremony. It starts no child and creates no home.
func (e *Engine) AdmitFreshHome(ctx context.Context, label string) error {
	a, err := e.enter(ctx, label, false)
	if err != nil {
		return err
	}
	defer e.leave(a)
	_, err = e.confidenceAt(ctx, a)
	return err
}
func evidenceName(id string, rev uint64) string {
	return fmt.Sprintf("owner-attempt-%s-%06d.json", id, rev)
}
func (e *Engine) evidence(ctx context.Context, a *account, b Binding, phase string, o Observation, absence string, rpc, outcome Disposition, store uint64, plan ...string) error {
	b.Revision = uint64(len(a.attempts[b.Attempt])) + 2
	p := ""
	if len(plan) > 0 {
		p = plan[0]
	}
	v := Evidence{Plan: p, Kind: "attempt-evidence/1", Binding: b, Phase: phase, Observation: o, Absence: absence, RPC: rpc, Outcome: outcome, StoreAfter: store}
	return e.appendEvidence(ctx, a, v, a.checkpoint)
}
func (e *Engine) appendEvidence(ctx context.Context, a *account, v Evidence, c Checkpoint) error {
	_, err := e.commitThenRevalidate(ctx, a, c, func() error {
		if a.config.Disk.Healthy() != nil || a.config.Disk.Append(evidenceName(v.Attempt, v.Revision), v) != nil {
			a.blocked = true
			return ErrUnavailable
		}
		a.attempts[v.Attempt] = append(a.attempts[v.Attempt], v)
		return nil
	})
	return err
}
func (e *Engine) attempt(ctx context.Context, a *account) (resultErr error) {
	// Retained attempts are never evicted to make room for a new writer.
	if ctx.Err() != nil || a.blocked || e.retained(a) != nil || len(a.intents) >= e.config.MaxAttempts {
		return ErrUnavailable
	}
	_, err := e.confidenceAt(ctx, a)
	if err != nil {
		return ErrUnavailable
	}
	old, err := e.durableMaterial(ctx, a)
	if err != nil || old.Digest != a.checkpoint.StoreDigest {
		return ErrUnavailable
	}
	attempt := id()
	if attempt == "" {
		return ErrUnavailable
	}
	b := Binding{Installation: e.config.Installation, Account: a.config.Label, Attempt: attempt, Sequence: uint64(len(a.intents)) + 1, Revision: 1, Operation: "refresh", Daemon: e.config.DaemonInstance, Policy: e.config.PolicyGeneration, Identity: e.identity, Unit: e.config.WriterPrefix + attempt + ".service", Executable: e.config.ExecutableSHA256, Home: a.config.HomeID, StoreBefore: a.checkpoint.StoreGeneration, TokenBefore: a.checkpoint.TokenGeneration, StoreDigestBefore: old.Digest, TokenDigestBefore: digestToken(old.Token), PlanBefore: a.checkpoint.Plan, TokenExpiresBefore: old.Expires}
	e.clock.stamp(a, &b, e.config.Runtime)
	intent := Intent{Kind: "attempt-intent/1", Binding: b, Phase: "intent"}
	pending := a.checkpoint
	pending.State = owner.Unavailable
	pending.PendingAttempt = attempt
	if _, err = e.commitCheckpoint(ctx, a, pending); err != nil {
		return ErrUnavailable
	}
	if e.appendIntent(ctx, a, intent) != nil {
		return ErrUnavailable
	}
	input, write, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer input.Close()
	defer write.Close()
	read, output, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer read.Close()
	defer output.Close()
	runtime, cancel := context.WithTimeout(context.Background(), e.config.Runtime+4*time.Second)
	defer cancel()
	s := UnitSpec{Name: b.Unit, Daemon: e.config.DaemonUnit, Executable: e.config.Executable, ExecutableSHA256: e.config.ExecutableSHA256, Args: []string{"app-server"}, Home: a.config.Home, Environment: []string{"HOME=" + a.config.Home, "CODEX_HOME=" + a.config.Home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, Runtime: e.config.Runtime, Input: input, Output: output}
	startErr := e.manager.Start(runtime, s)
	// Cleanup remains permitted after authority is withdrawn. A storage failure
	// preserves the existing interruption/recovery path. Never retry an
	// attempted stop (including an uncertain reference reply), publish substitute
	// evidence, or unload a unit whose terminal checkpoint is still pending.
	var before Observation
	stopAttempted := false
	defer func() {
		_, refused := resultErr.(timeAdmissionRefusal)
		if stopAttempted || !refused {
			return
		}
		if !validRunning(b, before) {
			var err error
			before, err = e.manager.Observe(runtime, b.Unit)
			if err != nil || !validRunning(b, before) {
				return
			}
		}
		_, _ = e.manager.Stop(runtime, b.Unit, before)
	}()
	input.Close()
	output.Close()
	// An uncertain reply is followed only by lookup of this durable unit name.
	if err := e.evidence(runtime, a, b, "submitted", Observation{}, "unknown", Unknown, Unknown, 0); err != nil {
		return err
	}
	o, err := e.manager.Observe(runtime, b.Unit)
	before = o
	if err != nil || !validRunning(b, o) || o.Active != "active" || o.Substate != "running" || o.MainPID == 0 || o.ProcessStart == 0 {
		return ErrUnavailable
	}
	if err := e.evidence(runtime, a, b, "running", o, "unknown", Unknown, Unknown, 0); err != nil {
		return err
	}
	// Do not exchange over uncertain FD ownership. Still stop and reconcile, with
	// an unknown RPC result; never create a replacement unit or retry this call.
	result := rpcResult{Outcome: Unknown}
	if startErr == nil {
		rpcctx, rpccancel := context.WithTimeout(runtime, 6*time.Second)
		stopCancellation := context.AfterFunc(ctx, rpccancel)
		defer stopCancellation()
		if d, ok := ctx.Deadline(); ok {
			var c context.CancelFunc
			rpcctx, c = context.WithDeadline(rpcctx, d)
			defer c()
		}
		result = managed(rpcctx, read, write, e.classifier)
		rpccancel()
	}
	if err := e.evidence(runtime, a, b, "stopping", o, "unknown", result.Outcome, Unknown, 0, result.Plan); err != nil {
		return err
	}
	stopAttempted = true
	absent, err := e.manager.Stop(runtime, b.Unit, o)
	if err != nil || !confirmed(b, o, absent) {
		return ErrUnavailable
	}
	if err := e.evidence(runtime, a, b, "absent", absent, "confirmed", result.Outcome, Unknown, 0, result.Plan); err != nil {
		return err
	}
	return e.resolve(runtime, a, b, absent, result)
}
func validRunning(b Binding, o Observation) bool {
	return o.Complete && o.RestartNo && o.Identity == b.Identity && o.Unit == b.Unit && o.Invocation != "" && o.Cgroup != "" && o.CgroupID != "" && o.Properties != ""
}

// sameWriter compares stable identity, not changing process or lifecycle status.
func sameWriter(a, b Observation) bool {
	return a.Identity == b.Identity && a.Unit == b.Unit && a.Invocation == b.Invocation && a.Cgroup == b.Cgroup && a.CgroupID == b.CgroupID && a.Properties == b.Properties
}
func confirmed(b Binding, before, after Observation) bool {
	return validRunning(b, before) && after.Complete && after.RestartNo && after.Identity == b.Identity && after.Unit == b.Unit && after.Invocation == before.Invocation && after.Cgroup == before.Cgroup && after.CgroupID == before.CgroupID && after.Properties == before.Properties && after.StopCompleted && after.Empty && after.PopulatedZero && (after.Active == "inactive" || after.Active == "failed")
}
func (e *Engine) resolve(ctx context.Context, a *account, b Binding, absent Observation, result rpcResult) error {
	if e.validateChain(a) != nil {
		return ErrUnavailable
	}
	material, err := e.durableMaterial(ctx, a)
	if err != nil {
		return ErrUnavailable
	}
	c := a.checkpoint
	if c.StoreGeneration != b.StoreBefore || c.TokenGeneration != b.TokenBefore {
		return ErrUnavailable
	}
	outcome := Unknown
	backoff := time.Duration(0)
	switch result.Outcome {
	case Committed:
		if material.Digest != c.StoreDigest && material.Token != "" {
			// Replacing only refresh-token metadata cannot satisfy rejected-token renewal.
			beforeToken := a.checkpoint.TokenDigest
			h := sha256.Sum256([]byte(material.Token))
			if hex.EncodeToString(h[:]) != beforeToken {
				outcome = Committed
				c.TokenDigest = hex.EncodeToString(h[:])
				c.TokenGeneration++
				c.StoreGeneration++
				c.State = owner.Active
				c.Plan = result.Plan
				c.Failures = 0
				c.RetryAt = time.Time{}
			}
		}
	case Safe, Rejected:
		if material.Digest == c.StoreDigest {
			outcome = result.Outcome
			if outcome == Safe {
				c.State = owner.Transient
				c.Failures++
				backoff = safeBackoff(c.Failures)
			} else {
				c.State = owner.Reauth
			}
		}
	}
	if outcome == Unknown {
		token := sha256.Sum256([]byte(material.Token))
		if result.Outcome == Committed && hex.EncodeToString(token[:]) == c.TokenDigest {
			return ErrRenewFailed
		}
		return ErrUnavailable
	}
	c.StoreDigest = material.Digest
	c.LastAttempt = b.Attempt
	c.PendingAttempt = ""
	c.RetainedAttempts = uint64(len(a.intents))
	list := a.attempts[b.Attempt]
	var recorded time.Time
	if len(list) > 0 && list[len(list)-1].Phase == "resolved" {
		last := list[len(list)-1]
		if last.Outcome != outcome || last.StoreAfter != c.StoreGeneration || !last.TokenExpires.Equal(material.Expires) || last.StoreDigestAfter != material.Digest || last.TokenDigestAfter != digestToken(material.Token) {
			return ErrUnavailable
		}
		recorded = last.ResolvedAt
	}
	resolvedAt, err := e.clock.resolution(ctx, e, a, &c, recorded, material.Expires, outcome, backoff)
	if err != nil {
		return ErrUnavailable
	}
	if len(list) == 0 || list[len(list)-1].Phase != "resolved" {
		b.Revision = uint64(len(list)) + 2
		v := Evidence{Kind: "attempt-evidence/1", Binding: b, Phase: "resolved", Observation: absent, Absence: "confirmed", RPC: result.Outcome, Outcome: outcome, StoreAfter: c.StoreGeneration, Plan: result.Plan, ResolvedAt: resolvedAt, TokenExpires: material.Expires, StoreDigestAfter: material.Digest, TokenDigestAfter: digestToken(material.Token)}
		if e.appendEvidence(ctx, a, v, c) != nil {
			return ErrUnavailable
		}
	}
	if _, err := e.commitCheckpoint(ctx, a, c); err != nil {
		// If the checkpoint completed before withdrawal, its full history is
		// already durable. Release containment retention, but refuse admission.
		if a.checkpoint.PendingAttempt == "" && a.checkpoint.LastAttempt == b.Attempt {
			_ = e.manager.Unload(ctx, b.Unit)
		}
		return ErrUnavailable
	}
	a.blocked = false
	// Retain the unit until terminal evidence and checkpoint are durable.
	if e.manager.Unload(ctx, b.Unit) != nil {
		a.blocked = true
		return ErrUnavailable
	}
	return nil
}

func (e *Engine) restore(a *account) error {
	records, err := a.config.Disk.Records()
	if err != nil {
		return ErrUnavailable
	}
	// Decode into fresh maps: a deleted record must not survive in memory from
	// an earlier successful load. Publish only a fully validated chain.
	next := &account{config: a.config, intents: map[string]Intent{}, attempts: map[string][]Evidence{}}
	for name, raw := range records {
		if !strings.HasPrefix(name, "owner-") {
			continue
		}
		if name == "owner-checkpoint.json" {
			if decodeRecord(raw, &next.checkpoint) != nil {
				return ErrUnavailable
			}
			continue
		}
		m, err := wire.Parse(raw)
		if err != nil {
			return ErrUnavailable
		}
		kind, _ := m["kind"].(string)
		switch kind {
		case "attempt-intent/1":
			var v Intent
			if decodeRecord(raw, &v) != nil || name != evidenceName(v.Attempt, v.Revision) || next.intents[v.Attempt].Kind != "" {
				return ErrUnavailable
			}
			next.intents[v.Attempt] = v
		case "attempt-evidence/1":
			var v Evidence
			if decodeRecord(raw, &v) != nil || name != evidenceName(v.Attempt, v.Revision) {
				return ErrUnavailable
			}
			next.attempts[v.Attempt] = append(next.attempts[v.Attempt], v)
		default:
			return ErrUnavailable
		}
	}
	for key, list := range next.attempts {
		sort.Slice(list, func(i, j int) bool { return list[i].Revision < list[j].Revision })
		next.attempts[key] = list
	}
	if e.validateChain(next) != nil {
		return ErrUnavailable
	}
	a.checkpoint, a.intents, a.attempts = next.checkpoint, next.intents, next.attempts
	return nil
}
func (e *Engine) binding(a *account, b Binding) bool {
	return b.Installation == e.config.Installation && b.Account == a.config.Label && attemptPattern.MatchString(b.Attempt) && b.Sequence > 0 && b.Operation == "refresh" && b.Daemon != "" && b.Policy == e.config.PolicyGeneration && b.Unit == e.config.WriterPrefix+b.Attempt+".service" && b.Executable == e.config.ExecutableSHA256 && b.Home == a.config.HomeID && b.StoreBefore > 0 && b.TokenBefore > 0 && !b.Created.IsZero() && b.Deadline.After(b.Created)
}
func (e *Engine) recover(ctx context.Context, a *account) error {
	if e.validateChain(a) != nil {
		return ErrUnavailable
	}
	if _, err := e.admissionTime(ctx, a, a.checkpoint); err != nil {
		return ErrUnavailable
	}
	var unresolved []Intent
	for id, intent := range a.intents {
		// Old boot/manager identity remains unavailable even with a new empty manager.
		if intent.Identity != e.identity {
			return ErrUnavailable
		}
		list := a.attempts[id]
		if len(list) > 0 && list[len(list)-1].Phase == "resolved" {
			last := list[len(list)-1]
			if last.Outcome == Unknown {
				return ErrUnavailable
			}
			if intent.Sequence <= a.checkpoint.RetainedAttempts && a.checkpoint.StoreGeneration >= last.StoreAfter {
				continue
			}

		}
		unresolved = append(unresolved, intent)
	}
	if len(unresolved) > 1 {
		return ErrUnavailable
	}
	if len(unresolved) == 1 {
		b := unresolved[0].Binding
		list := a.attempts[b.Attempt]
		if len(list) < 2 {
			return ErrUnavailable
		}
		var before Observation
		var rpc Disposition = Unknown
		plan := ""
		for _, v := range list {
			if v.Phase == "running" {
				before = v.Observation
			}
			if v.Phase == "stopping" {
				rpc = v.RPC
				plan = v.Plan
			}
		}
		if !validRunning(b, before) {
			return ErrUnavailable
		}
		absent, err := e.manager.Stop(ctx, b.Unit, before)
		if err != nil || !confirmed(b, before, absent) {
			return ErrUnavailable
		}
		// Durable response proof is essential. Absence alone cannot resolve rotation.
		last := list[len(list)-1]
		if last.Phase != "absent" && last.Phase != "resolved" {
			if e.evidence(ctx, a, b, "absent", absent, "confirmed", rpc, Unknown, 0, plan) != nil {
				return ErrUnavailable
			}
		}
		if rpc == Unknown {
			return ErrUnavailable
		}
		if err = e.resolve(ctx, a, b, absent, rpcResult{rpc, plan}); err != nil {
			return err
		}
	}
	// A checkpoint referring to a deleted attempt is record loss, never freshness.
	if a.checkpoint.LastAttempt != "" {
		list := a.attempts[a.checkpoint.LastAttempt]
		if len(list) == 0 || list[len(list)-1].Phase != "resolved" {
			return ErrUnavailable
		}
	}
	// Recovery may finish with a blocking manager unload. Its admission result
	// must pass the same final constructor after that operation has returned.
	_, err := e.admissionTime(ctx, a, a.checkpoint)
	return err
}

var _ owner.Owner = (*Engine)(nil)
