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
	confidence Confidence
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
func (e *Engine) confidenceAt(ctx context.Context, a *account) (TimeEvidence, error) {
	if a.blocked || a.config.Disk.Healthy() != nil {
		return TimeEvidence{}, ErrUnavailable
	}
	now, err := e.confidence.Validate(ctx, a.config.Label, a.config.HomeID, a.checkpoint.StoreGeneration, a.checkpoint.Watermark)
	if err != nil || !now.Trusted || !now.Fresh || now.Now.IsZero() || !now.Now.Before(now.AuthorityUntil) {
		return TimeEvidence{}, ErrUnavailable
	}
	current, err := e.manager.Identity(ctx)
	if err != nil || current != e.identity {
		return TimeEvidence{}, ErrUnavailable
	}
	if now.Now.After(a.checkpoint.Watermark) {
		c := a.checkpoint
		c.Watermark = now.Now.UTC()
		if e.checkpoint(a, c) != nil {
			return TimeEvidence{}, ErrUnavailable
		}
	}
	if now.Now.Before(a.checkpoint.Watermark) {
		now.Now = a.checkpoint.Watermark
	}
	if !now.Now.Before(now.AuthorityUntil) {
		return TimeEvidence{}, ErrUnavailable
	}
	return now, nil
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
	if err != nil || material.Digest != c.StoreDigest || digestToken(material.Token) != c.TokenDigest || !t.Now.Before(material.Expires) {
		return v, ErrUnavailable
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
	if now.Now.Before(a.checkpoint.RetryAt) {
		return current, nil
	}
	if err = e.attempt(ctx, a, now); err != nil {
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
	return s.State != owner.Reauth && !t.Now.Before(a.checkpoint.NextProactive) && !t.Now.Before(a.checkpoint.RetryAt) && !t.Now.Before(s.ExpiresAt.Add(-e.config.ProactiveWindow)), nil
}

// AdmitFreshHome checks only the lifecycle prerequisite for the separate
// administrative enrolment ceremony. It starts no child and creates no home.
func (e *Engine) AdmitFreshHome(ctx context.Context, label string) error {
	a, err := e.enter(ctx, label, false)
	if err != nil {
		return err
	}
	defer e.leave(a)
	if !a.historyValid || a.config.Disk.Healthy() != nil {
		return ErrUnavailable
	}
	for id := range a.intents {
		ev := a.attempts[id]
		if len(ev) == 0 {
			return ErrUnavailable
		}
		last := ev[len(ev)-1]
		if last.Absence != "confirmed" || !last.Observation.Complete || !last.Observation.StopCompleted || !last.Observation.Empty || !last.Observation.PopulatedZero {
			return ErrUnavailable
		}
	}
	identity, err := e.manager.Identity(ctx)
	if err != nil || identity != e.identity {
		return ErrUnavailable
	}
	t, err := e.confidence.Validate(ctx, label, a.config.HomeID, a.checkpoint.StoreGeneration, a.checkpoint.Watermark)
	if err != nil || !t.Trusted || !t.Fresh || !t.Now.Before(t.AuthorityUntil) {
		return ErrUnavailable
	}
	return nil
}
func evidenceName(id string, rev uint64) string {
	return fmt.Sprintf("owner-attempt-%s-%06d.json", id, rev)
}
func (e *Engine) evidence(a *account, b Binding, phase string, o Observation, absence string, rpc, outcome Disposition, store uint64, plan ...string) error {
	b.Revision = uint64(len(a.attempts[b.Attempt])) + 2
	p := ""
	if len(plan) > 0 {
		p = plan[0]
	}
	v := Evidence{Plan: p, Kind: "attempt-evidence/1", Binding: b, Phase: phase, Observation: o, Absence: absence, RPC: rpc, Outcome: outcome, StoreAfter: store}
	if a.config.Disk.Healthy() != nil || a.config.Disk.Append(evidenceName(b.Attempt, b.Revision), v) != nil {
		a.blocked = true
		return ErrUnavailable
	}
	a.attempts[b.Attempt] = append(a.attempts[b.Attempt], v)
	return nil
}
func (e *Engine) attempt(ctx context.Context, a *account, t TimeEvidence) error {
	// Retained attempts are never evicted to make room for a new writer.
	if ctx.Err() != nil || a.blocked || len(a.intents) >= e.config.MaxAttempts {
		return ErrUnavailable
	}
	old, err := load(a.config, false)
	if err != nil || old.Digest != a.checkpoint.StoreDigest {
		return ErrUnavailable
	}
	attempt := id()
	if attempt == "" {
		return ErrUnavailable
	}
	b := Binding{Installation: e.config.Installation, Account: a.config.Label, Attempt: attempt, Sequence: uint64(len(a.intents)) + 1, Revision: 1, Operation: "refresh", Daemon: e.config.DaemonInstance, Policy: e.config.PolicyGeneration, Identity: e.identity, Unit: e.config.WriterPrefix + attempt + ".service", Executable: e.config.ExecutableSHA256, Home: a.config.HomeID, StoreBefore: a.checkpoint.StoreGeneration, TokenBefore: a.checkpoint.TokenGeneration, Created: t.Now.UTC(), Deadline: t.Now.Add(e.config.Runtime).UTC()}
	intent := Intent{Kind: "attempt-intent/1", Binding: b, Phase: "intent"}
	pending := a.checkpoint
	pending.State = owner.Unavailable
	pending.PendingAttempt = attempt
	if _, err = load(a.config, true); err != nil || e.checkpoint(a, pending) != nil {
		return ErrUnavailable
	}
	if a.config.Disk.Healthy() != nil || a.config.Disk.Append(evidenceName(attempt, 1), intent) != nil {
		a.blocked = true
		return ErrUnavailable
	}
	a.intents[attempt] = intent
	// Once intent exists every failure remains closed until complete reconciliation.
	a.blocked = true
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
	input.Close()
	output.Close()
	// An uncertain reply is followed only by lookup of this durable unit name.
	if e.evidence(a, b, "submitted", Observation{}, "unknown", Unknown, Unknown, 0) != nil {
		return ErrUnavailable
	}
	o, err := e.manager.Observe(runtime, b.Unit)
	if err != nil || !validRunning(b, o) || o.Active != "active" || o.Substate != "running" || o.MainPID == 0 || o.ProcessStart == 0 {
		return ErrUnavailable
	}
	if e.evidence(a, b, "running", o, "unknown", Unknown, Unknown, 0) != nil {
		return ErrUnavailable
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
	if e.evidence(a, b, "stopping", o, "unknown", result.Outcome, Unknown, 0, result.Plan) != nil {
		return ErrUnavailable
	}
	absent, err := e.manager.Stop(runtime, b.Unit, o)
	if err != nil || !confirmed(b, o, absent) {
		return ErrUnavailable
	}
	if e.evidence(a, b, "absent", absent, "confirmed", result.Outcome, Unknown, 0, result.Plan) != nil {
		return ErrUnavailable
	}
	return e.resolve(runtime, a, b, absent, result)
}
func validRunning(b Binding, o Observation) bool {
	return o.Complete && o.RestartNo && o.Identity == b.Identity && o.Unit == b.Unit && o.Invocation != "" && o.Cgroup != "" && o.CgroupID != "" && o.Properties != ""
}
func confirmed(b Binding, before, after Observation) bool {
	return validRunning(b, before) && after.Complete && after.RestartNo && after.Identity == b.Identity && after.Unit == b.Unit && after.Invocation == before.Invocation && after.Cgroup == before.Cgroup && after.CgroupID == before.CgroupID && after.Properties == before.Properties && after.StopCompleted && after.Empty && after.PopulatedZero && (after.Active == "inactive" || after.Active == "failed")
}
func (e *Engine) resolve(ctx context.Context, a *account, b Binding, absent Observation, result rpcResult) error {
	material, err := load(a.config, true)
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
				delay := time.Second
				for i := uint64(1); i < c.Failures && delay < 60*time.Second; i++ {
					delay *= 2
				}
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				backoff = delay
			} else {
				c.State = owner.Reauth
			}
		}
	}
	if outcome == Unknown {
		if result.Outcome == Committed && material.Digest == c.StoreDigest {
			return ErrRenewFailed
		}
		return ErrUnavailable
	}
	c.StoreDigest = material.Digest
	c.LastAttempt = b.Attempt
	c.PendingAttempt = ""
	c.RetainedAttempts = uint64(len(a.intents))
	// Trusted time is revalidated after vendor I/O before checkpoint publication.
	t, err := e.confidence.Validate(ctx, a.config.Label, a.config.HomeID, c.StoreGeneration, c.Watermark)
	if err != nil || !t.Trusted || !t.Fresh || t.Now.IsZero() || !t.Now.Before(t.AuthorityUntil) {
		return ErrUnavailable
	}
	if t.Now.After(c.Watermark) {
		c.Watermark = t.Now.UTC()
	}
	if !c.Watermark.Before(t.AuthorityUntil) {
		return ErrUnavailable
	}
	if outcome == Safe {
		c.RetryAt = c.Watermark.Add(backoff)
	}
	if outcome == Committed {
		if !c.Watermark.Before(material.Expires) {
			return ErrUnavailable
		}
		c.NextProactive = c.Watermark.Add(material.Expires.Sub(c.Watermark) / 2)
	}
	list := a.attempts[b.Attempt]
	if len(list) == 0 || list[len(list)-1].Phase != "resolved" {
		if e.evidence(a, b, "resolved", absent, "confirmed", result.Outcome, outcome, c.StoreGeneration, result.Plan) != nil {
			return ErrUnavailable
		}
	} else if last := list[len(list)-1]; last.Outcome != outcome || last.StoreAfter != c.StoreGeneration {
		return ErrUnavailable
	}
	if e.checkpoint(a, c) != nil {
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
	for name, raw := range records {
		if !strings.HasPrefix(name, "owner-") {
			continue
		}
		if name == "owner-checkpoint.json" {
			if decodeRecord(raw, &a.checkpoint) != nil {
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
			if decodeRecord(raw, &v) != nil || !e.binding(a, v.Binding) || v.Revision != 1 || v.Phase != "intent" || name != evidenceName(v.Attempt, 1) || a.intents[v.Attempt].Kind != "" {
				return ErrUnavailable
			}
			a.intents[v.Attempt] = v
		case "attempt-evidence/1":
			var v Evidence
			if decodeRecord(raw, &v) != nil || !e.binding(a, v.Binding) || v.Revision < 2 || name != evidenceName(v.Attempt, v.Revision) {
				return ErrUnavailable
			}
			a.attempts[v.Attempt] = append(a.attempts[v.Attempt], v)
		default:
			return ErrUnavailable
		}
	}
	c := a.checkpoint
	if c.Kind != "account-checkpoint/1" || c.Installation != e.config.Installation || c.Account != a.config.Label || c.VendorID != a.config.VendorID || c.HomeID != a.config.HomeID || c.Revision == 0 || c.Policy != e.config.PolicyGeneration || c.StoreGeneration == 0 || c.TokenGeneration == 0 || c.StoreDigest == "" || c.TokenDigest == "" || !validPlan(c.Plan) || c.Watermark.IsZero() {
		return ErrUnavailable
	}
	if c.State != owner.Active && c.State != owner.Transient && c.State != owner.Reauth && !(c.State == owner.Unavailable && c.PendingAttempt != "") {
		return ErrUnavailable
	}
	if uint64(len(a.intents)) < c.RetainedAttempts {
		return ErrUnavailable
	}
	if c.PendingAttempt != "" {
		if _, ok := a.intents[c.PendingAttempt]; !ok {
			return ErrUnavailable
		}
	}
	for id, list := range a.attempts {
		intent, ok := a.intents[id]
		if !ok {
			return ErrUnavailable
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Revision < list[j].Revision })
		a.attempts[id] = list
		previous := 0
		for i, v := range list {
			b := v.Binding
			b.Revision = 1
			if b != intent.Binding || v.Revision != uint64(i)+2 {
				return ErrUnavailable
			}
			phase := map[string]int{"submitted": 1, "running": 2, "stopping": 3, "absent": 4, "resolved": 5}[v.Phase]
			if phase == 0 || phase <= previous {
				return ErrUnavailable
			}
			previous = phase
			if phase >= 2 && !validRunning(intent.Binding, v.Observation) {
				return ErrUnavailable
			}
			if phase >= 4 && (v.Absence != "confirmed" || !v.Observation.StopCompleted || !v.Observation.Empty || !v.Observation.PopulatedZero) {
				return ErrUnavailable
			}
		}
	}

	// Sequence and checkpoint retention count detect holes in older resolved
	// history as well as loss of the current intent. Counters are local integrity
	// checks, never independent rollback detection.
	ordered := make([]Intent, len(a.intents))
	for _, v := range a.intents {
		if v.Sequence == 0 || v.Sequence > uint64(len(ordered)) || ordered[v.Sequence-1].Kind != "" {
			return ErrUnavailable
		}
		ordered[v.Sequence-1] = v
	}
	sg, tg := uint64(1), uint64(1)
	if uint64(len(ordered)) > c.RetainedAttempts+1 {
		return ErrUnavailable
	}
	for _, v := range ordered {
		if v.StoreBefore != sg || v.TokenBefore != tg {
			return ErrUnavailable
		}
		list := a.attempts[v.Attempt]
		if len(list) == 0 || list[len(list)-1].Phase != "resolved" {
			if v.Sequence <= c.RetainedAttempts {
				return ErrUnavailable
			}
			continue
		}
		last := list[len(list)-1]
		switch last.Outcome {
		case Committed:
			if last.RPC != Committed {
				return ErrUnavailable
			}
			sg++
			tg++
		case Safe, Rejected:
			if last.RPC != last.Outcome {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
		if last.StoreAfter != sg {
			return ErrUnavailable
		}
		if v.Sequence == c.RetainedAttempts && (c.LastAttempt != v.Attempt || c.StoreGeneration != sg || c.TokenGeneration != tg) {
			return ErrUnavailable
		}
	}
	if c.RetainedAttempts == 0 && (c.LastAttempt != "" || c.StoreGeneration != 1 || c.TokenGeneration != 1) {
		return ErrUnavailable
	}
	if c.PendingAttempt != "" && a.intents[c.PendingAttempt].Sequence != c.RetainedAttempts+1 {
		return ErrUnavailable
	}

	return nil
}
func (e *Engine) binding(a *account, b Binding) bool {
	return b.Installation == e.config.Installation && b.Account == a.config.Label && attemptPattern.MatchString(b.Attempt) && b.Sequence > 0 && b.Operation == "refresh" && b.Daemon != "" && b.Policy == e.config.PolicyGeneration && b.Unit == e.config.WriterPrefix+b.Attempt+".service" && b.Executable == e.config.ExecutableSHA256 && b.Home == a.config.HomeID && b.StoreBefore > 0 && b.TokenBefore > 0 && !b.Created.IsZero() && b.Deadline.After(b.Created)
}
func (e *Engine) recover(ctx context.Context, a *account) error {
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
			if e.evidence(a, b, "absent", absent, "confirmed", rpc, Unknown, 0) != nil {
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
	return nil
}

var _ owner.Owner = (*Engine)(nil)
