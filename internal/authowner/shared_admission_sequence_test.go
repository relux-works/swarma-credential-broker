//go:build linux

package authowner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
)

type blockedAdmissionConfidence struct {
	mu                 sync.Mutex
	base, later, until time.Time
	second             string
}

func (s *blockedAdmissionConfidence) Validate(_ context.Context, label, _ string, _ uint64, _ time.Time) (TimeEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if label == s.second {
		return TimeEvidence{Now: s.later, AuthorityUntil: s.base.Add(3 * time.Hour), Trusted: true, Fresh: true}, nil
	}
	return TimeEvidence{Now: s.base, AuthorityUntil: s.until, Trusted: true, Fresh: true}, nil
}
func (s *blockedAdmissionConfidence) advance(later time.Time) {
	s.mu.Lock()
	s.later = later
	s.mu.Unlock()
}

type blockedAdmissionManager struct {
	Manager
	boundary    string
	at, calls   int
	during      func()
	beforeStart func()
}

func (m *blockedAdmissionManager) returned(boundary string) {
	if m.during == nil || boundary != m.boundary {
		return
	}
	m.calls++
	if m.calls == m.at {
		fn := m.during
		m.during = nil
		fn()
	}
}
func (m *blockedAdmissionManager) Identity(ctx context.Context) (Identity, error) {
	v, err := m.Manager.Identity(ctx)
	m.returned("identity")
	return v, err
}
func (m *blockedAdmissionManager) Start(ctx context.Context, s UnitSpec) error {
	if m.beforeStart != nil {
		m.beforeStart()
	}
	err := m.Manager.Start(ctx, s)
	m.returned("start")
	return err
}
func (m *blockedAdmissionManager) Stop(ctx context.Context, name string, before Observation) (Observation, error) {
	v, err := m.Manager.Stop(ctx, name, before)
	m.returned("stop")
	return v, err
}
func (m *blockedAdmissionManager) Unload(ctx context.Context, name string) error {
	err := m.Manager.Unload(ctx, name)
	m.returned("unload")
	return err
}

// Both synthetic accounts share one Engine, so the second public operation
// updates the real shared clock rather than planting its internal observed field.
func blockedAdmissionFixture(t *testing.T, hook func(string) error) (*fixture, *fixture, *Engine, *blockedAdmissionConfidence, *blockedAdmissionManager, string) {
	t.Helper()
	first := fixtureHook(t, "safe", hook)
	second := newFixture(t, "safe")
	first.e.Close()
	second.e.Close()
	base := first.t.now
	ac := second.c.Accounts[0]
	ac.Label = "example/codex/second"
	ac.VendorID = "fixture-second-account"
	claims, _ := json.Marshal(map[string]any{"exp": base.Add(4 * time.Hour).Unix(), "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": ac.VendorID}})
	token := "fixture." + base64.RawURLEncoding.EncodeToString(claims) + ".unsigned"
	raw, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh-second", "account_id": ac.VendorID}})
	if err := os.WriteFile(filepath.Join(ac.Home, "auth.json"), raw, 0600); err != nil {
		t.Fatal("synthetic second home", err)
	}
	material, err := load(ac, true)
	if err != nil {
		t.Fatal("synthetic second material", err)
	}
	cp := sequenceCheckpoint(t, second)
	disk, err := second.s.Account(ac.Label, true)
	if err != nil {
		t.Fatal("second protected account", err)
	}
	ac.Disk, second.disk = disk, disk
	cp.Revision = 1
	cp.Account = ac.Label
	cp.VendorID = ac.VendorID
	cp.StoreDigest = material.Digest
	cp.TokenDigest = digestToken(token)
	cp.Watermark = base
	if err := disk.Put("owner-checkpoint.json", 0, cp); err != nil {
		t.Fatal("second checkpoint", err)
	}
	source := &blockedAdmissionConfidence{base: base, later: base, until: base.Add(time.Hour), second: ac.Label}
	manager := &blockedAdmissionManager{Manager: first.m}
	c := first.c
	c.DaemonInstance = id()
	c.Accounts = append(c.Accounts, ac)
	current, err := New(context.Background(), c, manager, source, fakeClassifier{})
	if err != nil {
		t.Fatal("shared engine", err)
	}
	t.Cleanup(current.Close)
	return first, second, current, source, manager, token
}

func sharedAdmissionEntries() []string {
	return []string{"snapshot", "fresh-home", "refresh", "retry", "writer", "due", "recovery-stop", "recovery-unload", "writer-reply"}
}

func checkSharedAdmissionInterleaving(t *testing.T, entry string, crossed bool, fraction int) {
	t.Helper()
	var current *Engine
	var source *blockedAdmissionConfidence
	var label string
	auditing := false
	effective := func() time.Time {
		current.clock.mu.Lock()
		defer current.clock.mu.Unlock()
		return current.clock.observed
	}
	hook := func(stage string) error {
		if auditing && stage == "write" && !effective().Before(source.until) {
			t.Error("protected write after uncovered shared floor")
		}
		return nil
	}
	first, second, e, s, manager, secondToken := blockedAdmissionFixture(t, hook)
	current, source = e, s
	label = first.c.Accounts[0].Label
	initial := current.accounts[label].checkpoint
	if entry == "retry" {
		source.until = source.base.Add(time.Second)
	}
	if entry == "retry" || entry == "recovery-stop" || entry == "recovery-unload" {
		if got, err := current.Refresh(context.Background(), label, 1); err != nil || got.AccessToken != first.token {
			t.Fatal("safe resolution control", err)
		}
	}
	if entry == "recovery-stop" || entry == "recovery-unload" {
		a := current.accounts[label]
		pending := initial
		pending.State = owner.Unavailable
		pending.PendingAttempt = a.checkpoint.LastAttempt
		if err := current.checkpoint(a, pending); err != nil {
			t.Fatal("pending recovery prefix", err)
		}
		a.blocked = true
	}
	manager.boundary = "identity"
	manager.at = 1
	switch entry {
	case "refresh", "retry", "due":
		manager.at = 2
	case "writer":
		manager.at = 3
	case "recovery-stop":
		manager.boundary = "stop"
	case "recovery-unload":
		manager.boundary = "unload"
	case "writer-reply":
		manager.boundary = "start"
	}
	manager.calls = 0
	later := source.base.Add(source.until.Sub(source.base) * time.Duration(fraction) / 100)
	if crossed {
		later = source.until
	}
	before := sequenceCheckpoint(t, first)
	starts := first.m.count()
	previous := effective()
	triggered := false
	manager.during = func() {
		source.advance(later)
		got, err := current.Snapshot(context.Background(), source.second)
		if err != nil || got.AccessToken != secondToken {
			t.Fatal("completed second-account snapshot", err)
		}
		if effective().Before(previous) {
			t.Fatal("shared effective floor decreased")
		}
		triggered = true
	}
	manager.beforeStart = func() {
		if !effective().Before(source.until) {
			t.Error("new writer start after uncovered shared floor")
		}
	}
	auditing = true
	var got owner.Snapshot
	var due bool
	var err error
	switch entry {
	case "snapshot":
		got, err = current.Snapshot(context.Background(), label)
	case "fresh-home":
		err = current.AdmitFreshHome(context.Background(), label)
	case "due":
		due, err = current.Due(context.Background(), label)
	case "recovery-stop", "recovery-unload":
		err = recoverTimeFixture(current, label)
	default:
		got, err = current.Refresh(context.Background(), label, 1)
	}
	auditing = false
	after := sequenceCheckpoint(t, first)
	other := sequenceCheckpoint(t, second)
	if !triggered || !effective().Equal(later) || other.Watermark.Before(later) {
		t.Fatal("public cross-account interleaving not established")
	}
	if after.Watermark.Before(before.Watermark) || effective().Before(previous) {
		t.Fatal("effective or durable time decreased")
	}
	if crossed {
		if !errors.Is(err, ErrUnavailable) || got.AccessToken != "" || due {
			t.Fatal("admitted outside latest shared authority", err)
		}
	} else {
		if err != nil {
			t.Fatal("covered interleaving refused", err)
		}
		switch entry {
		case "snapshot", "refresh", "retry", "writer", "writer-reply":
			if got.AccessToken != first.token {
				t.Fatal("covered material missing")
			}
		case "due":
			if !due {
				t.Fatal("covered proactive decision refused")
			}
		case "recovery-stop", "recovery-unload":
			if after.PendingAttempt != "" || current.accounts[label].blocked {
				t.Fatal("covered recovery stayed pending")
			}
		}
	}
	// Identity can block even when the initial sample was covered by D. These
	// entries must merge the shared floor without adding any first-account write.
	if (entry == "fresh-home" || entry == "snapshot") && after.Revision != before.Revision {
		t.Fatal("no-write admission added a write")
	}
	wantStarts := starts
	if (!crossed && (entry == "refresh" || entry == "writer")) || entry == "writer-reply" {
		wantStarts++
	}
	if first.m.count() != wantStarts {
		t.Fatal("unexpected writer or retry count", first.m.count(), wantStarts)
	}
	if entry == "writer-reply" && crossed {
		// The submission preceded the raise while its reply was pending. Refusal
		// must contain that writer and retain pending evidence, never start another.
		for name := range first.m.specs {
			observation, observeErr := first.m.Observe(context.Background(), name)
			if observeErr != nil || !observation.StopCompleted || !observation.Empty {
				t.Fatal("in-flight writer not contained")
			}
		}
		if after.PendingAttempt == "" {
			t.Fatal("withdrawn writer history was discarded")
		}
	}
}

// Claim: each admission entry refuses a completed second-account raise to its
// exclusive authority end during a pending manager call; 30-minute covered
// controls (500 ms inside the retry interval) still admit. Writer reply and
// recovery unload also exercise the last blocking step after earlier proof.
// The schedule is a completed-call interleaving, not atomic asynchronous revocation.
func TestSharedFloorAdmissionEntries(t *testing.T) {
	for _, entry := range sharedAdmissionEntries() {
		for _, crossed := range []bool{false, true} {
			name := "covered-control"
			if crossed {
				name = "authority-end"
			}
			t.Run(entry+"/"+name, func(t *testing.T) { checkSharedAdmissionInterleaving(t, entry, crossed, 50) })
		}
	}
}

// Claim: the existing reproduction seeds now generate public cross-account
// floor raises inside blocking calls for all admission entries, including the
// no-write path. Independent assertions check latest-E grants, monotone floors,
// exclusive-bound effects, covered progress, and preserved safe retry counts.
// Earlier sequence suites continue to exercise expiry refusal and replacement.
func TestTimeAuthoritySharedAdmissionSequences(t *testing.T) {
	seeds := []int64{1, 7, 42, 20261023}
	t.Logf("reproduction seeds: %v", seeds)
	for _, seed := range seeds {
		rng := rand.New(rand.NewSource(seed))
		entries := sharedAdmissionEntries()
		for _, at := range rng.Perm(len(entries)) {
			entry := entries[at]
			for _, mode := range rng.Perm(2) {
				fraction := 1 + rng.Intn(99)
				t.Run(fmt.Sprintf("seed-%d/%s/end-%t/covered-%d", seed, entry, mode == 1, fraction), func(t *testing.T) { checkSharedAdmissionInterleaving(t, entry, mode == 1, fraction) })
			}
		}
	}
}
