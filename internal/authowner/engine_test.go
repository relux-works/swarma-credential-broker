//go:build linux

package authowner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// This executable is the fake vendor, never a login or real issuer. Its only
// home comes from the test's explicit fresh directory, not the parent environment.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "entry-echo" {
		group, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			os.Exit(12)
		}
		fmt.Fprintln(os.Stdout, strings.TrimSpace(string(group)))
		if _, err = io.Copy(os.Stdout, os.Stdin); err != nil {
			os.Exit(13)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "app-server" {
		fakeVendor()
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "grandchild" {
		signalIgnore()
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}
func jwt(exp time.Time, marker string) string {
	b, _ := json.Marshal(map[string]any{"exp": exp.Unix(), "marker": marker, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "fixture-account"}})
	return "fixture." + base64.RawURLEncoding.EncodeToString(b) + ".unsigned"
}
func fixtureAuth(home, token string) error {
	b, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh", "account_id": "fixture-account"}})
	f, e := os.OpenFile(filepath.Join(home, "fixture-pending"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(home, "fixture-pending"), filepath.Join(home, "auth.json")); e != nil {
		return e
	}
	d, e := os.Open(home)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func fakeVendor() {
	home := os.Getenv("CODEX_HOME")
	mode, e := os.ReadFile(filepath.Join(home, "scenario"))
	if e != nil {
		os.Exit(3)
	}
	scanner := bufio.NewScanner(os.Stdin)
	send := func(v any) { b, _ := json.Marshal(v); fmt.Fprintln(os.Stdout, string(b)) }
	state := 0
	for scanner.Scan() {
		var v struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &v) != nil {
			os.Exit(4)
		}
		switch state {
		case 0:
			if v.Method != "initialize" {
				os.Exit(5)
			}
			send(map[string]any{"id": v.ID, "result": map[string]any{"userAgent": "fixture"}})
			state++
		case 1:
			if v.Method != "initialized" {
				os.Exit(6)
			}
			state++
		case 2:
			var p struct {
				Refresh bool `json:"refreshToken"`
			}
			if v.Method != "account/read" || json.Unmarshal(v.Params, &p) != nil || !p.Refresh {
				os.Exit(7)
			}
			switch string(mode) {
			case "safe", "rejected":
				code := 1001
				if string(mode) == "rejected" {
					code = 1002
				}
				send(map[string]any{"id": v.ID, "error": map[string]any{"code": code, "message": "synthetic error"}})
			case "rotate-crash":
				os.WriteFile(filepath.Join(home, "exchange-observed"), []byte("1"), 0600)
				os.Exit(9)
			case "hang":
				for {
					time.Sleep(time.Hour)
				}
			case "grandchild":
				signalIgnore()
				exe, _ := os.Executable()
				cmd := exec.Command(exe, "grandchild")
				cmd.Env = []string{"HOME=" + home, "CODEX_HOME=" + home}
				if cmd.Start() != nil {
					os.Exit(10)
				}
				os.WriteFile(filepath.Join(home, "grandchild-pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
				for {
					time.Sleep(time.Hour)
				}
			case "exit-zero":
				return
			default:
				if string(mode) != "unchanged" {
					token, e := os.ReadFile(filepath.Join(home, "next-token"))
					if e != nil || fixtureAuth(home, string(token)) != nil {
						os.Exit(8)
					}
				}
				if string(mode) == "metadata-only" {
					token, e := os.ReadFile(filepath.Join(home, "next-token"))
					if e != nil || probeMetadata(home, string(token)) != nil {
						os.Exit(8)
					}
				}
				plan := "plus"
				if string(mode) == "bad-plan" {
					token, _ := os.ReadFile(filepath.Join(home, "next-token"))
					plan = string(token)
				}
				send(map[string]any{"id": v.ID, "result": map[string]any{"requiresOpenaiAuth": true, "account": map[string]string{"type": "chatgpt", "planType": plan}}})
			}
			state++
		default:
			os.Exit(11)
		}
	}
	// A detached writer can outlive both its daemon and private pipes. Preserve
	// this explicit witness instead of mistaking retained fake metadata for life.
	if string(mode) == "survive-pipe-loss" {
		signalIgnore()
		if os.WriteFile(filepath.Join(home, "pipes-closed-writer-live"), []byte("1"), 0600) != nil {
			os.Exit(14)
		}
		for {
			time.Sleep(time.Hour)
		}
	}

}

type fakeTime struct {
	mu             sync.Mutex
	now            time.Time
	trusted, fresh bool
}

func (f *fakeTime) Validate(context.Context, string, string, uint64, time.Time) (TimeEvidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return TimeEvidence{f.now, f.now.Add(time.Hour), f.trusted, f.fresh}, nil
}
func (f *fakeTime) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

type fakeClassifier struct{}

func (fakeClassifier) Classify(e RPCError) Disposition {
	if e.Code == 1001 {
		return Safe
	}
	if e.Code == 1002 {
		return Rejected
	}
	return Unknown
}

type fakeManager struct {
	mu            sync.Mutex
	identity      Identity
	disk          *store.Account
	starts        int
	units         map[string]*exec.Cmd
	specs         map[string]UnitSpec
	observation   map[string]Observation
	fault         string
	uncertain     bool
	gate          <-chan struct{}
	started       chan struct{}
	intentMissing bool
}

func (m *fakeManager) Owned(ctx context.Context) error { return m.Ready(ctx) }
func (m *fakeManager) Ready(ctx context.Context) error { _, err := m.Identity(ctx); return err }
func (m *fakeManager) Identity(context.Context) (Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fault == "manager-denied" {
		return Identity{}, ErrUnavailable
	}
	return m.identity, nil
}
func (m *fakeManager) Start(ctx context.Context, s UnitSpec) error {
	records, e := m.disk.Records()
	if e != nil {
		return ErrUnavailable
	}
	found := false
	for _, raw := range records {
		var v Intent
		if decodeRecord(raw, &v) == nil && v.Kind == "attempt-intent/1" && v.Unit == s.Name {
			found = true
		}
	}
	m.mu.Lock()
	m.starts++
	m.intentMissing = !found
	m.specs[s.Name] = s
	if m.fault == "start-denied" {
		m.mu.Unlock()
		return ErrUnavailable
	}
	cmd := exec.Command(s.Executable, s.Args...)
	cmd.Dir = s.Home
	cmd.Env = s.Environment
	cmd.Stdin = s.Input
	cmd.Stdout = s.Output
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e = cmd.Start(); e != nil {
		m.mu.Unlock()
		return e
	}
	m.units[s.Name] = cmd
	m.observation[s.Name] = Observation{Identity: m.identity, Unit: s.Name, Invocation: id(), Cgroup: "/fixture/" + id(), CgroupID: id(), MainPID: uint32(cmd.Process.Pid), ProcessStart: 1, Properties: "fixture-properties", Active: "active", Substate: "running", Complete: true, RestartNo: true, Observed: time.Now().UTC()}
	gate := m.gate
	uncertain := m.uncertain
	ch := m.started
	m.mu.Unlock()
	go cmd.Wait()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ErrUnavailable
		}
	}
	if uncertain {
		return ErrUnavailable
	}
	return nil
}
func (m *fakeManager) Observe(_ context.Context, name string) (Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.observation[name]
	if !ok {
		return Observation{}, ErrUnavailable
	}
	return o, nil
}
func (m *fakeManager) Stop(_ context.Context, name string, before Observation) (Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.observation[name]
	if !ok {
		return Observation{}, ErrUnavailable
	}
	if cmd := m.units[name]; cmd != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	o.Active = "inactive"
	o.Substate = "dead"
	o.StopCompleted = true
	o.Empty = true
	o.PopulatedZero = true
	switch m.fault {
	case "not-found", "timeout", "permission":
		return Observation{}, ErrUnavailable
	case "missing-path":
		o.Cgroup = ""
	case "pid-only":
		o.MainPID = 0
		o.Empty = false
		o.PopulatedZero = false
	case "partial":
		o.Complete = false
	case "contradictory":
		o.Invocation = id()
	case "boot":
		o.Identity.Boot = id()
	case "epoch":
		o.Identity.Epoch = id()
	}
	m.observation[name] = o
	return o, nil
}
func (m *fakeManager) Unload(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.units, name)
	return nil
}
func (m *fakeManager) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.starts }
func (m *fakeManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cmd := range m.units {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

type fixture struct {
	e                       *Engine
	c                       Config
	m                       *fakeManager
	t                       *fakeTime
	s                       *store.Store
	disk                    *store.Account
	home, token, next, root string
}

func newFixture(t *testing.T, mode string) *fixture { t.Helper(); return fixtureHook(t, mode, nil) }
func fixtureHook(t *testing.T, mode string, hook store.Durability) *fixture {
	t.Helper()
	root := t.TempDir()
	if !filepath.IsAbs(root) {
		var e error
		root, e = filepath.Abs(root)
		if e != nil {
			t.Fatal(e)
		}
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("protected parent")
	}
	home := filepath.Join(root, "home")
	if os.Mkdir(home, 0700) != nil {
		t.Fatal("home")
	}
	now := time.Now().UTC().Truncate(time.Second)
	token := jwt(now.Add(4*time.Hour), "synthetic-canary-initial")
	next := jwt(now.Add(5*time.Hour), "synthetic-canary-next")
	if fixtureAuth(home, token) != nil || os.WriteFile(filepath.Join(home, "next-token"), []byte(next), 0600) != nil || os.WriteFile(filepath.Join(home, "scenario"), []byte(mode), 0600) != nil {
		t.Fatal("fixture")
	}
	s, e := store.Open(filepath.Join(root, "store"), "fixture-install", uint32(os.Geteuid()), true, hook)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if s.PolicyGeneration(1, true) != nil {
		t.Fatal("policy floor")
	}
	disk, e := s.Account("example/codex/personal", true)
	if e != nil {
		t.Fatal(e)
	}
	homeID, e := HomeIdentity(home)
	if e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(b)
	c := Config{Installation: "fixture-install", DaemonInstance: id(), DaemonUnit: "fixture-daemon.service", WriterPrefix: "fixture-writer-", PolicyGeneration: 1, Executable: exe, ExecutableSHA256: hex.EncodeToString(hash[:]), QualificationID: "fixture-evidence", Accounts: []AccountConfig{{"example/codex/personal", "fixture-account", home, homeID, disk}}}
	mat, e := load(c.Accounts[0], true)
	if e != nil {
		t.Fatal("load initial", e)
	}
	h := sha256.Sum256([]byte(token))
	cp := Checkpoint{Kind: "account-checkpoint/1", Installation: c.Installation, Revision: 1, Account: c.Accounts[0].Label, VendorID: "fixture-account", HomeID: homeID, State: owner.Active, StoreGeneration: 1, TokenGeneration: 1, Policy: 1, Watermark: now, StoreDigest: mat.Digest, TokenDigest: hex.EncodeToString(h[:]), Plan: "plus"}
	if e = disk.Put("owner-checkpoint.json", 0, cp); e != nil {
		t.Fatal("initial checkpoint", e)
	}
	fm := &fakeManager{identity: Identity{"fixture-boot", uint32(os.Geteuid()), "fixture-epoch"}, disk: disk, units: map[string]*exec.Cmd{}, specs: map[string]UnitSpec{}, observation: map[string]Observation{}}
	ft := &fakeTime{now: now, trusted: true, fresh: true}
	engine, e := New(context.Background(), c, fm, ft, fakeClassifier{})
	if e != nil {
		t.Fatal("new engine", e)
	}
	t.Cleanup(func() { engine.Close(); fm.cleanup() })
	return &fixture{engine, c, fm, ft, s, disk, home, token, next, root}
}
func (f *fixture) refresh() (owner.Snapshot, error) {
	return f.e.Refresh(context.Background(), f.c.Accounts[0].Label, 1)
}
func (f *fixture) snapshot() (owner.Snapshot, error) {
	return f.e.Snapshot(context.Background(), f.c.Accounts[0].Label)
}
func (f *fixture) replacement(t *testing.T) *Engine {
	t.Helper()
	f.e.Close()
	c := f.c
	c.DaemonInstance = id()
	e, err := New(context.Background(), c, f.m, f.t, fakeClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}
func unavailable(t *testing.T, s owner.Snapshot, e error) {
	t.Helper()
	if e == nil || s.AccessToken != "" {
		t.Fatal("unsafe material admitted")
	}
}

// Claim: intent is durably present before any unit starts, and every successful
// refresh reloads replacement material only after confirmed absence/checkpoint.
func TestIntentBeforeStartAndCommittedControl(t *testing.T) {
	f := newFixture(t, "rotate")
	s, e := f.refresh()
	if e != nil || s.AccessToken != f.next || s.Generation != 2 || f.m.count() != 1 || f.m.intentMissing {
		t.Fatal("intent or committed control", e, s.State, s.Generation, f.m.count(), f.m.intentMissing)
	}
	records, e := f.disk.Records()
	if e != nil || len(records) != 7 {
		t.Fatal("append history lost", len(records), e)
	}
	if _, e = f.e.Refresh(context.Background(), f.c.Accounts[0].Label, 1); e != nil || f.m.count() != 1 {
		t.Fatal("superseded generation rotated")
	}
	r := f.replacement(t)
	s, e = r.Snapshot(context.Background(), f.c.Accounts[0].Label)
	if e != nil || s.AccessToken != f.next {
		t.Fatal("resolved replacement refused")
	}
}

// Claim: absence variants are unknown despite PID disappearance; no new writer,
// material, evidence deletion, or fresh-home admission follows any such result.
func TestAbsenceUnknownNoRetry(t *testing.T) {
	for _, fault := range []string{"not-found", "missing-path", "pid-only", "timeout", "permission", "partial", "contradictory", "boot", "epoch", "complete-control"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, "rotate")
			if fault != "complete-control" {
				f.m.fault = fault
			}
			s, e := f.refresh()
			if fault == "complete-control" {
				if e != nil || s.AccessToken != f.next {
					t.Fatal("control refused")
				}
				return
			}
			unavailable(t, s, e)
			before, _ := f.disk.Records()
			s, e = f.refresh()
			unavailable(t, s, e)
			after, _ := f.disk.Records()
			if f.m.count() != 1 || len(before) != len(after) || f.e.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label) == nil {
				t.Fatal("unknown retried or evidence lost")
			}
		})
	}
}

// Claim: an uncertain Start reply looks up the single recorded name, stops that
// unit, and holds ambiguous exchange state; it never allocates a second attempt.
func TestUncertainStartSingleRecordedName(t *testing.T) {
	f := newFixture(t, "rotate")
	f.m.uncertain = true
	s, e := f.refresh()
	unavailable(t, s, e)
	s, e = f.refresh()
	unavailable(t, s, e)
	if f.m.count() != 1 || len(f.m.specs) != 1 {
		t.Fatal("uncertain start duplicated")
	}
}

// Claim: an external-rotation witness without durable vendor persistence, a
// timeout, or exit zero cannot enter safe backoff or admit any automatic retry.
func TestAmbiguousRotationNoRetry(t *testing.T) {
	for _, mode := range []string{"rotate-crash", "exit-zero", "unchanged", "safe-control"} {
		t.Run(mode, func(t *testing.T) {
			actual := mode
			if mode == "safe-control" {
				actual = "safe"
			}
			f := newFixture(t, actual)
			s, e := f.refresh()
			if mode == "safe-control" {
				if e != nil || s.State != owner.Transient {
					t.Fatal("safe control refused")
				}
				return
			}
			unavailable(t, s, e)
			f.t.advance(61 * time.Second)
			s, e = f.refresh()
			unavailable(t, s, e)
			if f.m.count() != 1 {
				t.Fatal("ambiguous retry")
			}
		})
	}
}

// Claim: safe release-qualified nonrotation alone permits exponential backoff;
// conclusive rejection enters reauth, and expired old material is never leased.
func TestSafeBackoffRejectionAndExpiry(t *testing.T) {
	f := newFixture(t, "safe")
	for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second} {
		s, e := f.refresh()
		if e != nil || s.State != owner.Transient {
			t.Fatal("safe failure refused")
		}
		n := f.m.count()
		f.refresh()
		if f.m.count() != n {
			t.Fatal("backoff bypass")
		}
		f.t.advance(delay)
	}
	r := newFixture(t, "rejected")
	s, e := r.refresh()
	if e != nil || s.State != owner.Reauth || s.AccessToken != "" {
		t.Fatal("rejection not closed")
	}
	r.refresh()
	if r.m.count() != 1 {
		t.Fatal("rejected retried")
	}
	f.t.advance(5 * time.Hour)
	s, e = f.snapshot()
	unavailable(t, s, e)
}

// Claim: the retention bound closes admission without deleting resolved history;
// a larger adjacent bound admits a second independently fenced refresh.
func TestRetentionBound(t *testing.T) {
	for _, limit := range []int{1, 2} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			f := newFixture(t, "safe")
			f.e.config.MaxAttempts = limit
			if _, e := f.refresh(); e != nil {
				t.Fatal(e)
			}
			before, _ := f.disk.Records()
			f.t.advance(time.Second)
			_, e := f.refresh()
			after, _ := f.disk.Records()
			if limit == 1 {
				if e == nil || f.m.count() != 1 || len(before) != len(after) {
					t.Fatal("retention bound discarded or started")
				}
			} else if e != nil || f.m.count() != 2 {
				t.Fatal("retention control refused")
			}
		})
	}
}

// Claim: missing/rolled-back files, untrusted time, unknown external freshness,
// and a sticky future watermark refuse material without advancing on distrust.
func TestStoreTimeAndFreshnessFences(t *testing.T) {
	for _, mode := range []string{"missing", "rollback", "time", "freshness", "unknown-expiry", "watermark", "current-control"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "rotate")
			switch mode {
			case "missing":
				os.Remove(filepath.Join(f.home, "auth.json"))
			case "rollback":
				fixtureAuth(f.home, jwt(time.Now().Add(3*time.Hour), "old"))
			case "time":
				f.t.trusted = false
			case "freshness":
				f.t.fresh = false
			case "unknown-expiry":
				fixtureAuth(f.home, jwt(time.Time{}, "unknown"))
			case "watermark":
				a := f.e.accounts[f.c.Accounts[0].Label]
				cp := a.checkpoint
				cp.Watermark = f.t.now.Add(6 * time.Hour)
				f.e.checkpoint(a, cp)
			}
			s, e := f.snapshot()
			if mode == "current-control" {
				if e != nil || s.AccessToken != f.token {
					t.Fatal("current control")
				}
				return
			}
			unavailable(t, s, e)
			if f.m.count() != 0 {
				t.Fatal("fence started writer")
			}
			if mode == "time" && !f.e.accounts[f.c.Accounts[0].Label].checkpoint.Watermark.Equal(f.t.now) {
				t.Fatal("untrusted watermark advanced")
			}
		})
	}
}

// Claim: old manager/boot identity, missing intent/checkpoint and contradictory
// attempt identity cannot be repaired by a new manager's empty inventory.
func TestReplacementRecoveryFences(t *testing.T) {
	for _, mode := range []string{"boot", "epoch", "intent-loss", "checkpoint-loss", "identity", "resolved-control"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "rotate")
			if _, e := f.refresh(); e != nil {
				t.Fatal(e)
			}
			f.e.Close()
			switch mode {
			case "boot":
				f.m.identity.Boot = id()
			case "epoch":
				f.m.identity.Epoch = id()
			case "intent-loss":
				removeOwnerRecord(t, f, "intent")
			case "checkpoint-loss":
				removeOwnerRecord(t, f, "checkpoint")
			case "identity":
				cp := f.e.accounts[f.c.Accounts[0].Label].checkpoint
				cp.Revision++
				cp.VendorID = "other"
				if f.disk.Put("owner-checkpoint.json", cp.Revision-1, cp) != nil {
					t.Fatal("fixture")
				}
			}
			e := f.replacement(t)
			s, err := e.Snapshot(context.Background(), f.c.Accounts[0].Label)
			if mode == "resolved-control" {
				if err != nil || s.AccessToken != f.next {
					t.Fatal("control", err, s.State)
				}
			} else {
				unavailable(t, s, err)
				e.Refresh(context.Background(), f.c.Accounts[0].Label, 2)
				if f.m.count() != 1 {
					t.Fatal("replacement rotated")
				}
			}
		})
	}
}
func removeOwnerRecord(t *testing.T, f *fixture, which string) {
	t.Helper()
	records, e := f.disk.Records()
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte(f.c.Accounts[0].Label))
	dir := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(h[:]))
	for name, raw := range records {
		var v map[string]any
		json.Unmarshal(raw, &v)
		kind, _ := v["kind"].(string)
		if strings.Contains(kind, which) {
			if os.Remove(filepath.Join(dir, name)) != nil {
				t.Fatal("fixture remove")
			}
			return
		}
	}
	t.Fatal("missing fixture record")
}

// Claim: separate adapters cannot acquire the same stable per-home lock while
// live; a clean closed predecessor allows a fully reconciled replacement.
func TestStableHomeLock(t *testing.T) {
	f := newFixture(t, "rotate")
	if _, e := New(context.Background(), f.c, f.m, f.t, fakeClassifier{}); e == nil {
		t.Fatal("second owner admitted")
	}
	f.replacement(t)
}

// Claim: a 48-hour proactive window respects durable half-lifetime spacing for
// short-lived tokens and uses the same contained attempt gate as reactive work.
func TestProactiveShortLifetime(t *testing.T) {
	f := newFixture(t, "rotate")
	label := f.c.Accounts[0].Label
	due, e := f.e.Due(context.Background(), label)
	if e != nil || !due {
		t.Fatal("window")
	}
	if _, e = f.refresh(); e != nil {
		t.Fatal(e)
	}
	due, e = f.e.Due(context.Background(), label)
	if e != nil || due {
		t.Fatal("immediate proactive loop")
	}
	f.t.advance(150 * time.Minute)
	due, e = f.e.Due(context.Background(), label)
	if e != nil || !due {
		t.Fatal("proactive did not reopen")
	}
}

// Claim: token canaries stay out of every owner record, unit property, argv,
// environment, captured owner output and S2a status; only private vendor
// files/pipes carry material. This does not capture a separate daemon process.
func TestHygieneCanary(t *testing.T) {
	f := newFixture(t, "rotate")
	var refreshErr error
	captured := captureOwnerOutput(t, func() { _, refreshErr = f.refresh() })
	if refreshErr != nil {
		t.Fatal(refreshErr)
	}
	records, _ := f.disk.Records()
	all := append([]byte(nil), captured...)
	for _, b := range records {
		all = append(all, b...)
	}
	for _, s := range f.m.specs {
		b, _ := json.Marshal(properties(s))
		all = append(all, b...)
	}
	for _, token := range []string{f.token, f.next, "synthetic-refresh"} {
		if strings.Contains(string(all), token) {
			t.Fatal("material escaped private home/pipes")
		}
	}
}

// Claim: S2a N=8/64 distinct leases rejecting one token start exactly one real
// fake-vendor child through this owner; late callers receive the new generation.
func TestLeaseCoalescingCountsVendorUnits(t *testing.T) {
	for _, n := range []int{8, 64} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			f := newFixture(t, "rotate")
			uid := uint32(os.Geteuid())
			label := f.c.Accounts[0].Label
			p := policy.Policy{Installation: f.c.Installation, Generation: 1, BrokerUID: uid, Executable: f.c.Executable, ExecutableSHA256: f.c.ExecutableSHA256, MaxLeaseSeconds: 3600, Accounts: []policy.Account{{Label: label, VendorID: "fixture-account", AllowedUIDs: []uint32{uid}, Profiles: []string{"example"}, Endpoint: "https://chatgpt.com/backend-api/codex", ReleaseVersion: "0.163.0", QualificationID: f.c.QualificationID, Enabled: true}}}
			m, e := lease.New(p, f.s, f.e, lease.Options{Now: func() time.Time { return f.t.now }}, true)
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			rs := make([]wire.LeaseResult, n)
			for i := range rs {
				r := wire.LeaseRequest{Harness: "codex_cli", Profile: "example", Account: label, Channel: "external-token", Binding: p.Binding(uid, p.Accounts[0], "example"), Network: json.RawMessage("null"), LaunchID: fmt.Sprint("fixture-", i), Executor: wire.Executor{Capabilities: []string{"credential-injection/1"}, Version: "fixture"}}
				o := m.Call(context.Background(), uid, "lease.request", r, time.Now())
				if o.Err != nil {
					t.Fatal(o.Err)
				}
				rs[i] = o.Result.(wire.LeaseResult)
			}
			gate := make(chan struct{})
			f.m.gate = gate
			f.m.started = make(chan struct{}, 1)
			answers := make(chan lease.Outcome, n)
			for _, r := range rs {
				go func(r wire.LeaseResult) {
					answers <- m.Call(context.Background(), uid, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}, time.Now())
				}(r)
			}
			testutil.Await(t, func() bool { pending, _ := m.Stats(label); return pending == n })
			close(gate)
			for range n {
				o := <-answers
				if o.Err != nil || o.Result.(wire.LeaseResult).Payload.AccessToken != f.next {
					t.Fatal("coalescing result", o.Err)
				}
			}
			if f.m.count() != 1 {
				t.Fatal("N callers started N writers")
			}
			b, _ := json.Marshal(m.Status(context.Background(), uid))
			if strings.Contains(string(b), f.next) || strings.Contains(string(b), f.token) {
				t.Fatal("status contains material")
			}
		})
	}
}

// Claim: interruption before RPC leaves a live child and retained intent, closes
// replacement admission, and requires correlated absence before a fresh-home
// ceremony can become admissible. This models daemon-death/replacement-contention.
func TestDaemonDeathAndReplacementContention(t *testing.T) {
	armed := false
	syncs := 0
	f := fixtureHook(t, "survive-pipe-loss", func(stage string) error {
		if armed && stage == "directory-sync" {
			syncs++
			if syncs == 4 {
				return fmt.Errorf("synthetic crash after running evidence")
			}
		}
		return nil
	})
	armed = true
	s, e := f.refresh()
	unavailable(t, s, e)
	if f.m.count() != 1 {
		t.Fatal("no child witness")
	}
	testutil.Await(t, func() bool { _, err := os.Stat(filepath.Join(f.home, "pipes-closed-writer-live")); return err == nil })
	f.m.mu.Lock()
	var child *exec.Cmd
	for _, cmd := range f.m.units {
		child = cmd
	}
	f.m.mu.Unlock()
	if child == nil || child.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("old child did not survive lost pipes")
	}
	// A live-PID diagnostic is a positive witness only, never an absence proof.
	if f.e.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label) == nil {
		t.Fatal("unresolved writer admitted fresh home")
	}
	armed = false
	r := f.replacement(t)
	s, e = r.Snapshot(context.Background(), f.c.Accounts[0].Label)
	unavailable(t, s, e)
	r.Refresh(context.Background(), f.c.Accounts[0].Label, 1)
	if f.m.count() != 1 {
		t.Fatal("replacement writer admitted")
	}
	if r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label) != nil {
		t.Fatal("confirmed-absent old writer still barred from explicit fresh-home prerequisite")
	}
}

// Claim: interrupted cleanup with unreadable absence stays unavailable; complete
// re-observation plus durable RPC/store proof resolves once without another child.
// Terminal-evidence and checkpoint interruption also preserve a recoverable chain.
func TestCleanupInterruptedAndConfirmedRecovery(t *testing.T) {
	for _, point := range []int{6, 7, 8} {
		for _, partial := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d-partial-%t", point, partial), func(t *testing.T) {
				armed := false
				syncs := 0
				f := fixtureHook(t, "rotate", func(stage string) error {
					if armed && stage == "directory-sync" {
						syncs++
						if syncs == point {
							return fmt.Errorf("synthetic durability interruption")
						}
					}
					return nil
				})
				armed = true
				s, e := f.refresh()
				unavailable(t, s, e)
				armed = false
				if partial {
					f.m.fault = "partial"
				}
				r := f.replacement(t)
				s, e = r.Snapshot(context.Background(), f.c.Accounts[0].Label)
				// A durable checkpoint and resolved evidence need no new absence observation.
				if partial && point < 8 {
					unavailable(t, s, e)
				} else if e != nil || s.AccessToken != f.next || s.Generation != 2 {
					t.Fatal("safe recovery refused", e)
				}
				if f.m.count() != 1 {
					t.Fatal("recovery started a second child")
				}
			})
		}
	}
}

// Claim: losing even an intent with no subsequent evidence is detected by the
// prior durable pending marker; losing an earlier resolved history is detected
// by its checkpoint retention count. Neither case is reconstructed as empty.
func TestPendingAndRetainedRecordLoss(t *testing.T) {
	for _, mode := range []string{"only-intent", "earlier-history"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "safe")
			if mode == "earlier-history" {
				if _, e := f.refresh(); e != nil {
					t.Fatal(e)
				}
				f.t.advance(time.Second)
				if _, e := f.refresh(); e != nil {
					t.Fatal(e)
				}
			} else {
				a := f.e.accounts[f.c.Accounts[0].Label]
				cp := a.checkpoint
				cp.State = owner.Unavailable
				cp.PendingAttempt = id()
				if f.e.checkpoint(a, cp) != nil {
					t.Fatal("fixture pending")
				}
			}
			if mode == "earlier-history" {
				removeOwnerRecord(t, f, "intent")
			}
			r := f.replacement(t)
			s, e := r.Snapshot(context.Background(), f.c.Accounts[0].Label)
			unavailable(t, s, e)
			n := f.m.count()
			r.Refresh(context.Background(), f.c.Accounts[0].Label, 1)
			if f.m.count() != n {
				t.Fatal("lost record reconstructed")
			}
		})
	}
}

// Claim: caller cancellation interrupts private RPC promptly; uncertain rotation
// is stopped and held rather than treated as safe transient or retried.
func TestCancelledRPCNoRetry(t *testing.T) {
	f := newFixture(t, "hang")
	ctx, cancel := context.WithCancel(context.Background())
	f.m.started = make(chan struct{}, 1)
	answer := make(chan error, 1)
	go func() { _, err := f.e.Refresh(ctx, f.c.Accounts[0].Label, 1); answer <- err }()
	<-f.m.started
	cancel()
	select {
	case err := <-answer:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("RPC cancellation did not interrupt I/O")
	}
	s, e := f.refresh()
	unavailable(t, s, e)
	if f.m.count() != 1 {
		t.Fatal("cancellation retried")
	}
}

// Claim: the unchanged-token refusal survives the S2a boundary as renew_failed,
// while the owner remains unavailable for subsequent writers and material.
func TestUnchangedReportsRenewFailed(t *testing.T) {
	f := newFixture(t, "unchanged")
	_, err := f.refresh()
	if !errors.Is(err, owner.ErrRenewFailed) {
		t.Fatal("unchanged did not report renew_failed")
	}
	s, e := f.snapshot()
	unavailable(t, s, e)
	f.refresh()
	if f.m.count() != 1 {
		t.Fatal("unchanged outcome retried")
	}
}

type advancingClassifier struct{ clock *fakeTime }

func (a advancingClassifier) Classify(RPCError) Disposition {
	a.clock.advance(3 * time.Second)
	return Safe
}

// Claim: safe backoff starts after completed vendor I/O, and multiple retained
// nonrotating attempts remain recoverable despite unchanged store generations.
func TestSafeBackoffCompletionAndReplacement(t *testing.T) {
	f := newFixture(t, "safe")
	f.e.classifier = advancingClassifier{f.t}
	if _, e := f.refresh(); e != nil {
		t.Fatal(e)
	}
	a := f.e.accounts[f.c.Accounts[0].Label]
	if !a.checkpoint.RetryAt.Equal(f.t.now.Add(time.Second)) {
		t.Fatal("backoff measured from attempt start")
	}
	f.t.advance(time.Second)
	if _, e := f.refresh(); e != nil {
		t.Fatal(e)
	}
	r := f.replacement(t)
	s, e := r.Snapshot(context.Background(), f.c.Accounts[0].Label)
	if e != nil || s.State != owner.Transient || f.m.count() != 2 {
		t.Fatal("safe history not recoverable")
	}
}

// Claim: malformed, missing and unknown record members are rejected while an
// exact encoded flattened intent/control decodes; typed null cannot become zero.
func TestRecordClosureAndNull(t *testing.T) {
	f := newFixture(t, "rotate")
	if _, e := f.refresh(); e != nil {
		t.Fatal(e)
	}
	records, _ := f.disk.Records()
	for _, raw := range records {
		m, _ := wire.Parse(raw)
		if m["kind"] != "attempt-intent/1" {
			continue
		}
		var valid Intent
		if decodeRecord(raw, &valid) != nil {
			t.Fatal("flattened binding control")
		}
		for _, mode := range []string{"null", "missing", "unknown"} {
			mutated, _ := wire.Parse(raw)
			switch mode {
			case "null":
				mutated["manager_uid"] = nil
			case "missing":
				delete(mutated, "daemon_instance_id")
			case "unknown":
				mutated["extra"] = true
			}
			b, _ := wire.Encode(mutated)
			var out Intent
			if decodeRecord(b, &out) == nil {
				t.Fatal("record closure accepted", mode)
			}
		}
		return
	}
	t.Fatal("no intent witness")
}

// Claim: untrusted plan text cannot copy token material into evidence; a valid
// enum in the neighboring hygiene/control test does commit normally.
func TestUntrustedPlanCannotEnterEvidence(t *testing.T) {
	f := newFixture(t, "bad-plan")
	s, e := f.refresh()
	unavailable(t, s, e)
	records, _ := f.disk.Records()
	for _, b := range records {
		if strings.Contains(string(b), f.next) {
			t.Fatal("untrusted plan copied material into evidence")
		}
	}
}

// Claim: duplicate configured vendor identities cannot acquire independent homes
// and admit competing refresh writers, even before enrolment integration exists.
func TestDuplicateConfiguredVendorRefused(t *testing.T) {
	f := newFixture(t, "rotate")
	f.e.Close()
	c := f.c
	other := c.Accounts[0]
	other.Label = "example/codex/other"
	c.Accounts = append(c.Accounts, other)
	if e, err := New(context.Background(), c, f.m, f.t, fakeClassifier{}); err == nil {
		e.Close()
		t.Fatal("duplicate vendor mapping admitted")
	}
}
