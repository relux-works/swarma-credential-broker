// Package testutil supplies synthetic owners and protected, isolated test stores.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type Fake struct {
	mu           sync.Mutex
	view         owner.Snapshot
	calls        int
	live         int
	max          int
	gate         <-chan struct{}
	next         string
	refreshState string
}

func Token() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}
func (f *Fake) Snapshot(ctx context.Context, _ string) (owner.Snapshot, error) {
	if e := ctx.Err(); e != nil {
		return owner.Snapshot{}, e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.view, nil
}
func (f *Fake) Refresh(ctx context.Context, _ string, generation uint64) (owner.Snapshot, error) {
	f.mu.Lock()
	if f.view.Generation != generation {
		v := f.view
		f.mu.Unlock()
		return v, nil
	}
	f.calls++
	f.live++
	if f.live > f.max {
		f.max = f.live
	}
	gate := f.gate
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.live--; f.mu.Unlock() }()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return owner.Snapshot{State: owner.Unavailable}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshState != "" {
		f.view.State = f.refreshState
	}
	f.view.AccessToken = f.next
	f.view.Generation++
	return f.view, nil
}
func (f *Fake) Set(v owner.Snapshot)     { f.mu.Lock(); defer f.mu.Unlock(); f.view = v }
func (f *Fake) View() owner.Snapshot     { f.mu.Lock(); defer f.mu.Unlock(); return f.view }
func (f *Fake) Gate(ch <-chan struct{})  { f.mu.Lock(); defer f.mu.Unlock(); f.gate = ch }
func (f *Fake) Next(token string)        { f.mu.Lock(); defer f.mu.Unlock(); f.next = token }
func (f *Fake) Counts() (calls, max int) { f.mu.Lock(); defer f.mu.Unlock(); return f.calls, f.max }

type Env struct {
	Policy  policy.Policy
	Store   *store.Store
	Manager *lease.Manager
	Owner   *Fake
	Now     time.Time
	Root    string
	UID     uint32
	Account string
	Request wire.LeaseRequest
}

func New(t *testing.T, options lease.Options) *Env { return NewPolicy(t, options, nil) }
func NewPolicy(t *testing.T, options lease.Options, mutate func(*policy.Policy)) *Env {
	return NewFault(t, options, mutate, nil)
}
func NewFault(t *testing.T, options lease.Options, mutate func(*policy.Policy), hook store.Durability) *Env {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if options.Now == nil {
		options.Now = func() time.Time { return now }
	}
	uid := uint32(os.Geteuid())
	executable, e := os.Executable()
	if e != nil {
		t.Fatal("test executable unavailable")
	}
	label := "example/codex/personal"
	p := policy.Policy{Installation: lease.RandomID(), Generation: 1, BrokerUID: uid, Executable: executable, ExecutableSHA256: strings.Repeat("a", 64), MaxLeaseSeconds: 3600, Accounts: []policy.Account{{Label: label, VendorID: "fixture-account", AllowedUIDs: []uint32{uid}, Profiles: []string{"example"}, Endpoint: "https://chatgpt.com/backend-api/codex", ReleaseVersion: "0.163.0", QualificationID: "fixture-evidence", Enabled: true}, {Label: "example/codex/other", VendorID: "fixture-other", AllowedUIDs: []uint32{}, Profiles: []string{"example"}, Endpoint: "https://chatgpt.com/backend-api/codex", Enabled: true}}}
	if mutate != nil {
		mutate(&p)
	}
	root := filepath.Join(t.TempDir(), "store")
	disk, e := store.Open(root, p.Installation, uid, true, hook)
	if e != nil {
		t.Fatal("store setup failed")
	}
	f := &Fake{view: owner.Snapshot{State: owner.Active, AccessToken: Token(), AccountID: "fixture-account", ExpiresAt: now.Add(2 * time.Hour), Generation: 1, Trusted: true, Fresh: true, Qualified: true, PolicyGeneration: p.Generation, QualificationID: p.Accounts[0].QualificationID, ExecutableSHA256: p.ExecutableSHA256}, next: Token()}
	m, e := lease.New(p, disk, f, options, true)
	if e != nil {
		disk.Close()
		t.Fatal("lease setup failed")
	}
	t.Cleanup(func() { m.Close(); disk.Close() })
	request := wire.LeaseRequest{Harness: "codex_cli", Profile: "example", Account: label, Channel: "external-token", Binding: p.Binding(uid, p.Accounts[0], "example"), Network: json.RawMessage("null"), LaunchID: "fixture-launch", Executor: wire.Executor{Capabilities: []string{"credential-injection/1"}, Version: "fixture-1"}}
	return &Env{p, disk, m, f, now, root, uid, label, request}
}
func (e *Env) Issue(t *testing.T) wire.LeaseResult {
	t.Helper()
	out := e.Manager.Call(context.Background(), e.UID, "lease.request", e.Request, time.Now())
	if out.Err != nil {
		t.Fatal("positive lease admission failed:", lease.ErrorCode(out.Err))
	}
	r, ok := out.Result.(wire.LeaseResult)
	if !ok {
		t.Fatal("missing lease result")
	}
	return r
}
func (e *Env) Renew(ctx context.Context, r wire.LeaseResult, rejected string) lease.Outcome {
	return e.Manager.Call(ctx, e.UID, "lease.renew", wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: rejected}, time.Now())
}

// NoLeaseRecords checks the forbidden partial-write effect after a refusal.
func (e *Env) NoLeaseRecords(t *testing.T) {
	t.Helper()
	disk, err := e.Store.Account(e.Account, false)
	if err != nil {
		t.Fatal("metadata unavailable")
	}
	records, err := disk.Records()
	if err != nil || len(records) != 0 {
		t.Fatal("refusal left lease metadata")
	}
}
func Await(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bounded condition not reached")
}

type Vector struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Control string         `json:"control"`
	Setup   map[string]any `json:"setup"`
	Expect  map[string]any `json:"expect"`
	Request map[string]any `json:"request"`
	Runner  map[string]any `json:"runner"`
}

func Vectors(t *testing.T, name string) []Vector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "vectors", "v0", name+".json"))
	if err != nil {
		t.Fatal("vector input unavailable")
	}
	var d struct {
		Cases []Vector `json:"cases"`
	}
	if json.Unmarshal(b, &d) != nil {
		t.Fatal("invalid vector input")
	}
	return d.Cases
}
