//go:build linux

package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type inspectedOwner struct {
	owner.Owner
	inspect func()
	calls   atomic.Int32
}

func (o *inspectedOwner) Refresh(ctx context.Context, account string, generation uint64) (owner.Snapshot, error) {
	o.inspect()
	o.calls.Add(1)
	return o.Owner.Refresh(ctx, account, generation)
}

type observedClient struct {
	BrokerClient
	observations chan string
}

func (c observedClient) Renew(ctx context.Context, r RenewRequest) (Lease, error) {
	l, e := c.BrokerClient.Renew(ctx, r)
	if f, ok := e.(*Refusal); ok {
		c.observations <- "renew:" + f.Code
	}
	return l, e
}
func (c observedClient) Release(ctx context.Context, id string) error {
	e := c.BrokerClient.Release(ctx, id)
	if f, ok := e.(*Refusal); ok {
		c.observations <- "release:" + f.Code
	}
	return e
}

type daemonFixture struct {
	manager      *lease.Manager
	disk         *store.Store
	owner        *testutil.Fake
	inspection   *inspectedOwner
	observations chan string
}

func integratedFixture(t *testing.T, f *fixture, stopped bool, timeout bool, gates ...func(context.Context, policy.Policy) error) *daemonFixture {
	t.Helper()
	path, c := staticFixture(t, f)
	root, e := os.MkdirTemp("/tmp", "daemon-")
	must(t, e)
	must(t, os.Chmod(root, 0755))
	c.SocketPath = filepath.Join(root, "broker.sock")
	writeStatic(t, path, c)
	p := boundFixturePolicy(f, c)
	disk, e := store.Open(c.StoreRoot, c.Policy.Installation, c.Policy.BrokerUID, true, nil)
	must(t, e)
	fake := &testutil.Fake{}
	fake.Set(owner.Snapshot{State: owner.Active, AccessToken: canaryA, AccountID: p.ChatGPTAccountID, ExpiresAt: time.Now().Add(time.Hour), Generation: 1, Trusted: true, Fresh: true, Qualified: true, PolicyGeneration: p.PolicyGeneration, QualificationID: c.Policy.Accounts[0].QualificationID, ExecutableSHA256: p.ExecutableSHA256})
	fake.Next(canaryB)
	inspected := &inspectedOwner{Owner: fake, inspect: func() {
		pid := readPID(t, filepath.Join(f.home, "server-pid"))
		for _, name := range []string{"cmdline", "environ"} {
			b, e := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
			if e != nil {
				t.Error("child observation unavailable")
				continue
			}
			for _, token := range []string{canaryA, canaryB} {
				if bytes.Contains(b, []byte(token)) {
					t.Error("material in child process metadata")
				}
			}
		}
		entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if e != nil {
			t.Error("child descriptors unavailable")
		}
		for _, entry := range entries {
			target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
			if e == nil && strings.HasPrefix(target, "socket:") {
				t.Error("broker socket inherited")
			}
		}
	}}
	var backend owner.Owner = inspected
	if stopped {
		backend = owner.Stopped{}
	}
	options := lease.Options{Now: time.Now}
	if len(gates) > 0 {
		options.Qualification = gates[0]
	}
	if timeout {
		options.RenewTimeout = 100 * time.Millisecond
		fake.Gate(make(chan struct{}))
	}
	m, e := lease.New(c.Policy, disk, backend, options, true)
	must(t, e)
	l, e := server.Listen(c.SocketPath)
	must(t, e)
	srv := server.New(m)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var serve sync.WaitGroup
	serve.Add(1)
	go func() { defer serve.Done(); done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		srv.Close()
		serve.Wait()
		if <-done != nil {
			t.Error("daemon failed")
		}
		srv.Wait()
		m.Close()
		disk.Close()
		os.RemoveAll(root)
	})
	f.d = qualifiedFixture(path, p)
	observations := make(chan string, 4)
	connect := f.d.Connect
	f.d.Connect = func(ctx context.Context) (BrokerClient, error) {
		c, e := connect(ctx)
		if e != nil {
			return c, e
		}
		return observedClient{c, observations}, nil
	}
	return &daemonFixture{m, disk, fake, inspected, observations}
}

// Claim: the real daemon/lease engine refuses its shipped stopped owner without
// material; a test-only qualified tuple and synthetic owner complete a turn,
// refresh through lease.renew, and durably release. A still-running owner
// attempt can refuse cleanup release; timeout then reports 75, preserves output
// and leaves the original bounded lease rather than inventing a receipt.
func TestDaemonRunner(t *testing.T) {
	for _, mode := range []string{"stopped-owner", "renew-timeout", "completed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, map[string]any{"RefreshCount": 1, "Echo": true})
			d := integratedFixture(t, f, mode == "stopped-owner", mode == "renew-timeout")
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			got := f.run()
			want := 0
			if mode == "stopped-owner" {
				want = 69
			}
			if mode == "renew-timeout" {
				want = 75
			}
			requireStatus(t, got, want, f.err.String())
			b, e := os.ReadFile(f.output)
			must(t, e)
			if mode == "completed" {
				if string(b) == "old" || !strings.Contains(string(b), "[redacted]") {
					t.Fatal("completed output missing")
				}
				if calls, _ := d.owner.Counts(); calls != 1 || d.inspection.calls.Load() != 1 {
					t.Fatal("renewal did not reach owner exactly once")
				}
			} else {
				if string(b) != "old" {
					t.Fatal("failure replaced output")
				}
				if mode == "stopped-owner" {
					if !strings.Contains(f.err.String(), "lease_owner_unavailable") {
						t.Fatal("stopped owner refusal lost")
					}
					assertAbsent(t, filepath.Join(f.home, "server-pid"))
				} else {
					if !strings.Contains(f.err.String(), "lease_release_failed") {
						t.Fatal("unconfirmed release was hidden")
					}
					for _, want := range []string{"renew:renew_timeout", "release:renew_timeout"} {
						select {
						case got := <-d.observations:
							if got != want {
								t.Fatal("timeout observation mismatch")
							}
						default:
							t.Fatal("missing typed timeout observation")
						}
					}
				}
			}
			if mode != "stopped-owner" {
				account, e := d.disk.Account(f.o.Account, false)
				must(t, e)
				records, e := account.Records()
				must(t, e)
				released := 0
				for _, raw := range records {
					m, e := wire.Parse(raw)
					must(t, e)
					if m["state"] == "released" {
						released++
					}
				}
				wantReleased := 1
				if mode == "renew-timeout" {
					wantReleased = 0
				}
				if released != wantReleased {
					t.Fatal("unexpected durable release state")
				}
				if mode == "renew-timeout" && len(records) != 1 {
					t.Fatal("timed-out renewal changed lease count")
				}
				pid := readPID(t, filepath.Join(f.home, "server-pid"))
				if syscall.Kill(pid, 0) != syscall.ESRCH {
					t.Fatal("app-server still present")
				}
			}
			assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			for _, token := range []string{canaryA, canaryB} {
				if strings.Contains(f.out.String()+f.err.String(), token) {
					t.Fatal("material in streams")
				}
				must(t, filepath.Walk(f.root, func(path string, info os.FileInfo, e error) error {
					if e != nil {
						return e
					}
					if info.Mode().IsRegular() {
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						if bytes.Contains(b, []byte(token)) {
							return fmt.Errorf("material in owned artifact")
						}
					}
					return nil
				}))
			}
		})
	}
}

// Claim: same-owner release is idempotent on the real daemon, and neither it nor
// the client turns a stopped owner's request refusal into material.
func TestDaemonClientRelease(t *testing.T) {
	f := newFixture(t, nil)
	d := integratedFixture(t, f, false, false)
	p, e := f.d.Authority.Resolve(context.Background(), f.o)
	must(t, e)
	broker, e := f.d.Connect(context.Background())
	must(t, e)
	defer broker.Close()
	must(t, broker.VerifyServer(context.Background(), p.BrokerUID))
	_, e = broker.Hello(context.Background(), HelloRequest{[]int{1}, ProtocolProfile})
	must(t, e)
	b := p.BindingDigest
	l, e := broker.Request(context.Background(), LeaseRequest{Harness: "codex_cli", Profile: p.Profile, Account: p.Account, Channel: "external-token", LaunchID: "fixture-launch", CredentialBinding: Binding{b, "codex_cli", p.Profile, p.Account, "external-token", p.Endpoint, p.ExecutableSHA256, p.PolicyGeneration}, Executor: Executor{[]string{"credential-injection/1"}, Version}})
	must(t, e)
	defer l.erase()
	must(t, broker.Release(context.Background(), l.ID))
	must(t, broker.Release(context.Background(), l.ID))
	_, e = broker.Renew(context.Background(), RenewRequest{l.ID, digest(l.Token)})
	refusalCode(t, e, "lease_not_active", 75)
	if calls, _ := d.owner.Counts(); calls != 0 {
		t.Fatal("released lease started refresh")
	}
}
