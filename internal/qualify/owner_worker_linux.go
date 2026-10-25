//go:build linux

package qualify

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

const ownerLabel = "synthetic-owner"

type ownerContext struct {
	Root, HomeID, Candidate, Scenario, Image string
	Now                                      time.Time
	Epoch, Parent                            int
	Member                                   string
}
type ownerMessage struct {
	ID    int
	Op    string
	Data  json.RawMessage
	Error string
}
type ownerChannel struct {
	rpc           func(string, any, any) error
	reply         func(string, any, error) error
	r, w          *os.File
	mu            sync.Mutex
	reads, writes int
	limit         int
}

func (c *ownerChannel) bound() int {
	if c.limit == 512 {
		return 512
	}
	return 256
}
func (c *ownerChannel) send(op string, value any, err error) error {
	if c.reply != nil {
		return c.reply(op, value, err)
	}
	m := ownerMessage{ID: c.writes + 1, Op: op}
	if err != nil {
		m.Error = err.Error()
	}
	if value != nil {
		b, e := wire.Encode(value)
		if e != nil {
			return e
		}
		m.Data = b
	}
	b, e := wire.Encode(m)
	if e != nil || len(b) > 4096 || c.reads+c.writes >= c.bound() {
		return errors.New("owner evidence budget")
	}
	c.writes++
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, e = c.w.Write(h[:]); e != nil {
		return e
	}
	_, e = c.w.Write(b)
	return e
}
func (c *ownerChannel) read() (m ownerMessage, e error) {
	var h [4]byte
	if _, e = io.ReadFull(c.r, h[:]); e != nil {
		return
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > 4096 || c.reads+c.writes >= c.bound() {
		return m, errors.New("owner evidence budget")
	}
	c.reads++
	b := make([]byte, n)
	if _, e = io.ReadFull(c.r, b); e == nil {
		e = wire.Decode(b, &m)
		if e == nil && m.ID != c.reads {
			e = errors.New("owner protocol sequence")
		}
	}
	return
}
func (c *ownerChannel) call(op string, value, result any) error {
	if c.rpc != nil {
		return c.rpc(op, value, result)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.send(op, value, nil); e != nil {
		return e
	}
	m, e := c.read()
	if e != nil {
		return e
	}
	if m.Op != op {
		return errors.New("owner protocol order")
	}
	if m.Error != "" {
		return errors.New(m.Error)
	}
	if result != nil {
		return wire.Decode(m.Data, result)
	}
	return nil
}
func ownerPolicy(c ownerContext) policy.Policy {
	uid := uint32(os.Geteuid())
	return policy.Policy{Installation: "synthetic-install", Generation: 1, BrokerUID: uid, Executable: "/proc/self/fd/6", ExecutableSHA256: c.Candidate, MaxLeaseSeconds: 30, Accounts: []policy.Account{{Label: ownerLabel, VendorID: "synthetic-vendor", AllowedUIDs: []uint32{uid}, Profiles: []string{wire.Profile}, Endpoint: "https://example.invalid/inference", ReleaseVersion: "0.163.0", QualificationID: "synthetic-evidence", Enabled: true}}}
}
func ownerMain(args []string) int {
	if len(args) != 2 || os.Args[0] != "/proc/self/fd/4" || !policy.Hash(args[1]) {
		return 125
	}
	f := os.NewFile(5, "owner-context")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Mode()&os.ModeNamedPipe == 0 {
		return 125
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	var c ownerContext
	if e != nil || len(b) > 4096 || qualificationHash(b) != args[1] || wire.Decode(b, &c) != nil || !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || c.Parent != os.Getppid() || c.Epoch < 1 || c.Epoch > 2 || !ownerScenario(c.Scenario) || c.Now.IsZero() {
		return 125
	}
	image := os.NewFile(4, "owner-image")
	defer image.Close()
	if _, e = image.Seek(0, io.SeekStart); e != nil {
		return 125
	}
	measured, e := descriptorDigest(image)
	if e != nil || measured != c.Image {
		return 125
	}
	candidate := os.NewFile(6, "owner-approved-image")
	defer candidate.Close()
	digest, e := descriptorDigest(candidate)
	if e != nil || digest != c.Candidate {
		return 125
	}
	if unix.SetNonblock(7, true) != nil || unix.SetNonblock(8, true) != nil {
		return 125
	}
	ch := &ownerChannel{r: os.NewFile(8, "owner-input"), w: os.NewFile(7, "owner-output")}
	defer ch.r.Close()
	defer ch.w.Close()
	for _, f := range []*os.File{ch.r, ch.w} {
		st, e = f.Stat()
		if e != nil || st.Mode()&os.ModeNamedPipe == 0 {
			return 125
		}
		if f.SetDeadline(time.Now().Add(25*time.Second)) != nil {
			return 125
		}
	}
	if egress.EnterOwnerRole(args[1]) != nil {
		return 125
	}
	return ownerCompose(c, ch)
}

// ownerCompose is synthetic qualification authority, entered only after the
// protected descriptor/context and role barrier. Recovery never initializes.
func ownerCompose(c ownerContext, ch *ownerChannel) int {
	if parallelScenario(c.Scenario) {
		return parallelCompose(c, ch)
	}
	stage := "store"
	fail := func() int {
		if ch.send("startup", stage, errors.New("owner_startup_refused")) != nil {
			return 1
		}
		m, e := ch.read()
		if e != nil || m.Op != "close" {
			return 1
		}
		return 0
	}
	s, e := store.Open(filepath.Join(c.Root, "metadata"), "synthetic-install", uint32(os.Geteuid()), false, nil)
	if e != nil {
		return fail()
	}
	defer s.Close()
	stage = "account"
	disk, e := s.Account(ownerLabel, false)
	if e != nil {
		return fail()
	}
	adapter := &ownerAdapter{ch: ch}
	maxAttempts, capacity := 1, 1
	now := func() time.Time { return c.Now }
	var classifier authowner.Classifier
	if lifecycleScenario(c.Scenario) {
		maxAttempts, capacity = 4, 2
		adapter.clock = &lifecycleClock{value: c.Now}
		now = adapter.clock.now
		classifier = lifecycleClassifier{}
		ch.limit = 512
	}
	cfg := authowner.Config{Installation: "synthetic-install", DaemonInstance: lease.RandomID(), DaemonUnit: "synthetic-owner.service", WriterPrefix: "synthetic-writer-", PolicyGeneration: 1, Executable: "/proc/self/fd/6", ExecutableSHA256: c.Candidate, QualificationID: "synthetic-evidence", MaxAttempts: maxAttempts, ProactiveWindow: time.Minute, Accounts: []authowner.AccountConfig{{Label: ownerLabel, VendorID: "synthetic-vendor", Home: filepath.Join(c.Root, "home"), HomeID: c.HomeID, Disk: disk}}}
	stage = "owner"
	engine, e := authowner.New(context.Background(), cfg, adapter, adapter, classifier)
	if e != nil {
		return fail()
	}
	defer engine.Close()
	p := ownerPolicy(c)
	stage = "lease"
	manager, e := lease.New(p, s, engine, lease.Options{Now: now, MaxActive: capacity, MaxPending: capacity, MaxWaiters: capacity, Qualification: func(_ context.Context, q policy.Policy) error {
		if !reflect.DeepEqual(q, p) {
			return errors.New("synthetic tuple mismatch")
		}
		return nil
	}}, false)
	if e != nil {
		return fail()
	}
	defer manager.Close()
	if ch.send("startup", "lease", nil) != nil {
		return 1
	}
	counts := map[string]int{}
	maxCalls := 10
	if adapter.clock != nil {
		maxCalls = 14
	}
	for calls := 0; calls < maxCalls; calls++ {
		cmd, e := ch.read()
		if e != nil {
			return 1
		}
		if cmd.Op == "close" {
			return 0
		}
		if cmd.Op == "clock" && adapter.clock != nil {
			counts[cmd.Op]++
			if counts[cmd.Op] > 3 {
				return 1
			}
			var value time.Time
			if wire.Decode(cmd.Data, &value) != nil || value.Before(adapter.clock.now()) {
				return 1
			}
			adapter.clock.set(value)
			if ch.send(cmd.Op, nil, nil) != nil {
				return 1
			}
			continue
		}
		counts[cmd.Op]++
		limit := 3
		if adapter.clock != nil && cmd.Op == "lease.renew" {
			limit = 5
		}
		if counts[cmd.Op] > limit || (cmd.Op == "prerequisite" && counts[cmd.Op] > 2) {
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if cmd.Op == "prerequisite" {
			e = engine.AdmitFreshHome(ctx, ownerLabel)
			if e != nil {
				e = errors.New("lease_owner_unavailable")
			}
			e = ch.send(cmd.Op, nil, e)
			cancel()
			if e != nil {
				return 1
			}
			continue
		}
		var params any
		switch cmd.Op {
		case "lease.request":
			a := p.Accounts[0]
			params = wire.LeaseRequest{Harness: "codex_cli", Profile: wire.Profile, Account: ownerLabel, Channel: "external-token", Binding: p.Binding(p.BrokerUID, a, wire.Profile), Network: []byte("null"), LaunchID: "synthetic-launch", Executor: wire.Executor{Version: "fixture", Capabilities: []string{"credential-injection/1"}}}
		case "lease.renew":
			var r wire.Renew
			e = wire.Decode(cmd.Data, &r)
			params = r
		case "lease.release":
			var r wire.Release
			e = wire.Decode(cmd.Data, &r)
			params = r
		default:
			cancel()
			return 1
		}
		if e != nil {
			cancel()
			return 1
		}
		outcome := manager.Call(ctx, p.BrokerUID, cmd.Op, params, time.Now())
		if outcome.Err != nil {
			e = ch.send(cmd.Op, nil, outcome.Err)
		} else if result, ok := outcome.Result.(wire.LeaseResult); ok {
			e = manager.Publish(ctx, p.BrokerUID, p.Generation, result, func(context.Context, time.Time) error { return ch.send(cmd.Op, result, nil) })
			if e != nil {
				e = ch.send(cmd.Op, nil, errors.New("lease_owner_unavailable"))
			}
		} else {
			e = ch.send(cmd.Op, outcome.Result, nil)
		}
		cancel()
		if e != nil {
			return 1
		}
	}
	return 1
}

type ownerAdapter struct {
	ch     *ownerChannel
	bridge chan error
	clock  *lifecycleClock
}

func (a *ownerAdapter) Ready(context.Context) error { return a.ch.call("ready", nil, nil) }
func (a *ownerAdapter) Owned(context.Context) error { return a.ch.call("owned", nil, nil) }
func (a *ownerAdapter) Identity(context.Context) (v authowner.Identity, e error) {
	e = a.ch.call("identity", nil, &v)
	return
}
func (a *ownerAdapter) Validate(_ context.Context, label, home string, generation uint64, lower time.Time) (v authowner.TimeEvidence, e error) {
	e = a.ch.call("confidence", struct {
		Label, Home string
		Generation  uint64
		Lower       time.Time
	}{label, home, generation, lower}, &v)
	if e == nil && a.clock != nil {
		a.clock.set(v.Now)
	}
	return
}
func (a *ownerAdapter) Start(_ context.Context, s authowner.UnitSpec) error {
	v := struct {
		Name, Daemon, Executable, Home, Digest string
		Args, Environment                      []string
		Runtime                                time.Duration
	}{s.Name, s.Daemon, s.Executable, s.Home, s.ExecutableSHA256, s.Args, s.Environment, s.Runtime}
	if e := a.ch.call("start", v, nil); e != nil {
		return e
	}
	in, e := unix.Dup(int(s.Input.Fd()))
	if e != nil {
		return e
	}
	out, e := unix.Dup(int(s.Output.Fd()))
	if e != nil {
		unix.Close(in)
		return e
	}
	r, w := os.NewFile(uintptr(in), "model-read"), os.NewFile(uintptr(out), "model-write")
	a.bridge = make(chan error, 1)
	go func() {
		defer r.Close()
		defer w.Close()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 4096), 4096)
		for i := 0; i < 3; i++ {
			if !scanner.Scan() {
				a.bridge <- errors.New("native model read")
				return
			}
			var response json.RawMessage
			if e := a.ch.call("native", json.RawMessage(scanner.Bytes()), &response); e != nil {
				a.bridge <- e
				return
			}
			if len(response) > 0 && string(response) != "null" {
				if _, e := w.Write(append(response, '\n')); e != nil {
					a.bridge <- e
					return
				}
			}
		}
		a.bridge <- nil
	}()
	return nil
}
func (a *ownerAdapter) Observe(_ context.Context, name string) (v authowner.Observation, e error) {
	e = a.ch.call("observe", name, &v)
	return
}
func (a *ownerAdapter) Stop(_ context.Context, name string, before authowner.Observation) (v authowner.Observation, e error) {
	if a.bridge != nil {
		if e = <-a.bridge; e != nil {
			return
		}
		a.bridge = nil
	}
	e = a.ch.call("stop", before, &v)
	return
}
func (a *ownerAdapter) Unload(_ context.Context, name string) error {
	return a.ch.call("unload", name, nil)
}

func qualificationHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

var ownerStoreFaults = []string{"home-absent", "home-mode", "native-absent", "native-mode", "intent-absent-committed", "intent-mode-committed", "intent-absent-pending", "intent-mode-pending", "checkpoint-absent", "checkpoint-mode", "metadata-absent"}
var ownerAbsenceFaults = []string{"stop-denied", "unit-missing", "partial", "invocation", "cgroup", "pid-only", "boot", "epoch"}

func ownerScenario(s string) bool {
	if lifecycleScenario(s) {
		return true
	}
	for _, v := range append(append([]string{"current", "complete"}, ownerStoreFaults...), ownerAbsenceFaults...) {
		if s == v {
			return true
		}
	}
	return false
}
