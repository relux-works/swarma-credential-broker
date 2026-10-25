//go:build linux

package qualify

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func leaseProtocolRow(id string) bool {
	return id == "renew-unknown-digest" || id == "renew-contention" || id == "queue-full"
}
func leaseRowCount(in rowInput) int {
	if in.ID == "queue-full" {
		return 65
	}
	if in.ID == "renew-contention" && in.Side == "negative" {
		return 8
	}
	return 1
}
func leaseProtocolInput(in rowInput) rowInput {
	in = admissionInput(in)
	in.Policy.MaxLeaseSeconds = 30
	return in
}
func validLeaseProtocolInput(in rowInput) bool {
	if !leaseProtocolRow(in.ID) || in.Policy.MaxLeaseSeconds != 30 {
		return false
	}
	in.Policy = in.Policy.Clone()
	in.Policy.MaxLeaseSeconds = 5
	in.ID = "account-unknown"
	return validAdmissionInput(in)
}

type leaseRowEffects struct {
	StartedAt         string `json:"started_at"`
	Leases            int    `json:"leases"`
	Requests          int    `json:"requests"`
	Methods           int    `json:"methods"`
	AuthorityRefusals int    `json:"authority_refusals"`
	PeakPending       int    `json:"peak_pending"`
	Snapshots         int    `json:"snapshots"`
	Refreshes         int    `json:"refreshes"`
	Writers           int    `json:"writers"`
	Generation        uint64 `json:"generation"`
	GuardVerified     bool   `json:"guard_verified"`
	StateVerified     bool   `json:"state_verified"`
}

// This owner is private to these rows. Its parent-controlled gate holds real
// manager operations, not a client-reported queue. It has no network or store.
type leaseRowOwner struct {
	label                               string
	mu                                  sync.Mutex
	view                                owner.Snapshot
	snapshots, refreshes, live, writers int
	gate                                chan struct{}
	once                                sync.Once
}

func (o *leaseRowOwner) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx.Err() != nil {
		return owner.Snapshot{}, ctx.Err()
	}
	o.snapshots++
	if label != o.label {
		return owner.Snapshot{}, qualification.ErrUnavailable
	}
	return o.view, nil
}
func (o *leaseRowOwner) release() { o.once.Do(func() { close(o.gate) }) }
func (o *leaseRowOwner) Refresh(ctx context.Context, label string, _ uint64) (owner.Snapshot, error) {
	o.mu.Lock()
	if label != o.label {
		o.mu.Unlock()
		return owner.Snapshot{}, qualification.ErrUnavailable
	}
	o.refreshes++
	o.live++
	if o.live > o.writers {
		o.writers = o.live
	}
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.live--; o.mu.Unlock() }()
	select {
	case <-o.gate:
	case <-ctx.Done():
		return owner.Snapshot{}, ctx.Err()
	}
	next, err := syntheticMaterial()
	if err != nil {
		return owner.Snapshot{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.view.AccessToken = next
	o.view.Generation++
	return o.view, nil
}

// The distinct constructor keeps the original single-lease script and owner
// byte-identical. Each phase has the same fixed 30-second parent deadline.
func startLeaseProtocolRow(ctx context.Context, root string, in rowInput, pid *atomic.Int64, effects *leaseRowEffects, origins ...*rowOrigin) (string, func() bool, []*os.File, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second || ctx.Err() != nil || !validLeaseProtocolInput(in) || effects == nil || len(origins) != 1 || origins[0] == nil || origins[0].origin == nil {
		return "", nil, nil, qualification.ErrUnavailable
	}
	p := in.Policy
	now := time.Now().UTC()
	token, err := syntheticMaterial()
	if err != nil {
		return "", nil, nil, err
	}
	o := &leaseRowOwner{label: p.Accounts[0].Label, gate: make(chan struct{}), view: owner.Snapshot{State: owner.Active, AccessToken: token, AccountID: p.Accounts[0].VendorID, ExpiresAt: now.Add(time.Minute), AuthorityUntil: now.Add(30 * time.Second), Generation: 1, Trusted: true, Fresh: true, Qualified: true, PolicyGeneration: p.Generation, QualificationID: p.Accounts[0].QualificationID, ExecutableSHA256: p.ExecutableSHA256}}
	token = ""
	disk, err := store.Open(filepath.Join(root, "store"), p.Installation, in.Peer, true, nil)
	if err != nil {
		return "", nil, nil, err
	}
	var responses atomic.Int64
	maxActive, maxPending := leaseRowCount(in), 1
	if in.ID == "renew-contention" {
		maxPending = 8
	}
	if in.ID == "queue-full" {
		maxPending = 64
	}
	tuple, _ := wire.Encode(p)
	m, err := lease.New(p, disk, o, lease.Options{Now: func() time.Time { return now }, MaxActive: maxActive, MaxPending: maxPending, MaxWaiters: 1, Qualification: func(_ context.Context, current policy.Policy) error {
		b, e := wire.Encode(current)
		if e != nil || !reflect.DeepEqual(b, tuple) {
			return qualification.ErrUnavailable
		}
		return nil
	}, Observe: func(e lease.Event) {
		if e.Kind == "response" {
			responses.Add(1)
		}
	}}, true)
	if err != nil {
		disk.Close()
		return "", nil, nil, err
	}
	fail := func(e error) (string, func() bool, []*os.File, error) {
		o.release()
		m.Close()
		disk.Close()
		return "", nil, nil, e
	}
	srv, budget, err := server.NewQualificationLeaseRow(m, p.ExecutableSHA256, in.Peer, pid, in.ID, origins[0].origin.Live)
	if err != nil {
		return fail(err)
	}
	if err = os.Mkdir(filepath.Join(root, "q"), 0700); err != nil {
		return fail(err)
	}
	path := filepath.Join(root, "q", "s")
	closeListener, err := prepareRowListener(ctx, srv, path, 0600, origins...)
	if err != nil {
		return fail(err)
	}
	phaseR, phaseW, err := os.Pipe()
	if err != nil {
		closeListener()
		return fail(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		phaseR.Close()
		phaseW.Close()
		closeListener()
		return fail(err)
	}
	homeBefore, err := os.Stat(filepath.Join(root, "home"))
	if err != nil {
		phaseR.Close()
		phaseW.Close()
		ackR.Close()
		ackW.Close()
		closeListener()
		return fail(err)
	}
	records := func() (map[string]lease.Record, error) {
		a, e := disk.Account(p.Accounts[0].Label, false)
		if e != nil {
			return nil, e
		}
		raw, e := a.Records()
		if e != nil {
			return nil, e
		}
		out := map[string]lease.Record{}
		for name, b := range raw {
			var r lease.Record
			if wire.Decode(b, &r) != nil {
				return nil, qualification.ErrUnavailable
			}
			out[name] = r
		}
		return out, nil
	}
	done := make(chan bool, 1)
	stop := context.AfterFunc(ctx, func() { phaseR.Close(); ackW.Close(); o.release() })
	peak := 0
	go func() {
		good := false
		defer func() { ackW.Close(); done <- good }()
		phase := func(want byte) bool {
			var b [1]byte
			_, e := io.ReadFull(phaseR, b[:])
			return e == nil && b[0] == want
		}
		ack := func() bool { n, e := ackW.Write([]byte{'a'}); return n == 1 && e == nil }
		wait := func(check func(int, int) bool) bool {
			timer := time.NewTicker(time.Millisecond)
			defer timer.Stop()
			for samples := 0; samples < 30000; samples++ {
				pending, waiters := m.Stats(p.Accounts[0].Label)
				if pending > peak {
					peak = pending
				}
				if check(pending, waiters) {
					return true
				}
				select {
				case <-ctx.Done():
					return false
				case <-timer.C:
				}
			}
			return false
		}
		if !phase('g') {
			return
		}
		baseline, e := records()
		if e != nil || len(baseline) != leaseRowCount(in) {
			return
		}
		tree, e := admissionTree(filepath.Join(root, "store"))
		if e != nil {
			return
		}
		if in.ID == "renew-unknown-digest" && in.Side == "positive" {
			next, e := syntheticMaterial()
			if e != nil {
				return
			}
			o.mu.Lock()
			o.view.AccessToken = next
			o.view.Generation = 2
			o.mu.Unlock()
		}
		if !ack() {
			return
		}
		if in.ID == "renew-unknown-digest" {
			if !phase('i') {
				return
			}
			current, e := records()
			after, te := admissionTree(filepath.Join(root, "store"))
			o.mu.Lock()
			unchanged := o.snapshots == 2 && o.refreshes == 0 && o.view.Generation == 1
			o.mu.Unlock()
			if in.Side == "negative" && (e != nil || te != nil || !reflect.DeepEqual(current, baseline) || !reflect.DeepEqual(tree, after) || !unchanged) {
				return
			}
			good = ack()
			return
		}
		if !phase('h') {
			return
		}
		target := leaseRowCount(in)
		if in.ID == "queue-full" {
			target = 63
			if in.Side == "negative" {
				target = 64
			}
		}
		if !wait(func(p, w int) bool {
			o.mu.Lock()
			defer o.mu.Unlock()
			return p == target && w == target && o.refreshes == 1 && o.view.Generation == 1
		}) {
			return
		}
		if in.ID == "renew-contention" {
			o.release()
			good = ack()
			return
		}
		if !ack() || !phase('i') {
			return
		}
		if !wait(func(p, w int) bool {
			if in.Side == "positive" {
				return p == 64 && w == 64
			}
			return responses.Load() > int64(leaseRowCount(in)) || p > 64
		}) {
			return
		}
		current, e := records()
		after, te := admissionTree(filepath.Join(root, "store"))
		pending, waiters := m.Stats(p.Accounts[0].Label)
		guard := e == nil && te == nil && pending == 64 && waiters == 64 && reflect.DeepEqual(current, baseline) && reflect.DeepEqual(tree, after)
		o.mu.Lock()
		guard = guard && o.refreshes == 1 && o.view.Generation == 1
		o.mu.Unlock()
		// Release even a violated precondition so the intended queue assertion,
		// rather than a blocked writer or timeout, reports the narrowing control.
		o.release()
		sent := ack()
		good = guard && sent
	}()
	closeRow := func() bool {
		o.release()
		serveErr := closeListener()
		phaseR.Close()
		phaseOK := <-done
		ackW.Close()
		stop()
		stored, e := records()
		requests, methods, refused := budget.Counts()
		o.mu.Lock()
		snapshots, refreshes, writers, generation := o.snapshots, o.refreshes, o.writers, o.view.Generation
		o.view.AccessToken = ""
		o.mu.Unlock()
		count := leaseRowCount(in)
		success := count
		if in.ID == "queue-full" {
			success = 64
		}
		wantRefresh := 1
		wantGeneration := uint64(2)
		wantMethods := count * 3
		if in.ID == "queue-full" && in.Side == "positive" {
			wantMethods--
		}
		if in.ID == "renew-unknown-digest" {
			wantRefresh = 0
			if in.Side == "negative" {
				success = 0
				wantGeneration = 1
			}
		}
		state := e == nil && len(stored) == count && requests == count && methods == wantMethods && refused == 0 && refreshes == wantRefresh && writers == wantRefresh && generation == wantGeneration && snapshots == 2*count+2*success
		renewed := 0
		for name, r := range stored {
			gen, rev := uint64(1), uint64(2)
			if r.OfferedGeneration == 2 {
				gen, rev = 2, 3
				renewed++
			}
			state = state && name == store.LeaseName(r.LeaseID) && r.State == "released" && r.UID == in.Peer && r.Account == p.Accounts[0].Label && r.PolicyGeneration == p.Generation && r.OfferedGeneration == gen && r.Revision == rev && r.AuthorizedUntil.Equal(now.Add(30*time.Second).Truncate(time.Second))
		}
		state = state && renewed == success
		entries, he := os.ReadDir(filepath.Join(root, "home"))
		homeAfter, se := os.Stat(filepath.Join(root, "home"))
		homeSame := se == nil && os.SameFile(homeBefore, homeAfter) && homeBefore.Mode() == homeAfter.Mode() && homeBefore.ModTime() == homeAfter.ModTime() && homeBefore.Sys().(*syscall.Stat_t).Ctim == homeAfter.Sys().(*syscall.Stat_t).Ctim
		*effects = leaseRowEffects{now.Format(time.RFC3339Nano), count, requests, methods, refused, peak, snapshots, refreshes, writers, generation, phaseOK, state}
		m.Close()
		disk.Close()
		_, socketErr := os.Lstat(path)
		return phaseOK && state && serveErr == nil && he == nil && len(entries) == 0 && homeSame && os.IsNotExist(socketErr)
	}
	return path, closeRow, []*os.File{phaseW, ackR}, nil
}
