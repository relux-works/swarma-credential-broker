//go:build linux

package qualify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
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

func admissionRow(id string) bool {
	switch id {
	case "account-denied", "account-unknown", "release-unqualified", "lease-ended":
		return true
	}
	return runnerRow(id)
}
func rowPositive(id string) string {
	if lifecycleRow(id) || ownerRow(id) || leaseProtocolRow(id) {
		return "lease"
	}
	if runnerRow(id) {
		return "external-login"
	}
	if admissionRow(id) || id == "peer-denied" {
		return "lease"
	}
	return "hello"
}

// The selected configured account authorizes the fixture, but its real vendor
// identity, endpoint and owner are never used. The anchor admits the profile
// while a disabled subject is tested; it has no qualified tuple or snapshot.
func admissionInput(in rowInput) rowInput {
	p := in.Policy.Clone()
	a := p.Accounts[0]
	a.Label, a.VendorID, a.Endpoint = "synthetic-subject", "synthetic-vendor", "https://example.invalid/inference"
	a.ReleaseVersion, a.QualificationID, a.NetworkRequired = "0.163.0", "synthetic-evidence", false
	if runnerRow(in.ID) {
		a.VendorID = "vendor-account"
	}
	anchor := a
	anchor.Label, anchor.VendorID = "synthetic-anchor", "synthetic-anchor-vendor"
	anchor.ReleaseVersion, anchor.QualificationID = "", ""
	if in.ID == "account-denied" && in.Side == "negative" {
		a.Enabled = false
	}
	p.MaxLeaseSeconds, p.Accounts = 5, []policy.Account{a, anchor}
	// This fixture does not claim production owner time/watermark qualification.
	p.TimeConfidence = nil
	in.Policy = p
	if in.ID == "lease-ended" {
		in.EndedBy = "released"
	}
	return in
}
func validAdmissionInput(in rowInput) bool {
	p := in.Policy
	if (in.Side != "positive" && in.Side != "negative") || !admissionRow(in.ID) || len(p.Accounts) != 2 || p.MaxLeaseSeconds != 5 || p.TimeConfidence != nil {
		return false
	}
	if runnerRow(in.ID) && (!policy.Hash(in.ApprovedDigest) || !policy.Hash(in.RunnerDigest) || !policy.Hash(in.RunnerConfig) || p.ExecutableSHA256 != in.RunnerDigest) {
		return false
	}
	a, anchor := p.Accounts[0], p.Accounts[1]
	vendor := "synthetic-vendor"
	if runnerRow(in.ID) {
		vendor = "vendor-account"
	}
	return a.Label == "synthetic-subject" && a.VendorID == vendor && a.Endpoint == "https://example.invalid/inference" && a.ReleaseVersion == "0.163.0" && a.QualificationID == "synthetic-evidence" && !a.NetworkRequired && len(a.Profiles) > 0 && reflect.DeepEqual(a.AllowedUIDs, []uint32{in.Peer}) && a.Enabled == !(in.ID == "account-denied" && in.Side == "negative") && anchor.Label == "synthetic-anchor" && anchor.VendorID == "synthetic-anchor-vendor" && anchor.ReleaseVersion == "" && anchor.QualificationID == "" && anchor.Enabled && reflect.DeepEqual(anchor.AllowedUIDs, a.AllowedUIDs) && reflect.DeepEqual(anchor.Profiles, a.Profiles) && (in.ID != "lease-ended" && in.EndedBy == "" || in.ID == "lease-ended" && (in.EndedBy == "released" || in.EndedBy == "expired"))
}

type admissionOwner struct {
	mu                   sync.Mutex
	view                 owner.Snapshot
	label                string
	snapshots, refreshes int
}

func (o *admissionOwner) Snapshot(_ context.Context, label string) (owner.Snapshot, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.snapshots++
	if label != o.label {
		return owner.Snapshot{}, qualification.ErrUnavailable
	}
	return o.view, nil
}
func (o *admissionOwner) Refresh(context.Context, string, uint64) (owner.Snapshot, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshes++
	return owner.Snapshot{}, qualification.ErrUnavailable
}
func syntheticMaterial() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// This setup is distinct from the issuance-closed transport setup. Material
// exists only in the parent, wire exchange and isolated lease metadata store;
// neither material nor its digest is returned as diagnostic evidence.
func startAdmissionRow(ctx context.Context, root string, in rowInput, pid *atomic.Int64, effects *admissionEffects, origins ...*rowOrigin) (string, func() bool, []*os.File, error) {
	return startAdmissionFixture(ctx, root, in, pid, effects, nil, origins...)
}
func startAdmissionFixture(ctx context.Context, root string, in rowInput, pid *atomic.Int64, effects *admissionEffects, peers *peerFixture, origins ...*rowOrigin) (string, func() bool, []*os.File, error) {
	return startAdmissionObserved(ctx, root, in, pid, effects, peers, nil, origins...)
}
func startAdmissionObserved(ctx context.Context, root string, in rowInput, pid *atomic.Int64, effects *admissionEffects, peers *peerFixture, observed *runnerObservation, origins ...*rowOrigin) (string, func() bool, []*os.File, error) {
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 30*time.Second || ctx.Err() != nil || effects == nil || !validAdmissionInput(in) || in.Policy.Validate(in.Peer) != nil {
		return "", nil, nil, qualification.ErrUnavailable
	}
	p := in.Policy
	now := time.Now().UTC()
	effects.StartedAt = now.Format(time.RFC3339Nano)
	var clockMu sync.Mutex
	readClock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	token, err := syntheticMaterial()
	if err != nil {
		return "", nil, nil, err
	}
	o := &admissionOwner{label: p.Accounts[0].Label, view: owner.Snapshot{State: owner.Active, AccessToken: token, AccountID: p.Accounts[0].VendorID, ExpiresAt: now.Add(time.Minute), AuthorityUntil: now.Add(30 * time.Second), Generation: 1, Trusted: true, Fresh: true, Qualified: true, PolicyGeneration: p.Generation, QualificationID: p.Accounts[0].QualificationID, ExecutableSHA256: p.ExecutableSHA256}}
	token = ""
	disk, err := store.Open(filepath.Join(root, "store"), p.Installation, in.Peer, true, nil)
	if err != nil {
		return "", nil, nil, err
	}
	// Exact tuple membership is memory-only. Never use the protected release
	// repository or a callback which writes/publishes qualification here.
	tuple, _ := wire.Encode(p)
	qualified := map[string]bool{qualification.Hash(tuple): !(in.ID == "release-unqualified" && in.Side == "negative")}
	var qualificationRefused atomic.Bool
	gate := func(_ context.Context, candidate policy.Policy) error {
		b, e := wire.Encode(candidate)
		if e != nil || !qualified[qualification.Hash(b)] {
			qualificationRefused.Store(true)
			return qualification.ErrUnavailable
		}
		return nil
	}
	m, err := lease.New(p, disk, o, lease.Options{Now: readClock, Qualification: gate, MaxActive: 1, MaxPending: 1, MaxWaiters: 1}, true)
	if err != nil {
		disk.Close()
		return "", nil, nil, err
	}
	fail := func(e error) (string, func() bool, []*os.File, error) {
		m.Close()
		disk.Close()
		return "", nil, nil, e
	}
	srv, err := server.NewQualificationAdmission(m, p.ExecutableSHA256, in.Peer, pid, originCheck(origins)...)
	if observed != nil {
		srv, observed.broker, err = server.NewQualificationRunnerAdmission(m, p.ExecutableSHA256, in.Peer, pid, observed.origin.Live)
	}
	if peers != nil {
		srv, err = server.NewQualificationPeerAdmission(m, p.ExecutableSHA256, in.Peer, peers.foreign, peers.group, peers.foreignGID, peers.group, pid)
	}
	if err != nil {
		return fail(err)
	}
	dir := filepath.Join(root, "q")
	if err = os.Mkdir(dir, 0700); err != nil {
		return fail(err)
	}
	if peers != nil && os.Chmod(dir, 0750) != nil {
		return fail(qualification.ErrUnavailable)
	}
	path := filepath.Join(dir, "s")
	mode := os.FileMode(0600)
	if peers != nil {
		mode = 0660
	}
	var closeListener func() error
	if observed != nil {
		closeListener, err = runnerListener(ctx, srv, path, observed)
	} else {
		closeListener, err = prepareRowListener(ctx, srv, path, mode, origins...)
	}
	if err != nil {
		return fail(err)
	}
	records := func() (map[string][]byte, error) {
		out := map[string][]byte{}
		for _, a := range p.Accounts {
			account, e := disk.Account(a.Label, false)
			if e != nil || account.Healthy() != nil {
				return nil, qualification.ErrUnavailable
			}
			values, e := account.Records()
			if e != nil {
				return nil, e
			}
			for name, b := range values {
				out[a.Label+"/"+name] = b
			}
		}
		return out, nil
	}
	homeBefore, err := os.Stat(filepath.Join(root, "home"))
	if err != nil {
		closeListener()
		return fail(err)
	}
	initialTree, err := admissionTree(filepath.Join(root, "store"))
	if err != nil {
		closeListener()
		return fail(err)
	}
	if peers != nil {
		peers.negativeUnchanged = func() bool {
			stored, e := records()
			tree, te := admissionTree(filepath.Join(root, "store"))
			o.mu.Lock()
			defer o.mu.Unlock()
			return e == nil && te == nil && len(stored) == 0 && o.snapshots == 0 && o.refreshes == 0 && reflect.DeepEqual(initialTree, tree)
		}
	}
	var endedTree map[string]admissionFile
	var phaseFiles []*os.File
	var phaseRead, ackWrite *os.File
	phaseDone := make(chan bool, 1)
	var baseline map[string][]byte
	var baselineCalls int
	var granted lease.Record
	if in.ID == "lease-ended" {
		var phaseWrite, ackRead *os.File
		phaseRead, phaseWrite, err = os.Pipe()
		if err == nil {
			ackRead, ackWrite, err = os.Pipe()
		}
		if err != nil {
			for _, f := range []*os.File{phaseRead, phaseWrite, ackRead, ackWrite} {
				if f != nil {
					f.Close()
				}
			}
			closeListener()
			return fail(err)
		}
		phaseFiles = []*os.File{phaseWrite, ackRead}
		go func() {
			good := false
			defer func() { ackWrite.Close(); phaseDone <- good }()
			var b [1]byte
			if _, e := io.ReadFull(phaseRead, b[:]); e != nil || b[0] != 'a' {
				return
			}
			baseline, err = records()
			if err != nil || len(baseline) != 1 {
				return
			}
			for _, v := range baseline {
				if wire.Decode(v, &granted) != nil {
					return
				}
			}
			want := "active"
			if in.Side == "negative" && in.EndedBy == "released" {
				want = "released"
			}
			if granted.State != want || granted.Account != o.label || granted.AuthorizedUntil.After(readClock().Add(5*time.Second)) {
				return
			}
			endedTree, err = admissionTree(filepath.Join(root, "store"))
			if err != nil {
				return
			}
			next, e := syntheticMaterial()
			if e != nil {
				return
			}
			o.mu.Lock()
			o.view.AccessToken = next
			o.view.Generation = 2
			baselineCalls = o.snapshots
			o.mu.Unlock()
			if in.Side == "negative" && in.EndedBy == "expired" {
				clockMu.Lock()
				now = granted.AuthorizedUntil
				clockMu.Unlock()
			}
			n, e := ackWrite.Write([]byte{'a'})
			good = e == nil && n == 1
		}()
	}
	closeRow := func() bool {
		serveErr := closeListener()
		phaseOK := true
		if phaseRead != nil {
			phaseRead.Close()
			phaseOK = <-phaseDone
			ackWrite.Close()
		}
		stored, e := records()
		currentTree, treeErr := admissionTree(filepath.Join(root, "store"))
		o.mu.Lock()
		calls, refresh := o.snapshots, o.refreshes
		o.view.AccessToken = ""
		o.mu.Unlock()
		good := e == nil && treeErr == nil && phaseOK && refresh == 0
		if peers != nil {
			good = good && peers.deniedVerified
		}
		if in.Side == "negative" && in.ID != "lease-ended" {
			good = good && len(stored) == 0 && calls == 0 && reflect.DeepEqual(initialTree, currentTree)
		} else {
			good = good && len(stored) == 1
			for name, b := range stored {
				var rec lease.Record
				good = good && wire.Decode(b, &rec) == nil && rec.Account == o.label && name == o.label+"/"+store.LeaseName(rec.LeaseID) && rec.UID == in.Peer && rec.PolicyGeneration == p.Generation && rec.AuthorizedUntil.After(now.Add(-time.Second)) && !rec.AuthorizedUntil.After(now.Add(5*time.Second))
				if runnerRow(in.ID) {
					good = good && rec.State == "released" && rec.Revision == 2 && calls == 2
				} else if in.ID != "lease-ended" {
					good = good && rec.State == "active" && rec.Revision == 1 && calls == 2
				} else if in.Side == "negative" {
					good = good && reflect.DeepEqual(stored, baseline) && reflect.DeepEqual(endedTree, currentTree) && calls == baselineCalls && calls == 2 && rec.AuthorizedUntil == granted.AuthorizedUntil
				} else {
					good = good && rec.State == "released" && rec.Revision == 3 && rec.OfferedGeneration == 2 && calls == 4 && rec.LeaseID == granted.LeaseID && rec.AuthorizedUntil == granted.AuthorizedUntil
				}
			}
		}
		effects.QualificationRefused = qualificationRefused.Load()
		good = good && effects.QualificationRefused == (in.ID == "release-unqualified" && in.Side == "negative")
		effects.Records, effects.Snapshots, effects.Refreshes = len(stored), calls, refresh
		effects.StateVerified = good
		effects.FaultEstablished = in.Side == "negative" && good
		entries, homeErr := os.ReadDir(filepath.Join(root, "home"))
		homeAfter, statErr := os.Stat(filepath.Join(root, "home"))
		homeSame := statErr == nil && os.SameFile(homeBefore, homeAfter) && homeBefore.Mode() == homeAfter.Mode() && homeBefore.ModTime() == homeAfter.ModTime() && homeBefore.Sys().(*syscall.Stat_t).Ctim == homeAfter.Sys().(*syscall.Stat_t).Ctim
		m.Close()
		disk.Close()
		_, socketErr := os.Lstat(path)
		return good && homeSame && homeErr == nil && len(entries) == 0 && serveErr == nil && os.IsNotExist(socketErr)
	}
	return path, closeRow, phaseFiles, nil
}

// The fixed worker script has one grant request; all subsequent methods refer
// only to that grant. A private pipe acknowledges the parent-owned snapshot
// change after the grant/release response, never a synthetic lease tombstone.
func admissionExchange(in rowInput) (string, []rowEnvelope, error) {
	var phase, ack *os.File
	if in.ID == "lease-ended" {
		phase, ack = os.NewFile(7, "fixture-phase"), os.NewFile(8, "fixture-ack")
		if phase == nil || ack == nil {
			return "", nil, qualification.ErrUnavailable
		}
		defer phase.Close()
		defer ack.Close()
		for _, f := range []*os.File{phase, ack} {
			st, e := f.Stat()
			if e != nil || st.Mode()&os.ModeNamedPipe == 0 {
				return "", nil, qualification.ErrUnavailable
			}
		}
	}
	return admissionExchangeWithPhase(in, phase, ack)
}
func admissionExchangeWithPhase(in rowInput, phase, ack *os.File) (string, []rowEnvelope, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: in.Socket, Net: "unix"})
	if err != nil {
		return "", nil, err
	}
	defer c.Close()
	if c.SetDeadline(time.Now().Add(3*time.Second)) != nil {
		return "", nil, qualification.ErrUnavailable
	}
	exchange := func(method, id string, value any) ([]byte, error) {
		b, e := wire.Encode(value)
		if e != nil {
			return nil, e
		}
		if e = wire.Write(c, wire.Request{Method: method, ID: id, Params: b}); e != nil {
			return nil, e
		}
		return wire.Read(c)
	}
	b, err := exchange("hello", "fixture-hello", wire.Hello{Versions: []int{1}, Profile: wire.Profile})
	if err != nil {
		return "", nil, err
	}
	hello, err := decodeRowEnvelope(b, in.ID, "positive", in.Policy.Generation)
	if err != nil {
		return "", nil, err
	}
	facts := []rowEnvelope{hello}
	a := in.Policy.Accounts[0]
	label := a.Label
	if in.ID == "account-unknown" && in.Side == "negative" {
		label = "missing-synthetic-subject"
	}
	request := wire.LeaseRequest{Harness: "codex_cli", Profile: a.Profiles[0], Account: label, Channel: "external-token", Binding: in.Policy.Binding(in.Peer, a, a.Profiles[0]), Network: []byte("null"), LaunchID: "synthetic-launch", Executor: wire.Executor{Version: "fixture", Capabilities: []string{"credential-injection/1"}}}
	b, err = exchange("lease.request", "fixture-request", request)
	if err != nil {
		return "", nil, err
	}
	if in.Side == "negative" && in.ID != "lease-ended" {
		f, e := decodeAdmissionError(b, in.ID, "fixture-request")
		return rowRefusal(in.ID), append(facts, f), e
	}
	grant, f, err := decodeAdmissionGrant(b, "fixture-request", in)
	if err != nil {
		return "", nil, err
	}
	facts = append(facts, f)
	if in.ID != "lease-ended" {
		return "lease", facts, nil
	}
	release := func(id string) error {
		b, e := exchange("lease.release", id, wire.Release{LeaseID: grant.LeaseID})
		if e != nil {
			return e
		}
		f, e := decodeAdmissionRelease(b, id, grant.LeaseID)
		if e == nil {
			facts = append(facts, f)
		}
		return e
	}
	if in.Side == "negative" && in.EndedBy == "released" {
		if err = release("fixture-release"); err != nil {
			return "", nil, err
		}
	}
	if _, err = phase.Write([]byte{'a'}); err != nil {
		return "", nil, err
	}
	var one [1]byte
	if _, err = io.ReadFull(ack, one[:]); err != nil || one[0] != 'a' {
		return "", nil, qualification.ErrUnavailable
	}
	rejected := lease.Digest(grant.Payload.AccessToken)
	grant.Payload.AccessToken = ""
	b, err = exchange("lease.renew", "fixture-renew", wire.Renew{LeaseID: grant.LeaseID, RejectedSHA256: rejected})
	if err != nil {
		return "", nil, err
	}
	if in.Side == "negative" {
		f, e := decodeAdmissionError(b, in.ID, "fixture-renew")
		return rowRefusal(in.ID), append(facts, f), e
	}
	renewed, f, err := decodeAdmissionGrant(b, "fixture-renew", in)
	if err != nil || renewed.LeaseID != grant.LeaseID || renewed.AuthorizedUntil != grant.AuthorizedUntil || lease.Digest(renewed.Payload.AccessToken) == rejected {
		return "", nil, qualification.ErrUnavailable
	}
	renewed.Payload.AccessToken = ""
	facts = append(facts, f)
	if err = release("fixture-release"); err == nil {
		err = release("fixture-release-again")
	}
	return "lease", facts, err
}

var _ owner.Owner = (*admissionOwner)(nil)

// These are private comparisons, never serialized or hashed into diagnostics.
// Including ctime catches same-byte rewrites and temporary create/remove effects.
type admissionFile struct {
	Mode     os.FileMode
	Modified time.Time
	Changed  syscall.Timespec
	Inode    uint64
	Data     string
}

func admissionTree(root string) (map[string]admissionFile, error) {
	out := map[string]admissionFile{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return qualification.ErrUnavailable
		}
		unix, ok := st.Sys().(*syscall.Stat_t)
		if !ok || unix.Uid != uint32(os.Geteuid()) {
			return qualification.ErrUnavailable
		}
		f := admissionFile{Mode: st.Mode(), Modified: st.ModTime(), Changed: unix.Ctim, Inode: unix.Ino}
		if st.Mode().IsRegular() {
			b, e := store.ReadProtected(path, uint32(os.Geteuid()))
			if e != nil {
				return e
			}
			f.Data = string(b)
		} else if !entry.IsDir() {
			return qualification.ErrUnavailable
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		out[rel] = f
		return nil
	})
	return out, err
}
