//go:build peeraccounts

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type peerConfiguration struct {
	Allowed   string `json:"allowed_peer"`
	Foreign   string `json:"foreign_peer"`
	Directory string `json:"socket_directory"`
	Helper    string `json:"helper_executable"`
}

var peers peerConfiguration
var allowedUID, foreignUID uint32
var peerPending bool

// The standalone qualification binary returns 69 for missing/unusable configuration, never a skipped pass.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "peer-probe" {
		os.Exit(peerProbe(os.Args[2:]))
	}
	b, err := store.ReadProtected(os.Getenv("BROKER_TEST_PEER_CONFIG"), uint32(os.Geteuid()))
	if err != nil || wire.Decode(b, &peers) != nil || !filepath.IsAbs(peers.Directory) || !filepath.IsAbs(peers.Helper) {
		fmt.Fprintln(os.Stderr, "PENDING: protected peer configuration unavailable")
		os.Exit(69)
	}
	resolve := func(name string) (uint32, error) {
		u, e := user.Lookup(name)
		if e != nil {
			return 0, e
		}
		n, e := strconv.ParseUint(u.Uid, 10, 32)
		return uint32(n), e
	}
	allowedUID, err = resolve(peers.Allowed)
	if err == nil {
		foreignUID, err = resolve(peers.Foreign)
	}
	if err != nil || foreignUID == allowedUID || foreignUID == uint32(os.Geteuid()) {
		fmt.Fprintln(os.Stderr, "PENDING: configured peer identities unavailable or aliased")
		os.Exit(69)
	}
	code := m.Run()
	if peerPending {
		os.Exit(69)
	}
	os.Exit(code)
}
func peerProbe(args []string) int {
	if len(args) != 6 {
		return 69
	}
	uid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || uint32(os.Geteuid()) != uint32(uid) {
		return 69
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: args[0], Net: "unix"})
	if err != nil {
		if args[3] == "connect" {
			return 70
		}
		return 69
	}
	defer conn.Close()
	broker, err := strconv.ParseUint(args[2], 10, 32)
	actual, probeErr := PeerUID(conn)
	if err != nil || probeErr != nil || actual != uint32(broker) {
		return 70
	}
	if args[3] == "connect" {
		return 0
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if args[3] == "denied" {
		b, err := wire.Read(conn)
		var r response
		if err != nil || wire.Decode(b, &r) != nil || r.ID != nil || r.Error == nil || r.Error.Code != "role_not_permitted" {
			return 70
		}
		var one [1]byte
		if n, err := conn.Read(one[:]); n != 0 || err != io.EOF {
			return 70
		}
		return 0
	}
	exchange := func(method string, params json.RawMessage) (response, bool) {
		if wire.Write(conn, wire.Request{Method: method, ID: method, Params: params}) != nil {
			return response{}, false
		}
		b, e := wire.Read(conn)
		var r response
		if e != nil || wire.Decode(b, &r) != nil {
			return response{}, false
		}
		return r, true
	}
	h, _ := wire.Encode(wire.Hello{Versions: []int{1}, Profile: wire.Profile})
	if r, ok := exchange("hello", h); !ok || r.Error != nil {
		return 70
	}
	r, ok := exchange(args[3], json.RawMessage(args[4]))
	if !ok {
		return 70
	}
	if args[5] != "" {
		if r.Error == nil || r.Error.Code != args[5] || r.Result != nil {
			return 70
		}
		return 0
	}
	var result wire.LeaseResult
	if r.Error != nil || wire.Decode(r.Result, &result) != nil || result.LeaseID == "" || result.Payload.AccessToken == "" {
		return 70
	}
	// Only a non-secret correlation leaves the helper; token material stays in its memory.
	fmt.Fprintln(os.Stdout, result.LeaseID)
	return 0
}
func peerRun(t *testing.T, name string, uid uint32, path, method string, params any, code string) string {
	t.Helper()
	b, _ := wire.Encode(params)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sudo", "-n", "-u", name, "--", peers.Helper, "peer-probe", path, strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(os.Geteuid()), 10), method, string(b), code)
	command.Env = []string{}
	output, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 70 {
			t.Fatal("configured kernel peer assertion failed")
		}
		peerPending = true
		t.Fatal("PENDING: configured peer cannot start or reach fixture with intended permissions")
	}
	return string(output)
}

// Claim: configured OS processes reach actual kernel peer denial, allowed leasing and cross-UID ownership refusal; unavailable identities/permissions are PENDING with exit 69.
func TestConfiguredPeers(t *testing.T) {
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) { p.Accounts[0].AllowedUIDs = []uint32{allowedUID} })
	path := filepath.Join(peers.Directory, "probe-"+lease.RandomID())
	l, err := Listen(path)
	if err != nil {
		peerPending = true
		t.Fatal("PENDING: configured socket unavailable")
	}
	s := New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); stopped <- s.Serve(ctx, l) }()
	defer func() {
		testutil.StopServer(func() { cancel(); s.Close() }, serveDone, s.Wait)
		<-stopped
	}()
	beforeOwner := e.Owner.View()
	peerRun(t, peers.Foreign, foreignUID, path, "denied", struct{}{}, "")
	e.NoLeaseRecords(t)
	if pending, waiters := e.Manager.Stats(e.Account); pending != 0 || waiters != 0 || e.Owner.View() != beforeOwner {
		t.Fatal("denied peer changed owner or attempt state")
	}
	if n, _ := e.Owner.Counts(); n != 0 {
		t.Fatal("denied peer started refresh")
	}
	t.Log("peer-denied: PASS; terminal denial and EOF without client writes; no lease records, attempts, material changes or refresh")
	p := e.Policy.Clone()
	p.Generation++
	p.Accounts[1].AllowedUIDs = []uint32{foreignUID}
	if e.Manager.Replace(p) != nil {
		t.Fatal("ownership policy setup failed")
	}
	view := e.Owner.View()
	view.PolicyGeneration = p.Generation
	e.Owner.Set(view)
	r := e.Request
	r.Binding = p.Binding(allowedUID, p.Accounts[0], r.Profile)
	id := peerRun(t, peers.Allowed, allowedUID, path, "lease.request", r, "")
	if len(id) != 33 {
		t.Fatal("allowed peer did not create lease")
	}
	t.Log("peer-allowed: PASS; hello and lease.request returned material in helper memory")
	disk, err := e.Store.Account(e.Account, false)
	if err != nil {
		t.Fatal("lease metadata unavailable")
	}
	beforeRecords, err := disk.Records()
	if err != nil || len(beforeRecords) == 0 {
		t.Fatal("positive lease metadata unavailable")
	}
	beforeOwner = e.Owner.View()
	peerRun(t, peers.Foreign, foreignUID, path, "lease.renew", wire.Renew{LeaseID: id[:32], RejectedSHA256: fmt.Sprintf("%064d", 0)}, "lease_not_owner")
	if n, _ := e.Owner.Counts(); n != 0 {
		t.Fatal("ownership refusal started refresh")
	}
	afterRecords, err := disk.Records()
	if err != nil || !reflect.DeepEqual(beforeRecords, afterRecords) || e.Owner.View() != beforeOwner {
		t.Fatal("ownership refusal changed lease or material")
	}
	if pending, waiters := e.Manager.Stats(e.Account); pending != 0 || waiters != 0 {
		t.Fatal("ownership refusal left an attempt")
	}
	t.Log("owner-mismatch: PASS; separately admitted foreign peer received lease_not_owner; lease, material and writer state unchanged")
}

// Claim: both configured peer UIDs can connect to the candidate listener and
// verify its kernel UID before any protocol I/O. This isolates the socket-mode
// contract from Serve's independent startup checks; unavailable execution is
// PENDING, while a started helper unable to connect fails the assertion.
func TestConfiguredPeerConnect(t *testing.T) {
	path := filepath.Join(peers.Directory, "connect-"+lease.RandomID())
	l, err := Listen(path)
	if err != nil {
		t.Fatal("candidate socket creation failed")
	}
	defer func() { l.Close(); os.Remove(path) }()
	peerRun(t, peers.Allowed, allowedUID, path, "connect", struct{}{}, "")
	peerRun(t, peers.Foreign, foreignUID, path, "connect", struct{}{}, "")
}
