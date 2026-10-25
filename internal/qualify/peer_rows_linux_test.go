//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func configuredPeerRow(t *testing.T) fixtureConfiguration {
	t.Helper()
	path := os.Getenv("BROKER_TEST_PEER_CONFIG")
	if path == "" {
		t.Skip("UNRUN: protected peer configuration not supplied")
	}
	b, e := store.ReadProtected(path, uint32(os.Geteuid()))
	var f fixtureConfiguration
	if e != nil || wire.Decode(b, &f) != nil {
		t.Fatal("peer fixture configuration")
	}
	u, _ := user.Current()
	if f.Broker != u.Username || f.Allowed != u.Username || !f.SameUser {
		t.Fatal("same-user fixture mapping")
	}
	if _, e = resolvePeerFixture(f); e != nil {
		t.Fatalf("UNRUN: configured peer identities/group unavailable: %v", e)
	}
	f.PeerHelper = rowTool(t, "./testdata/peerhelper")
	return f
}

// Claim: a real configured foreign process sends nothing and receives the
// exact null-ID denial plus EOF, with zero baseline effects; the allowed real
// process leases on the same group-only socket. No UID substitution is used.
func TestPeerRowFixture(t *testing.T) {
	f := configuredPeerRow(t)
	_, c, root := setup(t)
	cases := qualification.Pending(qualification.Identity{}).Cases
	var row qualification.Case
	for _, v := range cases {
		if v.ID == "peer-denied" {
			row = v
		}
	}
	d := driver{}
	d.runPeerRows(context.Background(), f, c.Policy, root, &row)
	if row.Positive.Verdict != "passed" || row.Negative.Verdict != "passed" || validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, row) != nil {
		t.Fatalf("peer denial/effects: %+v", row)
	}
	for _, side := range []string{"positive", "negative"} {
		b, e := os.ReadFile(rowFile(root, row.ID, side))
		var a rowArtifact
		if e != nil || wire.Decode(b, &a) != nil {
			t.Fatal("peer evidence")
		}
		a.Observation.Peer.IdentityVerified = false
		if validPeerEnvelopes(a.Observation, c.Policy.Generation) {
			t.Fatal("unverified peer credited")
		}
	}
}

// Claim: the real private peer fixture uses exact group-only permissions and
// teardown removes its socket; world access cannot masquerade as a valid pair.
func TestPeerRowSocketMode(t *testing.T) {
	f := configuredPeerRow(t)
	peers, e := resolvePeerFixture(f)
	if e != nil {
		t.Fatal(e)
	}
	_, c, _ := setup(t)
	root := t.TempDir()
	if os.Mkdir(filepath.Join(root, "home"), 0700) != nil {
		t.Fatal("home")
	}
	in := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: "account-unknown", Side: "positive"})
	var pid atomic.Int64
	var effects admissionEffects
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, closeRow, _, e := startAdmissionFixture(ctx, root, in, &pid, &effects, peers)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		closeRow()
		if _, e := os.Lstat(socket); !os.IsNotExist(e) {
			t.Fatal("peer socket survived teardown")
		}
	}()
	if !server.QualificationPeerSocket(socket, peers.group) {
		t.Fatal("peer socket permissions")
	}
	if os.Chmod(socket, 0666) != nil {
		t.Fatal("mode plant")
	}
	if server.QualificationPeerSocket(socket, peers.group) {
		t.Fatal("unsafe peer socket accepted")
	}
}

func configurePeers(t *testing.T, path string) bool {
	t.Helper()
	if os.Getenv("BROKER_TEST_PEER_CONFIG") == "" {
		return false
	}
	f := configuredPeerRow(t)
	b, e := os.ReadFile(path)
	var original fixtureConfiguration
	if e != nil || wire.Decode(b, &original) != nil {
		t.Fatal("fixture configuration")
	}
	f.Runner = original.Runner
	f.Account = original.Account
	b, _ = wire.Encode(f)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("fixture configuration")
	}
	return true
}
