//go:build linux

package server

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
)

// Claim: the private listener accepts its bound kernel PID, refuses an ordinary
// same-UID child before input, and loses its socket and authority after teardown.
// This is not evidence for the distinct genuine foreign-UID role row.
func TestQualificationAuthority(t *testing.T) {
	if path := os.Getenv("QUALIFICATION_SOCKET_FIXTURE"); path != "" {
		c := dial(t, path)
		r := reply(t, c)
		if r.ID != nil || r.Error == nil || r.Error.Code != "peer_identity_unavailable" {
			t.Fatal("ordinary child admitted")
		}
		closed(t, c)
		return
	}
	e := testutil.New(t, lease.Options{Qualification: func(context.Context, policy.Policy) error { return qualification.ErrUnavailable }})
	var pid atomic.Int64
	pid.Store(int64(os.Getpid()))
	s, _, err := NewQualification(e.Manager, e.Policy.ExecutableSHA256, e.UID, &pid, false)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "q-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	os.Chmod(path, 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Serve(ctx, l) }()
	// The successful exchange is also the Serve-start barrier before Close.
	hello(t, dial(t, path))
	cmd := exec.Command(os.Args[0], "-test.run=^TestQualificationAuthority$")
	cmd.Env = []string{"QUALIFICATION_SOCKET_FIXTURE=" + path, "TMPDIR=" + os.TempDir(), "GOMAXPROCS=2"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	cancel()
	s.Close()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	s.Wait()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket authority survived")
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		t.Fatal("post-teardown admission")
	}
	e.NoLeaseRecords(t)
	if _, _, err := NewQualification(e.Manager, "wrong", e.UID, &pid, false); err == nil {
		t.Fatal("other release admitted")
	}
}
