//go:build linux && peeraccounts

package peercheck

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type configuration struct {
	Allowed   string `json:"allowed_peer"`
	Foreign   string `json:"foreign_peer"`
	Directory string `json:"socket_directory"`
	Helper    string `json:"helper_executable"`
}

var peers configuration
var allowed, foreign uint32
var pending bool

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "client-peer" {
		os.Exit(helper(os.Args[2:]))
	}
	b, e := store.ReadProtected(os.Getenv("BROKER_TEST_PEER_CONFIG"), uint32(os.Geteuid()))
	if e != nil || wire.Decode(b, &peers) != nil || !filepath.IsAbs(peers.Directory) || !filepath.IsAbs(peers.Helper) {
		fmt.Fprintln(os.Stderr, "PENDING: protected peer fixture unavailable")
		os.Exit(69)
	}
	resolve := func(name string) (uint32, error) {
		u, e := user.Lookup(name)
		if e != nil {
			return 0, e
		}
		id, e := strconv.ParseUint(u.Uid, 10, 32)
		return uint32(id), e
	}
	allowed, e = resolve(peers.Allowed)
	if e == nil {
		foreign, e = resolve(peers.Foreign)
	}
	if e != nil || allowed == foreign || allowed == uint32(os.Geteuid()) || foreign == uint32(os.Geteuid()) {
		fmt.Fprintln(os.Stderr, "PENDING: distinct configured peers unavailable")
		os.Exit(69)
	}
	code := m.Run()
	if pending {
		code = 69
	}
	os.Exit(code)
}
func helper(args []string) int {
	if len(args) < 2 {
		return 69
	}
	uid, e := strconv.ParseUint(args[1], 10, 32)
	if e != nil || uint32(os.Geteuid()) != uint32(uid) {
		return 69
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if args[0] == "connect" {
		if len(args) != 4 {
			return 69
		}
		pin, e := strconv.ParseUint(args[3], 10, 32)
		if e != nil {
			return 69
		}
		c, e := runner.DialBroker(ctx, args[2])
		if e != nil {
			return 69
		}
		defer c.Close()
		if c.VerifyServer(ctx, uint32(pin)) != nil {
			return 70
		}
		h, e := c.Hello(ctx, runner.HelloRequest{Versions: []int{1}, Profile: runner.ProtocolProfile})
		if e != nil || h.UID != uint32(uid) {
			return 70
		}
		return 0
	}
	if args[0] != "serve-denied" && args[0] != "serve-allowed" {
		return 69
	}
	dir, e := os.MkdirTemp("/tmp", "client-peer-")
	if e != nil {
		return 69
	}
	defer os.RemoveAll(dir)
	if os.Chmod(dir, 0755) != nil {
		return 69
	}
	path := filepath.Join(dir, "broker.sock")
	l, e := server.Listen(path)
	if e != nil {
		return 69
	}
	defer l.Close()
	l.SetDeadline(time.Now().Add(4 * time.Second))
	fmt.Fprintln(os.Stdout, path)
	c, e := l.AcceptUnix()
	if e != nil {
		return 69
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if args[0] == "serve-denied" {
		var b [1]byte
		n, e := c.Read(b[:])
		if n != 0 || e != io.EOF {
			return 70
		}
		return 0
	}
	peer, e := server.PeerUID(c)
	if e != nil {
		return 69
	}
	b, e := wire.Read(c)
	if e != nil {
		return 70
	}
	var r wire.Request
	if wire.Decode(b, &r) != nil || r.Method != "hello" {
		return 70
	}
	if wire.Write(c, map[string]any{"request_id": r.ID, "result": map[string]any{"version": 1, "profile": wire.Profile, "principal": map[string]any{"uid": peer}, "policy_generation": 1}}) != nil {
		return 70
	}
	return 0
}
func peerCommand(t *testing.T, name, mode string, uid uint32, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "sudo", append([]string{"-n", "-u", name, "--", peers.Helper, "client-peer", mode, strconv.FormatUint(uint64(uid), 10)}, args...)...)
	cmd.Env = []string{}
	return cmd
}
func peerResult(t *testing.T, e error) {
	t.Helper()
	if e == nil {
		return
	}
	if exit, ok := e.(*exec.ExitError); ok && exit.ExitCode() == 70 {
		t.Fatal("kernel peer assertion failed")
	}
	pending = true
	t.Fatal("PENDING: configured helper unavailable")
}

// Claim: an actual configured allowed-peer process verifies the real daemon's
// kernel UID and negotiates its own kernel principal. Clients send no bytes to
// a foreign-user server when its pin mismatches; the exact-pin control succeeds.
func TestConfiguredClientPins(t *testing.T) {
	env := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) { p.Accounts[0].AllowedUIDs = []uint32{allowed} })
	path := filepath.Join(peers.Directory, "client-"+lease.RandomID())
	l, e := server.Listen(path)
	if e != nil {
		pending = true
		t.Fatal("PENDING: configured socket unavailable")
	}
	srv := server.New(env.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); done <- srv.Serve(ctx, l) }()
	defer func() {
		testutil.StopServer(func() { cancel(); srv.Close() }, serveDone, srv.Wait)
		<-done
	}()
	cmd := peerCommand(t, peers.Allowed, "connect", allowed, path, strconv.FormatUint(uint64(os.Geteuid()), 10))
	peerResult(t, cmd.Run())
	t.Log("allowed_peer: PASS; distinct process verified broker UID and negotiated its own principal")
	for _, mode := range []string{"serve-denied", "serve-allowed"} {
		t.Run(mode, func(t *testing.T) {
			cmd := peerCommand(t, peers.Foreign, mode, foreign)
			out, e := cmd.StdoutPipe()
			if e != nil {
				pending = true
				t.Fatal("PENDING: helper pipe unavailable")
			}
			if e = cmd.Start(); e != nil {
				peerResult(t, e)
			}
			t.Logf("foreign_peer helper process PID: %d", cmd.Process.Pid)
			scanner := bufio.NewScanner(out)
			if !scanner.Scan() {
				peerResult(t, cmd.Wait())
				pending = true
				t.Fatal("PENDING: foreign server unavailable")
			}
			socket := scanner.Text()
			if !strings.HasPrefix(socket, "/tmp/client-peer-") {
				cmd.Wait()
				t.Fatal("invalid fixture socket")
			}
			c, e := runner.DialBroker(context.Background(), socket)
			if e != nil {
				cmd.Wait()
				pending = true
				t.Fatal("PENDING: foreign socket unreachable")
			}
			pin := uint32(os.Geteuid())
			if mode == "serve-allowed" {
				pin = foreign
			}
			e = c.VerifyServer(context.Background(), pin)
			if mode == "serve-denied" {
				r, ok := e.(*runner.Refusal)
				if !ok || r.Code != "server_identity_mismatch" {
					c.Close()
					cmd.Wait()
					t.Fatal("different UID accepted")
				}
			} else {
				if e != nil {
					c.Close()
					cmd.Wait()
					t.Fatal("correct server UID refused")
				}
				_, e = c.Hello(context.Background(), runner.HelloRequest{Versions: []int{1}, Profile: runner.ProtocolProfile})
				if e != nil {
					c.Close()
					cmd.Wait()
					t.Fatal("same pinned foreign server hello refused")
				}
			}
			c.Close()
			peerResult(t, cmd.Wait())
			t.Log("foreign_peer: PASS; intended kernel pin result and helper-observed protocol ordering")
		})
	}
	env.NoLeaseRecords(t)
}
