package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type publicationBarrier struct {
	*testutil.Fake
	owners  map[string]*testutil.Fake
	entered chan struct{}
	resume  chan struct{}
	enabled atomic.Bool
}

func (o *publicationBarrier) Snapshot(ctx context.Context, label string) (owner.Snapshot, error) {
	if _, ok := ctx.Deadline(); ok && o.enabled.Load() {
		o.entered <- struct{}{}
		select {
		case <-o.resume:
		case <-ctx.Done():
			return owner.Snapshot{}, ctx.Err()
		}
	}
	if f := o.owners[label]; f != nil {
		return f.Snapshot(ctx, label)
	}
	return o.Fake.Snapshot(ctx, label)
}

// Claim: six finite, nonreading material clients must not postpone another lease's renew reply past the default 8-second arrival budget; reading clients are the adjacent control.
func TestReviewSlowPublicationDeadline(t *testing.T) {
	for _, slow := range []bool{false, true} {
		name := "reading-control"
		if slow {
			name = "nonreading-peers"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			e.Manager.Close()
			v := e.Owner.View()
			v.AccessToken = strings.Repeat("x", 20000)
			e.Owner.Set(v)
			o := &publicationBarrier{Fake: e.Owner, entered: make(chan struct{}, 10), resume: make(chan struct{})}
			o.enabled.Store(true)
			var once sync.Once
			unblock := func() { once.Do(func() { close(o.resume) }) }
			defer unblock()
			m, err := lease.New(e.Policy, e.Store, o, lease.Options{Now: func() time.Time { return e.Now }}, false)
			if err != nil {
				t.Fatal("manager setup")
			}
			defer m.Close()
			e.Manager = m
			victim := e.Issue(t)
			path := start(t, e, func(s *Server) {
				s.peer = func(c *net.UnixConn) (uint32, error) {
					if err := c.SetWriteBuffer(1024); err != nil {
						return 0, err
					}
					return PeerUID(c)
				}
			})
			var peers []*net.UnixConn
			var readers sync.WaitGroup
			defer func() {
				for _, peer := range peers {
					peer.Close()
				}
				readers.Wait()
			}()
			for i := 0; i < 6; i++ {
				c := dial(t, path)
				c.SetDeadline(time.Now().Add(20 * time.Second))
				hello(t, c)
				peers = append(peers, c)
				b, _ := wire.Encode(e.Request)
				if wire.Write(c, wire.Request{Method: "lease.request", ID: "blocked", Params: b}) != nil {
					t.Fatal("request setup")
				}
			}
			for i := 0; i < 6; i++ {
				awaitReview(t, o.entered)
			}
			drained := make(chan error, len(peers))
			if !slow {
				for _, c := range peers {
					readers.Add(1)
					go func(c *net.UnixConn) { defer readers.Done(); _, err := wire.Read(c); drained <- err }(c)
				}
			}
			c := dial(t, path)
			c.SetDeadline(time.Now().Add(16 * time.Second))
			hello(t, c)
			unblock()
			for _, peer := range peers {
				if slow {
					awaitIncoming(t, peer, 5)
				} else if err := <-drained; err != nil {
					t.Fatal("reading control", err)
				}
			}
			begin := time.Now()
			b, _ := wire.Encode(wire.Renew{LeaseID: victim.LeaseID, RejectedSHA256: lease.Digest(victim.Payload.AccessToken)})
			if wire.Write(c, wire.Request{Method: "lease.renew", ID: "victim", Params: b}) != nil {
				t.Fatal("victim write")
			}
			raw, err := wire.Read(c)
			elapsed := time.Since(begin)
			if err != nil {
				t.Fatalf("victim response missing after %s", elapsed)
			}
			var reply response
			if json.Unmarshal(raw, &reply) != nil {
				t.Fatal("bad response")
			}
			code := "success"
			if reply.Error != nil {
				code = reply.Error.Code
			}
			t.Logf("victim result=%s elapsed=%s", code, elapsed)
			if elapsed > 8500*time.Millisecond {
				t.Errorf("renew arrival deadline exceeded behind publication locks: %s", elapsed)
			}
			if !slow && reply.Error != nil {
				t.Error("reading control refused")
			}
			for _, c := range peers {
				c.Close()
			}
			c.Close()
		})
	}
}

func incoming(c *net.UnixConn) (int, error) {
	var count int32
	var probe error
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = raw.Control(func(fd uintptr) {
		_, _, eno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&count)))
		if eno != 0 {
			probe = eno
		}
	})
	if err != nil {
		return 0, err
	}
	return int(count), probe
}

// awaitIncoming uses kernel readiness for fixture setup without consuming bytes
// or assuming the publisher has run after a fixed sleep. Socket deadlines remain
// deadlock guards; measured arrival budgets start only after this rendezvous.
func awaitIncoming(t *testing.T, c *net.UnixConn, minimum int) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var count int32
	var probe error
	err = raw.Read(func(fd uintptr) bool {
		_, _, eno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&count)))
		if eno != 0 {
			probe = eno
		}
		return probe != nil || int(count) >= minimum
	})
	if err != nil || probe != nil || int(count) < minimum {
		t.Fatalf("publication readiness: queued=%d need=%d error=%v/%v", count, minimum, err, probe)
	}
}

// awaitFrames peeks complete warm-up frames without draining socket capacity.
// A byte-count approximation could mistake the tail of a warm frame for the
// next partial publication; all warm frames must be complete first.
func awaitFrames(t *testing.T, c *net.UnixConn, frames int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, frames*(wire.MaxPayload+4))
	var probe error
	total := 0
	err = raw.Read(func(fd uintptr) bool {
		n, _, e := syscall.Recvfrom(int(fd), image, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		if e == syscall.EAGAIN {
			return false
		}
		if e != nil {
			probe = e
			return true
		}
		offset := 0
		for i := 0; i < frames; i++ {
			if n-offset < 4 {
				return false
			}
			size := int(binary.BigEndian.Uint32(image[offset : offset+4]))
			if size == 0 || size > wire.MaxPayload {
				probe = wire.ErrMalformed
				return true
			}
			offset += 4 + size
			if offset > n {
				return false
			}
		}
		total = offset
		return true
	})
	if err != nil || probe != nil || total == 0 {
		t.Fatalf("warm frame readiness: %v/%v", err, probe)
	}
	return total
}

// Claim: six ordinary default-buffer clients leaving responses unread cannot postpone another lease renewal beyond its eight-second arrival budget plus 500 ms scheduling allowance; this changes no socket options.
func TestReviewDefaultSocketPublicationDeadline(t *testing.T) { defaultSocketPublication(t, true) }

// Claim: draining ordinary default-buffer responses allows the neighboring lease renewal to succeed.
func TestReviewDefaultSocketPublicationControl(t *testing.T) { defaultSocketPublication(t, false) }

type publicationVariant struct {
	peers           int
	otherAccount    bool
	requireProgress bool
}

func defaultSocketPublication(t *testing.T, slow bool, variants ...publicationVariant) {
	cfg := publicationVariant{peers: 6}
	if len(variants) > 0 {
		cfg = variants[0]
	}
	e := testutil.NewPolicy(t, lease.Options{}, func(p *policy.Policy) {
		if cfg.otherAccount {
			p.Accounts[1].AllowedUIDs = []uint32{p.BrokerUID}
			p.Accounts[1].Profiles = append([]string{}, p.Accounts[0].Profiles...)
			p.Accounts[1].ReleaseVersion = p.Accounts[0].ReleaseVersion
			p.Accounts[1].QualificationID = p.Accounts[0].QualificationID
		}
	})
	e.Manager.Close()
	v := e.Owner.View()
	v.AccessToken = strings.Repeat("y", 60000)
	e.Owner.Set(v)
	o := &publicationBarrier{Fake: e.Owner, entered: make(chan struct{}, cfg.peers+2), resume: make(chan struct{})}
	slowRequest := e.Request
	if cfg.otherAccount {
		other := testutil.New(t, lease.Options{}).Owner
		v := other.View()
		v.AccessToken = strings.Repeat("q", 60000)
		v.AccountID = e.Policy.Accounts[1].VendorID
		other.Set(v)
		o.owners = map[string]*testutil.Fake{e.Policy.Accounts[1].Label: other}
		slowRequest.Account = e.Policy.Accounts[1].Label
		slowRequest.Binding = e.Policy.Binding(e.UID, e.Policy.Accounts[1], slowRequest.Profile)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(o.resume) }) }
	defer unblock()
	m, err := lease.New(e.Policy, e.Store, o, lease.Options{Now: func() time.Time { return e.Now }}, false)
	if err != nil {
		t.Fatal("manager setup")
	}
	defer m.Close()
	e.Manager = m
	victim := e.Issue(t)
	path := start(t, e, nil)
	var peers []*net.UnixConn
	var readers sync.WaitGroup
	defer func() {
		for _, peer := range peers {
			peer.Close()
		}
		readers.Wait()
	}()
	var warmBytes []int
	for i := 0; i < cfg.peers; i++ {
		c := dial(t, path)
		c.SetDeadline(time.Now().Add(30 * time.Second))
		hello(t, c)
		peers = append(peers, c)
		b, _ := wire.Encode(slowRequest)
		for _, id := range []string{"warm1", "warm2", "warm3"} {
			if wire.Write(c, wire.Request{Method: "lease.request", ID: id, Params: b}) != nil {
				t.Fatal("warm request")
			}
		}
		warmBytes = append(warmBytes, awaitFrames(t, c, 3))
	}
	o.enabled.Store(true)
	for _, c := range peers {
		b, _ := wire.Encode(slowRequest)
		if wire.Write(c, wire.Request{Method: "lease.request", ID: "blocked", Params: b}) != nil {
			t.Fatal("blocked request")
		}
	}
	for i := 0; i < cfg.peers; i++ {
		awaitReview(t, o.entered)
	}
	c := dial(t, path)
	c.SetDeadline(time.Now().Add(16 * time.Second))
	hello(t, c)
	drained := make(chan error, len(peers))
	if !slow {
		for _, peer := range peers {
			readers.Add(1)
			go func(c *net.UnixConn) {
				defer readers.Done()
				for i := 0; i < 4; i++ {
					if _, err := wire.Read(c); err != nil {
						drained <- err
						return
					}
				}
				drained <- nil
			}(peer)
		}
	}
	unblock()
	for i, peer := range peers {
		if slow {
			awaitIncoming(t, peer, warmBytes[i]+5)
		} else if err := <-drained; err != nil {
			t.Fatal("draining control", err)
		}
	}
	begin := time.Now()
	b, _ := wire.Encode(wire.Renew{LeaseID: victim.LeaseID, RejectedSHA256: lease.Digest(victim.Payload.AccessToken)})
	if wire.Write(c, wire.Request{Method: "lease.renew", ID: "victim", Params: b}) != nil {
		t.Fatal("victim write")
	}
	raw, err := wire.Read(c)
	elapsed := time.Since(begin)
	if err != nil {
		t.Fatalf("missing reply after %s", elapsed)
	}
	var response response
	if wire.Decode(raw, &response) != nil {
		t.Fatal("response decode")
	}
	code := "success"
	if response.Error != nil {
		code = response.Error.Code
	}
	t.Logf("default buffers result=%s elapsed=%s", code, elapsed)
	if !slow && response.Error != nil {
		t.Error("drained-buffer control refused")
	}
	if cfg.requireProgress && (response.Error != nil || elapsed > 2*time.Second) {
		t.Errorf("unrelated reading lease stalled behind slow publications: code=%s elapsed=%s", code, elapsed)
	}
	if elapsed > 8500*time.Millisecond {
		t.Errorf("default-buffer publication locks exceeded renewal budget: %s", elapsed)
	}
	for _, peer := range peers {
		peer.Close()
	}
	c.Close()
}

// Claim: twelve stalled peers on the same or a different account cannot occupy a shared state fence; an unrelated reading lease still makes successful progress within two seconds, below its arrival budget.
func TestPublicationContentionIsolation(t *testing.T) {
	for _, other := range []bool{false, true} {
		name := "same-account"
		if other {
			name = "other-account"
		}
		t.Run(name, func(t *testing.T) {
			defaultSocketPublication(t, true, publicationVariant{peers: 12, otherAccount: other, requireProgress: true})
		})
	}
}

// Claim: a renewal queued behind a filled connection writer keeps its configured 250 ms arrival budget and closes that non-draining transport within 750 ms; draining the same responses lets renewal succeed.
func TestConnectionWriterWaitDeadline(t *testing.T) {
	for _, drain := range []bool{false, true} {
		name := "non-draining"
		if drain {
			name = "draining-control"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			e.Manager.Close()
			v := e.Owner.View()
			v.AccessToken = strings.Repeat("w", 60000)
			e.Owner.Set(v)
			o := &publicationBarrier{Fake: e.Owner, entered: make(chan struct{}, 2), resume: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(o.resume) }) }
			defer unblock()
			m, err := lease.New(e.Policy, e.Store, o, lease.Options{Now: func() time.Time { return e.Now }, RenewTimeout: 250 * time.Millisecond}, false)
			if err != nil {
				t.Fatal("manager fixture failed")
			}
			e.Manager = m
			t.Cleanup(m.Close)
			r := e.Issue(t)
			var srv *Server
			c := dial(t, start(t, e, func(s *Server) { srv = s }))
			hello(t, c)
			params, _ := wire.Encode(e.Request)
			for _, id := range []string{"warm1", "warm2", "warm3"} {
				if wire.Write(c, wire.Request{Method: "lease.request", ID: id, Params: params}) != nil {
					t.Fatal("warm fixture failed")
				}
			}
			warmBytes := awaitFrames(t, c, 3)
			o.enabled.Store(true)
			if wire.Write(c, wire.Request{Method: "lease.request", ID: "blocked", Params: params}) != nil {
				t.Fatal("blocked fixture failed")
			}
			awaitReview(t, o.entered)
			unblock()
			awaitIncoming(t, c, warmBytes+5)
			params, _ = wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
			begin := time.Now()
			if wire.Write(c, wire.Request{Method: "lease.renew", ID: "queued-renew", Params: params}) != nil {
				t.Fatal("renew fixture failed")
			}
			if drain {
				for i := 0; i < 5; i++ {
					out := reply(t, c)
					if out.Error != nil {
						t.Fatal("draining control refused")
					}
					if i == 4 && (out.ID == nil || *out.ID != "queued-renew") {
						t.Fatal("unexpected final response")
					}
				}
				return
			}
			for time.Since(begin) < 750*time.Millisecond {
				srv.mu.Lock()
				closed := len(srv.connections) == 0
				srv.mu.Unlock()
				if closed {
					testutil.Await(t, func() bool { p, w := m.Stats(e.Account); return p == 0 && w == 0 })
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("connection writer queue ignored the renewal arrival deadline")
		})
	}
}
