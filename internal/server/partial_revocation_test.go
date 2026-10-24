package server

import (
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Claim: release, replacement and authority expiry interrupt a real partial material frame; draining without revocation yields a complete success.
func TestReviewRevokedPartialFrame(t *testing.T) {
	for _, action := range []string{"release", "replacement", "expiry", "draining-control"} {
		t.Run(action, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			e.Manager.Close()
			v := e.Owner.View()
			v.AccessToken = strings.Repeat("a", 60000)
			e.Owner.Set(v)
			e.Owner.Next(strings.Repeat("b", 60000))
			started := time.Now()
			now := func() time.Time { return e.Now.Add(time.Since(started)) }
			if action == "expiry" {
				v.ExpiresAt = e.Now.Add(2 * time.Second)
				e.Owner.Set(v)
			}
			o := &publicationBarrier{Fake: e.Owner, entered: make(chan struct{}, 4), resume: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(o.resume) }) }
			defer unblock()
			m, err := lease.New(e.Policy, e.Store, o, lease.Options{Now: now}, false)
			if err != nil {
				t.Fatal("manager")
			}
			e.Manager = m
			t.Cleanup(m.Close)
			r := e.Issue(t)
			path := start(t, e, nil)
			c := dial(t, path)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			hello(t, c)
			b, _ := wire.Encode(e.Request)
			for _, id := range []string{"warm1", "warm2", "warm3"} {
				if wire.Write(c, wire.Request{Method: "lease.request", ID: id, Params: b}) != nil {
					t.Fatal("warm write")
				}
			}
			awaitFrames(t, c, 3)
			before, err := incoming(c)
			if err != nil {
				t.Fatal("queue inspect")
			}
			o.enabled.Store(true)
			b, _ = wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
			if wire.Write(c, wire.Request{Method: "lease.renew", ID: "partial", Params: b}) != nil {
				t.Fatal("renew write")
			}
			awaitReview(t, o.entered)
			unblock()
			awaitIncoming(t, c, before+5)
			begin := time.Now()
			switch action {
			case "release":
				other := dial(t, path)
				hello(t, other)
				out := request(t, other, "lease.release", "release", wire.Release{LeaseID: r.LeaseID})
				if out.Error != nil {
					t.Fatal("release refused")
				}
				disk, _ := e.Store.Account(e.Account, false)
				records, err := disk.Records()
				if err != nil {
					t.Fatal("durable read")
				}
				var record lease.Record
				if wire.Decode(records["lease-"+r.LeaseID+".json"], &record) != nil || record.State != "released" {
					t.Fatal("ack preceded durable release")
				}
			case "replacement":
				p := e.Policy.Clone()
				p.Generation++
				replaced := make(chan error, 1)
				var replacement sync.WaitGroup
				replacement.Add(1)
				defer replacement.Wait()
				go func() { defer replacement.Done(); replaced <- m.Replace(p) }()
				select {
				case err := <-replaced:
					if err != nil {
						t.Fatal("replacement refused")
					}
				case <-time.After(time.Second):
					t.Fatal("replacement deadlocked with socket writer")
				}
				raw, err := os.ReadFile(filepath.Join(e.Root, "policy-watermark.json"))
				if err != nil {
					t.Fatal("watermark read")
				}
				var mark struct {
					Generation uint64 `json:"policy_generation"`
				}
				if json.Unmarshal(raw, &mark) != nil || mark.Generation != p.Generation {
					t.Fatal("replacement ack preceded durable successor")
				}
				other := dial(t, path)
				hello(t, other)
			case "expiry":
				time.Sleep(time.Until(started.Add(2100 * time.Millisecond)))
			}
			for i := 0; i < 3; i++ {
				if out := reply(t, c); out.Error != nil {
					t.Fatal("earlier complete frame damaged")
				}
			}
			raw, err := wire.Read(c)
			if action == "draining-control" {
				var out response
				if err != nil || wire.Decode(raw, &out) != nil || out.Error != nil || out.ID == nil || *out.ID != "partial" {
					t.Fatal("draining control did not complete")
				}
				return
			}
			if err == nil {
				t.Fatal("revoked partial frame became a successful material response")
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("partial frame ended without terminal EOF: %T", err)
			}
			t.Logf("%s acknowledged/expired in %s; prior complete frames intact and partial material frame ended with EOF", action, time.Since(begin))
		})
	}
}
