package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"testing"
	"time"
)

// Claim: a peer that has consumed a complete response can reuse that request ID
// for its next sequential request; distinct IDs are the nearby valid control.
// This probes observed schedules, not a universal ordering proof.
func TestSequentialRequestIDReuseProbe(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		name := "distinct-control"
		if reuse {
			name = "completed-id-reuse"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			path := start(t, e, nil)
			c := dial(t, path)
			hello(t, c)
			c.SetDeadline(time.Now().Add(30 * time.Second))
			for i := 0; i < 500; i++ {
				id := fmt.Sprintf("issue-%d", i)
				raw, _ := wire.Encode(e.Request)
				if err := wire.Write(c, wire.Request{Method: "lease.request", ID: id, Params: raw}); err != nil {
					t.Fatalf("issue write failed at cycle %d", i)
				}
				b, err := wire.Read(c)
				var issue response
				var material wire.LeaseResult
				if err != nil || wire.Decode(b, &issue) != nil || issue.Error != nil || wire.Decode(issue.Result, &material) != nil {
					t.Fatalf("issue unavailable at cycle %d", i)
				}
				if !reuse {
					id = fmt.Sprintf("release-%d", i)
				}
				raw, _ = wire.Encode(wire.Release{LeaseID: material.LeaseID})
				if err = wire.Write(c, wire.Request{Method: "lease.release", ID: id, Params: raw}); err != nil {
					t.Fatalf("release write failed at cycle %d", i)
				}
				b, err = wire.Read(c)
				var receipt response
				if err != nil || wire.Decode(b, &receipt) != nil || receipt.Error != nil {
					retry := dial(t, path)
					hello(t, retry)
					recovered := request(t, retry, "lease.release", "recover", wire.Release{LeaseID: material.LeaseID})
					retry.Close()
					t.Fatalf("complete response ID rejected at cycle %d: receipt_error=%t eof=%t recovery=%t", i, err != nil, errors.Is(err, io.EOF), recovered.Error == nil)
				}
			}
			t.Log("500 sequential issue/release pairs completed")
		})
	}
}

// Claim: after consuming a status response, sequential reuse of its ID remains
// legal; the empty params object is unchanged across these requests.
func TestSequentialStatusIDReuseProbe(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		name := "distinct-control"
		if reuse {
			name = "completed-id-reuse"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			c := dial(t, start(t, e, nil))
			hello(t, c)
			c.SetDeadline(time.Now().Add(30 * time.Second))
			for i := 0; i < 3000; i++ {
				id := "status"
				if !reuse {
					id = fmt.Sprintf("status-%d", i)
				}
				if wire.Write(c, wire.Request{Method: "status", ID: id, Params: json.RawMessage("{}")}) != nil {
					t.Fatalf("status write failed at cycle %d", i)
				}
				b, err := wire.Read(c)
				var out response
				if err != nil || wire.Decode(b, &out) != nil || out.Error != nil {
					t.Fatalf("completed status ID rejected at cycle %d: eof=%t", i, errors.Is(err, io.EOF))
				}
			}
			t.Log("3000 sequential status replies completed")
		})
	}
}
