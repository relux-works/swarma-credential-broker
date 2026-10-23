package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: after a complete successful material frame on a draining connection, a valid immediate release receives its terminal receipt on that connection. A delayed-release control uses the same sequence; no owner refresh or external credentials are involved.
func TestReviewImmediateReleaseReceipt(t *testing.T) {
	for _, delay := range []time.Duration{time.Millisecond, 0} {
		name := "immediate"
		if delay != 0 {
			name = "settled-control"
		}
		t.Run(name, func(t *testing.T) {
			e := testutil.New(t, lease.Options{})
			path := start(t, e, nil)
			cycles := 250
			if delay != 0 {
				cycles = 10
			}
			for i := 0; i < cycles; i++ {
				c := dial(t, path)
				hello(t, c)
				out := request(t, c, "lease.request", fmt.Sprintf("issue-%d", i), e.Request)
				var result wire.LeaseResult
				if out.Error != nil || wire.Decode(out.Result, &result) != nil {
					t.Fatal("initial issue failed")
				}
				if delay != 0 {
					time.Sleep(delay)
				}
				params, _ := wire.Encode(wire.Release{LeaseID: result.LeaseID})
				if err := wire.Write(c, wire.Request{Method: "lease.release", ID: "release", Params: params}); err != nil {
					t.Fatalf("release send failed after full material frame at iteration %d: %T", i, err)
				}
				raw, err := wire.Read(c)
				if err != nil {
					ecode := "other"
					if errors.Is(err, io.EOF) {
						ecode = "EOF"
					}
					if errors.Is(err, io.ErrUnexpectedEOF) {
						ecode = "unexpected EOF"
					}
					retry := dial(t, path)
					hello(t, retry)
					r := request(t, retry, "lease.release", "retry", wire.Release{LeaseID: result.LeaseID})
					t.Fatalf("complete material frame followed by lost release receipt: iteration=%d read=%s reconnect_receipt=%t", i, ecode, r.Error == nil)
				}
				var released response
				if json.Unmarshal(raw, &released) != nil || released.Error != nil || released.ID == nil || *released.ID != "release" {
					t.Fatal("release receipt mismatch")
				}
				c.Close()
			}
			if n, _ := e.Owner.Counts(); n != 0 {
				t.Fatal("release sequence started refresh")
			}
		})
	}
}
