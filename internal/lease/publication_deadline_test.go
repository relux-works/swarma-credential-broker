package lease_test

import (
	"context"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"strings"
	"testing"
	"time"
)

type deadlineAdmission struct {
	until          time.Time
	delay          bool
	ignoreDeadline bool
}

type revokedPublicationGate struct{ entered chan struct{} }

func (*revokedPublicationGate) Peer(ctx context.Context, _ uint32) error            { return ctx.Err() }
func (*revokedPublicationGate) Check(ctx context.Context, _ uint32, _ string) error { return ctx.Err() }
func (g *revokedPublicationGate) Publish(ctx context.Context, _ uint32, _ string, write func(context.Context) error) error {
	close(g.entered)
	<-ctx.Done()
	// Even an adapter supplying a fresh context cannot erase revocation.
	return write(context.Background())
}

func TestPublicationCancellationStillFencesMaterial(t *testing.T) {
	for _, reason := range []string{"caller", "release", "replacement"} {
		t.Run(reason, func(t *testing.T) {
			gate := &revokedPublicationGate{entered: make(chan struct{})}
			e := testutil.New(t, lease.Options{DemoAdmission: gate, Now: time.Now})
			e.Request.LaunchID = strings.Repeat("a", 64)
			result := e.Issue(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			wrote := false
			go func() {
				done <- e.Manager.Publish(ctx, e.UID, e.Policy.Generation, result, func(context.Context, time.Time) error { wrote = true; return nil })
			}()
			select {
			case <-gate.entered:
			case <-time.After(time.Second):
				t.Fatal("gate not reached")
			}
			switch reason {
			case "caller":
				cancel()
			case "release":
				if e.Manager.Call(context.Background(), e.UID, "lease.release", wire.Release{LeaseID: result.LeaseID}, time.Now()).Err != nil {
					t.Fatal("release failed")
				}
			case "replacement":
				p := e.Policy.Clone()
				p.Generation++
				if err := e.Manager.Replace(p); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err == nil || wrote {
					t.Fatal("revoked delivery reached material callback")
				}
			case <-time.After(time.Second):
				t.Fatal("revoked publication did not stop")
			}
		})
	}
}

func (a *deadlineAdmission) Peer(ctx context.Context, uid uint32) error { return ctx.Err() }
func (a *deadlineAdmission) Check(ctx context.Context, uid uint32, digest string) error {
	return ctx.Err()
}
func (a *deadlineAdmission) Publish(ctx context.Context, uid uint32, digest string, write func(context.Context) error) error {
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(a.until) {
		return fmt.Errorf("gate did not receive the immutable authority deadline")
	}
	if a.delay {
		if a.ignoreDeadline {
			time.Sleep(time.Until(a.until.Add(100 * time.Millisecond)))
			// A broken adapter cannot replace the manager's cancellation fence.
			return write(context.Background())
		}
		timer := time.NewTimer(time.Until(a.until.Add(100 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return write(ctx)
}
func TestPublicationDeadlineSurvivesDemoGate(t *testing.T) {
	for _, name := range []string{"live-positive-control", "gate-crosses-lease-expiry", "gate-ignores-expiry"} {
		delayed := name != "live-positive-control"
		t.Run(name, func(t *testing.T) {
			admission := &deadlineAdmission{delay: delayed, ignoreDeadline: name == "gate-ignores-expiry"}
			e := testutil.New(t, lease.Options{DemoAdmission: admission, Now: time.Now})
			view := e.Owner.View()
			view.AuthorityUntil = time.Now().Add(2 * time.Second).Truncate(time.Second)
			e.Owner.Set(view)
			e.Request.LaunchID = strings.Repeat("a", 64)
			result := e.Issue(t)
			until, err := time.Parse(time.RFC3339, result.AuthorizedUntil)
			if err != nil {
				t.Fatal(err)
			}
			admission.until = until
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			wrote := false
			publishErr := e.Manager.Publish(ctx, e.UID, e.Policy.Generation, result, func(call context.Context, cutoff time.Time) error {
				wrote = true
				now := time.Now()
				t.Logf("delayed=%t late_by=%s cutoff_extension=%s caller_live=%t", delayed, now.Sub(until), cutoff.Sub(until), call.Err() == nil)
				if !now.Before(until) {
					t.Error("material publication callback admitted after immutable lease expiry")
				}
				if cutoff.After(until) {
					t.Error("publication callback received a shifted future deadline")
				}
				return nil
			})
			if !delayed && (!wrote || publishErr != nil) {
				t.Fatalf("live control failed: wrote=%v err=%v", wrote, publishErr)
			}
			if delayed && (wrote || publishErr == nil) {
				t.Fatalf("expired publication not refused: wrote=%v err=%v", wrote, publishErr)
			}
		})
	}
}
