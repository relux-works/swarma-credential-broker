//go:build linux

package qualify

import (
	"context"
	"net"
	"os"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"golang.org/x/sys/unix"
)

// This private observation is preparatory evidence, never serialized authority.
// The evidence-class/artifact gate is deliberately still unavailable.
type runnerObservation struct {
	origin      *egress.RunnerOrigin
	broker      *server.RunnerAdmissionCounts
	bind        func() error
	outcome     runner.Outcome
	trace       egress.RunnerTraceResult
	admission   admissionEffects
	observation rowObservation
	available   bool
}

func (d driver) runRunnerPair(ctx context.Context, p policy.Policy, root string, c *qualification.Case) {
	var o runnerObservation
	d.runRowObserved(ctx, p, root, c.ID, "positive", &o)
	if o.available && o.trace.State.ExitCode() == 0 {
		d.runRow(ctx, p, root, c.ID, "negative")
	} else {
		e := newRowExecution()
		e.Diagnostic = "case_pair_unavailable"
		d.recordExecution(c.ID, "negative", e)
	}
	c.Positive, c.Negative = pendingRowControl(), pendingRowControl()
}

// Gates require joined parent facts and agreement with child testimony.
func (o runnerObservation) validate(in rowInput, joined, effects bool) bool {
	if !joined || !effects || o.origin == nil || o.broker == nil || o.trace.State == nil {
		return false
	}
	f := o.origin.Facts()
	if !f.Verified || !f.Joined || f.PID != o.trace.State.Pid() {
		return false
	}
	ob := o.observation
	if ob.Owner != nil || ob.Lifecycle != nil || ob.Admission != nil || ob.LeaseProtocol != nil || ob.ProbeFault || len(ob.Envelopes) != 0 {
		return false
	}
	if ob.ID != in.ID || ob.Side != in.Side || ob.Candidate != in.ApprovedDigest || !ob.NoEffects || ob.Refusal != map[bool]string{true: "credential_source_conflict", false: "external-login"}[in.Side == "negative"] || !validRunnerEffects(ob) {
		return false
	}
	connections, requests, releases, other := o.broker.Counts()
	if other != 0 || connections != int64(ob.Runner.Connects) || requests != int64(ob.Runner.Requests) || releases != int64(ob.Runner.Releases) {
		return false
	}
	if in.Side == "negative" {
		return o.trace.Children == 0 && connections == 0 && requests == 0 && releases == 0 && o.admission.Records == 0 && o.admission.Snapshots == 0 && o.admission.Refreshes == 0 && o.outcome == (runner.Outcome{Status: 69, Kind: runner.OutcomeSourceConflict})
	}
	return connections == 1 && requests == 1 && releases == 1 && o.admission.Records == 1 && o.admission.Snapshots == 2 && o.admission.Refreshes == 0 && o.outcome == (runner.Outcome{Status: 0, Kind: runner.OutcomeSuccess})
}

// No listener exists until the trace's verified exec stop. Poll before closing
// and read counts after Serve/Wait join: a queued, unaccepted connection refuses
// completeness rather than disappearing during cancellation.
func runnerListener(ctx context.Context, srv *server.Server, path string, o *runnerObservation) (func() error, error) {
	var l *net.UnixListener
	var done chan error
	o.bind = func() error {
		var e error
		l, e = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			return e
		}
		if e = os.Chmod(path, 0600); e != nil {
			l.Close()
			return e
		}
		done = make(chan error, 1)
		go func() { done <- srv.Serve(ctx, l) }()
		return nil
	}
	return func() error {
		var e error
		if l != nil {
			raw, re := l.SyscallConn()
			e = re
			pending := false
			if re == nil {
				e = raw.Control(func(fd uintptr) {
					p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					if _, pe := unix.Poll(p, 0); pe != nil || p[0].Revents != 0 {
						pending = true
					}
				})
			}
			if pending {
				e = qualification.ErrUnavailable
			}
			l.Close()
			if done != nil {
				if se := <-done; se != nil {
					e = se
				}
			}
		}
		srv.Close()
		srv.Wait()
		return e
	}, nil
}
