//go:build linux && amd64

package qualify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

// Claim: each pair uses a real traced Command and parent effects; no row credit
// is granted without the separate accepted-image artifact proof gate.
func TestRunnerParentEffects(t *testing.T) {
	worker, fake := rowTool(t, "../../cmd/swarma-credential-broker"), rowTool(t, "../runner/testdata/appserver")
	for _, id := range []string{"home-auth-present", "source-conflict"} {
		for _, side := range []string{"positive", "negative"} {
			t.Run(id+"/"+side, func(t *testing.T) {
				_, c, _ := setup(t)
				o, e := (driver{rowExecutable: worker, runnerExecutable: fake}).observeRunnerRow(context.Background(), c.Policy, id, side)
				if !o.available {
					t.Fatalf("parent effect gate: execution=%+v outcome=%+v trace=%+v admission=%+v observation=%+v runner=%+v", e, o.outcome, o.trace, o.admission, o.observation, o.observation.Runner)
				}
			})
		}
		_, c, root := setup(t)
		var records []rowExecutionRecord
		pair := qualification.Case{ID: id}
		d := acceptedRunnerDriver(t, worker, fake)
		d.executions = &records
		d.runRunnerPair(context.Background(), c.Policy, root, &pair)
		if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, pair, records) != nil {
			t.Fatal("joined pair proof unavailable", pair)
		}
		if len(records) != 2 || !records[0].Execution.Joined || !records[1].Execution.Joined || records[0].Execution.HelperExit != 0 || records[1].Execution.HelperExit != 0 {
			t.Fatal("pair did not join both real controls", records)
		}
	}
}

func (d driver) observeRunnerRow(ctx context.Context, p policy.Policy, id, side string) (o runnerObservation, e rowExecution) {
	var records []rowExecutionRecord
	d.executions = &records
	d.runRowObserved(ctx, p, "", id, side, &o)
	if len(records) == 1 {
		e = records[0].Execution
	}
	return
}

func runnerFaultTool(t *testing.T, mode string) string {
	t.Helper()
	tool := filepath.Join(t.TempDir(), "worker")
	cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-ldflags=-X main.fault="+mode, "-o", tool, "./testdata/runnerfault")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal("fixture build", e, string(b))
	}
	mustTestimony(t, os.Chmod(tool, 0700))
	return tool
}

// Claim: independent parent connection/method counts, transient filesystem
// events, child creation and missing testimony each refuse an otherwise local
// 69 result. Child counts include the toolchain's first-exec PIDFD probe.
// Each fault image also runs its adjacent real successful control.
func TestRunnerParentRefusals(t *testing.T) {
	fake := rowTool(t, "../runner/testdata/appserver")
	for _, mode := range []string{"connection", "request", "method", "filesystem", "child", "missing"} {
		t.Run(mode, func(t *testing.T) {
			worker := runnerFaultTool(t, mode)
			_, c, root := setup(t)
			d := driver{rowExecutable: worker, runnerExecutable: fake}
			positive, _ := d.observeRunnerRow(context.Background(), c.Policy, "source-conflict", "positive")
			if !positive.available {
				t.Fatal("adjacent positive unavailable")
			}
			o, e := d.observeRunnerRow(context.Background(), c.Policy, "source-conflict", "negative")
			if !e.Joined || e.HelperExit != 0 {
				t.Fatal("fault lost actual case wait", e)
			}
			if mode != "missing" && o.outcome != (runner.Outcome{Status: 69, Kind: runner.OutcomeSourceConflict}) {
				t.Fatal("fault did not reach real local outcome", o.outcome)
			}
			connections, requests, _, other := o.broker.Counts()
			if mode == "connection" && connections != 1 || mode == "request" && requests != 1 || mode == "method" && other != 1 || mode == "child" && o.trace.Children == 0 {
				t.Fatal("fault not observed", connections, requests, other, o.trace)
			}
			if o.admission.Records != 0 || o.admission.Snapshots != 0 || o.admission.Refreshes != 0 {
				t.Fatal("forbidden material or lease effect")
			}
			if o.available {
				t.Fatal("parent gate accepted forbidden effect", mode)
			}
			d.runnerAcceptedImage = acceptedRunnerDriver(t, worker, fake).runnerAcceptedImage
			control := d.runRow(context.Background(), c.Policy, root, "source-conflict", "negative")
			assertOriginPending(t, root, "source-conflict", control)
		})
	}
}

// Claim: completed, real negative evidence cannot substitute for a missing
// trace/testimony join or a contradictory post-return outcome. A distinct
// nonzero case wait remains an independent diagnostic, never Command's 69.
func TestRunnerParentJoinOutcome(t *testing.T) {
	worker, fake := runnerFaultTool(t, "case-status"), rowTool(t, "../runner/testdata/appserver")
	_, c, _ := setup(t)
	o, e := (driver{rowExecutable: worker, runnerExecutable: fake}).observeRunnerRow(context.Background(), c.Policy, "source-conflict", "negative")
	in := rowInput{ID: "source-conflict", Side: "negative", ApprovedDigest: c.Policy.ExecutableSHA256}
	if !o.available || !e.Joined || e.HelperExit != 17 || e.CaseExit != -1 || o.outcome.Status != 69 {
		t.Fatal("actual separate outcomes", e, o.outcome)
	}
	t.Run("join", func(t *testing.T) {
		if o.validate(in, false, true) {
			t.Fatal("missing join accepted")
		}
	})
	t.Run("wait", func(t *testing.T) {
		missing := o
		missing.trace.State = nil
		if missing.validate(in, true, true) {
			t.Fatal("missing consuming wait accepted")
		}
	})
	t.Run("outcome", func(t *testing.T) {
		wrong := o
		wrong.outcome = runner.Outcome{Status: 0, Kind: runner.OutcomeSuccess}
		if wrong.validate(in, true, true) {
			t.Fatal("contradictory outcome accepted")
		}
	})
}

// Claim: the watcher has a valid empty control; removed watches and transient
// out-of-set mutations are incomplete/refused, even with unchanged final entries.
func TestRunnerWatcherCompleteness(t *testing.T) {
	for _, mode := range []string{"removed", "transient", "positive-transient"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"home", "project"} {
				mustTestimony(t, os.Mkdir(filepath.Join(root, name), 0700))
			}
			f := &runnerRowFixture{root: root, watch: -1}
			mustTestimony(t, f.startWatch())
			defer f.close()
			if !f.watchComplete("negative") {
				t.Fatal("valid watcher unavailable")
			}
			side := "negative"
			if mode == "removed" {
				for wd := range f.watches {
					_, e := unix.InotifyRmWatch(f.watch, uint32(wd))
					mustTestimony(t, e)
					break
				}
			} else {
				path := filepath.Join(root, "project", "unexpected")
				mustTestimony(t, os.WriteFile(path, nil, 0600))
				mustTestimony(t, os.Remove(path))
				if mode == "positive-transient" {
					side = "positive"
				}
			}
			if f.watchComplete(side) {
				t.Fatal("incomplete or unexpected watcher accepted")
			}
		})
	}
}

// Claim: even a matching UID/PID cannot obtain fixture admission without a
// live verified origin; the listener is absent before its exec callback.
func TestRunnerAdmissionExecOnly(t *testing.T) {
	_, c, _ := setup(t)
	root := t.TempDir()
	mustTestimony(t, os.Mkdir(filepath.Join(root, "home"), 0700))
	in := admissionInput(rowInput{Policy: c.Policy, Peer: uint32(os.Geteuid()), ID: "source-conflict", Side: "negative"})
	fake, f, e := prepareRunnerRow(root, rowTool(t, "../runner/testdata/appserver"), &in)
	mustTestimony(t, e)
	defer fake.Close()
	defer f.close()
	image, e := os.Open("/proc/self/exe")
	mustTestimony(t, e)
	defer image.Close()
	origin, e := egress.NewRunnerOrigin(image, strings.Repeat("a", 64), []string{"fixture"})
	mustTestimony(t, e)
	o := runnerObservation{origin: origin}
	var pid atomic.Int64
	pid.Store(int64(os.Getpid()))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	path, closeRow, _, e := startAdmissionObserved(ctx, filepath.Join(root, "service"), in, &pid, &o.admission, nil, &o)
	mustTestimony(t, e)
	defer closeRow()
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("listener exists before verified exec")
	}
	mustTestimony(t, o.bind())
	code, _, e := transportExchangeFacts(path, "peer-identity-unavailable", "negative", c.Policy.Generation)
	if e != nil || code != "peer_identity_unavailable" {
		t.Fatal("unverified peer admitted", code, e)
	}
	if origin.Live(os.Getpid()) {
		t.Fatal("unverified origin live")
	}
}
