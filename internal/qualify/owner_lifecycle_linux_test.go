//go:build linux && amd64

package qualify

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/testutil/hosttest"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Claim: attempted Start is counted before an audit rejection; other rejected
// operations do not count as Start. Neither path can reach child creation.
func TestOwnerLifecycleAttemptedStart(t *testing.T) {
	m := &lifecycleModel{audit: &lifecycleAudit{fd: -1}}
	if e := m.serve(nil, ownerMessage{Op: "start"}); !errors.Is(e, unix.EBADF) || m.starts != 1 {
		t.Fatalf("rejected Start missing from ledger: starts=%d error=%v", m.starts, e)
	}
	if e := m.serve(nil, ownerMessage{Op: "confidence"}); !errors.Is(e, unix.EBADF) || m.starts != 1 {
		t.Fatalf("non-Start changed ledger: starts=%d error=%v", m.starts, e)
	}
}

func lifecycleTest(t *testing.T, scenarios ...string) []lifecycleFact {
	t.Helper()
	broker, candidate, digest := ownerTools(t)
	lifecycleObserverProbe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var facts []lifecycleFact
	for _, scenario := range scenarios {
		start := time.Now()
		diagnostic := withOwnerDiagnostics(ctx, func(s string) { t.Log(s) })
		f, x, _, e := lifecycleRun(diagnostic, broker, candidate, digest, scenario)
		if e != nil || !x.credit(false) || x.CaseExit != 0 || !validLifecycleFact(f) {
			if f.Parallel != nil {
				t.Logf("parallel effects: %+v", f.Parallel)
			}
			t.Fatalf("lifecycle %s invariant: %v; %+v", scenario, e, f)
		}
		t.Logf("%s joined in %s; frames=%v; filesystem events=%d", scenario, time.Since(start), f.Frames, f.Events)
		facts = append(facts, f)
	}
	return facts
}

// Claim: fixed ambiguous replies with either old or changed native bytes retain
// Unknown across a complete Stop and first replacement constructor; Safe replies
// instead resolve Transient and permit the independently checked due successor.
func TestOwnerTransientAmbiguousPair(t *testing.T) {
	lifecycleTest(t, "ambiguous-old", "ambiguous-new", "safe-safe-committed")
}

// Claim: Safe resolution time sets persisted 1s/2s backoff across restart; early
// valid rejected-token demands return renew_failed and never start another W.
func TestOwnerTransientBackoffResolution(t *testing.T) { lifecycleTest(t, "safe-safe-committed") }

// Claim: owner SIGKILL before stopping proof leaves both native variants blocked
// after complete singleton Stop; normal committed history reloads generation 2.
func TestOwnerRotationCrashPair(t *testing.T) {
	lifecycleTest(t, "rotation-no-store", "rotation-no-proof", "rotation-committed")
}

// Claim: the same durable Committed prefix needs complete evidence at the first
// replacement constructor. Partial evidence cannot resolve or publish; complete
// evidence resolves that attempt without another Start. Terminal reload is valid.
func TestOwnerCleanupInterruptedPair(t *testing.T) {
	lifecycleTest(t, "cleanup-incomplete", "cleanup-complete", "rotation-committed")
}

// Claim: the aggregate requires each crash epoch, held prefix and writer stop;
// a later normally joined owner never repairs deleted or altered crash evidence.
func TestOwnerCrashGateCertificate(t *testing.T) {
	f := lifecycleTest(t, "rotation-no-proof")[0]
	raw, e := wire.Encode(f)
	if e != nil {
		t.Fatal(e)
	}
	for _, plant := range []func(*lifecycleFact){func(f *lifecycleFact) { f.Crashes = nil }, func(f *lifecycleFact) { f.Crashes[0].Signal = 15 }, func(f *lifecycleFact) { f.Crashes[0].Exit = 0 }, func(f *lifecycleFact) { f.Gate.State = "released" }, func(f *lifecycleFact) { f.Gate.Prefix = strings.Repeat("a", 64) }, func(f *lifecycleFact) { f.Writers[0].Stop.TraceComplete = false }, func(f *lifecycleFact) { f.Writers[0].Survived = false }} {
		var copy lifecycleFact
		if wire.Decode(raw, &copy) != nil {
			t.Fatal("certificate codec")
		}
		plant(&copy)
		if validLifecycleFact(copy) {
			t.Fatal("missing crash placement obligation accepted")
		}
	}
}

// Claim: two actually launched and entered isolated writers trip the same peak
// observer used by the manager; suppression of the second launch is not a plant.
func TestOwnerWriterOverlapObserver(t *testing.T) {
	broker, _, digest := ownerTools(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	root := t.TempDir()
	c, _, e := ownerSeed(root, digest, "rotation-committed")
	if e != nil {
		t.Fatal(e)
	}
	native, _ := ownerMaterial(c.Now, "replacement")
	var writers []*lifecycleWriter
	peak := 0
	for i := 0; i < 2; i++ {
		w, e := startWriter(ctx, c, broker, lease.RandomID(), native)
		if w != nil {
			defer w.cleanup()
			writers = append(writers, w)
		}
		if e != nil {
			t.Fatal(e)
		}
		e = writerPeak(writers, &peak)
		if i == 0 && e != nil {
			t.Fatal(e)
		}
		if i == 1 && (e == nil || e.Error() != "second physical synthetic writer" || peak != 2) {
			t.Fatal("physical overlap not detected", e, peak)
		}
	}
	t.Log("CONTROL APPLIED two entered synthetic writers")
}

// Claim: successful native persist acknowledgements require the generated bytes
// and observed filesystem events; a no-op writer cannot pass the normal control.
func TestOwnerWriterPersistEffects(t *testing.T) { lifecycleTest(t, "rotation-committed") }

// Claim: bounded directory events admit expected atomic native replacement only
// in its explicit phase. Overflow, watch loss and other paths remain evidence errors.
func TestOwnerLifecycleAuditControls(t *testing.T) {
	for _, test := range []struct {
		mask        uint32
		name, phase string
		native      bool
		want        string
	}{{unix.IN_MODIFY, "auth.json", "writer", true, ""}, {unix.IN_MODIFY, "auth.json", "owner", false, "lifecycle phase write not admitted"}, {unix.IN_MODIFY, "unexpected", "writer", true, "lifecycle phase write not admitted"}, {unix.IN_Q_OVERFLOW, "", "owner", false, "lifecycle event overflow"}, {unix.IN_IGNORED, "", "owner", false, "lifecycle lost watch"}} {
		a := &lifecycleAudit{root: "/fixture", watches: map[int]string{1: "/fixture/home"}, native: test.native}
		name := append([]byte(test.name), 0)
		b := make([]byte, 16+len(name))
		binary.NativeEndian.PutUint32(b, 1)
		binary.NativeEndian.PutUint32(b[4:], test.mask)
		binary.NativeEndian.PutUint32(b[12:], uint32(len(name)))
		copy(b[16:], name)
		e := a.parse(b, test.phase)
		if test.want == "" && e != nil || test.want != "" && (e == nil || e.Error() != test.want) {
			t.Fatal("lifecycle completeness control", test, e)
		}
	}
}

// Claim: all six row-side collectors keep every variant and joined cleanup
// within the unchanged 30s bound, and artifacts need the private parent binding.
func TestOwnerLifecycleRows(t *testing.T) {
	broker, _, _ := ownerTools(t)
	lifecycleObserverProbe(t)
	path, c, root := setup(t)
	d := newFixtureDriver(path, "0.163.0")
	d.rowExecutable = broker.Name()
	var records []rowExecutionRecord
	d.executions = &records
	for _, id := range []string{"transient-ambiguous", "rotation-crash", "cleanup-interrupted"} {
		q := qualification.Case{ID: id}
		for _, side := range []string{"positive", "negative"} {
			x := d.runRow(withOwnerDiagnostics(context.Background(), func(s string) { t.Log(s) }), c.Policy, root, id, side)
			if !x.Executed || x.Verdict != "passed" || x.DurationNS <= 0 || x.DurationNS > x.BoundNS || x.BoundNS != int64(30*time.Second) {
				t.Fatal("lifecycle row collector", id, side, x)
			}
			t.Logf("%s/%s all variants and cleanup %s", id, side, time.Duration(x.DurationNS))
			if side == "positive" {
				q.Positive = x
			} else {
				q.Negative = x
			}
		}
		if e := validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, q, records); e != nil {
			t.Fatal("lifecycle row artifact", id, e)
		}
		if validateRow(root, c.Policy.ExecutableSHA256, c.Policy.Generation, q) == nil {
			t.Fatal("unbound lifecycle artifact accepted")
		}
	}
}

// Claim: fixture classification and pending-state rules remain pure default-CI
// checks, independent of host process capabilities. Only code 1001 is Safe;
// changed material, an elapsed retry time or a resolved record cannot turn an
// Unknown prefix into a passing pending proof.
func TestOwnerLifecyclePureContracts(t *testing.T) {
	for _, code := range []int{0, 1001, 1002} {
		want := authowner.Unknown
		if code == 1001 {
			want = authowner.Safe
		}
		if (lifecycleClassifier{}).Classify(authowner.RPCError{Code: code}) != want {
			t.Fatal("synthetic classifier widened")
		}
	}
	cp := authowner.Checkpoint{State: "owner_unavailable", TokenGeneration: 1, StoreGeneration: 1, PendingAttempt: "attempt"}
	intents := []authowner.Intent{{Binding: authowner.Binding{Attempt: "attempt"}}}
	if lifecyclePending(cp, intents, nil) != nil {
		t.Fatal("pending positive rejected")
	}
	changed := cp
	changed.RetryAt = time.Now()
	if lifecyclePending(changed, intents, nil) == nil {
		t.Fatal("Unknown acquired retry time")
	}
	if lifecyclePending(cp, intents, []authowner.Evidence{{Phase: "resolved"}}) == nil {
		t.Fatal("Unknown acquired terminal record")
	}
	clock := &lifecycleClock{value: time.Unix(100, 0)}
	clock.set(time.Unix(99, 0))
	if !clock.now().Equal(time.Unix(100, 0)) {
		t.Fatal("clock reversed")
	}
	clock.set(time.Unix(101, 0))
	if !clock.now().Equal(time.Unix(101, 0)) {
		t.Fatal("clock failed to advance")
	}
}

func lifecycleObserverProbe(t *testing.T) {
	t.Helper()
	fd, e := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if e != nil {
		hosttest.Require(t, "inotify initialization: "+e.Error())
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if _, e = unix.InotifyAddWatch(fd, t.TempDir(), unix.IN_CREATE|unix.IN_MODIFY|unix.IN_MOVED_TO); e != nil {
		hosttest.Require(t, "inotify directory watch: "+e.Error())
		t.Fatal(e)
	}
}
