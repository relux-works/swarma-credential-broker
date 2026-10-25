//go:build linux && amd64

package qualify

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-credential-broker/internal/testutil/hosttest"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

var ownerTestBuild struct {
	sync.Once
	image []byte
	err   error
}

func ownerTools(t *testing.T) (*os.File, *os.File, string) {
	t.Helper()
	// Actual kernel prerequisite checks precede the synthetic store. A failed
	// scenario after these checks is a test failure, never a capability skip.
	probeKernel := exec.Command(os.Args[0], "-test.run=^TestOwnerKernelCapability$")
	probeKernel.Env = []string{"OWNER_KERNEL_PROBE=1", "GOMAXPROCS=2"}
	if out, e := probeKernel.CombinedOutput(); e != nil {
		hosttest.Require(t, "seccomp listener probe: "+string(out))
		t.Fatalf("seccomp listener probe: %s", out)
	}
	fd, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		hosttest.Require(t, "pidfd_open: "+e.Error())
		t.Fatal(e)
	}
	unix.Close(fd)
	supported, e := os.ReadFile("/proc/sys/kernel/seccomp/actions_avail")
	if e != nil || !strings.Contains(string(supported), "user_notif") {
		hosttest.Require(t, "seccomp user_notif unavailable")
		t.Fatal("seccomp capability unavailable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer probeCancel()
	probe := exec.CommandContext(probeCtx, "/bin/true")
	probe.SysProcAttr = ownerTraceProbe()
	if e = probe.Start(); e != nil {
		hosttest.Require(t, "ptrace start: "+e.Error())
		t.Fatal(e)
	}
	var ws unix.WaitStatus
	for {
		_, e = unix.Wait4(probe.Process.Pid, &ws, 0, nil)
		if e != unix.EINTR {
			break
		}
	}
	if e == nil {
		e = unix.PtraceDetach(probe.Process.Pid)
	}
	if e != nil {
		probe.Process.Kill()
	}
	wait := probe.Wait()
	if e != nil || wait != nil {
		t.Fatal("ptrace capability probe", e, wait)
	}
	ownerTestBuild.Do(func() {
		path := filepath.Join(t.TempDir(), "image")
		cmd := exec.Command(os.Getenv("GO"), "build", "-p=1", "-o", path, "../../cmd/swarma-credential-broker")
		if out, e := cmd.CombinedOutput(); e != nil {
			ownerTestBuild.err = errors.New(string(out))
			return
		}
		ownerTestBuild.image, ownerTestBuild.err = os.ReadFile(path)
	})
	if ownerTestBuild.err != nil {
		t.Fatal(ownerTestBuild.err)
	}
	path := filepath.Join(t.TempDir(), "image")
	if os.WriteFile(path, ownerTestBuild.image, 0700) != nil {
		t.Fatal("image fixture")
	}
	broker, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { broker.Close() })
	candidate, e := os.Open("/usr/bin/gnutrue")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { candidate.Close() })
	digest, e := descriptorDigest(candidate)
	if e != nil {
		t.Fatal(e)
	}
	return broker, candidate, digest
}
func ownerTestScenario(t *testing.T, broker, candidate *os.File, digest, scenario, recovery string) ownerScenarioFact {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fact, x, _, e := ownerScenarioRun(ctx, broker, candidate, digest, scenario, recovery)
	if e != nil || !x.credit(false) || x.CaseExit != 0 {
		t.Fatalf("owner %s/%s invariant: %v; %+v", scenario, recovery, e, fact)
	}
	return fact
}

// Claim: all eleven fixed live faults refuse twice with no publication/start or
// reconstruction, then reopen without initialization. Intact control publishes.
// Unsafe-mode cases prove protected-mode rejection, not kernel EACCES.
func TestOwnerStoreMissingPair(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	for _, scenario := range append([]string{"current"}, ownerStoreFaults...) {
		t.Run(scenario, func(t *testing.T) {
			f := ownerTestScenario(t, broker, candidate, digest, scenario, "refused")
			if scenario != "current" && (!f.Audited || f.Budgets[0].Requests != 3) {
				t.Fatal("missing complete audit/request budget")
			}
		})
	}
}

// Claim: eight exact incomplete/error inputs cannot resolve a retained attempt.
// O2 incomplete remains blocked; an INDEPENDENT O2 complete at its first New
// resolves that same attempt. Boot/epoch contradictions remain negative.
func TestOwnerAbsenceUnreadablePair(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	t.Run("complete-publishes-generation-two", func(t *testing.T) {
		f := ownerTestScenario(t, broker, candidate, digest, "complete", "intact")
		if f.Generation != 2 {
			t.Fatal("complete generation")
		}
	})
	for _, scenario := range ownerAbsenceFaults {
		t.Run("O1-"+scenario+"-O2-incomplete-stays-refused", func(t *testing.T) {
			f := ownerTestScenario(t, broker, candidate, digest, scenario, "refused")
			if f.Generation != 1 || f.Starts != 1 {
				t.Fatal("incomplete recovery resolved/retried")
			}
		})
	}
	t.Run("independent-O1-partial-O2-complete-first-construction-resolves-same-attempt", func(t *testing.T) {
		f := ownerTestScenario(t, broker, candidate, digest, "partial", "complete-on-construction")
		if f.Generation != 2 || f.Starts != 1 || f.Stops != 2 {
			t.Fatal("constructor recovery did not resolve retained attempt")
		}
	})
}

// Claim: inotify detects a create-then-delete even with identical final inventory;
// synthetic overflow/lost-watch frames fail as unknown, without queue flooding.
func TestOwnerFilesystemAuditControls(t *testing.T) {
	root := t.TempDir()
	a, e := newOwnerAudit(root)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(a.fd)
	path := filepath.Join(root, "transient")
	if os.WriteFile(path, []byte("fixture"), 0600) != nil || os.Remove(path) != nil {
		t.Fatal("audit plant not applied")
	}
	t.Log("CONTROL APPLIED create-delete")
	if e = a.drain(false); e == nil || e.Error() != "audit mutation" {
		t.Fatal("create-delete not detected", e)
	}
	for _, c := range []struct {
		mask uint32
		wd   int32
		want string
	}{{unix.IN_Q_OVERFLOW, -1, "audit overflow"}, {unix.IN_IGNORED, 1, "audit lost watch"}} {
		a := &ownerAudit{watches: map[int]string{1: root}}
		var b [16]byte
		binary.NativeEndian.PutUint32(b[:], uint32(c.wd))
		binary.NativeEndian.PutUint32(b[4:], c.mask)
		if e := a.parse(b[:], false); e == nil || e.Error() != c.want {
			t.Fatal("incomplete audit accepted", e)
		}
	}
	// Expected retirement is admitted only for the exact parent-deleted object.
	child := filepath.Join(root, "removed")
	if os.Mkdir(child, 0700) != nil {
		t.Fatal("retirement fixture")
	}
	r, e := newOwnerAudit(root)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(r.fd)
	if os.Remove(child) != nil || r.drain(true) != nil || r.drain(false) != nil {
		t.Fatal("expected retirement rejected")
	}
}

// Claim: the parent's attempted-Start ledger rejects an extra attempt before
// any response/model activation, independent of the engine's MaxAttempts cap.
func TestOwnerEvidenceRejectsHiddenStart(t *testing.T) {
	model := &ownerModel{starts: 1}
	e := model.serve(nil, ownerMessage{Op: "start"})
	if e == nil || e.Error() != "unexpected model start" || model.starts != 2 {
		t.Fatal("hidden start excluded from attempted ledger", e)
	}
}

// Claim: size/count exhaustion is an evidence error, never an expected refusal.
func TestOwnerBudgetsAndCodec(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ch := &ownerChannel{r: r, w: w, writes: 256}
	if ch.send("test", nil, nil) == nil {
		t.Fatal("message budget accepted")
	}
	s := &ownerSession{budget: ownerBudget{Requests: 3}}
	if _, e = s.call("lease.request", nil, "lease_owner_unavailable"); e == nil || e.Error() != "owner scenario budget exhausted" {
		t.Fatal("request cap not enforced")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], 4097)
	if _, e = w.Write(h[:]); e != nil {
		t.Fatal(e)
	}
	if _, e = ch.read(); e == nil {
		t.Fatal("oversize frame accepted")
	}
	valid := &ownerChannel{r: r, w: w}
	if e = valid.send("ready", nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = valid.read(); e != nil {
		t.Fatal("ordered frame rejected", e)
	}
	duplicate, _ := wire.Encode(ownerMessage{ID: 1, Op: "ready"})
	binary.BigEndian.PutUint32(h[:], uint32(len(duplicate)))
	if _, e = w.Write(h[:]); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(duplicate); e != nil {
		t.Fatal(e)
	}
	if _, e = valid.read(); e == nil || e.Error() != "owner protocol sequence" {
		t.Fatal("duplicate same-method reply accepted", e)
	}

}

// Claim: parent artifact validation demands all fixed subcases and their exact
// setup-inclusive counts; a hash-consistent invented count earns no credit.
func TestOwnerRows(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	_ = candidate
	_, c, root := setup(t)
	c.Policy.Executable = "/usr/bin/gnutrue"
	c.Policy.ExecutableSHA256 = digest
	var records []rowExecutionRecord
	d := driver{rowExecutable: broker.Name(), executions: &records}
	for _, id := range []string{"store-missing", "absence-unreadable"} {
		pair := qualificationCase(id)
		pair.Positive = d.runRow(context.Background(), c.Policy, root, id, "positive")
		pair.Negative = d.runRow(context.Background(), c.Policy, root, id, "negative")
		if pair.Positive.Verdict != "passed" || pair.Negative.Verdict != "passed" || validateRow(root, digest, c.Policy.Generation, pair, records) != nil {
			t.Fatalf("owner row pair unavailable: %+v", pair)
		}
		b, e := os.ReadFile(rowFile(root, id, "negative"))
		var a rowArtifact
		if e != nil || wire.Decode(b, &a) != nil {
			t.Fatal("owner artifact")
		}
		a.Observation.Owner.Scenarios[0].Budgets[0].Requests++
		if validOwnerEffects(a.Observation) {
			t.Fatal("invented owner budget credited")
		}
		if wire.Decode(b, &a) != nil {
			t.Fatal("original artifact")
		}
		a.Observation.Owner.Scenarios[0].Origins[0].Command[1] = "qualification-case"
		if validOwnerEffects(a.Observation) {
			t.Fatal("generic case argv earned owner credit")
		}
	}
}

func ownerTraceProbe() *syscall.SysProcAttr          { return &syscall.SysProcAttr{Ptrace: true} }
func qualificationCase(id string) qualification.Case { return qualification.Case{ID: id} }

// Claim: even transient recovery initialization of a removed metadata root is
// rejected by the parent audit after the actual second owner joins.
func TestOwnerStoreMissingRejectsReconstruction(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	ownerTestScenario(t, broker, candidate, digest, "metadata-absent", "refused")
}

// Claim: the real complete control publishes, while PID-only model evidence
// cannot resolve or deliver replacement material. A narrowed confirmed gate
// must fail this named test on the negative, not on setup.
func TestOwnerAbsenceRejectsPIDOnlyResolution(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	ownerTestScenario(t, broker, candidate, digest, "complete", "intact")
	ownerTestScenario(t, broker, candidate, digest, "pid-only", "refused")
}

// Claim: a measured owner entry with a zero-exit/no-op composition cannot earn
// execution credit without the real initial lease and reopened-store effects.
func TestOwnerRoleDispatchEffects(t *testing.T) {
	broker, candidate, digest := ownerTools(t)
	ownerTestScenario(t, broker, candidate, digest, "current", "intact")
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, broker.Name(), "qualification-owner", strings.Repeat("0", 64))
	cmd.Env = []string{"HOME=" + root, "GOMAXPROCS=2"}
	err := cmd.Run()
	entries, e := os.ReadDir(root)
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 125 || e != nil || len(entries) != 0 {
		t.Fatal("direct owner invocation constructed authority", err)
	}
}

// Claim: the integrated tests probe actual NEW_LISTENER permission in a clean
// disposable process before building any synthetic store. Ordinary test runs
// do not change their own seccomp state.
func TestOwnerKernelCapability(t *testing.T) {
	if os.Getenv("OWNER_KERNEL_PROBE") != "1" {
		return
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		t.Fatal("no_new_privs:", e)
	}
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}}
	program := unix.SockFprog{Len: 1, Filter: &filter[0]}
	fd, _, e := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&program)))
	if e != 0 {
		t.Fatal("seccomp_new_listener:", e)
	}
	unix.Close(int(fd))
}
