//go:build linux

package timeconf

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Claim: ordinary construction, zero values and a fixture with its qualification
// removed all return a typed activation refusal before storage or collection.
// A qualified test-only path with the identical enrollment is a positive control.
func TestProductionActivation(t *testing.T) {
	f := newSettlementFixture(t)
	ordinary, e := NewConsumer(f.enrollment, f.policy, filepath.Join(f.root, "absent"))
	if e != nil {
		t.Fatal(e)
	}
	inactive := &Consumer{}
	q := f.consumer.timePath
	f.consumer.timePath = nil
	for _, c := range []*Consumer{nil, inactive, ordinary, f.consumer} {
		raw, e := c.ConsumeBeforePin(context.Background(), f.request(strings.Repeat("0", 32)))
		var a *ActivationRefusal
		if len(raw) != 0 || !errors.As(e, &a) || !errors.Is(e, ErrUnavailable) {
			t.Fatal("unqualified path produced success or untyped refusal", e)
		}
	}
	if f.collected != 0 {
		t.Fatal("inactive path touched collector")
	}
	if _, e = os.Stat(filepath.Join(f.root, "absent")); !os.IsNotExist(e) {
		t.Fatal("ordinary construction created history")
	}
	f.consumer.timePath = q
	fixturePass(t, f, strings.Repeat("1", 32))
	f.consumer.store.witness = ClosedWitness{}
	raw, e := f.call(strings.Repeat("2", 32))
	var closed *ActivationRefusal
	if len(raw) != 0 || !errors.As(e, &closed) || closed.Reason != "witness_unavailable" {
		t.Fatal("closed witness consumption not typed", e)
	}
}

// Claim: one aggregate deadline returns refusal while an uncooperative fixture
// is pending. A late result cannot pass or reopen the leaf; busy contention and
// independent stop dispatch do not wait. The fixture is always released/joined.
func TestConsumeDeadlineNoLatePass(t *testing.T) {
	f := newSettlementFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	ended := make(chan struct{})
	var once sync.Once
	var released atomic.Bool
	unblock := func() { once.Do(func() { released.Store(true); close(release) }) }
	f.consumer.collector = fixtureLocal{func(context.Context, Policy) (localCollection, error) {
		close(started)
		<-release
		close(ended)
		return f.collection, nil
	}}
	timer := time.AfterFunc(200*time.Millisecond, unblock)
	defer timer.Stop()
	defer unblock()
	request := f.request(strings.Repeat("2", 32))
	request.Deadline = time.Now().Add(20 * time.Millisecond)
	raw, e := f.consumer.ConsumeBeforePin(context.Background(), request)
	requireRefusal(t, raw, e)
	if released.Load() {
		t.Fatal("deadline return waited for collector")
	}
	select {
	case <-started:
	default:
		t.Fatal("hang fixture was not reached")
	}
	// Stop is intentionally unrelated to Consumer. This checks no shared test
	// exclusion is needed; each real consumer must prove its own stop integration.
	stop := make(chan struct{})
	go func() { close(stop) }()
	select {
	case <-stop:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("independent stop blocked")
	}
	request = f.request(strings.Repeat("3", 32))
	raw, e = f.consumer.ConsumeBeforePin(context.Background(), request)
	var refused *ConsumptionRefusal
	if len(raw) != 0 || !errors.As(e, &refused) || refused.Code != "busy" {
		t.Fatal("pending collector did not fence admission", e)
	}
	unblock()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("fixture did not join")
	}
	joinFixtureWorker(t, f)
	// The file lock is released by the worker after its clock read. Inspect the
	// durable record directly: no final record may follow the expired begin.
	h, _ := f.witness.Read(context.Background())
	if h.Generation != 1 {
		t.Fatal("late sample settled or passed")
	}
}

// Claim: expiration while waiting for local durability also returns refusal by
// the original deadline. A lost or delayed acknowledgment cannot deliver pass.
func TestConsumeStorageDeadline(t *testing.T) {
	f := newSettlementFixture(t)
	release := make(chan struct{})
	ended := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	f.consumer.store.syncFault = func(point string) error {
		if point == "record-file" {
			<-release
			close(ended)
		}
		return nil
	}
	request := f.request(strings.Repeat("4", 32))
	request.Deadline = time.Now().Add(20 * time.Millisecond)
	raw, e := f.consumer.ConsumeBeforePin(context.Background(), request)
	requireRefusal(t, raw, e)
	if f.collected != 0 {
		t.Fatal("storage timeout collected")
	}
	unblock()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("storage fixture did not join")
	}
	joinFixtureWorker(t, f)
	h, _ := f.witness.Read(context.Background())
	if h.Generation != 0 {
		t.Fatal("expired begin advanced witness")
	}
}

// Claim: missing terminal subtree or drain evidence refuses despite a good
// report and direct-child result. No incomplete collection can settle its begin.
func TestConsumeCompletionAndDrain(t *testing.T) {
	for _, defect := range []string{"terminal", "drain", "boot", "elapsed", "source", "authdata", "uncertainty", "authority"} {
		t.Run(defect, func(t *testing.T) {
			f := newSettlementFixture(t)
			switch defect {
			case "terminal":
				f.collection.terminal = false
			case "drain":
				f.collection.drained = false
			case "boot":
				f.after.Boot = secondBoot
			case "elapsed":
				f.after.Elapsed = -1
			case "source":
				f.collection.evidence.Sources.AllNTS = false
			case "authdata":
				p := f.policy
				p.Source = NTSAuthData
				f.applyPolicy(t, p)
				f.collection.evidence.Authentication.Addresses = nil
			case "uncertainty":
				f.consumer.timePath.reserve = 2 * time.Second
			case "authority":
				p := f.policy
				p.AuthorityWindow = time.Second
				f.applyPolicy(t, p)
			}
			raw, e := f.call(strings.Repeat("5", 32))
			requireRefusal(t, raw, e)
			s, oe := f.consumer.store.open()
			if oe != nil {
				t.Fatal(oe)
			}
			r, re := s.record(f.witness.head)
			s.close()
			if re != nil {
				t.Fatal(re)
			}
			if r.HighWater != "140000000000" {
				t.Fatal("unqualified candidate consumed time")
			}
			if defect == "terminal" || defect == "drain" || defect == "elapsed" {
				if !r.InFlight {
					t.Fatal("unresolved completion lost begin")
				}
			}
		})
	}
	f := newSettlementFixture(t)
	fixturePass(t, f, strings.Repeat("6", 32))
}

type traceFixtureRunner struct{ raw [][]byte }

func (r *traceFixtureRunner) Run(ctx context.Context, path string, args []string, timeout time.Duration, limit int) ([]byte, error) {
	b, e := (SystemRunner{}).Run(ctx, path, args, timeout, limit)
	if e == nil {
		r.raw = append(r.raw, append([]byte(nil), b...))
	}
	return b, e
}

// Claim: the accepting fixture uses the real descriptor execution child and
// fixed argv/output policy. Its known no-descendant test binary supplies fixture
// completion only; this does not qualify the native chronyc/daemon subtree.
func TestConsumeExistingCollectorChild(t *testing.T) {
	f := newSettlementFixture(t)
	binary := executableFixture(t)
	config := filepath.Join(filepath.Dir(binary), "source.conf")
	if e := os.WriteFile(config, []byte("server 192.0.2.1 nts\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f.consumer.policy.Chronyc = binary
	f.consumer.policy.SourceFiles = []string{config}
	// The native fixture report is fixed at this instant; reserve remains 1s.
	f.now = time.Unix(1893553445, 0).UTC()
	f.before = ClockPoint{f.now, time.Hour, fixtureBoot}
	f.after = f.before
	f.seed(t, 140, 140, secondBoot)
	f.consumer.collector = fixtureLocal{func(ctx context.Context, p Policy) (localCollection, error) {
		trace := &traceFixtureRunner{}
		e, err := (SystemCollector{Runner: trace}).Collect(ctx, p)
		original, readErr := os.ReadFile(config)
		if readErr != nil {
			return localCollection{}, readErr
		}
		return localCollection{e, append(trace.raw, original), true, true}, err
	}}
	// Bind the exact applied fixture policy, not the old policy manifest.
	f.enrollment.Policy.EffectiveDigest, _ = EffectivePolicyDigest(f.consumer.policy, f.enrollment.Policy.SharedDigest, "none")
	f.consumer.enrollment = f.enrollment
	b, _ := canonical(f.enrollment)
	f.consumer.store.binding = sum(b)
	f.seed(t, 140, 140, secondBoot)
	r := fixturePass(t, f, strings.Repeat("7", 32))
	if r.Facts.Evidence.Source != NTSConfig || r.Facts.Evidence.NTSAssociation != "unproven" {
		t.Fatal("fixture invented negotiated authentication")
	}
}

// Claim: a real test child that forks and leaves the pipe open cannot count as
// completed/drained. The test retains/reaps its own child through a subreaper;
// a passing unit result or direct-child exit cannot substitute for that proof.
func TestConsumeForkedCollector(t *testing.T) {
	var previous int32
	e := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&previous)), 0, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); e != nil {
		t.Fatal(e)
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(previous), 0, 0, 0)
	binary := executableFixture(t)
	dir := filepath.Dir(binary)
	if e = os.WriteFile(filepath.Join(dir, "scenario"), []byte("qualified-fork"), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, runErr := (SystemRunner{}).Run(ctx, binary, []string{"-c", "tracking"}, 300*time.Millisecond, 4096)
	pidBytes, e := os.ReadFile(filepath.Join(dir, "child.pid"))
	if e != nil {
		t.Fatal("fork control not applied", e)
	}
	pid, e := strconv.Atoi(string(pidBytes))
	if e != nil || pid <= 0 {
		t.Fatal("invalid owned child identity")
	}
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		t.Fatal(e)
	}
	reaped := false
	defer func() {
		if !reaped {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			var status unix.WaitStatus
			_, _ = unix.Wait4(pid, &status, 0, nil)
		}
		_ = unix.Close(fd)
	}()
	if runErr == nil {
		t.Fatal("inherited open pipe was treated as drained")
	}
	if e = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); e != nil {
		t.Fatal(e)
	}
	var status unix.WaitStatus
	if _, e = unix.Wait4(pid, &status, 0, nil); e != nil {
		t.Fatal("owned descendant not reaped", e)
	}
	reaped = true
	f := newSettlementFixture(t)
	f.collection.terminal = false
	f.collection.drained = false
	raw, e := f.call(strings.Repeat("8", 32))
	requireRefusal(t, raw, e)
}

// Invoked only by the synthetic descriptor-pinned executable fixture. It uses
// no account, policy, environment selector or production qualification path.
func qualifiedForkFixture() bool {
	if len(os.Args) < 3 || os.Args[1] != "-c" {
		return false
	}
	if os.Args[2] == "qualified-descendant" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	// Descriptor execution reports /proc/self/fd/3 as argv[0]; /proc/self/exe is
	// the pinned native fixture inode after the CollectorEntry exec.
	path, _ := os.Executable()
	scenario, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "scenario"))
	if string(bytes.TrimSpace(scenario)) != "qualified-fork" {
		return false
	}
	cmd := exec.Command(path, "-c", "qualified-descendant")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmd.Start() != nil {
		os.Exit(11)
	}
	if os.WriteFile(filepath.Join(filepath.Dir(path), "child.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600) != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		os.Exit(12)
	}
	os.Exit(0)
	return true
}

// Claim: provider-applicable paired vectors have executable negative/positive
// controls. Consumer release/window/lock/deadline adapters remain explicitly
// outside this package; no local synthetic predicate claims their integration.
func TestQualifiedProviderVectors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{"exclusive-authority", func(r *Receipt) { r.Facts.AuthorityUntil = r.Facts.Continuity.HighWater }},
		{"boot-domains", func(r *Receipt) { r.Facts.Clock.Monotonic = "unknown" }},
		{"known-bounded-time", func(r *Receipt) { r.Facts.Uncertainty = "-1" }},
		{"provenance-qualified", func(r *Receipt) { r.Facts.Evidence.Qualified = false }},
		{"provenance-nts", func(r *Receipt) { r.Facts.Evidence.NTSConfig = false }},
		{"identity-scope", func(r *Receipt) { r.Facts.Scope.Consumer = "" }},
		{"new-observation", func(r *Receipt) { r.Facts.Sample.Fresh = false }},
		{"continuity-required", func(r *Receipt) { r.Facts.Continuity.RecordDigest = "" }},
		{"sticky-hold", func(r *Receipt) { r.Facts.Continuity.Held = true }},
		{"write-before-reply", func(r *Receipt) { r.Facts.Continuity.Generation = "0" }},
		{"receipt-authority-mapping", func(r *Receipt) { r.Facts.Authority.Version = strings.Repeat("a", 33) }},
		{"native-identity", func(r *Receipt) { r.Facts.Scope.OperationDigest = "sha256:abc" }},
		{"overflow", func(r *Receipt) { r.Facts.Observed = ns(math.MaxInt64) }},
		{"authority-ceiling", func(r *Receipt) { r.Facts.AuthorityUntil = ns(1000 * int64(time.Second)) }},
		{"sample-generation", func(r *Receipt) { r.Facts.Sample.Generation = "01" }},
		{"boot-transition", func(r *Receipt) { r.Facts.Clock.Boot = secondBoot }},
	}
	f := newSettlementFixture(t)
	base := fixturePass(t, f, strings.Repeat("9", 32))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			tc.mutate(&bad)
			raw, _ := canonical(bad)
			if _, e := DecodeReceipt(raw); e == nil {
				t.Fatal("invalid vector admitted")
			}
			good, e := EncodeReceipt(base)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = DecodeReceipt(good); e != nil {
				t.Fatal("paired valid control refused", e)
			}
		})
	}
}

// Claim: closed canonical decoding rejects every tested alternate JSON form,
// bound excess and integer encoding; its exact canonical positive control passes.
func TestQualifiedReceiptCodec(t *testing.T) {
	f := newSettlementFixture(t)
	r := fixturePass(t, f, strings.Repeat("a", 32))
	raw, _ := EncodeReceipt(r)
	forms := [][]byte{
		append(append([]byte{}, raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"qualified-time/1"`, `"qualified-time/2"`, 1)),
		[]byte(strings.Replace(string(raw), `"facts":{`, `"extra":true,"facts":{`, 1)),
		[]byte(strings.Replace(string(raw), `"fresh":true`, `"fresh":true,"fresh":true`, 1)),
		[]byte(strings.Replace(string(raw), `"fresh":true`, `"fresh":null`, 1)),
		[]byte(strings.Replace(string(raw), `"fresh":true,`, ``, 1)),
		[]byte(strings.Replace(string(raw), `"fresh":true`, `"Fresh":true`, 1)),
		[]byte(strings.Replace(string(raw), `"observed":"211000000000"`, `"observed":211000000000`, 1)),
		[]byte(strings.Replace(string(raw), `"observed":"211000000000"`, `"observed":"0211000000000"`, 1)),
		[]byte(strings.Replace(string(raw), `"observed":"211000000000"`, `"observed":"2.11e11"`, 1)),
		[]byte(strings.Replace(string(raw), `"observed":"211000000000"`, `"observed":"+211000000000"`, 1)),
		[]byte(strings.Replace(string(raw), `"uncertainty":"1000000000"`, `"uncertainty":"-0"`, 1)),
		[]byte(strings.Replace(string(raw), `"generation":"2"`, `"generation":"18446744073709551616"`, 1)),
		[]byte(strings.Replace(string(raw), `"consumer"`, `"con\u0073umer"`, 1)),
		bytes.Repeat([]byte(" "), receiptLimit+1),
		[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17)),
	}
	for i, b := range forms {
		if bytes.Equal(b, raw) {
			t.Fatalf("codec plant %d not applied", i)
		}
		if _, e := DecodeReceipt(b); e == nil {
			t.Fatalf("noncanonical form %d accepted", i)
		}
	}
	if out, e := DecodeReceipt(raw); e != nil || out != r {
		t.Fatal("canonical positive control failed", e)
	}
}

// Claim: domain separation, profile/identity lengths and full original bytes
// determine operation digests. These helpers never validate a consumer codec.
func TestQualifiedOperationRecipes(t *testing.T) {
	executor, e := ExecutorOperationDigest([]byte(`{}`))
	if e != nil || executor != "sha256:08d7c7a9ada35f95af2b836edadcb07e4a59ef95c8b9ead80b0e23990ee5640a" {
		t.Fatal("executor digest recipe", executor, e)
	}
	native, e := NativeOperationDigest("native-v1", []byte(`{"request":"abc"}`))
	if e != nil || native != "sha256:4e964bac0dfee939c06f29078380ad2bfbc42309793b113c5c1304a5675f411b" {
		t.Fatal("native digest recipe", native, e)
	}
	changed, _ := NativeOperationDigest("native-v2", []byte(`{"request":"abc"}`))
	if changed == native {
		t.Fatal("profile omitted")
	}
	changed, _ = NativeOperationDigest("native-v1", []byte(`{"request":"abd"}`))
	if changed == native {
		t.Fatal("original identity omitted")
	}
	for _, v := range [][]byte{nil, bytes.Repeat([]byte("x"), receiptLimit+1), []byte("{}\n")} {
		if _, e := ExecutorOperationDigest(v); e == nil {
			t.Fatal("executor helper bound ignored")
		}
	}
	if _, e := NativeOperationDigest("unpublished profile", []byte(`{}`)); e == nil {
		t.Fatal("profile encoding ignored")
	}
}

func joinFixtureWorker(t *testing.T, f *settlementFixture) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s, e := f.consumer.store.open()
		if e == nil {
			s.close()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture storage worker did not release its leaf")
}

// Claim: canonical decimal generations admit the uint64 endpoints except zero
// for successful consumption; malformed encodings never wrap/coerce. Boundaries
// on public IDs and owner versions have adjacent valid controls.
func TestQualifiedReceiptRepresentationLimits(t *testing.T) {
	f := newSettlementFixture(t)
	base := fixturePass(t, f, strings.Repeat("b", 32))
	for _, value := range []Generation{"-1", "+1", "00", "01", "1.0", "1e1", "18446744073709551616", "0"} {
		r := base
		r.Facts.Sample.Generation = value
		r.Facts.Continuity.Generation = value
		if _, e := EncodeReceipt(r); e == nil {
			t.Fatal("invalid generation encoded", value)
		}
	}
	r := base
	r.Facts.Sample.Generation = "18446744073709551615"
	r.Facts.Continuity.Generation = r.Facts.Sample.Generation
	if _, e := EncodeReceipt(r); e != nil {
		t.Fatal("maximum generation refused", e)
	}
	r = base
	r.Facts.Scope.Consumer = strings.Repeat("a", 128)
	r.Facts.Authority.Version = strings.Repeat("v", 32)
	if _, e := EncodeReceipt(r); e != nil {
		t.Fatal("identifier positive boundary refused", e)
	}
	r.Facts.Scope.Consumer += "a"
	if _, e := EncodeReceipt(r); e == nil {
		t.Fatal("overlong identifier accepted")
	}
	r = base
	r.Facts.Clock.Boot = "00000000-0000-0000-0000-000000000000"
	if _, e := EncodeReceipt(r); e == nil {
		t.Fatal("zero boot accepted")
	}
	r = base
	r.Facts.Adapter.ImageDigest = strings.ToUpper(r.Facts.Adapter.ImageDigest)
	if _, e := EncodeReceipt(r); e == nil {
		t.Fatal("noncanonical digest accepted")
	}
}

// Claim: even a random-ID collision refuses, without retrying or reusing that
// observation. A distinct full 128-bit ID is the paired positive control.
func TestQualifiedObservationCollision(t *testing.T) {
	old := strings.Repeat("ab", 16)
	used := map[string]bool{old: true}
	if id, e := observationID(bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)), used); e == nil || id != "" {
		t.Fatal("repeated sample ID accepted")
	}
	id, e := observationID(bytes.NewReader(bytes.Repeat([]byte{0xcd}, 16)), used)
	if e != nil || id != strings.Repeat("cd", 16) {
		t.Fatal("fresh ID refused", e)
	}
	if id, e := observationID(bytes.NewReader([]byte{1}), used); e == nil || id != "" {
		t.Fatal("truncated randomness accepted")
	}
}

// Claim: a new operation digest shares the provider high-water, rather than
// selecting an empty history. The retained previous association remains intact.
func TestSettlementOperationSharesHistory(t *testing.T) {
	f := newSettlementFixture(t)
	f.setTime(200, fixtureBoot)
	fixturePass(t, f, strings.Repeat("c", 32))
	f.setTime(171, secondBoot)
	request := f.request(strings.Repeat("d", 32))
	request.OperationDigest = sum([]byte("another-operation"))
	raw, e := f.consumer.ConsumeBeforePin(context.Background(), request)
	requireRefusal(t, raw, e)
	f.setTime(211, secondBoot)
	request.Challenge = strings.Repeat("e", 32)
	request.Deadline = time.Now().Add(400 * time.Millisecond)
	raw, e = f.consumer.ConsumeBeforePin(context.Background(), request)
	if e != nil {
		t.Fatal("new-operation time control refused", e)
	}
	r, e := DecodeReceipt(raw)
	if e != nil || r.Facts.Scope.OperationDigest != request.OperationDigest || r.Facts.Continuity.PriorHighWater != "201000000000" {
		t.Fatal("operation association or shared high-water lost", e)
	}
}

// Claim: malformed enrollment, an unbound operation in enrollment and an
// incorrect effective manifest cannot construct a usable public consumer.
func TestConsumerEnrollmentValidation(t *testing.T) {
	f := newSettlementFixture(t)
	for _, change := range []func(*Enrollment){
		func(e *Enrollment) { e.Authority.Version = strings.Repeat("v", 33) },
		func(e *Enrollment) { e.Adapter.CollectorEntry = "unknown" },
		func(e *Enrollment) { e.Scope.OperationDigest = sum([]byte("operation")) },
		func(e *Enrollment) { e.Policy.EffectiveDigest = sum([]byte("different-policy")) },
		func(e *Enrollment) { e.Authority.TrustRootDigest = "unknown" },
	} {
		e := f.enrollment
		change(&e)
		if c, err := NewConsumer(e, f.policy, f.root); err == nil || c != nil {
			t.Fatal("invalid enrollment accepted")
		}
	}
	if c, e := NewConsumer(f.enrollment, f.policy, f.root); e != nil || c == nil {
		t.Fatal("public construction control refused", e)
	}
}

// Claim: changing the enrolled scope cannot select a clean history in the same
// protected directory. The original witness/head stays intact with no query.
func TestSettlementRebindingRefused(t *testing.T) {
	f := newSettlementFixture(t)
	enrolled := f.enrollment
	enrolled.Scope.Consumer = "another-consumer"
	c, e := NewConsumer(enrolled, f.policy, f.root)
	if e != nil {
		t.Fatal(e)
	}
	c.timePath = f.consumer.timePath
	c.clock = f
	c.collector = f.consumer.collector
	c.store.witness = f.witness
	request := f.request(strings.Repeat("6", 32))
	request.Expected = enrolled
	raw, e := c.ConsumeBeforePin(context.Background(), request)
	requireRefusal(t, raw, e)
	if f.collected != 0 || f.witness.head.Generation != 0 {
		t.Fatal("rebinding reset existing history")
	}
	fixturePass(t, f, strings.Repeat("7", 32))
}
