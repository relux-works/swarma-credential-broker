//go:build linux

package qualify

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type fixtureObserver struct {
	qualification.NativeObserver
	version string
}

func (o fixtureObserver) Version(context.Context) (string, error) { return o.version, nil }

// newFixtureDriver is test-compiled only. Production cannot select a candidate
// version or substitute any observer using arguments or the environment.
func newFixtureDriver(path, version string) driver {
	return driver{path: path, observer: func(c policy.Config) qualification.IdentityObserver {
		raw, _ := wire.Encode(c)
		return fixtureObserver{qualification.NativeObserver{ExecutablePath: c.Policy.Executable, StaticPolicy: raw}, version}
	}}
}
func setup(t *testing.T) (string, policy.Config, string) {
	t.Helper()
	sealFixtureDescriptors(t)
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if os.WriteFile(candidate, []byte("synthetic non-executed executable"), 0700) != nil {
		t.Fatal("candidate fixture")
	}
	c := policy.Config{SocketPath: filepath.Join(root, "broker.sock"), StoreRoot: filepath.Join(root, "store"), Policy: policy.Policy{Installation: "fixture", Generation: 1, BrokerUID: uint32(os.Geteuid()), Executable: candidate, ExecutableSHA256: qualification.Hash([]byte("synthetic non-executed executable")), MaxLeaseSeconds: 3600, Accounts: []policy.Account{{Label: "fixture", VendorID: "fixture-account", Endpoint: "https://example.invalid/inference", AllowedUIDs: []uint32{uint32(os.Geteuid())}, Profiles: []string{"fixture"}, Enabled: true, ReleaseVersion: "0.163.0", QualificationID: "fixture-evidence"}}}}
	path := filepath.Join(root, "config.json")
	b, _ := wire.Encode(c)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("policy fixture")
	}
	evidence := filepath.Join(root, "evidence")
	if os.Mkdir(evidence, 0700) != nil {
		t.Fatal("evidence fixture")
	}
	return path, c, evidence
}

// Claim: invalid flags give 64; live requests, unavailable environment and a
// wrong observed version give 69 without publication or reflected private input.
func TestCommandRefusals(t *testing.T) {
	for _, kind := range []string{"bad", "missing", "duplicate", "duplicate-alias", "modes", "live", "approved-live", "environment", "scratch", "missing-policy", "version", "digest"} {
		t.Run(kind, func(t *testing.T) {
			path, c, evidence := setup(t)
			args := []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}
			d := newFixtureDriver(path, "0.163.0")
			want := 69
			switch kind {
			case "bad":
				args = append(args, "--unknown=fixture-material-canary")
				want = 64
			case "missing":
				args = []string{"--fixtures"}
				want = 64
			case "duplicate":
				args = append(args, "--fixtures")
				want = 64
			case "duplicate-alias":
				args = append(args, "-fixtures")
				want = 64
			case "modes":
				args = append(args, "--live")
				want = 64
			case "live":
				args[len(args)-1] = "--live"
			case "approved-live":
				args[len(args)-1] = "--live"
				args = append(args, "--approval-ref", "fixture-material-canary", "--account", "fixture")
			case "environment":
				d.environment = []string{"OPENAI_API_KEY=fixture-material-canary"}
			case "scratch":
				os.Chmod(evidence, 0755)
			case "missing-policy":
				os.Remove(path)
			case "version":
				d = newFixtureDriver(path, "0.162.0")
			case "digest":
				os.WriteFile(c.Policy.Executable, []byte("changed candidate"), 0700)
			}
			var out bytes.Buffer
			if code := d.run(context.Background(), args, &out); code != want {
				t.Fatalf("exit %d want %d", code, want)
			}
			if bytes.Contains(out.Bytes(), []byte("fixture-material-canary")) {
				t.Fatal("reflected material")
			}
			if _, e := os.Lstat(filepath.Join(qualification.Directory(path), "qualified.json")); !os.IsNotExist(e) {
				t.Fatal("refusal published qualification")
			}
			if _, e := os.Lstat(filepath.Join(evidence, "qualification.sock")); !os.IsNotExist(e) {
				t.Fatal("private socket survived")
			}
		})
	}
}

// Claim: production unavailable probes and all required pending rows are
// recorded with no fabricated command/exit; the owner-only report is flushed,
// ordinary qualification stays fenced, and the private socket is removed.
func TestCommandPending(t *testing.T) {
	path, c, evidence := setup(t)
	if !cleanEnvironment(nil) {
		t.Fatal("fixture has inheritable descriptors")
	}
	if !privateDirectory(evidence) {
		t.Fatal("fixture directory not private")
	}
	if _, e := policy.Load(path, uint32(os.Geteuid())); e != nil {
		t.Fatalf("fixture policy unavailable: %v", e)
	}
	var out bytes.Buffer
	code := Command(context.Background(), []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}, path, nil, &out)
	if code != 69 {
		t.Fatalf("pending exit %d", code)
	}
	var r report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil {
		t.Fatal("report unavailable")
	}
	if len(r.Cases) != len(qualification.RequiredCases()) || r.Disposition != "pending" {
		t.Fatal("required rows missing")
	}
	for _, c := range r.Cases {
		for _, x := range []qualification.Control{c.Positive, c.Negative} {
			if x.Verdict != "pending" || x.Executed || x.ExitCode != -1 || len(x.Command) != 0 || len(x.Artifacts) != 0 {
				t.Fatal("pending row gained execution credit")
			}
		}
	}
	for _, name := range []string{"version/1", "schema/1", "properties/1", "catalog/1"} {
		if !strings.Contains(strings.Join(r.Unavailable, ","), name) {
			t.Fatal("unavailable probe not reported")
		}
	}
	saved, e := os.ReadFile(filepath.Join(evidence, "run.json"))
	if e != nil || !bytes.Equal(bytes.TrimSpace(out.Bytes()), saved) {
		t.Fatal("report not persisted")
	}
	info, e := os.Stat(filepath.Join(evidence, "run.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("report not protected")
	}
	if _, e = os.Lstat(filepath.Join(evidence, "qualification.sock")); !os.IsNotExist(e) {
		t.Fatal("private socket survived")
	}
	if _, e = os.Lstat(filepath.Join(qualification.Directory(path), "in-progress")); e != nil {
		t.Fatal("admission fence missing")
	}
	if _, e = os.Lstat(filepath.Join(qualification.Directory(path), "qualified.json")); !os.IsNotExist(e) {
		t.Fatal("pending rows published")
	}
}

// Claim: private reservation expires with its context and teardown preserves a
// replacement path; an already-existing endpoint is never adopted or removed.
func TestPrivateSocketLifetime(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s, e := reserve(ctx, dir, qualification.Hash([]byte("fixture candidate")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := reserve(ctx, dir, qualification.Hash([]byte("fixture candidate"))); e == nil {
		t.Fatal("existing socket adopted")
	}
	cancel()
	_, e = s.listener.AcceptUnix()
	if e == nil {
		t.Fatal("expired socket accepted")
	}
	os.Remove(s.path)
	if os.WriteFile(s.path, []byte("replacement"), 0600) != nil {
		t.Fatal("replacement fixture")
	}
	s.close()
	if b, e := os.ReadFile(s.path); e != nil || string(b) != "replacement" {
		t.Fatal("replacement removed")
	}
}

// The shared test wrapper intentionally inherits its lock descriptor. Seal only
// this test process's extra descriptors and restore their original flags; no
// descriptor contents are read, closed or copied, and the wrapper keeps its lock.
func sealFixtureDescriptors(t *testing.T) {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil || fd < 3 {
			continue
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if e == unix.EBADF {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			if _, e := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags) })
		}
	}
}

// Claim: only fully executed green rows select 0; executed failure selects 1,
// while pending/missing environment stays 69. No row body is run by this test.
func TestRowExitContract(t *testing.T) {
	cases := qualification.Pending(qualification.Identity{}).Cases
	if resultCode(cases, nil) != 69 {
		t.Fatal("pending gained pass credit")
	}
	for n := range cases {
		cases[n].Positive.Executed = true
		cases[n].Positive.Verdict = "passed"
		cases[n].Positive.ExitCode = 0
		cases[n].Negative = cases[n].Positive
	}
	if resultCode(cases, nil) != 0 {
		t.Fatal("green aggregation failed")
	}
	cases[0].Negative.Verdict = "failed"
	cases[0].Negative.ExitCode = 1
	if resultCode(cases, nil) != 1 {
		t.Fatal("executed failure hidden")
	}
	if resultCode(cases, []string{"schema/1"}) != 69 {
		t.Fatal("missing environment hidden")
	}
}
