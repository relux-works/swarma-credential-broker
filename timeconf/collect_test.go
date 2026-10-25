//go:build linux

package timeconf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const goodCSV = "C0000201,192.0.2.1,3,1893553444.000000000,0.001,0.001,0.001,1.0,0.1,0.1,0.002,0.001,10.0,Normal\n"
const goodAuth = "192.0.2.1,NTS,1,15,256,60,0,0,8,100\n"

// CollectorEntry must run before the test harness for descriptor execution.
// Synthetic collector behavior lives in a separate, uninstrumented test helper.
func TestMain(m *testing.M) {
	CollectorEntry()
	code := m.Run()
	if collectorFixture.root != "" {
		if err := os.RemoveAll(collectorFixture.root); err != nil {
			fmt.Fprintln(os.Stderr, "collector fixture cleanup failed")
			code = 1
		}
	}
	os.Exit(code)
}

var collectorFixture struct {
	once sync.Once
	root string
	path string
	err  error
}

// Build once per test process, outside any consumption deadline. Explicitly
// disable race instrumentation: its process-exit delay is not collector work.
// The runner and provider remain race-instrumented in race test runs.
func collectorFixtureExecutable(t *testing.T) string {
	t.Helper()
	collectorFixture.once.Do(func() {
		collectorFixture.root, collectorFixture.err = os.MkdirTemp("", "collector-fixture-")
		if collectorFixture.err != nil {
			return
		}
		collectorFixture.path = filepath.Join(collectorFixture.root, "collector")
		goTool := os.Getenv("GO")
		if goTool == "" {
			goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, goTool, "build", "-p=1", "-race=false", "-o", collectorFixture.path, "./testdata/collector")
		if out, err := cmd.CombinedOutput(); err != nil {
			collectorFixture.err = fmt.Errorf("build collector fixture: %w: %s", err, out)
		}
	})
	if collectorFixture.err != nil {
		t.Fatal(collectorFixture.err)
	}
	return collectorFixture.path
}

func executableFixture(t *testing.T) string {
	t.Helper()
	dir := protectedTemp(t)
	in, err := os.Open(collectorFixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	path := filepath.Join(dir, "chronyc-fixture")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0500)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("fixture copy failed")
	}
	return path
}

// Claim: every CSV column is checked, and truncated/extra/nonfinite/malformed
// reports refuse instead of treating an otherwise valid prefix as confidence.
func TestTrackingParserNegativeAndControl(t *testing.T) {
	bad := map[int]string{0: "00000000", 1: "not/an/address", 2: "16", 3: "NaN", 4: "NaN", 5: "Inf", 6: "-1", 7: "1000001", 8: "-1000001", 9: "-1", 10: "-1", 11: "-1", 12: "NaN", 13: "unexpected"}
	for index, value := range bad {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			v := strings.Split(strings.TrimSpace(goodCSV), ",")
			v[index] = value
			if _, err := ParseTracking([]byte(strings.Join(v, ",") + "\n")); err == nil {
				t.Fatal("invalid tracking field accepted")
			}
			if _, err := ParseTracking([]byte(goodCSV)); err != nil {
				t.Fatal("valid tracking refused")
			}
		})
	}
	for _, value := range []string{"", goodCSV[:len(goodCSV)-1], goodCSV + goodCSV, strings.TrimSuffix(goodCSV, "\n") + ",extra\n", strings.Replace(goodCSV, "Normal", "NaN", 1), strings.Repeat("x", 65537), goodCSV + "\x00", goodCSV + "\n", "\n" + goodCSV, strings.Replace(goodCSV, "Normal", `"Normal"`, 1), strings.Replace(goodCSV, "0.001", "0x1p-10", 1)} {
		if _, err := ParseTracking([]byte(value)); err == nil {
			t.Fatal("malformed report accepted")
		}
	}
	v, err := ParseTracking([]byte(goodCSV))
	if err != nil || v.Stratum != 3 || v.Address != "192.0.2.1" || v.RootDelay != 0.002 {
		t.Fatal("positive report mismatch")
	}
}

// Claim: source directives require nts as an actual option, not a comment or
// option argument; hidden/dynamic/unrecognized sources are refused.
func TestNTSSourceConfiguration(t *testing.T) {
	for _, bad := range []string{"server time.example iburst\n", "pool time.example iburst # nts\n", "server time.example maxpoll nts\n", "server time.example nts mystery\n", "server time.example nts nts\n", "peer time.example nts\n", "refclock PHC /dev/example\n", "local stratum 8\n", "include /etc/example.conf\n", "sourcedir /etc/example\n", "confdir /etc/example\n", "server time.example nts\x00\n", "rtcsync extra\nserver time.example nts\n", "maxupdateskew NaN\nserver time.example nts\n"} {
		if _, err := ParseSources([]byte(bad)); err == nil {
			t.Fatal("non-NTS/unknown configuration accepted")
		}
	}
	for _, good := range []string{"server time.example nts iburst\n", "pool time.example nts maxsources 4 minpoll 6 maxpoll 10\n", "# comment\ndriftfile /var/lib/chrony/drift\nrtcsync\nserver time.example iburst nts # comment\n"} {
		v, err := ParseSources([]byte(good))
		if err != nil || !v.AllNTS || v.Count != 1 {
			t.Fatal("valid NTS configuration refused")
		}
	}
}

// Claim: optional authentication rejects non-NTS rows, missing cookies, NAKs,
// failed establishment, duplicate/extra fields and malformed output.
func TestAuthenticationParser(t *testing.T) {
	for _, bad := range []string{strings.Replace(goodAuth, ",NTS,", ",SK,", 1), strings.Replace(goodAuth, ",8,100", ",0,100", 1), strings.Replace(goodAuth, ",0,0,8,", ",0,1,8,", 1), strings.Replace(goodAuth, ",0,0,8,", ",2,0,8,", 1), goodAuth + goodAuth, strings.TrimSuffix(goodAuth, "\n") + ",extra\n", "501 Not authorised\n", goodAuth[:len(goodAuth)-1]} {
		if _, err := ParseAuthData([]byte(bad)); err == nil {
			t.Fatal("invalid authdata accepted")
		}
	}
	v, err := ParseAuthData([]byte(goodAuth))
	if err != nil || !v.Addresses["192.0.2.1"] {
		t.Fatal("NTS authdata control refused")
	}
}

// Claim: protected policy/config reads reject links, hardlinks, public policy,
// writable files and writable ancestors; the private regular control loads.
func TestProtectedPolicyAndConfiguration(t *testing.T) {
	dir := protectedTemp(t)
	path := filepath.Join(dir, "policy.json")
	p := testPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if _, err := LoadPolicy(path, uint32(os.Geteuid())); err != nil {
		t.Fatal("private policy refused", err)
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("chmod failed")
	}
	if _, err := LoadPolicy(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("public policy accepted")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("chmod failed")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink failed")
	}
	if _, err := LoadPolicy(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("policy link followed")
	}
	if os.Link(path, filepath.Join(dir, "hardlink")) != nil {
		t.Fatal("hardlink failed")
	}
	if _, err := LoadPolicy(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(filepath.Join(dir, "hardlink"))
	if os.Chmod(dir, 0777) != nil {
		t.Fatal("chmod failed")
	}
	if _, err := LoadPolicy(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	os.Chmod(dir, 0700)
	for _, bad := range [][]byte{append([]byte(`{"source":"off",`), b[1:]...), append([]byte(`{"extra":1,`), b[1:]...), []byte(`{"source":"chrony-nts-config"}`), []byte(`null`), append(b, []byte(` {}`)...), []byte(`{"source":null}`)} {
		if _, err := DecodePolicy(bad); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if _, err := DecodePolicy([]byte(`{"source":"off"}`)); err != nil {
		t.Fatal("off policy refused")
	}
	for _, field := range []string{"MaxSyncAge", "MaxUncertainty", "MaxOffset", "MaxRootDistance", "AuthorityWindow", "StepTolerance", "Timeout", "MaxOutputBytes"} {
		q := p
		reflect.ValueOf(&q).Elem().FieldByName(field).SetInt(0)
		if q.Validate() == nil {
			t.Fatal("missing bound accepted", field)
		}
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.AuthorityWindow = p.MaxSyncAge + time.Nanosecond }, func(p *Policy) { p.Source = "unknown" }, func(p *Policy) { p.SourceFiles = append(p.SourceFiles, p.SourceFiles[0]) }, func(p *Policy) { p.Chronyc = "relative" }, func(p *Policy) { p.MaxOutputBytes = 65537 }} {
		q := p
		change(&q)
		if q.Validate() == nil {
			t.Fatal("invalid bound accepted")
		}
	}
}

type runnerFixture struct {
	output   []byte
	err      error
	named    []byte
	namedErr error
	auth     []byte
	authErr  error
	calls    [][]string
}

func (r *runnerFixture) Run(_ context.Context, _ string, args []string, _ time.Duration, _ int) ([]byte, error) {
	r.calls = append(r.calls, args)
	if len(args) == 3 && args[1] == "authdata" && r.auth != nil {
		return r.auth, r.authErr
	}
	if len(args) == 3 && args[1] == "-N" && r.named != nil {
		return r.named, r.namedErr
	}
	return r.output, r.err
}

// Claim: the real collector protects and parses source configuration before
// executing the fixed tracking argv; runtime/parse failures never return a prefix.
func TestSystemCollectorFailureAndNTS(t *testing.T) {
	p := testPolicy()
	p.Chronyc = executableFixture(t)
	path := filepath.Join(protectedTemp(t), "sources.conf")
	p.SourceFiles = []string{path}
	runner := &runnerFixture{output: []byte(goodCSV)}
	collector := SystemCollector{Runner: runner}
	for _, bad := range []string{"server time.example\n", "include /etc/example.conf\n"} {
		if os.WriteFile(path, []byte(bad), 0600) != nil {
			t.Fatal("write failed")
		}
		if _, err := collector.Collect(context.Background(), p); err == nil || len(runner.calls) != 0 {
			t.Fatal("invalid NTS config reached command")
		}
	}
	if os.WriteFile(path, []byte("server 192.0.2.1 nts\n"), 0600) != nil {
		t.Fatal("write failed")
	}
	for _, bad := range []struct {
		out []byte
		err error
	}{{[]byte(goodCSV), errors.New("exit")}, {[]byte(goodCSV), context.DeadlineExceeded}, {[]byte("invalid\n"), nil}, {[]byte(strings.Repeat("x", 5000)), nil}} {
		runner.output, runner.err = bad.out, bad.err
		if _, err := collector.Collect(context.Background(), p); err == nil {
			t.Fatal("collector failure trusted")
		}
	}
	runner.output = []byte(goodCSV)
	runner.err = nil
	v, err := collector.Collect(context.Background(), p)
	if err != nil || !v.Sources.AllNTS || v.Sources.Count != 1 || !reflect.DeepEqual(runner.calls[len(runner.calls)-1], []string{"-c", "tracking"}) {
		t.Fatal("collector control failed", err)
	}
	if os.Chmod(path, 0666) != nil {
		t.Fatal("chmod failed")
	}
	if _, err := collector.Collect(context.Background(), p); err == nil {
		t.Fatal("writable config accepted")
	}
}

// Claim: actual child exit, timeout, stderr and output overflow are failures,
// while the same fixture succeeds with exactly the minimal production environment.
func TestBoundedCommandExecution(t *testing.T) {
	path := executableFixture(t)
	scenario := filepath.Join(filepath.Dir(path), "scenario")
	for _, name := range []string{"exit", "timeout", "oversized", "stderr", "environment"} {
		t.Run(name, func(t *testing.T) {
			if os.WriteFile(scenario, []byte(name), 0600) != nil {
				t.Fatal("scenario write failed")
			}
			timeout := 2 * time.Second
			if name == "timeout" {
				timeout = 50 * time.Millisecond
			}
			out, err := (SystemRunner{}).Run(context.Background(), path, []string{"-c", "tracking"}, timeout, 4096)
			if name == "environment" {
				if err != nil || !bytes.Equal(out, []byte(goodCSV)) {
					t.Fatal("minimal environment control refused", err)
				}
				return
			}
			if name == "stderr" {
				if err != nil {
					t.Fatal("fixture failed before parsing")
				}
				if _, err := ParseTracking(out); err == nil {
					t.Fatal("diagnostic parsed as tracking")
				}
			} else if !errors.Is(err, ErrUnavailable) || len(out) != 0 {
				t.Fatal("failed process supplied output")
			}
		})
	}
}

func protectedTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("protect fixture directory")
	}
	return dir
}

// Claim: the protected service loader rejects every loosened upper bound and
// source/recovery substitution; an equal or stricter override loads successfully.
func TestServicePolicyRestrictions(t *testing.T) {
	shared := testPolicy()
	shared.BackwardTolerance = time.Millisecond
	path := filepath.Join(protectedTemp(t), "service-policy.json")
	load := func(p Policy) error {
		t.Helper()
		b, err := json.Marshal(p)
		if err != nil || os.WriteFile(path, b, 0600) != nil {
			t.Fatal("write service policy")
		}
		_, err = LoadServicePolicy(path, uint32(os.Geteuid()), shared)
		return err
	}
	for _, field := range []string{"MaxSyncAge", "MaxUncertainty", "MaxOffset", "MaxRootDistance", "AuthorityWindow", "StepTolerance", "BackwardTolerance", "Timeout", "MaxOutputBytes"} {
		t.Run(field, func(t *testing.T) {
			q := shared
			v := reflect.ValueOf(&q).Elem().FieldByName(field)
			v.SetInt(v.Int() + 1)
			if load(q) == nil {
				t.Fatal("looser override accepted")
			}
			if load(shared) != nil {
				t.Fatal("equal control refused")
			}
		})
	}
	q := shared
	q.BackwardTolerance = 0
	q.MaxOffset /= 2
	q.MaxUncertainty /= 2
	q.Resync = "operator"
	if load(q) != nil {
		t.Fatal("stricter control refused")
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.Source = "unknown" }, func(p *Policy) { p.Chronyc = "/usr/local/bin/chronyc" }, func(p *Policy) { p.SourceFiles = []string{"/etc/example.conf"} }} {
		q = shared
		change(&q)
		if load(q) == nil {
			t.Fatal("shared authority replaced")
		}
	}
	shared.Resync = "operator"
	q = shared
	q.Resync = "new-authenticated-sync"
	if load(q) == nil {
		t.Fatal("recovery loosened")
	}
	if load(Policy{Source: Off}) != nil {
		t.Fatal("service cannot close")
	}
	shared = Policy{Source: Off}
	if load(testPolicy()) == nil {
		t.Fatal("service enabled shared off")
	}
	b, _ := json.Marshal(testPolicy())
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	delete(raw, "backward_tolerance_ns")
	b, _ = json.Marshal(raw)
	if _, err := DecodePolicy(b); err == nil {
		t.Fatal("missing explicit backward bound accepted")
	}
}

// Claim: the selected reference must map to an NTS configuration entry by
// numeric address or chronyd's original name; PTR/DNS guesses, absent sources,
// a changed reference tuple and failed original-name collection cannot admit it.
func TestSelectedNTSAssociation(t *testing.T) {
	exe := executableFixture(t)
	path := filepath.Join(protectedTemp(t), "sources.conf")
	named := []byte(strings.Replace(goodCSV, "192.0.2.1", "Time.Example.", 1))
	for _, tc := range []struct {
		name, config string
		named        []byte
		err          error
		ok           bool
	}{
		{"address", "server 192.0.2.1 nts\n", nil, nil, true},
		{"name", "pool time.example nts\n", named, nil, true},
		{"unconfigured", "server other.example nts\n", named, nil, false},
		{"changed-reference", "server time.example nts\n", []byte(strings.Replace(string(named), "1893553444", "1893553443", 1)), nil, false},
		{"name-command-error", "server time.example nts\n", named, context.DeadlineExceeded, false},
		{"name-extra-field", "server time.example nts\n", []byte(strings.TrimSuffix(string(named), "\n") + ",extra\n"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.WriteFile(path, []byte(tc.config), 0600) != nil {
				t.Fatal("source fixture write")
			}
			r := &runnerFixture{output: []byte(goodCSV), named: tc.named, namedErr: tc.err}
			policy := testPolicy()
			policy.Chronyc = exe
			policy.SourceFiles = []string{path}
			clock := &fakeClock{point: ClockPoint{Now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Elapsed: time.Hour, Boot: "fixture-boot"}}
			p, err := New(policy, SystemCollector{Runner: r}, clock, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ok {
				trusted(t, p)
			} else {
				refused(t, p)
			}
			want := []string{"-c", "tracking"}
			if tc.name != "address" {
				want = []string{"-c", "-N", "tracking"}
			}
			if !reflect.DeepEqual(r.calls[len(r.calls)-1], want) {
				t.Fatal("selection command argv changed")
			}
		})
	}
}

// Claim: option B uses the fixed authdata argv and requires successful parsed
// authentication for the selected address; option A cannot satisfy that gate.
func TestSystemCollectorAuthenticationMode(t *testing.T) {
	policy := testPolicy()
	policy.Source = NTSAuthData
	policy.Chronyc = executableFixture(t)
	path := filepath.Join(protectedTemp(t), "sources.conf")
	policy.SourceFiles = []string{path}
	if os.WriteFile(path, []byte("server 192.0.2.1 nts\n"), 0600) != nil {
		t.Fatal("source fixture write")
	}
	r := &runnerFixture{output: []byte(goodCSV), auth: []byte(goodAuth)}
	clock := &fakeClock{point: ClockPoint{Now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Elapsed: time.Hour, Boot: "fixture-boot"}}
	p, err := New(policy, SystemCollector{Runner: r}, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.authErr = ErrUnavailable
	refused(t, p)
	r.authErr = nil
	r.auth = []byte(strings.Replace(goodAuth, "192.0.2.1", "192.0.2.2", 1))
	refused(t, p)
	r.auth = []byte(goodAuth)
	trusted(t, p)
	if !reflect.DeepEqual(r.calls[len(r.calls)-1], []string{"-c", "authdata", "-a"}) {
		t.Fatal("authentication argv changed")
	}
	shared := testPolicy()
	if _, err := ServicePolicy(shared, policyWithSource(shared, NTSAuthData)); err != nil {
		t.Fatal("stronger authentication override refused")
	}
	shared.Source = NTSAuthData
	if _, err := ServicePolicy(shared, policyWithSource(shared, NTSConfig)); err == nil {
		t.Fatal("authentication override weakened")
	}
}
func policyWithSource(p Policy, s Source) Policy { p.Source = s; return p }

// Claim: the explicit uncertainty cap survives protected shared/service policy
// loading, rejects omission, malformed values and loosening, and permits a
// smaller service cap. No fallback infers the cap from measured error limits.
func TestUncertaintyPolicyContract(t *testing.T) {
	shared := platformTestPolicy()
	b, err := json.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `"max_uncertainty_ns":1500000000`
	if !bytes.Contains(b, []byte(canonical)) {
		t.Fatal("shared cap not encoded explicitly")
	}
	for name, replacement := range map[string]string{
		"zero":      `"max_uncertainty_ns":0`,
		"negative":  `"max_uncertainty_ns":-1`,
		"above":     `"max_uncertainty_ns":1500000001`,
		"null":      `"max_uncertainty_ns":null`,
		"fraction":  `"max_uncertainty_ns":1.5`,
		"alias":     `"MAX_UNCERTAINTY_NS":1500000000`,
		"duplicate": canonical + `,` + canonical,
	} {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Replace(b, []byte(canonical), []byte(replacement), 1)
			if _, err := DecodePolicy(raw); !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid uncertainty cap accepted", err)
			}
		})
	}
	if _, err := DecodePolicy(bytes.Replace(b, []byte(canonical+","), nil, 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing uncertainty cap accepted", err)
	}
	path := filepath.Join(protectedTemp(t), "confidence-policy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPolicy(path, uint32(os.Geteuid()))
	if err != nil || loaded.MaxUncertainty != 1500*time.Millisecond || loaded.MaxSyncAge != 2048*time.Second {
		t.Fatal("shared bounds changed while loading", err)
	}
	q := loaded
	q.MaxUncertainty = time.Second
	raw, err := json.Marshal(q)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("service fixture write failed")
	}
	service, err := LoadServicePolicy(path, uint32(os.Geteuid()), loaded)
	if err != nil || service.MaxUncertainty != time.Second {
		t.Fatal("stricter cap refused", err)
	}
	if _, err := ServicePolicy(service, loaded); !errors.Is(err, ErrUnavailable) {
		t.Fatal("service loosened its uncertainty cap", err)
	}
	if _, err := DecodePolicy([]byte(`{"source":"off","max_uncertainty_ns":1}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("off policy retained an authority bound", err)
	}
}

// Claim: reference epochs reject nonfinite, exponent and out-of-range values;
// the nearby valid report preserves all nine fractional timestamp digits.
func TestReferenceTimestampParserBoundaries(t *testing.T) {
	for _, reference := range []string{"NaN", "Inf", "+Inf", "-Inf", "1e1000", "0", "-1", "253402300800", "1893553444.0000000001"} {
		report := strings.Replace(goodCSV, "1893553444.000000000", reference, 1)
		if _, err := ParseTracking([]byte(report)); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid reference timestamp accepted", err)
		}
	}
	report := strings.Replace(goodCSV, "1893553444.000000000", "1893553444.999999999", 1)
	v, err := ParseTracking([]byte(report))
	if err != nil || v.Reference.Unix() != 1893553444 || v.Reference.Nanosecond() != 999999999 {
		t.Fatal("nanosecond reference lost", err)
	}
}
