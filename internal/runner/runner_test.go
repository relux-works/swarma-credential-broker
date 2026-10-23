//go:build linux

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var fakePath, supervisorPath, buildDir string

func TestMain(m *testing.M) {
	// A traced stop test reuses this parent process's already-built helpers.
	// This is an explicit child-only invocation, not an ambient build override.
	if len(os.Args) > 4 && os.Args[1] == "--fixture-tools" {
		fakePath, supervisorPath = os.Args[2], os.Args[3]
		os.Args = append(os.Args[:1], os.Args[4:]...)
		os.Exit(m.Run())
	}
	if len(os.Args) > 1 && os.Args[1] == "--fixture-parent" {
		fixtureParent(os.Args[2:])
		return
	}
	var err error
	buildDir, err = os.MkdirTemp("", "runner-build-")
	if err != nil {
		panic(err)
	}
	fakePath = filepath.Join(buildDir, "fake-app-server")
	supervisorPath = filepath.Join(buildDir, "runner")
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	for _, b := range []struct{ out, pkg string }{{fakePath, "./testdata/appserver"}, {supervisorPath, "../../cmd/swarma-credential-broker"}} {
		cmd := exec.Command(goTool, "build", "-p=2", "-o", b.out, b.pkg)
		data, e := cmd.CombinedOutput()
		if e != nil {
			fmt.Fprintf(os.Stderr, "helper build %s: %v\n%s", b.pkg, e, data)
			os.RemoveAll(buildDir)
			os.Exit(1)
		}
		if e = os.Chmod(b.out, 0755); e != nil {
			panic(e)
		}
	}
	code := m.Run()
	os.RemoveAll(buildDir)
	os.Exit(code)
}

type fakeAuthority struct {
	p      Policy
	calls  int
	change bool
}

func (a *fakeAuthority) Resolve(context.Context, Options) (Policy, error) {
	a.calls++
	p := a.p
	if a.change && a.calls > 1 {
		p.PolicyGeneration++
	}
	return p, nil
}

type fakeBroker struct {
	onRenew                                               func()
	mu                                                    sync.Mutex
	p                                                     Policy
	home                                                  string
	calls                                                 []string
	renewals                                              []RenewRequest
	transferred                                           [][]byte
	verifyErr, helloErr, requestErr, renewErr, releaseErr error
	mismatch, extend, slow, ignoreCancel                  bool
	beforeRequest                                         func()
	closed                                                chan struct{}
	once                                                  sync.Once
	expiry                                                time.Time
}

func (b *fakeBroker) note(s string) { b.mu.Lock(); defer b.mu.Unlock(); b.calls = append(b.calls, s) }
func (b *fakeBroker) VerifyServer(context.Context, uint32) error {
	b.note("verify")
	return b.verifyErr
}
func (b *fakeBroker) Hello(context.Context, HelloRequest) (HelloResult, error) {
	b.note("hello")
	return HelloResult{1, ProtocolProfile, b.p.UID, b.p.PolicyGeneration}, b.helloErr
}
func (b *fakeBroker) lease(token string) Lease {
	l := Lease{ID: "lease", Account: b.p.Account, Harness: "codex_cli", Channel: "external-token", ChatGPTAccountID: b.p.ChatGPTAccountID, Token: []byte(token), TokenExpiresAt: time.Now().Add(time.Hour), AuthorizedUntil: b.expiry, Renewable: true}
	b.mu.Lock()
	b.transferred = append(b.transferred, l.Token)
	b.mu.Unlock()
	return l
}

const canaryA = "CANARY_access_A_6f34a9a2"
const canaryB = "CANARY_access_B_22a37ba6"
const canaryC = "CANARY_access_C_18c23af8"

func (b *fakeBroker) Request(_ context.Context, r LeaseRequest) (Lease, error) {
	b.note("request")
	if _, err := os.Stat(filepath.Join(b.home, "server-pid")); err == nil {
		panic("harness preceded lease")
	}
	if r.Harness != "codex_cli" || r.Channel != "external-token" || r.Account != b.p.Account || r.Profile != b.p.Profile || r.CredentialBinding.Digest != b.p.BindingDigest || r.LaunchID == "" || r.Executor.Version != Version {
		panic("invalid lease request")
	}
	if b.beforeRequest != nil {
		b.beforeRequest()
	}
	if b.requestErr != nil {
		return Lease{}, b.requestErr
	}
	return b.lease(canaryA), nil
}
func (b *fakeBroker) Renew(ctx context.Context, r RenewRequest) (Lease, error) {
	b.note("renew")
	if b.onRenew != nil {
		b.onRenew()
	}
	b.mu.Lock()
	b.renewals = append(b.renewals, r)
	index := len(b.renewals)
	b.mu.Unlock()
	if b.slow {
		if b.ignoreCancel {
			<-ctx.Done()
			time.Sleep(30 * time.Millisecond)
		} else {
			select {
			case <-ctx.Done():
				return Lease{}, ctx.Err()
			case <-b.closed:
				return Lease{}, errors.New("closed")
			}
		}
	}
	if b.renewErr != nil {
		return Lease{}, b.renewErr
	}
	token := canaryB
	if index > 1 {
		token = canaryC
	}
	l := b.lease(token)
	if b.mismatch {
		l.ChatGPTAccountID = "wrong-account"
	}
	if b.extend {
		l.AuthorizedUntil = l.AuthorizedUntil.Add(time.Hour)
	}
	return l, nil
}
func (b *fakeBroker) Release(_ context.Context, id string) error {
	b.note("release")
	if id != "lease" {
		panic("wrong release")
	}
	return b.releaseErr
}
func (b *fakeBroker) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

type fixture struct {
	t                  *testing.T
	root, home, output string
	o                  Options
	d                  Dependencies
	a                  *fakeAuthority
	b                  *fakeBroker
	out, err           bytes.Buffer
}

func newFixture(t *testing.T, s map[string]any) *fixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	must(t, os.Mkdir(home, 0700))
	must(t, os.Mkdir(work, 0700))
	data, e := json.Marshal(s)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(home, "scenario.json"), data, 0600))
	o := Options{Account: "account", Profile: "profile", LaunchHome: home, Cwd: work, PromptStdin: true, Model: "fixture-model", ReasoningEffort: "medium", Output: filepath.Join(root, "result"), Timeout: 20 * time.Second}
	raw, e := os.ReadFile(fakePath)
	must(t, e)
	fp, e := inspectSources(o, nil)
	must(t, e)
	p := Policy{Account: o.Account, Profile: o.Profile, Endpoint: "https://example.invalid/inference", Executable: fakePath, ExecutableSHA256: digest(raw), Release: "codex-cli 0.163.0", SchemaSHA256: strings.Repeat("a", 64), ChatGPTAccountID: "vendor-account", ConfigSHA256: fp, BindingDigest: strings.Repeat("b", 64), UID: uint32(os.Getuid()), BrokerUID: uint32(os.Getuid()), PolicyGeneration: 1, Qualified: true, Catalog: map[string][]string{o.Model: {"medium"}}}
	a := &fakeAuthority{p: p}
	b := &fakeBroker{p: p, home: home, closed: make(chan struct{}), expiry: time.Now().Add(time.Hour).Truncate(time.Second)}
	f := &fixture{t: t, root: root, home: home, output: o.Output, o: o, a: a, b: b}
	f.d = Dependencies{Authority: a, Connect: func(context.Context) (BrokerClient, error) { return b, nil }, Supervisor: supervisorPath}
	return f
}
func (f *fixture) args() []string {
	return []string{"--account", f.o.Account, "--profile", f.o.Profile, "--launch-home", f.home, "--prompt-stdin", "--model", f.o.Model, "--reasoning-effort", f.o.ReasoningEffort, "--output-last-message", f.output, "--cwd", f.o.Cwd, "--timeout", fmt.Sprint(f.o.Timeout.Seconds())}
}
func (f *fixture) run() int {
	return Command(context.Background(), f.args(), IO{strings.NewReader("prompt"), &f.out, &f.err}, f.d)
}
func (f *fixture) noLease() {
	f.t.Helper()
	if len(f.b.calls) > 0 {
		f.t.Fatalf("unexpected broker calls: %v", f.b.calls)
	}
}
func (f *fixture) events() []map[string]any {
	f.t.Helper()
	data, e := os.ReadFile(filepath.Join(f.home, "events.jsonl"))
	must(f.t, e)
	var events []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var v map[string]any
		must(f.t, json.Unmarshal(line, &v))
		events = append(events, v)
	}
	return events
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func requireStatus(t *testing.T, got, want int, diagnostic string) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d; %s", got, want, diagnostic)
	}
}
func assertAbsent(t *testing.T, path string) {
	t.Helper()
	_, e := os.Lstat(path)
	if !os.IsNotExist(e) {
		t.Fatalf("expected absent %s: %v", filepath.Base(path), e)
	}
}

// Missing/ambiguous selectors, malformed prompt bytes and unqualified resume
// fail before leasing; a valid input exercises the adjacent successful path.
func TestInputRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]string) []string
		input  string
		want   int
	}{
		{"missing-source", func(a []string) []string { return removeArg(a, "--prompt-stdin", false) }, "ok", 64},
		{"both-sources", func(a []string) []string { return append(a, "--prompt-file", "absent") }, "ok", 64},
		{"unknown", func(a []string) []string { return append(a, "--unknown") }, "ok", 64},
		{"zero-timeout", func(a []string) []string { return setArg(a, "--timeout", "0") }, "ok", 64},
		{"negative-timeout", func(a []string) []string { return setArg(a, "--timeout", "-1") }, "ok", 64},
		{"nan-timeout", func(a []string) []string { return setArg(a, "--timeout", "NaN") }, "ok", 64},
		{"infinite-timeout", func(a []string) []string { return setArg(a, "--timeout", "Inf") }, "ok", 64},
		{"missing-model", func(a []string) []string { return removeArg(a, "--model", true) }, "ok", 64},
		{"missing-effort", func(a []string) []string { return removeArg(a, "--reasoning-effort", true) }, "ok", 64},
		{"missing-output", func(a []string) []string { return removeArg(a, "--output-last-message", true) }, "ok", 64},
		{"unsupported-effort", func(a []string) []string { return setArg(a, "--reasoning-effort", "unknown") }, "ok", 64},
		{"unsupported-model", func(a []string) []string { return setArg(a, "--model", "unknown") }, "ok", 64},
		{"resume", func(a []string) []string { return append(a, "--resume", "thread") }, "ok", 69},
		{"invalid-utf8", func(a []string) []string { return a }, string([]byte{255}), 64},
		{"oversize", func(a []string) []string { return a }, strings.Repeat("x", MaxPrompt+1), 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			code := Command(context.Background(), tc.change(f.args()), IO{strings.NewReader(tc.input), &f.out, &f.err}, f.d)
			requireStatus(t, code, tc.want, f.err.String())
			f.noLease()
			assertAbsent(t, f.output)
		})
	}
	t.Run("valid", func(t *testing.T) { f := newFixture(t, nil); requireStatus(t, f.run(), 0, f.err.String()) })
}
func removeArg(a []string, key string, value bool) []string {
	for i, v := range a {
		if v == key {
			n := 1
			if value {
				n = 2
			}
			return append(a[:i], a[i+n:]...)
		}
	}
	return a
}
func setArg(a []string, key, value string) []string {
	for i, v := range a {
		if v == key {
			a[i+1] = value
			return a
		}
	}
	panic("missing flag")
}

// Prompt-file symlinks and nonregular inputs are never followed; a regular
// UTF-8 file and exactly 1 MiB stdin remain valid controls.
func TestPromptFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "invalid", "regular"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			path := filepath.Join(f.root, "prompt")
			switch kind {
			case "symlink":
				must(t, os.Symlink("missing", path))
			case "directory":
				must(t, os.Mkdir(path, 0700))
			case "invalid":
				must(t, os.WriteFile(path, []byte{255}, 0600))
			default:
				must(t, os.WriteFile(path, []byte("hello"), 0600))
			}
			a := removeArg(f.args(), "--prompt-stdin", false)
			a = append(a, "--prompt-file", path)
			want := 64
			if kind == "regular" {
				want = 0
			}
			code := Command(context.Background(), a, IO{nil, &f.out, &f.err}, f.d)
			requireStatus(t, code, want, f.err.String())
			if want != 0 {
				f.noLease()
			}
		})
	}
	f := newFixture(t, nil)
	code := Command(context.Background(), f.args(), IO{strings.NewReader(strings.Repeat("x", MaxPrompt)), &f.out, &f.err}, f.d)
	requireStatus(t, code, 0, f.err.String())
}

// Every reserved variable conflicts even when explicitly empty; the clean
// environment control leases successfully without clearing the caller's env.
func TestReservedVariables(t *testing.T) {
	for key := range reserved {
		for _, value := range []string{"", "synthetic"} {
			t.Run(key+value, func(t *testing.T) {
				f := newFixture(t, nil)
				f.d.Environment = []string{key + "=" + value}
				requireStatus(t, f.run(), 69, f.err.String())
				if !strings.Contains(f.err.String(), "credential_source_conflict") {
					t.Fatal(f.err.String())
				}
				f.noLease()
			})
		}
	}
	t.Run("clean", func(t *testing.T) {
		f := newFixture(t, nil)
		f.d.Environment = []string{"UNRELATED=value"}
		requireStatus(t, f.run(), 0, f.err.String())
	})
}

// Auth paths are detected by metadata only (including dangling symlinks);
// unknown/invalid config is unavailable, never silently treated as absent.
func TestSources(t *testing.T) {
	for _, tc := range []struct {
		name, config, code string
		auth, link         bool
	}{
		{"auth-path", "", "credential_source_conflict", true, false},
		{"auth-link", "", "credential_source_conflict", false, true},
		{"provider-env", "[model_providers.custom]\nenv_key='KEY'", "credential_source_conflict", false, false},
		{"provider-header", "[model_providers.custom]\nhttp_headers={Authorization='synthetic'}", "credential_source_conflict", false, false},
		{"provider-env-header", "[model_providers.custom]\nenv_http_headers={Authorization='KEY'}", "credential_source_conflict", false, false},
		{"helper", "auth_helper='helper'", "credential_source_conflict", false, false},
		{"issuer", "login_issuer='https://example.invalid'", "credential_source_conflict", false, false},
		{"hook", "hooks=[]", "credential_source_conflict", false, false},
		{"mcp", "[mcp_servers.x]\ncommand='helper'", "credential_source_conflict", false, false},
		{"native-store", "cli_auth_credentials_store='file'", "credential_source_conflict", false, false},
		{"unknown", "unreviewed=true", "credential_injection_unavailable", false, false},
		{"malformed", "[", "credential_injection_unavailable", false, false},
		{"clean", "cli_auth_credentials_store='ephemeral'", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			if tc.auth {
				must(t, os.WriteFile(filepath.Join(f.home, "auth.json"), []byte("unreadable-fixture"), 0000))
			}
			if tc.link {
				must(t, os.Symlink("missing", filepath.Join(f.home, "auth.json")))
			}
			if tc.config != "" {
				must(t, os.WriteFile(filepath.Join(f.home, "config.toml"), []byte(tc.config), 0600))
			}
			if tc.code == "" {
				fp, e := inspectSources(f.o, nil)
				must(t, e)
				f.a.p.ConfigSHA256 = fp
				f.b.p.ConfigSHA256 = fp
				requireStatus(t, f.run(), 0, f.err.String())
			} else {
				requireStatus(t, f.run(), 69, f.err.String())
				if !strings.Contains(f.err.String(), tc.code) {
					t.Fatal(f.err.String())
				}
				f.noLease()
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		f := newFixture(t, nil)
		path := filepath.Join(f.home, "config.toml")
		must(t, os.WriteFile(path, []byte(""), 0000))
		defer os.Chmod(path, 0600)
		requireStatus(t, f.run(), 69, f.err.String())
		if !strings.Contains(f.err.String(), "credential_injection_unavailable") {
			t.Fatal(f.err.String())
		}
		f.noLease()
	})
	t.Run("cwd-source", func(t *testing.T) {
		f := newFixture(t, nil)
		must(t, os.Mkdir(filepath.Join(f.o.Cwd, ".codex"), 0700))
		must(t, os.WriteFile(filepath.Join(f.o.Cwd, ".codex", "config.toml"), []byte("auth_helper='helper'"), 0600))
		requireStatus(t, f.run(), 69, f.err.String())
		f.noLease()
	})
}

// Unqualified/drifted releases are denied before any lease; a qualified fake
// tuple must also match the executable's actual version and protected identity.
func TestQualification(t *testing.T) {
	for _, kind := range []string{"unqualified", "digest", "schema", "release", "version", "binding", "qualified"} {
		t.Run(kind, func(t *testing.T) {
			s := map[string]any{}
			if kind == "version" {
				s["Version"] = "codex-cli 0.162.0"
			}
			f := newFixture(t, s)
			switch kind {
			case "unqualified":
				f.a.p.Qualified = false
			case "digest":
				f.a.p.ExecutableSHA256 = strings.Repeat("0", 64)
			case "schema":
				f.a.p.SchemaSHA256 = ""
			case "release":
				f.a.p.Release = "codex-cli 0.162.0"
			case "binding":
				f.a.p.Account = "other"
			}
			want := 69
			if kind == "qualified" {
				want = 0
			}
			requireStatus(t, f.run(), want, f.err.String())
			if want != 0 {
				f.noLease()
			}
		})
	}
}

// Failed/changed output destinations preserve old content, remove staging
// files and refuse publication; successful publication has mode 0600.
func TestOutputAtomicity(t *testing.T) {
	for _, kind := range []string{"symlink", "unwritable", "changed-after-lease", "success"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			old := []byte("old-output")
			must(t, os.WriteFile(f.output, old, 0644))
			switch kind {
			case "symlink":
				must(t, os.Remove(f.output))
				must(t, os.Symlink("missing", f.output))
			case "unwritable":
				must(t, os.Chmod(f.root, 0500))
				defer os.Chmod(f.root, 0700)
			case "changed-after-lease":
				f.b.beforeRequest = func() { must(t, os.Rename(f.output, f.output+".old")); must(t, os.Symlink("missing", f.output)) }
			}
			want := 75
			if kind == "success" {
				want = 0
			}
			requireStatus(t, f.run(), want, f.err.String())
			if kind == "symlink" || kind == "unwritable" {
				f.noLease()
			}
			if kind == "success" {
				b, e := os.ReadFile(f.output)
				must(t, e)
				if string(b) != "answer" {
					t.Fatal(string(b))
				}
				info, e := os.Stat(f.output)
				must(t, e)
				if info.Mode().Perm() != 0600 {
					t.Fatal(info.Mode())
				}
			}
			if kind == "changed-after-lease" {
				b, e := os.ReadFile(f.output + ".old")
				must(t, e)
				if !bytes.Equal(b, old) {
					t.Fatal("old output changed")
				}
			}
			matches, e := filepath.Glob(filepath.Join(f.root, ".run-codex-output-*"))
			must(t, e)
			if len(matches) != 0 {
				t.Fatal("staging output leaked")
			}
		})
	}
}

// Initialization and terminal vendor failures never publish a partial result;
// only a matching completed turn, verified teardown and release produce zero.
func TestLifecycleStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    map[string]any
		want int
	}{
		{"initialize", map[string]any{"InitFail": true}, 69}, {"login", map[string]any{"LoginFail": true}, 69},
		{"failed", map[string]any{"Status": "failed"}, 1}, {"interrupted", map[string]any{"Status": "interrupted"}, 1},
		{"completed", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.s)
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			requireStatus(t, f.run(), tc.want, f.err.String())
			if tc.want != 0 {
				b, e := os.ReadFile(f.output)
				must(t, e)
				if string(b) != "old" {
					t.Fatal("failed run published output")
				}
			}
			if !reflect.DeepEqual(f.b.calls[:3], []string{"verify", "hello", "request"}) || f.b.calls[len(f.b.calls)-1] != "release" {
				t.Fatal(f.b.calls)
			}
			assertAbsent(t, filepath.Join(f.home, "auth.json"))
			assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			for _, b := range f.b.transferred {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("owned token buffer retained")
				}
			}
		})
	}
}

// Peer/hello refusal cannot lease, and policy/source drift between leasing
// and exec releases without starting the app-server.
func TestAdmissionAndRecheck(t *testing.T) {
	for _, kind := range []string{"peer", "hello", "request", "policy-drift", "source-drift"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			switch kind {
			case "peer":
				f.b.verifyErr = errors.New("synthetic")
			case "hello":
				f.b.helloErr = refuse("version_unsupported", 69)
			case "request":
				f.b.requestErr = refuse("lease_not_authorised", 69)
			case "policy-drift":
				f.a.change = true
			case "source-drift":
				f.b.beforeRequest = func() {
					must(t, os.WriteFile(filepath.Join(f.home, "config.toml"), []byte("auth_helper='helper'"), 0600))
				}
			}
			requireStatus(t, f.run(), 69, f.err.String())
			assertAbsent(t, filepath.Join(f.home, "server-pid"))
			if strings.HasSuffix(kind, "drift") && f.b.calls[len(f.b.calls)-1] != "release" {
				t.Fatal(f.b.calls)
			}
		})
	}
}

// All headless approval variants are denied with schema-valid results; the
// server continues to a completed turn without terminal interaction.
func TestApprovalDenial(t *testing.T) {
	f := newFixture(t, map[string]any{"Approvals": []string{"item/commandExecution/requestApproval", "item/fileChange/requestApproval", "execCommandApproval", "applyPatchApproval", "item/permissions/requestApproval", "item/tool/requestUserInput"}})
	requireStatus(t, f.run(), 0, f.err.String())
	count := 0
	for _, v := range f.events() {
		id, _ := v["reply"].(string)
		if strings.Contains(id, "approval-") {
			count++
			result, _ := v["result"].(map[string]any)
			switch count {
			case 1, 2:
				if result["decision"] != "decline" {
					t.Fatal(v)
				}
			case 3, 4:
				if result["decision"] != "abort" {
					t.Fatal(v)
				}
			case 5:
				if result["scope"] != "turn" {
					t.Fatal(v)
				}
			case 6:
				if v["error"] != true {
					t.Fatal(v)
				}
			}
		}
	}
	if count != 6 {
		t.Fatal(count)
	}
}

// Renewal errors/mismatches never answer with material; sequential valid
// callbacks renew using the digest of exactly the token last sent to that server.
func TestRenewal(t *testing.T) {
	for _, kind := range []string{"refused", "previous-mismatch", "account-mismatch", "limit-extension", "duplicate", "once", "twice"} {
		t.Run(kind, func(t *testing.T) {
			s := map[string]any{"RefreshCount": 1}
			if kind == "previous-mismatch" {
				s["PreviousMismatch"] = true
			}
			if kind == "twice" || kind == "duplicate" {
				s["RefreshCount"] = 2
			}
			if kind == "duplicate" {
				s["Duplicate"] = true
			}
			f := newFixture(t, s)
			switch kind {
			case "refused":
				f.b.renewErr = refuse("renew_not_current", 75)
			case "account-mismatch":
				f.b.mismatch = true
			case "limit-extension":
				f.b.extend = true
			}
			want := 75
			if kind == "once" || kind == "twice" {
				want = 0
			}
			requireStatus(t, f.run(), want, f.err.String())
			n := 1
			if kind == "previous-mismatch" {
				n = 0
			}
			if kind == "twice" {
				n = 2
			}
			if len(f.b.renewals) != n {
				t.Fatal(f.b.renewals)
			}
			for i, r := range f.b.renewals {
				token := canaryA
				if i > 0 {
					token = canaryB
				}
				if r.LeaseID != "lease" || r.RejectedSHA256 != digest([]byte(token)) {
					t.Fatal("incorrect token-generation digest")
				}
			}
			if want != 0 {
				assertAbsent(t, f.output)
			}
			if f.b.calls[len(f.b.calls)-1] != "release" {
				t.Fatal(f.b.calls)
			}
		})
	}
}

// An adapter returning after the local 8.5s cutoff cannot produce a late
// success reply; the callback gets one error and teardown/release still run.
func TestRenewCutoffNoLateAnswer(t *testing.T) {
	f := newFixture(t, map[string]any{"RefreshCount": 2, "RetryAfterError": true})
	f.b.slow = true
	f.b.ignoreCancel = true
	start := time.Now()
	requireStatus(t, f.run(), 75, f.err.String())
	elapsed := time.Since(start)
	if elapsed < 8500*time.Millisecond || elapsed > 14*time.Second {
		t.Fatal(elapsed)
	}
	replies := 0
	for _, event := range f.events() {
		if event["reply"] == `"refresh-2"` {
			t.Fatal("late callback received an answer")
		}
		if event["reply"] == `"refresh-1"` {
			replies++
			if event["error"] != true {
				t.Fatal("late success reply")
			}
		}
	}
	if len(f.b.renewals) != 1 {
		t.Fatal("renewal admitted after cutoff")
	}
	if replies != 1 {
		t.Fatalf("callback replies: %d", replies)
	}
	assertAbsent(t, f.output)
}

// Cleanup/release unavailability dominates successful and failed vendor turns;
// an execution deadline and handled signal keep their code only after cleanup.
func TestExitDominance(t *testing.T) {
	for _, kind := range []string{"release-success-turn", "release-failed-turn", "timeout", "signal", "release-timeout", "release-signal", "wrong-turn"} {
		t.Run(kind, func(t *testing.T) {
			s := map[string]any{}
			if strings.Contains(kind, "failed-turn") {
				s["Status"] = "failed"
			}
			if strings.Contains(kind, "timeout") || strings.Contains(kind, "signal") || kind == "wrong-turn" {
				s["Hang"] = true
			}
			if kind == "wrong-turn" {
				s["Hang"] = false
				s["WrongTurn"] = true
			}
			f := newFixture(t, s)
			f.o.Timeout = 600 * time.Millisecond
			if strings.HasPrefix(kind, "release") {
				f.b.releaseErr = errors.New("synthetic")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if strings.Contains(kind, "signal") {
				go func() { waitFile(filepath.Join(f.home, "server-pid")); cancel() }()
			}
			got := Command(ctx, f.args(), IO{strings.NewReader("prompt"), &f.out, &f.err}, f.d)
			want := 75
			if kind == "timeout" || kind == "wrong-turn" {
				want = 124
			}
			if kind == "signal" {
				want = 130
			}
			requireStatus(t, got, want, f.err.String())
			assertAbsent(t, f.output)
		})
	}
}

// Raw canary tokens and their lower/upper hex SHA-256 forms may appear in fake
// vendor text/stderr, but never escape
// runner output, owned files, the child's argv/environment or inherited FDs.
func TestCanaryNoLeak(t *testing.T) {
	f := newFixture(t, map[string]any{"RefreshCount": 2, "Echo": true})
	f.b.beforeRequest = func() { f.b.note("before-exec") }
	f.d.Environment = []string{"UNRELATED_SECRET=must-not-inherit"}
	f.b.onRenew = func() {
		pid := readPID(t, filepath.Join(f.home, "server-pid"))
		for _, name := range []string{"environ", "cmdline"} {
			data, e := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
			must(t, e)
			for _, token := range append(canaryMaterials(), "must-not-inherit") {
				if bytes.Contains(data, []byte(token)) {
					t.Fatal("inherited material")
				}
			}
			if name == "environ" {
				if !bytes.Contains(data, []byte("HOME="+f.home+"\x00")) || !bytes.Contains(data, []byte("CODEX_HOME="+f.home+"\x00")) {
					t.Fatal("wrong child home")
				}
			}
		}
		files, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		must(t, e)
		for _, fd := range files {
			target, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if os.IsNotExist(e) {
				continue
			}
			must(t, e)
			if strings.Contains(target, ".run-codex.lock") || strings.Contains(target, "socket:") {
				t.Fatal("inherited broker/home descriptor")
			}
		}
	}
	requireStatus(t, f.run(), 0, f.err.String())
	for _, token := range canaryMaterials() {
		if strings.Contains(f.out.String()+f.err.String(), token) {
			t.Fatal("stream leak")
		}
		must(t, filepath.Walk(f.root, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			if info.Mode().IsRegular() {
				data, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				if bytes.Contains(data, []byte(token)) {
					return errors.New("owned file leak")
				}
			}
			return nil
		}))
	}
	if !strings.Contains(f.out.String(), "[redacted]") {
		t.Fatal("missing stream redaction")
	}
}

// A SIGTERM-ignoring child and grandchild are both reaped before clean exit;
// the launch-home lock and unresolved-intent fence reject concurrent reuse.
func TestDescendantTeardownAndHomeFence(t *testing.T) {
	f := newFixture(t, map[string]any{"Spawn": true, "Hang": true})
	f.o.Timeout = 600 * time.Millisecond
	requireStatus(t, f.run(), 124, f.err.String())
	for _, name := range []string{"server-pid", "child-pid", "grandchild-pid"} {
		pid := readPID(t, filepath.Join(f.home, name))
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			t.Fatalf("descendant %s survives: %v", name, err)
		}
	}
	t.Run("lock-held", func(t *testing.T) {
		f := newFixture(t, nil)
		g, e := lockHome(f.home)
		must(t, e)
		defer g.close(true)
		requireStatus(t, f.run(), 75, f.err.String())
		f.noLease()
	})
	t.Run("unresolved", func(t *testing.T) {
		f := newFixture(t, nil)
		must(t, os.WriteFile(filepath.Join(f.home, ".run-codex-unresolved"), []byte("unresolved"), 0600))
		requireStatus(t, f.run(), 75, f.err.String())
		f.noLease()
	})
}

// Abrupt runner death closes the guard lifeline: descendants disappear without
// an exit callback; the retained intent blocks unreviewed reuse of that home.
func TestRunnerKilled(t *testing.T) {
	f := newFixture(t, map[string]any{"Spawn": true, "Hang": true})
	exe, e := os.Executable()
	must(t, e)
	cmd := exec.Command(exe, "--fixture-parent", f.root, fakePath, supervisorPath)
	cmd.Env = os.Environ()
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}
	must(t, cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	if !waitFile(filepath.Join(f.home, "grandchild-pid")) {
		t.Fatal("grandchild not ready")
	}
	pids := []int{readPID(t, filepath.Join(f.home, "server-pid")), readPID(t, filepath.Join(f.home, "child-pid")), readPID(t, filepath.Join(f.home, "grandchild-pid"))}
	must(t, cmd.Process.Kill())
	if cmd.Wait() == nil {
		t.Fatal("expected signal exit")
	}
	until := time.Now().Add(5 * time.Second)
	for _, pid := range pids {
		for syscall.Kill(pid, 0) != syscall.ESRCH && time.Now().Before(until) {
			time.Sleep(10 * time.Millisecond)
		}
		if syscall.Kill(pid, 0) != syscall.ESRCH {
			t.Fatal("orphan survives parent death")
		}
	}
	requireStatus(t, f.run(), 75, f.err.String())
	f.noLease()
}
func fixtureParent(args []string) {
	root := args[0]
	fakePath = args[1]
	supervisorPath = args[2]
	home := filepath.Join(root, "home")
	o := Options{Account: "account", Profile: "profile", LaunchHome: home, Cwd: filepath.Join(root, "work"), PromptStdin: true, Model: "fixture-model", ReasoningEffort: "medium", Output: filepath.Join(root, "result"), Timeout: time.Minute}
	raw, _ := os.ReadFile(fakePath)
	fp, _ := inspectSources(o, nil)
	p := Policy{Account: o.Account, Profile: o.Profile, Endpoint: "https://example.invalid/inference", Executable: fakePath, ExecutableSHA256: digest(raw), Release: "codex-cli 0.163.0", SchemaSHA256: strings.Repeat("a", 64), ChatGPTAccountID: "vendor-account", ConfigSHA256: fp, BindingDigest: strings.Repeat("b", 64), UID: uint32(os.Getuid()), BrokerUID: uint32(os.Getuid()), PolicyGeneration: 1, Qualified: true, Catalog: map[string][]string{o.Model: {"medium"}}}
	b := &fakeBroker{p: p, home: home, closed: make(chan struct{}), expiry: time.Now().Add(time.Hour)}
	d := Dependencies{Authority: &fakeAuthority{p: p}, Connect: func(context.Context) (BrokerClient, error) { return b, nil }, Supervisor: supervisorPath}
	f := fixture{o: o, home: home, output: o.Output}
	os.Exit(Command(context.Background(), f.args(), IO{strings.NewReader("prompt"), os.Stdout, os.Stderr}, d))
}
func waitFile(path string) bool {
	return awaitFixtureBytes(path, func(b []byte) bool { return len(b) > 0 }) == nil
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	b, e := os.ReadFile(path)
	must(t, e)
	pid, e := strconv.Atoi(string(b))
	must(t, e)
	return pid
}

// Partial/unreadable process evidence remains unknown; complete parsed
// metadata distinguishes a live group member from an empty fixture group.
func TestAbsenceObservation(t *testing.T) {
	root := t.TempDir()
	if _, e := scanGroup(filepath.Join(root, "missing"), 99); e == nil {
		t.Fatal("unreadable proc root treated as absent")
	}
	must(t, os.Mkdir(filepath.Join(root, "101"), 0700))
	statPath := filepath.Join(root, "101", "stat")
	must(t, os.WriteFile(statPath, []byte("partial"), 0600))
	if _, e := scanGroup(root, 99); e == nil {
		t.Fatal("partial metadata treated as absent")
	}
	must(t, os.WriteFile(statPath, []byte("101 (fixture) S 1 99 99"), 0600))
	members, e := scanGroup(root, 99)
	must(t, e)
	if !reflect.DeepEqual(members, []int{101}) {
		t.Fatal(members)
	}
	members, e = scanGroup(root, 100)
	must(t, e)
	if len(members) != 0 {
		t.Fatal(members)
	}
}

// A callback already past the local cutoff starts no renewal; once the
// reply reserve has also expired it cannot produce any late wire answer.
func TestExpiredCallback(t *testing.T) {
	for _, age := range []time.Duration{8501 * time.Millisecond, 10 * time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			f := newFixture(t, nil)
			read, write, e := os.Pipe()
			must(t, e)
			defer read.Close()
			defer write.Close()
			l := f.b.lease(canaryA)
			defer l.erase()
			s := session{ctx: context.Background(), broker: f.b, lease: &l, policy: f.a.p, rpc: &rpc{in: write}, stream: &textStream{}, answered: map[string]bool{}}
			defer s.stream.erase()
			err := s.callback(message{ID: json.RawMessage(`"expired"`), Method: "account/chatgptAuthTokens/refresh", Params: json.RawMessage(`{"reason":"unauthorized","previousAccountId":"vendor-account"}`), received: time.Now().Add(-age)})
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != "renew_timeout" {
				t.Fatal(err)
			}
			if len(f.b.renewals) != 0 {
				t.Fatal("expired callback renewed")
			}
			must(t, read.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
			b := make([]byte, 512)
			n, e := read.Read(b)
			if age < 9*time.Second {
				if e != nil || !bytes.Contains(b[:n], []byte(`"error"`)) {
					t.Fatal("missing bounded error answer")
				}
			} else if n != 0 {
				t.Fatal("late wire reply")
			}
		})
	}
}

// Hook/MCP files outside config.toml still conflict before a lease, and
// an absent file remains an admissible control.
func TestDiscoveredHookSources(t *testing.T) {
	for _, name := range []string{"hooks.json", "mcp.json"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			must(t, os.WriteFile(filepath.Join(f.home, name), []byte("{}"), 0600))
			requireStatus(t, f.run(), 69, f.err.String())
			f.noLease()
		})
	}
	t.Run("absent", func(t *testing.T) { f := newFixture(t, nil); requireStatus(t, f.run(), 0, f.err.String()) })
}

// Cancellation unblocks a genuinely full stdout pipe so teardown can proceed;
// the adjacent writable pipe control still transmits ordinary text.
func TestBlockedOutputCancellation(t *testing.T) {
	read, write, e := os.Pipe()
	must(t, e)
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := (contextWriter{ctx, write}).Write(make([]byte, 1<<20)); done <- err }()
	awaitPipeFull(t, read)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left stdout blocked")
	}
	r, w, e := os.Pipe()
	must(t, e)
	defer r.Close()
	defer w.Close()
	if n, e := (contextWriter{context.Background(), w}).Write([]byte("ok")); n != 2 || e != nil {
		t.Fatal(n, e)
	}
	b := make([]byte, 2)
	_, e = r.Read(b)
	must(t, e)
	if string(b) != "ok" {
		t.Fatal("valid write changed")
	}
}

// The shipped command cannot self-qualify or invent a broker; invalid options
// return 64 and otherwise-valid unwired admission returns typed 69.
func TestStandaloneCLI(t *testing.T) {
	for _, kind := range []string{"invalid", "unwired"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			args := append([]string{"run-codex"}, f.args()...)
			want := 69
			if kind == "invalid" {
				args = append(args, "--unknown")
				want = 64
			}
			cmd := exec.Command(supervisorPath, args...)
			cmd.Env = cleanEnvironment(f.home)
			cmd.Stdin = strings.NewReader("prompt")
			var out, diagnostics bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diagnostics
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("missing refusal: %v", err)
			}
			requireStatus(t, exit.ExitCode(), want, diagnostics.String())
			if out.Len() != 0 {
				t.Fatal("refusal wrote stdout")
			}
			assertAbsent(t, f.output)
			assertAbsent(t, filepath.Join(f.home, "server-pid"))
		})
	}
}

// Each defined renewal refusal is preserved as typed metadata and prevents
// output publication; valid renewal is the adjacent positive control.
func TestRenewalRefusalCodes(t *testing.T) {
	for _, code := range []string{"renew_not_current", "renew_timeout", "renew_failed", "lease_owner_unavailable", "lease_reauth_required", "lease_not_active", "lease_not_owner"} {
		t.Run(code, func(t *testing.T) {
			f := newFixture(t, map[string]any{"RefreshCount": 1})
			f.b.renewErr = refuse(code, 75)
			requireStatus(t, f.run(), 75, f.err.String())
			if !strings.Contains(f.err.String(), code) {
				t.Fatal("lost refusal code")
			}
			assertAbsent(t, f.output)
		})
	}
	t.Run("valid", func(t *testing.T) {
		f := newFixture(t, map[string]any{"RefreshCount": 1})
		requireStatus(t, f.run(), 0, f.err.String())
	})
}

// Equivalent JSON spellings of a callback ID share one answer identity;
// invalid ID shapes cannot acquire an answer slot.
func TestCallbackIDIdentity(t *testing.T) {
	a, ok := callbackID(json.RawMessage(`"refresh"`))
	if !ok {
		t.Fatal("valid ID rejected")
	}
	b, ok := callbackID(json.RawMessage(`"refr\u0065sh"`))
	if !ok || a != b {
		t.Fatal("escaped ID bypassed duplicate detection")
	}
	for _, raw := range []string{`null`, `{}`, `[]`, `1.5`, `true`} {
		if _, ok := callbackID(json.RawMessage(raw)); ok {
			t.Fatalf("invalid callback ID accepted: %s", raw)
		}
	}
	if _, ok := callbackID(json.RawMessage(`123`)); !ok {
		t.Fatal("integer control rejected")
	}
}

// An ancestor symlink cannot bypass prompt-file no-follow admission; the
// same regular file is accepted through its direct path.
func TestPromptAncestorSymlink(t *testing.T) {
	f := newFixture(t, nil)
	dir := filepath.Join(f.root, "prompts")
	must(t, os.Mkdir(dir, 0700))
	file := filepath.Join(dir, "prompt")
	must(t, os.WriteFile(file, []byte("prompt"), 0600))
	link := filepath.Join(f.root, "alias")
	must(t, os.Symlink(dir, link))
	a := append(removeArg(f.args(), "--prompt-stdin", false), "--prompt-file", filepath.Join(link, "prompt"))
	requireStatus(t, Command(context.Background(), a, IO{nil, &f.out, &f.err}, f.d), 64, f.err.String())
	f.noLease()
	a = append(removeArg(f.args(), "--prompt-stdin", false), "--prompt-file", file)
	requireStatus(t, Command(context.Background(), a, IO{nil, &f.out, &f.err}, f.d), 0, f.err.String())
}

// Stop cannot equate a waited child with group absence: an independently live
// observed group is rejected, while the actual stopped private group is absent.
func TestStopRequiresAbsentGroup(t *testing.T) {
	f := newFixture(t, nil)
	h, e := lockHome(f.home)
	must(t, e)
	defer h.close(true)
	must(t, h.intent())
	p, e := startProcess(f.d, f.o, h, f.a.p, []string{"--version"})
	must(t, e)
	actual := p.group
	p.group = syscall.Getpgrp()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if p.stop(ctx) == nil {
		t.Fatal("live group accepted as absent")
	}
	p.group = actual
	must(t, p.stop(ctx))
}

// A PID outside the guard's group must never be signalled; an owned group
// member is killed through its pinned pidfd, then reaped by its test parent.
func TestPidfdGroupCheck(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			f := newFixture(t, nil)
			cmd := exec.Command(fakePath, "--child")
			cmd.Env = cleanEnvironment(f.home)
			if foreign {
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			}
			must(t, cmd.Start())
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			err := signalMember(cmd.Process.Pid, syscall.Getpgrp(), syscall.SIGKILL)
			if foreign {
				if err == nil {
					t.Fatal("foreign group accepted")
				}
				if e := syscall.Kill(cmd.Process.Pid, 0); e != nil {
					t.Fatal("foreign process was killed")
				}
			} else {
				must(t, err)
				if cmd.Wait() == nil {
					t.Fatal("expected signal termination")
				}
			}
		})
	}
}

// A child that creates a new session and then spawns a grandchild cannot
// escape cleanup: subreaper adoption and pidfds cover both after parent death.
func TestEscapedDescendantTeardown(t *testing.T) {
	f := newFixture(t, map[string]any{"Spawn": true, "Escape": true, "Hang": true})
	f.o.Timeout = 600 * time.Millisecond
	requireStatus(t, f.run(), 124, f.err.String())
	for _, name := range []string{"server-pid", "child-pid", "grandchild-pid"} {
		pid := readPID(t, filepath.Join(f.home, name))
		if e := syscall.Kill(pid, 0); e != syscall.ESRCH {
			t.Fatalf("escaped descendant %s survives: %v", name, e)
		}
	}
}
