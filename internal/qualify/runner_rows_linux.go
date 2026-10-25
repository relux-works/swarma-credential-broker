//go:build linux

package qualify

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

func runnerRow(id string) bool { return id == "home-auth-present" || id == "source-conflict" }

type runnerRowEffects struct {
	Resolves      int  `json:"resolves"`
	Connects      int  `json:"connects"`
	Requests      int  `json:"requests"`
	Releases      int  `json:"releases"`
	Status        int  `json:"status"`
	LocalConflict bool `json:"local_conflict"`
	Login         int  `json:"login"`
	Version       bool `json:"version"`
	StateVerified bool `json:"state_verified"`
}

func validRunnerEffects(o rowObservation) bool {
	f := o.Runner
	if f == nil || o.Peer != nil || !f.StateVerified {
		return false
	}
	if o.Side == "negative" {
		return f.Status == 69 && f.LocalConflict && f.Resolves == 0 && f.Connects == 0 && f.Requests == 0 && f.Releases == 0 && f.Login == 0 && !f.Version
	}
	return o.Side == "positive" && f.Status == 0 && !f.LocalConflict && f.Resolves == 2 && f.Connects == 1 && f.Requests == 1 && f.Releases == 1 && f.Login == 1 && f.Version
}

type runnerBoundary struct {
	Summary    map[string]egress.Counts
	Incomplete bool
}
type runnerRowFixture struct {
	network map[string]egress.Counts
	runs    int
	root    string
	stamp   os.FileInfo
	watch   int
}

func (f *runnerRowFixture) close() { unix.Close(f.watch) }
func runnerArgs(root string) []string {
	return []string{"--account", "synthetic-subject", "--profile", "fixture", "--launch-home", filepath.Join(root, "home"), "--prompt-stdin", "--model", "synthetic-model", "--reasoning-effort", "medium", "--output-last-message", filepath.Join(root, "answer.txt"), "--cwd", filepath.Join(root, "project"), "--timeout", "10"}
}
func runnerEnvironment(home string) []string {
	return []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
}

// The parent creates only synthetic sources. Neither fixture setup nor teardown
// reads auth-shaped contents; inotify and lstat observe access and preservation.
func prepareRunnerRow(root, executable string, in *rowInput) (*os.File, *runnerRowFixture, error) {
	f, e := qualification.OpenExecutable(executable)
	if e != nil {
		return nil, nil, e
	}
	fail := func() (*os.File, *runnerRowFixture, error) { f.Close(); return nil, nil, qualification.ErrUnavailable }
	digest, e := descriptorDigest(f)
	if e != nil {
		return fail()
	}
	if _, e = f.Seek(0, 0); e != nil {
		return fail()
	}
	// Bind the real runner and its synthetic broker to the same fake release.
	// The separately retained approved descriptor remains diagnostic identity,
	// never executable or issuance authority for this synthetic runner fixture.
	in.ApprovedDigest = in.Policy.ExecutableSHA256
	in.Policy.Executable, in.Policy.ExecutableSHA256 = executable, digest
	in.RunnerDigest = digest
	if os.Mkdir(filepath.Join(root, "project"), 0700) != nil || os.WriteFile(filepath.Join(root, "project", ".git"), nil, 0600) != nil || os.WriteFile(filepath.Join(root, "home", "scenario.json"), []byte("{\"Boundary\":true}\n"), 0600) != nil || os.Mkdir(filepath.Join(root, "service"), 0700) != nil || os.Mkdir(filepath.Join(root, "service", "home"), 0700) != nil {
		return fail()
	}
	args := runnerArgs(root)
	args[3] = in.Policy.Accounts[0].Profiles[0]
	o, e := runner.Parse(args)
	if e != nil {
		return fail()
	}
	in.RunnerConfig, e = runner.ConfigurationDigest(o, runnerEnvironment(o.LaunchHome))
	if e != nil {
		return fail()
	}
	fixture := &runnerRowFixture{root: root, watch: -1}
	if in.ID == "home-auth-present" && in.Side == "negative" {
		path := filepath.Join(root, "home", "auth.json")
		if os.WriteFile(path, []byte("synthetic fixture\n"), 0000) != nil {
			return fail()
		}
		fixture.stamp, e = os.Lstat(path)
		if e != nil {
			return fail()
		}
	}
	fixture.watch, e = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if e != nil {
		return fail()
	}
	if _, e = unix.InotifyAddWatch(fixture.watch, filepath.Join(root, "home"), unix.IN_OPEN); e != nil {
		fixture.close()
		return fail()
	}
	return f, fixture, nil
}
func (f *runnerRowFixture) verify(o rowObservation) bool {
	if o.Runner == nil {
		return false
	}
	good := true
	var events [8192]byte
	for {
		n, e := unix.Read(f.watch, events[:])
		if e == unix.EAGAIN {
			break
		}
		if e != nil || n == 0 {
			return false
		}
		for at := 0; at+unix.SizeofInotifyEvent <= n; {
			// The kernel encodes inotify's fixed header in native byte order.
			length := int(binary.NativeEndian.Uint32(events[at+12 : at+16]))
			if at+16+length > n {
				return false
			}
			name := strings.TrimRight(string(events[at+16:at+16+length]), "\x00")
			if name == "auth.json" {
				good = false
			}
			at += 16 + length
		}
	}
	path := filepath.Join(f.root, "home", "auth.json")
	after, e := os.Lstat(path)
	if f.stamp != nil {
		good = good && e == nil && os.SameFile(f.stamp, after) && reflect.DeepEqual(f.stamp.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t))
	} else {
		good = good && os.IsNotExist(e)
	}
	eventPath := filepath.Join(f.root, "home", "events.jsonl")
	b, e := os.ReadFile(eventPath)
	if o.Side == "negative" {
		good = good && os.IsNotExist(e)
	} else if e != nil || len(b) > 65536 {
		good = false
	} else {
		decoder := json.NewDecoder(bytes.NewReader(b))
		for {
			var event struct {
				Method string `json:"method"`
			}
			e := decoder.Decode(&event)
			if e == io.EOF {
				break
			}
			if e != nil {
				good = false
				break
			}
			if event.Method == "account/login/start" {
				o.Runner.Login++
			}
		}
	}
	_, e = os.Lstat(filepath.Join(f.root, "home", "version-probe"))
	o.Runner.Version = e == nil
	if o.Side == "negative" {
		entries, e := os.ReadDir(filepath.Join(f.root, "home"))
		want := 1
		if f.stamp != nil {
			want++
		}
		good = good && e == nil && len(entries) == want
	}
	if o.Side == "positive" {
		b, e := os.ReadFile(filepath.Join(f.root, "home", "boundary.jsonl"))
		if e != nil || len(b) > 65536 {
			good = false
		} else {
			decoder := json.NewDecoder(bytes.NewReader(b))
			f.network = map[string]egress.Counts{}
			for {
				var run runnerBoundary
				e := decoder.Decode(&run)
				if e == io.EOF {
					break
				}
				if e != nil || run.Incomplete || run.Summary == nil {
					good = false
					break
				}
				f.runs++
				for class, count := range run.Summary {
					total := f.network[class]
					total.Allowed += count.Allowed
					total.Refused += count.Refused
					f.network[class] = total
				}
			}
			good = good && f.runs == 2
		}
	} else {
		f.network = map[string]egress.Counts{}
	}
	o.Runner.StateVerified = good
	return good && validRunnerEffects(o)
}

type runnerFixtureAuthority struct {
	p       runner.Policy
	effects *runnerRowEffects
}

func (a runnerFixtureAuthority) Resolve(context.Context, runner.Options) (runner.Policy, error) {
	a.effects.Resolves++
	return a.p, nil
}

type runnerFixtureBroker struct {
	runner.BrokerClient
	effects *runnerRowEffects
}

func (b runnerFixtureBroker) Request(ctx context.Context, r runner.LeaseRequest) (runner.Lease, error) {
	b.effects.Requests++
	return b.BrokerClient.Request(ctx, r)
}
func (b runnerFixtureBroker) Release(ctx context.Context, id string) error {
	b.effects.Releases++
	return b.BrokerClient.Release(ctx, id)
}

// Command executes its actual preflight before resolving the synthetic authority.
// Only the existing account-free app-server fixture is selected; the approved
// candidate descriptor remains measured and is never used as a native harness.
func runnerExchange(in rowInput) (string, *runnerRowEffects, error) {
	root := filepath.Dir(os.Getenv("HOME"))
	f := os.NewFile(7, "synthetic-runner")
	if f == nil {
		return "", nil, qualification.ErrUnavailable
	}
	defer f.Close()
	digest, e := descriptorDigest(f)
	if e != nil || digest != in.RunnerDigest {
		return "", nil, qualification.ErrUnavailable
	}
	if _, e = f.Seek(0, 0); e != nil {
		return "", nil, e
	}
	executable := filepath.Join(root, "runner-fixture")
	out, e := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return "", nil, e
	}
	_, e = io.Copy(out, f)
	ce := out.Close()
	if e != nil || ce != nil {
		return "", nil, qualification.ErrUnavailable
	}
	effects := &runnerRowEffects{}
	a := in.Policy.Accounts[0]
	p := runner.Policy{Account: a.Label, Profile: a.Profiles[0], Endpoint: a.Endpoint, Executable: executable, ExecutableSHA256: digest, Release: "codex-cli 0.163.0", SchemaSHA256: qualification.Hash([]byte("synthetic schema")), ChatGPTAccountID: a.VendorID, ConfigSHA256: in.RunnerConfig, BindingDigest: in.Policy.Binding(in.Peer, a, a.Profiles[0]).Digest, UID: in.Peer, BrokerUID: in.Policy.BrokerUID, PolicyGeneration: in.Policy.Generation, Qualified: true, Catalog: map[string][]string{"synthetic-model": {"medium"}}}
	env := runnerEnvironment(os.Getenv("HOME"))
	if in.ID == "source-conflict" && in.Side == "negative" {
		env = append(env, "OPENAI_API_KEY=")
	}
	d := runner.Dependencies{Authority: runnerFixtureAuthority{p, effects}, Environment: env, Supervisor: "/proc/self/exe", Connect: func(ctx context.Context) (runner.BrokerClient, error) {
		effects.Connects++
		b, e := runner.DialBroker(ctx, in.Socket)
		if e != nil {
			return nil, e
		}
		return runnerFixtureBroker{b, effects}, nil
	}}
	args := runnerArgs(root)
	args[3] = a.Profiles[0]
	var stdout, stderr bytes.Buffer
	effects.Status = runner.Command(context.Background(), args, runner.IO{In: strings.NewReader("synthetic prompt"), Out: &stdout, Err: &stderr}, d)
	effects.LocalConflict = effects.Status == 69 && stderr.String() == "runner: credential_source_conflict\n"
	if in.Side == "negative" {
		return "credential_source_conflict", effects, nil
	}
	result, e := os.ReadFile(filepath.Join(root, "answer.txt"))
	if e != nil || string(result) != "answer" || stderr.Len() != 0 {
		return "", effects, qualification.ErrUnavailable
	}
	return "external-login", effects, nil
}
