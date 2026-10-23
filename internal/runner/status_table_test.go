//go:build linux

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type statusReader func([]byte) (int, error)

func (r statusReader) Read(b []byte) (int, error) { return r(b) }

type statusWriter func([]byte) (int, error)

func (w statusWriter) Write(b []byte) (int, error) { return w(b) }

// Conversion methods belong to foreign code. None may be called to classify
// a bounded adapter/writer error, including typed-nil and noncomparable errors.
type conversionFault struct{ values []int }

func (conversionFault) Error() string { panic("foreign Error called") }
func (conversionFault) As(any) bool   { panic("foreign As called") }
func (conversionFault) Is(error) bool { panic("foreign Is called") }
func (conversionFault) Unwrap() error { panic("foreign Unwrap called") }

// Each phase of the normative docs table is driven through public Command.
// Own execution stops, independent context errors and ordinary I/O/refusals
// have adjacent success controls. Assertions cover resource obligations before
// status: exactly one release after acquisition, child ESRCH and old output.
// Protocol failures model unexpected vendor errors, not arbitrary runtime faults.
// Ordinary rows retain the normal fixture budget so setup is not their subject.
// The authority-expiry row has a shorter lease than execution budget, allowing
// child startup before testing expiry; own-deadline rows still wait for expiry.
func TestCommandStatusTable(t *testing.T) {
	type row struct {
		phase, origin string
		stage         string
		method        string
		want          int
		leased, child bool
	}
	var rows []row
	add := func(p, o string, want int, leased, child bool) {
		rows = append(rows, row{phase: p, origin: o, want: want, leased: leased, child: child})
	}
	for _, o := range []string{"invalid-input", "catalog-input", "admission", "qualification", "output-io", "valid", "panic"} {
		want := 69
		switch o {
		case "invalid-input", "catalog-input":
			want = 64
		case "output-io":
			want = 75
		case "valid":
			want = 0
		}
		add("preflight", o, want, o == "valid", o == "valid")
	}
	for _, st := range []struct{ p, s string }{
		{"authority", "authority-first"}, {"connect/verify", "connect"}, {"connect/verify", "verify"},
		{"hello", "hello"}, {"request", "request"}, {"recheck", "authority-recheck"},
	} {
		for _, o := range []string{"admission", "transport", "independent-cancel", "independent-deadline", "conversion", "typed-nil", "panic", "own-interrupt", "own-deadline", "valid"} {
			want := 69
			switch o {
			case "own-interrupt":
				want = 130
			case "own-deadline":
				want = 124
			case "valid":
				want = 0
			}
			rows = append(rows, row{st.p, o, st.s, "", want, o == "valid" || st.s == "authority-recheck", o == "valid"})
		}
	}
	for _, st := range []struct{ p, m string }{{"start/initialize", "initialize"}, {"login", "account/login/start"}, {"turn", "turn/start"}} {
		for _, o := range []string{"admission", "transport", "unexpected", "own-interrupt", "own-deadline", "valid"} {
			want := 69
			switch o {
			case "own-interrupt":
				want = 130
			case "own-deadline":
				want = 124
			case "valid":
				want = 0
			}
			rows = append(rows, row{st.p, o, "", st.m, want, true, true})
		}
	}
	for _, o := range []string{"vendor-failed", "vendor-interrupted", "authority-expiry"} {
		want := 1
		if o == "authority-expiry" {
			want = 75
		}
		add("turn", o, want, true, true)
	}
	for _, o := range []string{"owner-unavailable", "independent-cancel", "independent-deadline", "conversion", "panic", "identity", "duplicate", "own-interrupt", "valid"} {
		want := 75
		if o == "valid" {
			want = 0
		}
		add("refresh", o, want, true, true)
	}
	for _, p := range []string{"streaming", "final"} {
		for _, o := range []string{"output-io", "independent-cancel", "independent-deadline", "conversion", "typed-nil", "alternate-as", "panic", "valid"} {
			want := 75
			if o == "valid" {
				want = 0
			}
			add(p, o, want, true, true)
		}
	}
	for _, o := range []string{"cleanup-unknown", "valid"} {
		want := 75
		if o == "valid" {
			want = 0
		}
		add("teardown", o, want, true, true)
	}
	for _, o := range []string{"transport", "independent-cancel", "independent-deadline", "conversion", "panic", "own-interrupt", "valid"} {
		want := 75
		if o == "valid" {
			want = 0
		}
		add("release", o, want, true, true)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		t.Run(r.phase+"/"+r.origin+"/"+r.stage, func(t *testing.T) {
			seen[r.phase] = true
			scenario := map[string]any{}
			if r.method != "" {
				switch r.origin {
				case "admission":
					scenario["FailAt"] = r.method
				case "transport", "unexpected":
					scenario["ExitAt"] = r.method
				case "own-interrupt", "own-deadline":
					scenario["HangAt"] = r.method
				}
			}
			if r.phase == "turn" {
				switch r.origin {
				case "vendor-failed":
					scenario["Status"] = "failed"
				case "vendor-interrupted":
					scenario["Status"] = "interrupted"
				case "authority-expiry":
					scenario["Hang"] = true
				}
			}
			if r.phase == "refresh" {
				scenario["RefreshCount"] = 1
				if r.origin == "duplicate" {
					scenario["RefreshCount"] = 2
					scenario["Duplicate"] = true
				}
				if r.origin == "identity" {
					scenario["PreviousMismatch"] = true
				}
			}
			if r.phase == "streaming" {
				scenario["LargeOutput"] = true
			}
			f := newFixture(t, scenario)
			if r.origin == "own-deadline" {
				f.o.Timeout = 250 * time.Millisecond
			}
			must(t, os.WriteFile(f.output, []byte("old"), 0600))
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := false
			fault := func(ctx context.Context) error {
				reached = true
				switch r.origin {
				case "own-interrupt":
					cancel()
					<-ctx.Done()
					return ctx.Err()
				case "own-deadline":
					<-ctx.Done()
					return ctx.Err()
				case "independent-cancel":
					return context.Canceled
				case "independent-deadline":
					return context.DeadlineExceeded
				case "conversion":
					return conversionFault{}
				case "typed-nil":
					var e *Refusal
					return e
				case "panic":
					panic(conversionFault{})
				case "admission":
					return &Refusal{"lease_not_authorised", 130} // foreign status is not authority
				case "transport", "output-io", "owner-unavailable":
					return errors.New("bounded fixture fault")
				}
				return nil
			}
			if r.stage != "" {
				a := &faultAuthority{inner: f.a, stop: fault}
				if r.stage == "authority-first" {
					a.at = 1
				}
				if r.stage == "authority-recheck" {
					a.at = 2
				}
				f.d.Authority = a
				b := faultStageBroker{BrokerClient: f.b, stage: r.stage, stop: fault}
				f.d.Connect = func(ctx context.Context) (BrokerClient, error) {
					if r.stage == "connect" {
						if e := fault(ctx); e != nil {
							return nil, e
						}
					}
					return b, nil
				}
			}
			var wait chan struct{}
			if r.method != "" && r.origin == "own-interrupt" {
				wait = make(chan struct{})
				go func() {
					defer close(wait)
					if err := awaitFixtureBytes(filepath.Join(f.home, "events.jsonl"), func(b []byte) bool {
						return strings.Contains(string(b), r.method)
					}); err != nil {
						t.Error("fixture method rendezvous", err)
					}
					cancel()
				}()
			}
			if r.phase == "turn" && r.origin == "authority-expiry" {
				f.b.expiry = time.Now().Add(2 * time.Second)
			}
			if r.phase == "refresh" {
				switch r.origin {
				case "owner-unavailable":
					f.b.renewErr = errors.New("owner unavailable")
				case "independent-cancel":
					f.b.renewErr = context.Canceled
				case "independent-deadline":
					f.b.renewErr = context.DeadlineExceeded
				case "conversion":
					f.b.renewErr = conversionFault{}
				case "panic":
					f.d.Connect = func(context.Context) (BrokerClient, error) {
						return statusFaultBroker{BrokerClient: f.b, renew: fault}, nil
					}
				case "own-interrupt":
					f.b.onRenew = cancel
					f.b.slow = true
				}
			}
			if r.phase == "release" || r.phase == "teardown" {
				b := statusFaultBroker{BrokerClient: f.b}
				if r.phase == "release" && r.origin != "valid" {
					b.release = fault
				}
				if r.origin == "cleanup-unknown" {
					b.afterStop = func() {
						p := filepath.Join(f.home, ".run-codex-unresolved")
						must(t, os.Remove(p))
						must(t, os.Mkdir(p, 0700))
						must(t, os.WriteFile(filepath.Join(p, "held"), []byte("fixture"), 0600))
					}
				}
				f.d.Connect = func(context.Context) (BrokerClient, error) { return b, nil }
			}
			var out io.Writer = io.Discard
			if (r.phase == "streaming" || r.phase == "final") && r.origin != "valid" {
				out = statusWriter(func([]byte) (int, error) {
					if r.origin == "alternate-as" {
						return 0, alternateError{}
					}
					e := fault(context.Background())
					return 0, e
				})
			}
			var input io.Reader = strings.NewReader("prompt")
			args := f.args()
			if r.phase == "preflight" {
				switch r.origin {
				case "invalid-input":
					args = append(args, "--unknown")
				case "qualification":
					scenario["Version"] = "codex-cli 0.163.1"
					data, e := json.Marshal(scenario)
					must(t, e)
					must(t, os.WriteFile(filepath.Join(f.home, "scenario.json"), data, 0600))
				case "catalog-input":
					f.a.p.Catalog = map[string][]string{}
				case "admission":
					f.d.Environment = []string{"OPENAI_API_KEY="}
				case "output-io":
					must(t, os.Symlink("missing", f.output+"-link"))
					f.output += "-link"
					f.o.Output = f.output
					args = f.args()
				case "panic":
					input = statusReader(func([]byte) (int, error) { panic("bounded prompt reader fault") })
				}
			}
			got := Command(parent, args, IO{input, out, &f.err}, f.d)
			if wait != nil {
				<-wait
			}
			if r.stage != "" && !reached {
				t.Fatal("fault stage not reached")
			}
			releases := 0
			for _, c := range f.b.calls {
				if c == "release" {
					releases++
				}
			}
			wantRelease := 0
			if r.leased {
				wantRelease = 1
			}
			if releases != wantRelease {
				t.Fatalf("release=%d want=%d", releases, wantRelease)
			}
			if r.child {
				pid := readPID(t, filepath.Join(f.home, "server-pid"))
				if syscall.Kill(pid, 0) != syscall.ESRCH {
					t.Fatal("child remains")
				}
			} else {
				assertAbsent(t, filepath.Join(f.home, "server-pid"))
			}
			if r.origin == "cleanup-unknown" {
				if _, e := os.Stat(filepath.Join(f.home, ".run-codex-unresolved", "held")); e != nil {
					t.Fatal("lost unresolved fence")
				}
			} else {
				assertAbsent(t, filepath.Join(f.home, ".run-codex-unresolved"))
			}
			if r.want != 0 && !(r.phase == "preflight" && r.origin == "output-io") {
				b, e := os.ReadFile(f.output)
				must(t, e)
				if string(b) != "old" {
					t.Fatal("old output replaced")
				}
			}
			for _, b := range f.b.transferred {
				for _, v := range b {
					if v != 0 {
						t.Fatal("transferred material retained")
					}
				}
			}
			requireStatus(t, got, r.want, f.err.String())
		})
	}
	for _, p := range []phase{phasePreflight, phaseAuthority, phaseConnect, phaseHello, phaseRequest, phaseRecheck, phaseInitialize, phaseLogin, phaseTurn, phaseRefresh, phaseStreaming, phaseFinal, phaseTeardown, phaseRelease} {
		if !seen[string(p)] {
			t.Fatalf("missing normative phase %s", p)
		}
	}
	// Boundary combinations are distinct rows, not inferred from phase labels:
	// recognized invalid options beat an already stopped parent, while valid
	// options honor it; stops on either side of rename preserve status/output.
	t.Run("preflight/input-stop-boundary", inputStopPrecedence)
	// A validator reused after lease admission follows the recheck phase row.
	t.Run("recheck/catalog-input-origin", postLeaseCatalog)
	for _, timing := range []string{"fsync", "rename", "undelayed"} {
		t.Run("final/publication-"+timing, func(t *testing.T) {
			tracePublicationTiming(t, timing)
		})
	}
}

type statusFaultBroker struct {
	BrokerClient
	renew, release func(context.Context) error
	afterStop      func()
}

func (b statusFaultBroker) Renew(ctx context.Context, r RenewRequest) (Lease, error) {
	if b.renew != nil {
		if e := b.renew(ctx); e != nil {
			return Lease{}, e
		}
	}
	return b.BrokerClient.Renew(ctx, r)
}
func (b statusFaultBroker) Release(ctx context.Context, id string) error {
	// Record the one attempted release even when the injected adapter panics.
	if e := b.BrokerClient.Release(ctx, id); e != nil {
		return e
	}
	if b.afterStop != nil {
		b.afterStop()
	}
	if b.release != nil {
		return b.release(ctx)
	}
	return nil
}

// A panic in the diagnostic writer occurs inside classification, after child
// absence and release. It must return 75 without publishing the old output.
func TestClassificationPanicGuard(t *testing.T) {
	f := newFixture(t, map[string]any{"LargeOutput": true})
	must(t, os.WriteFile(f.output, []byte("old"), 0600))
	var got int
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		got = Command(context.Background(), f.args(), IO{strings.NewReader("prompt"), independentContextWriter{syscall.EPIPE}, statusWriter(func([]byte) (int, error) { panic("diagnostic fault") })}, f.d)
	}()
	pid := readPID(t, filepath.Join(f.home, "server-pid"))
	if syscall.Kill(pid, 0) != syscall.ESRCH {
		t.Fatal("child remains")
	}
	n := 0
	for _, c := range f.b.calls {
		if c == "release" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("release=%d", n)
	}
	b, e := os.ReadFile(f.output)
	must(t, e)
	if string(b) != "old" {
		t.Fatal("old output replaced")
	}
	if panicked != nil {
		t.Fatalf("classification panicked: %v", panicked)
	}
	requireStatus(t, got, 75, "")
}

// Prompt acquisition observes its parent directly before any resources exist;
// independent reader errors remain input errors. Both own stop causes are kept.
func TestPromptStopStatus(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			f := newFixture(t, nil)
			rd, wr, e := os.Pipe()
			must(t, e)
			defer rd.Close()
			defer wr.Close()
			var ctx context.Context
			var cancel context.CancelFunc
			want := 130
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
				want = 124
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			got := Command(ctx, f.args(), IO{rd, io.Discard, &f.err}, f.d)
			f.noLease()
			assertAbsent(t, filepath.Join(f.home, "server-pid"))
			requireStatus(t, got, want, f.err.String())
		})
	}
}
