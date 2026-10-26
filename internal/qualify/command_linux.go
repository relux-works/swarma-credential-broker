//go:build linux

// Package qualify implements the owner-only qualification command frame.
package qualify

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

type options struct {
	executable, evidence, approval, account string
	fixtureConfig                           string
	fixtures, live                          bool
}

func parse(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("qualify-codex", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.executable, "executable", "", "")
	f.StringVar(&o.evidence, "evidence-dir", "", "")
	f.StringVar(&o.approval, "approval-ref", "", "")
	f.StringVar(&o.account, "account", "", "")
	f.StringVar(&o.fixtureConfig, "fixture-config", "", "")
	f.BoolVar(&o.fixtures, "fixtures", false, "")
	f.BoolVar(&o.live, "live", false, "")
	counts := map[string]int{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			key, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			counts[key]++
			if counts[key] > 1 {
				return o, qualification.ErrInvalid
			}
		}
	}
	if f.Parse(args) != nil || f.NArg() != 0 || o.fixtures == o.live || !filepath.IsAbs(o.executable) || filepath.Clean(o.executable) != o.executable || !filepath.IsAbs(o.evidence) || filepath.Clean(o.evidence) != o.evidence || o.fixtures && (o.approval != "" || o.account != "") {
		return o, qualification.ErrInvalid
	}
	if o.fixtureConfig != "" && (!o.fixtures || !filepath.IsAbs(o.fixtureConfig) || filepath.Clean(o.fixtureConfig) != o.fixtureConfig) {
		return o, qualification.ErrInvalid
	}
	return o, nil
}

type driver struct {
	runnerAcceptedImage string // private audited-image acceptance, never serialized or configured
	executions          *[]rowExecutionRecord
	path                string
	environment         []string
	observer            func(policy.Config) qualification.IdentityObserver
	ops                 commandSyscalls
	runnerExecutable    string // protected synthetic fixture only
	rowExecutable       string // no production flag or environment selector
}

func Command(ctx context.Context, args []string, configPath string, environment []string, out io.Writer) int {
	d := driver{path: configPath, environment: environment}
	return d.run(ctx, args, out)
}

type report struct {
	Executions  []rowExecutionRecord            `json:"row_executions,omitempty"`
	CompletedAt string                          `json:"completed_at"`
	Kind        string                          `json:"kind"`
	Identity    qualification.Identity          `json:"identity"`
	Unavailable []string                        `json:"unavailable_observers"`
	Cases       []qualification.Case            `json:"cases"`
	Disposition string                          `json:"disposition"`
	Observers   qualification.CandidateEvidence `json:"candidate_observers"`
}

// Inherited credentials are refused by name; their values and native homes are
// never inspected. Inheritable extra descriptors are also unavailable inputs.
func cleanEnvironment(env []string) bool {
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if key == "CODEX_HOME" || strings.HasPrefix(upper, "CODEX_") || strings.HasPrefix(upper, "OPENAI_") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "API_KEY") || strings.Contains(upper, "AUTH_HELPER") {
			return false
		}
	}
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return false
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
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			return false
		}
	}
	return true
}
func privateDirectory(path string) bool {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return false
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return false
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && s.Mode() == os.ModeDir|0700
}

func (d driver) run(parent context.Context, args []string, out io.Writer) int {
	o, e := parse(args)
	if e != nil {
		return 64
	}
	// This slice grants no live authority, even with a syntactically valid ref.
	if o.live {
		return 69
	}
	if !cleanEnvironment(d.environment) || !privateDirectory(o.evidence) {
		return 69
	}
	c, e := policy.Load(d.path, uint32(os.Geteuid()))
	if e != nil || c.Policy.Executable != o.executable {
		return 69
	}
	raw, e := wire.Encode(c)
	if e != nil {
		return 69
	}
	var candidateEvidence qualification.CandidateEvidence
	var observer qualification.IdentityObserver = qualification.NativeObserver{ExecutablePath: o.executable, StaticPolicy: raw, ExecutableSHA256: c.Policy.ExecutableSHA256, ScratchRoot: o.evidence, Evidence: &candidateEvidence}
	if d.observer != nil {
		observer = d.observer(c)
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	repository := qualification.Repository{Path: qualification.Directory(d.path), UID: c.Policy.BrokerUID, Observer: observer}
	var outcome report
	e = repository.WhileClosed(ctx, func() (runError error) {
		var socket *privateSocket
		defer func() {
			if socket != nil {
				runError = errors.Join(runError, socket.close())
			}
		}()
		identity, _, missing := qualification.Observe(ctx, observer)
		if identity.Version != "" && identity.Version != "0.163.0" {
			return qualification.ErrUnavailable
		}
		if identity.Executable.SHA256 != "" && identity.Executable.SHA256 != c.Policy.ExecutableSHA256 {
			return qualification.ErrUnavailable
		}
		if policy.Hash(identity.Executable.SHA256) {
			var e error
			socket, e = d.reserve(ctx, o.evidence, identity.Executable.SHA256)
			if e != nil {
				return e
			}
		}
		// Unimplemented bodies remain pending. -1 denotes no execution.
		pending := qualification.Pending(identity)
		var executions []rowExecutionRecord
		d.executions = &executions
		if identity.Executable.SHA256 == c.Policy.ExecutableSHA256 && identity.Version == "0.163.0" {
			d.runRows(ctx, o.fixtureConfig, c.Policy, o.evidence, pending.Cases)
		}
		sort.Strings(missing)
		r := report{Kind: "qualification-run/1", Identity: identity, Unavailable: missing, Cases: pending.Cases, Disposition: "pending", CompletedAt: pending.CompletedAt}
		r.Executions = executions
		next, e := policy.Load(d.path, c.Policy.BrokerUID)
		if e != nil {
			return qualification.ErrUnavailable
		}
		before, e := wire.Encode(c)
		if e != nil {
			return e
		}
		after, e := wire.Encode(next)
		if e != nil || string(before) != string(after) {
			return qualification.ErrUnavailable
		}
		again, _, missingAgain := qualification.Observe(ctx, observer)
		sort.Strings(missingAgain)
		if again != identity || strings.Join(missingAgain, ",") != strings.Join(missing, ",") {
			return qualification.ErrUnavailable
		}
		if source, ok := observer.(interface {
			CandidateMeasurements() qualification.CandidateEvidence
		}); ok {
			r.Observers = source.CandidateMeasurements()
		}
		b, e := wire.Encode(r)
		if e != nil {
			return qualification.ErrUnavailable
		}
		if socket != nil {
			closeError := socket.close()
			socket = nil
			if closeError != nil {
				return closeError
			}
		}
		if ctx.Err() != nil {
			return qualification.ErrUnavailable
		}
		f, e := os.OpenFile(filepath.Join(o.evidence, "run.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return qualification.ErrUnavailable
		}
		n, e := f.Write(b)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return qualification.ErrUnavailable
		}
		dir, e := os.Open(o.evidence)
		if e != nil {
			return qualification.ErrUnavailable
		}
		e = dir.Sync()
		ce = d.syscall("close:report-directory", dir.Close)
		e = errors.Join(e, ce)
		if e != nil {
			return qualification.ErrUnavailable
		}
		_, e = out.Write(append(b, '\n'))
		if e == nil {
			outcome = r
		}
		return e
	})
	if e != nil {
		return 69
	}
	return resultCode(outcome.Cases, outcome.Unavailable)
}

// resultCode defines the frame's exit contract before row bodies are supplied.
// Pending or absent execution is unavailable, distinct from an executed failure.
func resultCode(cases []qualification.Case, unavailable []string) int {
	if len(unavailable) > 0 || len(cases) != len(qualification.RequiredCases()) {
		return 69
	}
	failed := false
	for n, c := range cases {
		if c.ID != qualification.RequiredCases()[n] {
			return 69
		}
		for _, x := range []qualification.Control{c.Positive, c.Negative} {
			if !x.Executed || x.Verdict == "pending" {
				return 69
			}
			if x.Verdict == "failed" {
				failed = true
			} else if x.Verdict != "passed" || x.ExitCode != 0 {
				return 69
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}
