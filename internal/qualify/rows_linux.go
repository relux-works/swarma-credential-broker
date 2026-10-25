//go:build linux

package qualify

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

type fixtureConfiguration struct {
	Broker   string `json:"broker"`
	Allowed  string `json:"allowed_peer"`
	Foreign  string `json:"foreign_peer"`
	Account  string `json:"account"`
	SameUser bool   `json:"same_user_r2"`
}

func fixturePolicy(path string, p policy.Policy) (policy.Policy, error) {
	b, e := store.ReadProtected(path, uint32(os.Geteuid()))
	var f fixtureConfiguration
	if e != nil || wire.Decode(b, &f) != nil {
		return policy.Policy{}, qualification.ErrUnavailable
	}
	resolve := func(name string) (uint32, error) {
		u, e := user.Lookup(name)
		if e != nil {
			return 0, e
		}
		n, e := strconv.ParseUint(u.Uid, 10, 32)
		return uint32(n), e
	}
	broker, e := resolve(f.Broker)
	if e != nil || broker != p.BrokerUID || broker != uint32(os.Geteuid()) {
		return policy.Policy{}, qualification.ErrUnavailable
	}
	allowed, e := resolve(f.Allowed)
	if e != nil || allowed != uint32(os.Geteuid()) || allowed == broker && !f.SameUser {
		return policy.Policy{}, qualification.ErrUnavailable
	}
	// This first transport slice never substitutes a UID for a missing foreign
	// process. peer-denied remains pending; its separate genuine helper is later.
	if f.Foreign == "" || f.Account == "" {
		return policy.Policy{}, qualification.ErrUnavailable
	}
	for _, a := range p.Accounts {
		if a.Label == f.Account && a.Enabled {
			found := false
			for _, uid := range a.AllowedUIDs {
				found = found || uid == allowed
			}
			if !found {
				return policy.Policy{}, qualification.ErrUnavailable
			}
			q := p.Clone()
			a.AllowedUIDs = []uint32{allowed}
			q.Accounts = []policy.Account{a}
			return q, nil
		}
	}
	return policy.Policy{}, qualification.ErrUnavailable
}

type rowArtifact struct {
	Kind            string                   `json:"kind"`
	Candidate       string                   `json:"candidate"`
	ID              string                   `json:"id"`
	Side            string                   `json:"side"`
	Control         qualification.Control    `json:"control"`
	Observation     rowObservation           `json:"observation"`
	Network         map[string]egress.Counts `json:"network"`
	IsolationFailed bool                     `json:"isolation_failed"`
	Incomplete      bool                     `json:"incomplete"`
}

func rowFile(root, id, side string) string { return filepath.Join(root, "row-"+id+"-"+side+".json") }

func validateRow(root, digest string, generation uint64, c qualification.Case) error {
	if !rowImplemented(c.ID) {
		return qualification.ErrUnavailable
	}
	for side, x := range map[string]qualification.Control{"positive": c.Positive, "negative": c.Negative} {
		if !x.Executed || len(x.Artifacts) != 1 || x.DurationNS <= 0 || x.DurationNS > x.BoundNS || x.BoundNS != int64(30*time.Second) || x.ExitCode < 0 || x.ExitCode > 255 || !reflect.DeepEqual(x.Command, qualification.CaseCommand(c.ID, side)) {
			return qualification.ErrUnavailable
		}
		b, e := store.ReadProtected(rowFile(root, c.ID, side), uint32(os.Geteuid()))
		var a rowArtifact
		if e != nil || qualification.Hash(b) != x.Artifacts[0] || wire.Decode(b, &a) != nil || a.Kind != "qualification-row-control/1" || a.Candidate != digest || a.ID != c.ID || a.Side != side {
			return qualification.ErrUnavailable
		}
		x.Artifacts = []string{}
		if !reflect.DeepEqual(a.Control, x) {
			return qualification.ErrUnavailable
		}
		if x.Verdict == "passed" {
			want := rowPositive(c.ID)
			if side == "negative" {
				want = rowRefusal(c.ID)
			}
			o := a.Observation
			if x.ExitCode != 0 || !rowIsolated(a) || o.ID != c.ID || o.Side != side || o.Candidate != digest || !o.NoEffects || !validRowEnvelopes(o, generation) || !validAdmissionEffects(o) || o.Refusal != want || o.ProbeFault != (c.ID == "peer-identity-unavailable" && side == "negative") {
				return qualification.ErrUnavailable
			}
		} else if x.Verdict != "failed" {
			return qualification.ErrUnavailable
		}
	}
	return nil
}

func rowIsolated(a rowArtifact) bool {
	if a.IsolationFailed || a.Incomplete || a.Network == nil {
		return false
	}
	for class, count := range a.Network {
		if count.Refused != 0 || (class == "external" || class == "loopback" || class == "other") && count.Allowed != 0 {
			return false
		}
	}
	return true
}

func (d driver) runRows(ctx context.Context, configuration string, p policy.Policy, root string, cases []qualification.Case) {
	q, e := fixturePolicy(configuration, p)
	if e != nil {
		return
	}
	for n := range cases {
		c := &cases[n]
		if !rowImplemented(c.ID) {
			continue
		}
		c.Positive = d.runRow(ctx, q, root, c.ID, "positive")
		c.Negative = d.runRow(ctx, q, root, c.ID, "negative")
		if validateRow(root, p.ExecutableSHA256, p.Generation, *c) != nil {
			// Unverifiable evidence is never credited, including a missing
			// positive control. Retain no fabricated execution or artifact.
			pending := qualification.Pending(qualification.Identity{})
			for _, row := range pending.Cases {
				if row.ID == c.ID {
					*c = row
					break
				}
			}
		}
	}
}

func (d driver) runRow(parent context.Context, p policy.Policy, root, id, side string) (control qualification.Control) {
	control = qualification.Control{Verdict: "pending", ExitCode: -1, Command: []string{}, Artifacts: []string{}, BoundNS: int64(30 * time.Second)}
	if !rowImplemented(id) || side != "positive" && side != "negative" {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	broker, e := os.Open("/proc/self/exe")
	if d.rowExecutable != "" {
		if broker != nil {
			broker.Close()
		}
		broker, e = qualification.OpenExecutable(d.rowExecutable)
	}
	if e != nil {
		return
	}
	defer broker.Close()
	candidate, e := qualification.OpenExecutable(p.Executable)
	if e != nil {
		return
	}
	defer candidate.Close()
	digest, e := descriptorDigest(candidate)
	if e != nil || digest != p.ExecutableSHA256 {
		return
	}
	if _, e = candidate.Seek(0, io.SeekStart); e != nil {
		return
	}
	// Unix sockaddr limits require the documented short qualification TMPDIR;
	// evidence paths may themselves be long. Homes remain fresh owned 0700.
	scratch, e := os.MkdirTemp("", "qualification-row-")
	if e != nil {
		return
	}
	defer func() {
		if os.RemoveAll(scratch) != nil {
			control.Verdict = "pending"
			control.Executed = false
			control.ExitCode = -1
			control.Command = []string{}
			control.Artifacts = []string{}
			control.DurationNS = 0
		}
	}()
	home := filepath.Join(scratch, "home")
	if os.Mkdir(home, 0700) != nil {
		return
	}
	var pid atomic.Int64
	inputValue := rowInput{Policy: p, Peer: uint32(os.Geteuid()), ID: id, Side: side}
	var socket string
	var closeRow func() bool
	var phaseFiles []*os.File
	var effects admissionEffects
	if admissionRow(id) {
		inputValue = admissionInput(inputValue)
		socket, closeRow, phaseFiles, e = startAdmissionRow(ctx, scratch, inputValue, &pid, &effects)
	} else {
		socket, closeRow, e = startTransportRow(ctx, scratch, inputValue, &pid)
	}
	for _, f := range phaseFiles {
		defer f.Close()
	}
	if e != nil {
		return
	}
	closed := false
	defer func() {
		if !closed {
			closeRow()
		}
	}()
	inputValue.Socket = socket
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return
	}
	defer unix.Close(fd)
	if unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}) != nil {
		return
	}
	addr, e := unix.Getsockname(fd)
	if e != nil {
		return
	}
	env, e := egress.ProxyEnvironment([]string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, uint16(addr.(*unix.SockaddrInet4).Port), nil)
	if e != nil {
		return
	}
	input, e := wire.Encode(inputValue)
	if e != nil || len(input) > 4096 {
		return
	}
	inputR, inputW, e := os.Pipe()
	if e != nil {
		return
	}
	defer inputR.Close()
	n, e := inputW.Write(input)
	closeError := inputW.Close()
	if e != nil || n != len(input) || closeError != nil {
		return
	}
	outR, outW, e := os.Pipe()
	if e != nil {
		return
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, e := os.Pipe()
	if e != nil {
		return
	}
	defer errR.Close()
	defer errW.Close()
	stop := context.AfterFunc(ctx, func() { outR.Close(); errR.Close() })
	defer stop()
	type capture struct {
		b []byte
		e error
	}
	output := make(chan capture, 1)
	diagnostic := make(chan capture, 1)
	collect := func(f *os.File, limit int, ch chan capture) {
		b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
		if e != nil || len(b) > limit {
			e = qualification.ErrUnavailable
			cancel()
		}
		ch <- capture{b, e}
	}
	go collect(outR, 8192, output)
	go collect(errR, 16384, diagnostic)
	command := qualification.CaseCommand(id, side)
	start := time.Now()
	report, runError := egress.Run(ctx, egress.Config{Launcher: "/proc/self/fd/4", Started: func(n int) { pid.Store(int64(n)) }, LauncherArgs: []string{"--internal-qualification-candidate"}, Executable: command[0], Args: command[1:], Env: env, Policy: egress.Policy{UnixPaths: []string{socket}, MaxEvents: 4096}, Stdout: outW, Stderr: errW, ExtraFiles: append([]*os.File{broker, inputR, candidate}, phaseFiles...)})
	elapsed := time.Since(start)
	noEffects := closeRow()
	closed = true
	outW.Close()
	errW.Close()
	out, diag := <-output, <-diagnostic
	exit := 0
	var exitError *exec.ExitError
	if runError != nil {
		if !errors.As(runError, &exitError) || exitError.ExitCode() < 0 {
			return
		}
		exit = exitError.ExitCode()
	}
	if elapsed <= 0 || elapsed > 30*time.Second {
		return
	}
	isolation := false
	for _, event := range report.Events {
		if event.Verdict == "refuse" {
			isolation = true
		}
	}
	var observation rowObservation
	observationValid := wire.Decode(out.b, &observation) == nil && validRowEnvelopes(observation, p.Generation)
	if !observationValid {
		observation = rowObservation{Envelopes: []rowEnvelope{}}
	}
	passed := noEffects && runError == nil && out.e == nil && diag.e == nil && rowIsolated(rowArtifact{Network: report.Summary, Incomplete: report.Incomplete, IsolationFailed: isolation}) && observationValid
	// Only the parent can attest that the injected server probe actually fired.
	if passed && id == "peer-identity-unavailable" && side == "negative" {
		observation.ProbeFault = true
	}
	if admissionRow(id) {
		observation.Admission = &effects
	}
	control = qualification.Control{Verdict: "failed", Executed: true, Command: command, ExitCode: exit, Artifacts: []string{}, DurationNS: int64(elapsed), BoundNS: int64(30 * time.Second)}
	if passed {
		control.Verdict = "passed"
	}
	a := rowArtifact{"qualification-row-control/1", p.ExecutableSHA256, id, side, control, observation, report.Summary, isolation, report.Incomplete}
	b, e := wire.Encode(a)
	if e != nil {
		return
	}
	f, e := os.OpenFile(rowFile(root, id, side), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	n, e = f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return
	}
	control.Artifacts = []string{qualification.Hash(b)}
	return
}
