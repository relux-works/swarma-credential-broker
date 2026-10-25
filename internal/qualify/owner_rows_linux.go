//go:build linux

package qualify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

func ownerRow(id string) bool { return id == "store-missing" || id == "absence-unreadable" }

type ownerBudget struct{ Requests, Renewals, Releases, Prerequisites int }
type ownerService interface {
	setContext(ownerContext)
	serve(*ownerChannel, ownerMessage) error
}
type ownerEpochFact struct {
	Command                   [3]string
	Image                     string
	Verified, Entered, Joined bool
	Exit, Waits               int
}
type ownerScenarioFact struct {
	Origins            []ownerEpochFact
	Inputs             []ownerStopFact
	Scenario, Recovery string
	Budgets            []ownerBudget
	Startup            []string
	Starts, Stops      int
	Generation         uint64
	Audited            bool
	Inventory          [3]int
	Tombstones         int
}
type ownerRowFacts struct {
	Scope     string
	Scenarios []ownerScenarioFact
}
type ownerSession struct {
	ch          *ownerChannel
	origin      *egress.CaseOrigin
	model       ownerService
	termination *egress.TerminationController
	done        chan struct{}
	cancel      context.CancelFunc
	pid         atomic.Int64
	execution   rowExecution
	report      egress.Report
	err         error
	waits       int
	command     [3]string
	image       string
	budget      ownerBudget
}

func startOwner(ctx context.Context, c ownerContext, broker, candidate *os.File, model ownerService) (*ownerSession, error) {
	return startOwnedRole(ctx, c, broker, candidate, model, false)
}
func startOwnedRole(ctx context.Context, c ownerContext, broker, candidate *os.File, model ownerService, writer bool) (*ownerSession, error) {
	cr, cw, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer cw.Close()
	inR, inW, e := os.Pipe()
	if e != nil {
		cr.Close()
		return nil, e
	}
	outR, outW, e := os.Pipe()
	if e != nil {
		cr.Close()
		inR.Close()
		inW.Close()
		return nil, e
	}
	files := []*os.File{cr, inR, inW, outR, outW}
	fail := func(e error) (*ownerSession, error) {
		for _, f := range files {
			f.Close()
		}
		return nil, e
	}
	if _, e = broker.Seek(0, io.SeekStart); e != nil {
		return fail(e)
	}
	c.Image, e = descriptorDigest(broker)
	if e != nil {
		return fail(e)
	}
	b, e := wire.Encode(c)
	if e != nil || len(b) > 4096 {
		return fail(errors.New("owner context budget"))
	}
	if _, e = cw.Write(b); e != nil {
		return fail(e)
	}
	cw.Close()
	digest := qualificationHash(b)
	var o *egress.CaseOrigin
	var termination *egress.TerminationController
	role := "qualification-owner"
	if writer {
		role = "qualification-writer"
		o, termination, e = egress.NewWriterOrigin(broker, digest)
	} else if lifecycleScenario(c.Scenario) {
		o, termination, e = egress.NewCrashOwnerOrigin(broker, digest)
	} else {
		o, e = egress.NewOwnerOrigin(broker, digest)
	}
	if e != nil {
		return fail(e)
	}
	candidate.Seek(0, io.SeekStart)
	child, cancel := context.WithCancel(ctx)
	command := [3]string{"/proc/self/fd/4", role, digest}
	s := &ownerSession{image: c.Image, command: command, ch: &ownerChannel{r: outR, w: inW}, origin: o, model: model, done: make(chan struct{}), cancel: cancel, execution: newRowExecution()}
	s.termination = termination
	if model != nil {
		model.setContext(c)
	}
	if termination != nil {
		s.ch.limit = 512
	}
	deadline, _ := ctx.Deadline()
	if outR.SetReadDeadline(deadline) != nil || inW.SetWriteDeadline(deadline) != nil {
		cancel()
		o.Close()
		return fail(errors.New("owner pipe deadline"))
	}
	go func() {
		defer close(s.done)
		defer cr.Close()
		defer inR.Close()
		defer outW.Close()
		s.report, s.err = egress.Run(child, egress.Config{Origin: o, Launcher: "/proc/self/fd/4", LauncherArgs: []string{"--internal-qualification-candidate"}, Executable: command[0], Args: command[1:], Env: []string{"GOMAXPROCS=2", "LANG=C.UTF-8"}, Policy: egress.Policy{MaxEvents: 4096}, ExtraFiles: []*os.File{broker, cr, candidate, outW, inR}, Started: func(pid int) {
			s.execution.Launched = true
			s.pid.Store(int64(pid))
			cr.Close()
			inR.Close()
			outW.Close()
		}, Waited: func(state *os.ProcessState) { s.waits++; s.execution.waited(state) }})
		f := o.Facts()
		s.execution.Handshake = f.Verified
		s.execution.Started = f.Entered
		if f.Verified && f.Entered && f.Joined && s.execution.Joined {
			s.execution.Completed = true
			s.execution.attested = true
			s.execution.WorkerExit = s.execution.HelperExit
			s.execution.CaseExit = s.execution.HelperExit
		}
	}()
	return s, nil
}
func (s *ownerSession) receive(op string) (ownerMessage, error) {
	for {
		m, e := s.ch.read()
		if e != nil {
			return m, fmt.Errorf("owner %s effects missing: %w", op, e)
		}
		if m.Op == op {
			return m, nil
		}
		if !s.origin.Live(int(s.pid.Load())) {
			return m, errors.New("model authority before owner entry")
		}
		if s.model == nil {
			return m, errors.New("unexpected writer method")
		}
		if e = s.model.serve(s.ch, m); e != nil {
			return m, e
		}
	}
}
func (s *ownerSession) call(op string, v any, want string) (wire.LeaseResult, error) {
	var result wire.LeaseResult
	switch op {
	case "lease.request":
		s.budget.Requests++
	case "lease.renew":
		s.budget.Renewals++
	case "lease.release":
		s.budget.Releases++
	case "prerequisite":
		s.budget.Prerequisites++
	}
	b := s.budget
	renewals := 3
	if s.termination != nil {
		renewals = 5
	}
	if b.Requests > 3 || b.Renewals > renewals || b.Releases > 2 || b.Prerequisites > 2 || b.Requests+b.Renewals+b.Releases > 8 {
		return result, errors.New("owner scenario budget exhausted")
	}
	if e := s.ch.send(op, v, nil); e != nil {
		return result, e
	}
	m, e := s.receive(op)
	if e != nil {
		return result, e
	}
	if m.Error != want || want != "" && len(m.Data) != 0 && string(m.Data) != "null" {
		return result, fmt.Errorf("owner %s expected %q refusal/no payload, got %q", op, want, m.Error)
	}
	if want == "" && (op == "lease.request" || op == "lease.renew") {
		if wire.Decode(m.Data, &result) != nil || result.Payload.AccessToken == "" {
			return result, errors.New("owner publication missing")
		}
	}
	if want == "" && op == "lease.release" {
		var r wire.ReleaseResult
		if wire.Decode(m.Data, &r) != nil || r.State != "released" {
			return result, errors.New("owner release effect missing")
		}
	}
	return result, nil
}
func (s *ownerSession) close() error {
	defer s.origin.Close()
	defer s.ch.r.Close()
	defer s.ch.w.Close()
	defer s.cancel()
	if e := s.ch.send("close", nil, nil); e != nil {
		s.cancel()
	}
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		s.cancel()
		s.ch.r.Close()
		s.ch.w.Close()
		<-s.done
	}
	if s.err != nil || s.waits != 1 || !s.execution.credit(false) || s.execution.CaseExit != 0 || !rowIsolated(rowArtifact{Network: s.report.Summary, Incomplete: s.report.Incomplete}) {
		return fmt.Errorf("owner origin/lifecycle incomplete: %v %+v", s.err, s.execution)
	}
	return nil
}
func ownerFault(root, scenario string) error {
	path := filepath.Join(root, "home")
	switch {
	case strings.HasPrefix(scenario, "native-"):
		path = filepath.Join(path, "auth.json")
	case strings.HasPrefix(scenario, "intent-"):
		names, e := filepath.Glob(filepath.Join(ownerAccountPath(root), "owner-attempt-*-000001.json"))
		if e != nil || len(names) != 1 {
			return errors.New("fault intent missing")
		}
		path = names[0]
	case strings.HasPrefix(scenario, "checkpoint-"):
		path = filepath.Join(ownerAccountPath(root), "owner-checkpoint.json")
	case scenario == "metadata-absent":
		path = filepath.Join(root, "metadata")
	}
	if strings.Contains(scenario, "-mode") {
		mode := os.FileMode(0644)
		if scenario == "home-mode" {
			mode = 0750
		}
		return os.Chmod(path, mode)
	}
	return os.RemoveAll(path)
}

// ownerScenarioRun uses at most two independently attested constructions. The
// parent owns scripts, premises, effects and counts; no child pass flag exists.
func ownerScenarioRun(ctx context.Context, broker, candidate *os.File, digest, scenario, recovery string) (fact ownerScenarioFact, exec rowExecution, network map[string]egress.Counts, err error) {
	fact.Scenario, fact.Recovery = scenario, recovery
	network = map[string]egress.Counts{}
	root, e := os.MkdirTemp("", "qualification-owner-")
	if e != nil {
		err = e
		return
	}
	defer func() {
		if e := os.RemoveAll(root); e != nil {
			err = errors.Join(err, errors.New("owner cleanup failed"))
		}
	}()
	c, tokens, e := ownerSeed(root, digest, scenario)
	if e != nil {
		err = e
		return
	}
	model := &ownerModel{c: c, mode: "complete", inputs: []ownerStopFact{}}
	isStore := scenario != "current" && scenario != "complete" && !containsOwner(ownerAbsenceFaults, scenario)
	if containsOwner(ownerAbsenceFaults, scenario) || strings.HasSuffix(scenario, "-pending") {
		model.mode = scenario
		if isStore {
			model.mode = "partial"
		}
	}
	var audit *ownerAudit
	var baseline map[string]ownerFile
	defer func() {
		fact.Starts, fact.Stops = model.starts, model.stops
		fact.Inputs = model.inputs
		if audit != nil {
			if e := audit.seal(root, baseline); e != nil {
				err = errors.Join(err, e)
			} else {
				fact.Audited = true
				fact.Inventory = [3]int{len(audit.before), len(baseline), len(audit.after)}
				fact.Tombstones = len(audit.tombstones)
			}
			unix.Close(audit.fd)
		}
	}()
	absorb := func(s *ownerSession) error {
		e := s.close()
		fact.Budgets = append(fact.Budgets, s.budget)
		fact.Origins = append(fact.Origins, ownerEpochFact{s.command, s.image, s.execution.Handshake, s.execution.Started, s.execution.Joined, s.execution.CaseExit, s.waits})
		exec = s.execution
		for k, v := range s.report.Summary {
			n := network[k]
			n.Allowed += v.Allowed
			n.Refused += v.Refused
			network[k] = n
		}
		return e
	}
	for epoch := 1; epoch <= 2; epoch++ {
		c.Epoch = epoch
		if epoch == 2 && recovery == "complete-on-construction" {
			model.mode = "complete"
		}
		s, e := startOwner(ctx, c, broker, candidate, model)
		if e != nil {
			err = e
			return
		}
		run := func() error {
			startup, e := s.receive("startup")
			if e != nil {
				return e
			}
			var stage string
			if wire.Decode(startup.Data, &stage) != nil {
				return errors.New("owner startup stage missing")
			}
			status := stage + "-ready"
			if startup.Error != "" {
				status = stage + "-refused"
			}
			fact.Startup = append(fact.Startup, status)
			if startup.Error != "" {
				if epoch != 2 || !isStore || startup.Error != "owner_startup_refused" || stage != "store" && stage != "owner" && stage != "lease" {
					return errors.New("unexpected startup refusal")
				}
				return nil
			}
			want := ""
			if epoch == 2 && (isStore || containsOwner(ownerAbsenceFaults, scenario) && recovery != "complete-on-construction") {
				want = "lease_owner_unavailable"
			}
			grant, e := s.call("lease.request", nil, want)
			if e != nil {
				return e
			}
			if want != "" {
				return nil
			}
			expected := tokens[0]
			if epoch == 2 && scenario != "current" {
				expected = tokens[1]
			}
			if grant.Payload.AccessToken != expected || grant.Payload.AccountID != "synthetic-vendor" || grant.Payload.PlanType != "plus" {
				return errors.New("owner payload correlation")
			}
			renew := wire.Renew{LeaseID: grant.LeaseID, RejectedSHA256: lease.Digest(tokens[0])}
			refresh := epoch == 1 && (scenario == "complete" || containsOwner(ownerAbsenceFaults, scenario) || strings.HasPrefix(scenario, "intent-"))
			if refresh {
				refusal := ""
				if model.mode != "complete" {
					refusal = "lease_owner_unavailable"
				}
				rotated, e := s.call("lease.renew", renew, refusal)
				if e != nil {
					return e
				}
				if refusal == "" && rotated.Payload.AccessToken != tokens[1] {
					return errors.New("owner rotation not published")
				}
				if _, e = s.call("lease.renew", renew, refusal); e != nil {
					return e
				}
				cp, intents, events, e := ownerRecords(root)
				if e != nil || len(intents) != 1 || intents[0].Attempt != model.attempt {
					return errors.New("owner retained attempt missing")
				}
				if refusal == "" {
					if cp.State != "active" || cp.StoreGeneration != 2 || cp.TokenGeneration != 2 || cp.LastAttempt != model.attempt || events[len(events)-1].Phase != "resolved" {
						return errors.New("owner resolution missing")
					}
				} else if cp.State != "owner_unavailable" || cp.StoreGeneration != 1 || cp.PendingAttempt != model.attempt || events[len(events)-1].Phase != "stopping" {
					return errors.New("incomplete absence resolved")
				}
			}
			if _, e = s.call("lease.release", wire.Release{LeaseID: grant.LeaseID}, ""); e != nil {
				return e
			}
			if epoch == 1 && isStore {
				audit, e = newOwnerAudit(root)
				if e != nil {
					return e
				}
				if e = ownerFault(root, scenario); e != nil {
					return e
				}
				if e = audit.drain(true); e != nil {
					return e
				}
				audit.retireMissing()
				baseline, e = ownerInventory(root)
				if e != nil {
					return e
				}
				for i := 0; i < 2; i++ {
					if _, e = s.call("lease.request", nil, "lease_owner_unavailable"); e != nil {
						return e
					}
				}
			} else if epoch == 1 && containsOwner(ownerAbsenceFaults, scenario) {
				if _, e = s.call("lease.request", nil, "lease_owner_unavailable"); e != nil {
					return e
				}
				if _, e = s.call("prerequisite", nil, "lease_owner_unavailable"); e != nil {
					return e
				}
			}
			if epoch == 1 && containsOwner(ownerAbsenceFaults, scenario) {
				if e = ownerReleasedRecords(root, 1); e != nil {
					return e
				}
			}
			return nil
		}
		err = run()
		err = errors.Join(err, absorb(s))
		if err != nil {
			return
		}
	}
	expectedStarts := 0
	if scenario == "complete" || containsOwner(ownerAbsenceFaults, scenario) || strings.HasPrefix(scenario, "intent-") {
		expectedStarts = 1
	}
	if model.starts != expectedStarts || expectedStarts == 1 && model.native != 3 {
		err = errors.New("unexpected model start/native count")
		return
	}
	if !isStore {
		cp, intents, _, e := ownerRecords(root)
		if e != nil {
			err = e
			return
		}
		fact.Generation = cp.StoreGeneration
		expectedRecords := 2
		if containsOwner(ownerAbsenceFaults, scenario) && recovery != "complete-on-construction" {
			expectedRecords = 1
		}
		if err = ownerReleasedRecords(root, expectedRecords); err != nil {
			return
		}
		expected := uint64(1)
		if scenario == "complete" || recovery == "complete-on-construction" {
			expected = 2
		}
		native, token := ownerMaterial(c.Now, "initial")
		if expected == 2 {
			native, token = ownerMaterial(c.Now, "replacement")
		}
		homeID, e := authowner.HomeIdentity(filepath.Join(root, "home"))
		if e != nil || homeID != c.HomeID || cp.HomeID != c.HomeID || cp.StoreDigest != qualificationHash(native) || cp.TokenDigest != lease.Digest(token) || cp.TokenGeneration != expected {
			err = errors.New("durable material/home correlation")
			return
		}
		actualNative, e := os.ReadFile(filepath.Join(root, "home", "auth.json"))
		if expectedStarts == 1 {
			native, _ = ownerMaterial(c.Now, "replacement")
		}
		if e != nil || qualificationHash(actualNative) != qualificationHash(native) {
			err = errors.New("native write correlation")
			return
		}
		if cp.StoreGeneration != expected || expectedStarts == 1 && (len(intents) != 1 || intents[0].Attempt != model.attempt) {
			err = errors.New("recovery generation/attempt mismatch")
		}
	}
	return
}
func containsOwner(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
