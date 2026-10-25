//go:build linux

package qualify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/authowner"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var errOwnerHeld = errors.New("owner synchronous call held")

type lifecycleGate struct {
	Phase, Context, Nonce, Prefix, State string
	Call                                 int
}
type lifecycleModel struct {
	c                              ownerContext
	ctx                            context.Context
	broker                         *os.File
	initial                        time.Time
	writers                        []*lifecycleWriter
	writer                         *lifecycleWriter
	before                         authowner.Observation
	starts, native, stops, entries int
	peak                           int
	gate                           *lifecycleGate
	held                           *ownerMessage
	inputs                         []ownerStopFact
	endpoint                       []string
	audit                          *lifecycleAudit
}

func (m *lifecycleModel) setContext(c ownerContext) { m.c = c }
func (m *lifecycleModel) identity() authowner.Identity {
	return authowner.Identity{Boot: "synthetic-boot", UID: uint32(os.Geteuid()), Epoch: "synthetic-epoch"}
}
func (m *lifecycleModel) records() (authowner.Checkpoint, []authowner.Intent, []authowner.Evidence, error) {
	return ownerRecordsBound(m.c.Root, 32)
}
func (m *lifecycleModel) prefix() (string, error) {
	cp, is, es, e := m.records()
	if e != nil {
		return "", e
	}
	b, e := os.ReadFile(filepath.Join(m.c.Root, "home", "auth.json"))
	if e != nil {
		return "", e
	}
	raw, e := wire.Encode([]any{cp, is, es, qualificationHash(b), m.starts, m.native, m.stops, m.endpoint})
	if e != nil {
		return "", e
	}
	return qualificationHash(raw), nil
}
func (m *lifecycleModel) phase(phase string) bool {
	cp, is, es, e := m.records()
	nativeCount, endpointCount := 3, 1
	if phase == "running" {
		nativeCount, endpointCount = 0, 0
	}
	if e != nil || len(is) != 1 || cp.PendingAttempt != is[0].Attempt || cp.TokenGeneration != 1 || cp.StoreGeneration != 1 || cp.State != "owner_unavailable" || m.starts != 1 || m.native != nativeCount || m.writer == nil {
		return false
	}
	want := 2
	if phase == "stop-before-absence" {
		want = 3
	}
	if len(es) != want || es[0].Phase != "submitted" || es[1].Phase != "running" || es[1].Observation != m.before {
		return false
	}
	if want == 3 && (es[2].Phase != "stopping" || es[2].RPC != authowner.Committed || !m.writer.fact.Stop.Valid()) {
		return false
	}
	native, e := os.ReadFile(filepath.Join(m.c.Root, "home", "auth.json"))
	if e != nil {
		return false
	}
	old, _ := ownerMaterial(m.initial, "initial")
	next, _ := ownerMaterial(m.initial, "replacement")
	expected := next
	if phase == "rotation-no-store" || phase == "running" {
		expected = old
	}
	return qualificationHash(native) == qualificationHash(expected) && cp.StoreDigest == qualificationHash(old) && len(m.endpoint) == endpointCount
}
func (m *lifecycleModel) hold(req ownerMessage, phase string) error {
	if m.held != nil || m.gate != nil || !m.phase(phase) {
		return errors.New("owner gate prefix mismatch")
	}
	prefix, e := m.prefix()
	if e != nil {
		return e
	}
	m.held = &req
	m.gate = &lifecycleGate{Phase: phase, Prefix: prefix, State: "checked", Call: req.ID}
	ownerDiagnosticPhase(m.ctx, "crash gate held")
	return errOwnerHeld
}
func (m *lifecycleModel) crash(s *ownerSession) error {
	g := m.gate
	if g == nil || g.State != "checked" || m.held == nil || !m.phase(g.Phase) {
		return errors.New("owner crash gate not held")
	}
	prefix, e := m.prefix()
	if e != nil || prefix != g.Prefix {
		return errors.New("owner crash gate changed")
	}
	g.Context = s.command[2]
	g.Nonce = lease.RandomID()
	g.State = "sealed"
	data, _ := wire.Encode(g)
	digest := qualificationHash(data)
	endKill := ownerDiagnosticWait(m.ctx, "owner kill certificate")
	e = s.termination.Kill(m.ctx, digest)
	endKill(e)
	if e != nil {
		return e
	}
	g.State = "kill-sent"
	endJoin := ownerDiagnosticWait(m.ctx, "owner crash join")
	<-s.done
	endJoin(nil)
	f := s.termination.Facts()
	if !f.Valid() || f.Context != g.Context || f.Gate != digest || s.err == nil || !s.report.Incomplete || s.waits != 1 {
		return errors.New("owner crash certificate missing")
	}
	g.State = "terminal-joined"
	if g.Phase != "stop-before-absence" {
		if e = m.writer.challenge(); e != nil {
			return e
		}
		m.writer.fact.Survived = true
	}
	return nil
}
func (m *lifecycleModel) serve(ch *ownerChannel, req ownerMessage) error {
	if req.Op == "start" {
		m.starts++ // Count even attempts rejected by the audit or request validation.
	}
	if req.Op != "confidence" {
		m.entries++
	}
	if m.entries > 64 {
		return errors.New("owner lifecycle budget")
	}
	if e := m.audit.drain(req.Op); e != nil {
		return e
	}
	var result any
	switch req.Op {
	case "ready", "owned":
	case "identity":
		result = m.identity()
	case "confidence":
		var q struct {
			Label, Home string
			Generation  uint64
			Lower       time.Time
		}
		generationLimit := uint64(2)
		if parallelScenario(m.c.Scenario) {
			generationLimit = 3
		}
		if wire.Decode(req.Data, &q) != nil || q.Label != ownerLabel || q.Home != m.c.HomeID || q.Generation < 1 || q.Generation > generationLimit || q.Lower.After(m.c.Now) {
			return errors.New("lifecycle confidence binding")
		}
		if m.c.Epoch == 1 && parallelUnresolved(m.c.Scenario) && m.phase("running") {
			if e := m.writer.challenge(); e != nil {
				return e
			}
			return m.hold(req, "running")
		}
		if m.c.Epoch == 1 && m.native == 3 && (m.c.Scenario == "rotation-no-store" || m.c.Scenario == "rotation-no-proof") {
			return m.hold(req, m.c.Scenario)
		}
		result = authowner.TimeEvidence{Now: m.c.Now, AuthorityUntil: m.c.Now.Add(time.Minute), Trusted: true, Fresh: true}
	case "start":
		cap := 1
		if parallelScenario(m.c.Scenario) && !parallelUnresolved(m.c.Scenario) {
			cap = 2
		}
		if m.c.Scenario == "safe-safe-committed" {
			cap = 3
		}
		if m.starts > cap || m.writer != nil && !m.writer.fact.Stop.Valid() {
			return errors.New("unexpected lifecycle Start or writer overlap")
		}
		var spec struct {
			Name, Daemon, Executable, Home, Digest string
			Args, Environment                      []string
			Runtime                                time.Duration
		}
		cp, is, es, e := m.records()
		sort.Slice(is, func(i, j int) bool { return is[i].Sequence < is[j].Sequence })
		if e != nil || len(is) != m.starts || wire.Decode(req.Data, &spec) != nil {
			return errors.New("lifecycle start records")
		}
		intent := is[len(is)-1]
		if cp.PendingAttempt != intent.Attempt || cp.State != "owner_unavailable" || spec.Name != intent.Unit || spec.Daemon != "synthetic-owner.service" || spec.Executable != "/proc/self/fd/6" || spec.Home != filepath.Join(m.c.Root, "home") || spec.Digest != m.c.Candidate || strings.Join(spec.Args, " ") != "app-server" || spec.Runtime != 120*time.Second || strings.Join(spec.Environment, "\x00") != strings.Join([]string{"HOME=" + spec.Home, "CODEX_HOME=" + spec.Home, "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}, "\x00") {
			return errors.New("lifecycle start binding")
		}
		if parallelScenario(m.c.Scenario) && m.starts > 1 {
			if e := m.successorOrder(cp, is, es); e != nil {
				return e
			}
		}
		which := "replacement"
		if parallelScenario(m.c.Scenario) && m.starts > 1 {
			which = "successor"
		}
		native, _ := ownerMaterial(m.initial, which)
		w, e := startWriter(m.ctx, m.c, m.broker, intent.Attempt, native)
		if w != nil {
			m.writers = append(m.writers, w)
		}
		if e != nil {
			return e
		}
		m.writer = w
		if e = writerPeak(m.writers, &m.peak); e != nil {
			return e
		}
		if e = w.challenge(); e != nil {
			return e
		}
		m.before = authowner.Observation{Identity: m.identity(), Unit: spec.Name, Invocation: intent.Attempt, Cgroup: "/synthetic-singleton/" + intent.Attempt, CgroupID: intent.Attempt, MainPID: uint32(w.session.pid.Load()), ProcessStart: w.fact.Start, Properties: "synthetic-properties", Active: "active", Substate: "running", Complete: true, RestartNo: true, Observed: m.c.Now}
		m.native = 0
	case "observe":
		var name string
		if wire.Decode(req.Data, &name) != nil || name != m.before.Unit {
			return errors.New("lifecycle observe binding")
		}
		result = m.before
	case "native":
		m.native++
		var v struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(req.Data, &v) != nil {
			return errors.New("lifecycle native frame")
		}
		switch m.native {
		case 1:
			if v.ID != 1 || v.Method != "initialize" || !strings.Contains(string(v.Params), `"experimentalApi":false`) {
				return errors.New("lifecycle initialize")
			}
			result = json.RawMessage(`{"id":1,"result":{}}`)
		case 2:
			if v.ID != 0 || v.Method != "initialized" {
				return errors.New("lifecycle initialized")
			}
			result = json.RawMessage("null")
		case 3:
			if v.ID != 2 || v.Method != "account/read" || string(v.Params) != `{"refreshToken":true}` {
				return errors.New("lifecycle native refresh")
			}
			safe := m.c.Scenario == "safe-safe-committed" && m.starts < 3
			if safe {
				m.endpoint = append(m.endpoint, "unchanged")
				result = json.RawMessage(`{"id":2,"error":{"code":1001}}`)
				if m.starts == 1 {
					m.c.Now = m.c.Now.Add(3 * time.Second)
				}
			} else {
				m.endpoint = append(m.endpoint, "rotated")
				if m.c.Scenario != "ambiguous-old" && m.c.Scenario != "rotation-no-store" {
					m.audit.native = true
					if e := m.writer.persist(); e != nil {
						return e
					}
					if e := m.audit.drain("writer"); e != nil {
						return e
					}
					m.audit.native = false
				}
				if m.c.Scenario == "ambiguous-old" || m.c.Scenario == "ambiguous-new" || m.c.Scenario == "rotation-no-store" {
					result = json.RawMessage(`{"id":2,"error":{"code":1002}}`)
				} else {
					result = json.RawMessage(`{"id":2,"result":{"requiresOpenaiAuth":true,"account":{"type":"chatgpt","planType":"plus"}}}`)
				}
			}
		default:
			return errors.New("lifecycle native budget")
		}
	case "stop":
		m.stops++
		var before authowner.Observation
		if wire.Decode(req.Data, &before) != nil || before != m.before || m.writer == nil || m.stops > 4 {
			return errors.New("lifecycle stop binding")
		}
		if m.c.Epoch == 2 && parallelPartial(m.c.Scenario) {
			if e := m.writer.challenge(); e != nil {
				return e
			}
			after := before
			after.Complete = false
			after.StopCompleted = false
			after.Empty = false
			after.PopulatedZero = false
			m.inputs = append(m.inputs, ownerStopFact{Before: before, After: after})
			result = after
			break
		}
		if !m.writer.fact.Stop.Valid() {
			if e := m.writer.stop(m.ctx, fmt.Sprint(req.ID)); e != nil {
				return e
			}
		}
		if m.c.Epoch == 1 && strings.HasPrefix(m.c.Scenario, "cleanup-") {
			return m.hold(req, "stop-before-absence")
		}
		result = before
		v := before
		v.MainPID = 0
		v.Active = "inactive"
		v.Substate = "dead"
		v.StopCompleted = true
		v.Empty = true
		v.PopulatedZero = true
		if m.c.Epoch == 2 && m.c.Scenario == "cleanup-incomplete" {
			v.Complete = false
		}
		result = v
		m.inputs = append(m.inputs, ownerStopFact{Before: before, After: v})
	case "unload":
		cp, _, es, e := m.records()
		if e != nil || cp.PendingAttempt != "" || len(es) < 5 || !m.writer.fact.Stop.Valid() {
			return errors.New("terminal gate missing durable resolution")
		}
	default:
		return fmt.Errorf("unexpected lifecycle method %s", req.Op)
	}
	return ch.send(req.Op, result, nil)
}
