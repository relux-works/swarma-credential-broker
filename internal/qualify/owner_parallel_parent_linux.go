//go:build linux

package qualify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

type parallelEvent struct {
	Member, Kind, LeaseID string
	Sequence              int
}
type parallelOverlap struct {
	First, Second, Hold              string
	Dequeue, Arrival, Resume, Queued int
}
type parallelCandidate struct {
	Error                        string
	Member, Context, Startup     string
	Constructor, Ready, LockHeld bool
	Origin                       int
}
type parallelResult struct {
	Member, Method, LeaseID, Rejected, Error, TokenDigest                    string
	Command                                                                  int
	PolicyGeneration, TokenGeneration, OfferedGeneration, ObservedGeneration uint64
	Published                                                                bool
}
type parallelFacts struct {
	Entries                                     int
	Winner                                      string
	Candidates                                  []parallelCandidate
	Together, HistoryPreserved, LiveAtAssertion bool
	Children                                    int
	Frames                                      []int
	Events                                      []parallelEvent
	Overlap                                     *parallelOverlap
	Results                                     []parallelResult
	Cleanup                                     []string
}
type parallelSession struct {
	images   []*os.File
	base     *ownerSession
	mux      *parallelMux
	service  *parallelService
	member   string
	index    int
	issued   map[int]parallelFrame
	results  map[int]parallelFrame
	finished map[int]bool
	closed   bool
}
type parallelHarness struct {
	ctx      context.Context
	ledger   *lifecycleModel
	sessions []*parallelSession
	fact     *lifecycleFact
	sequence int
	entries  int
}

func (h *parallelHarness) start(c ownerContext, broker, candidate *os.File) (*parallelSession, error) {
	images := make([]*os.File, 0, 2)
	for _, image := range []*os.File{broker, candidate} {
		f, e := os.Open(fmt.Sprintf("/proc/self/fd/%d", image.Fd()))
		if e != nil {
			for _, f := range images {
				f.Close()
			}
			return nil, e
		}
		images = append(images, f)
	}
	service := &parallelService{ledger: h.ledger}
	s, e := startOwner(h.ctx, c, images[0], images[1], service)
	if e != nil {
		for _, f := range images {
			f.Close()
		}
		return nil, e
	}
	p := &parallelSession{images: images, base: s, service: service, member: c.Member, index: len(h.sessions), issued: map[int]parallelFrame{}, results: map[int]parallelFrame{}, finished: map[int]bool{}}
	p.mux = newParallelMux(h.ctx, s.ch, s.command[2], true)
	h.sessions = append(h.sessions, p)
	h.fact.Origins = append(h.fact.Origins, ownerEpochFact{})
	h.fact.Budgets = append(h.fact.Budgets, ownerBudget{})
	h.fact.Parallel.Frames = append(h.fact.Parallel.Frames, 0)
	return p, nil
}
func (h *parallelHarness) children() error {
	n := 0
	for _, s := range h.sessions {
		if s.base.pid.Load() > 0 && !s.base.origin.Facts().Joined {
			n++
		}
	}
	for _, w := range h.ledger.writers {
		if w.session.pid.Load() > 0 && !w.session.origin.Facts().Joined {
			n++
		}
	}
	if n > h.fact.Parallel.Children {
		h.fact.Parallel.Children = n
	}
	if n > 3 {
		return errors.New("parallel child budget")
	}
	return nil
}
func (h *parallelHarness) observe(s *parallelSession, f parallelFrame) error {
	if f.Op != "confidence" && f.Op != "call-event" {
		h.fact.Parallel.Entries++
		if h.fact.Parallel.Entries > 64 {
			return errors.New("parallel lifecycle budget")
		}
	}
	if !s.base.origin.Live(int(s.base.pid.Load())) {
		return errors.New("parallel authority before live role")
	}
	if f.Op == "call-event" {
		var event lease.Event
		if wire.Decode(f.Data, &event) != nil || event.LeaseID == "" || event.Arrival.IsZero() || event.At.IsZero() || event.Kind != "arrival" && event.Kind != "dequeue" && event.Kind != "response" {
			return errors.New("parallel callback binding")
		}
		h.sequence++
		h.fact.Parallel.Events = append(h.fact.Parallel.Events, parallelEvent{s.member, event.Kind, event.LeaseID, h.sequence})
		if len(h.fact.Parallel.Events) > 64 {
			return errors.New("parallel callback budget")
		}
	}
	return h.children()
}
func (h *parallelHarness) serve(s *parallelSession, f parallelFrame) (err error) {
	endWait := ownerDiagnosticWait(h.ctx, "callback/"+ownerDiagnosticOp(f.Op)+"/"+ownerDiagnosticMember(s.member))
	defer func() { endWait(err) }()
	if f.Op == "call-event" {
		return s.mux.replyTo(f, nil, nil)
	}
	if f.Op == "constructor" {
		var member string
		if wire.Decode(f.Data, &member) != nil || member != s.member {
			return errors.New("parallel constructor binding")
		}
		return s.mux.replyTo(f, nil, nil)
	}
	proxy := &ownerChannel{reply: func(op string, v any, e error) error {
		if op != f.Op {
			return errors.New("parallel model reply method")
		}
		return s.mux.replyTo(f, v, e)
	}}
	return s.service.serve(proxy, ownerMessage{ID: f.ID, Op: f.Op, Data: f.Data})
}
func (h *parallelHarness) take(s *parallelSession, match func(parallelFrame) bool) (parallelFrame, error) {
	for {
		endWait := ownerDiagnosticWait(h.ctx, "mux.nextFrame/"+ownerDiagnosticMember(s.member))
		f, e := s.mux.nextFrame()
		endWait(e)
		if e != nil {
			return f, e
		}
		if f.Kind == "rpc" {
			if e = h.observe(s, f); e != nil {
				return f, e
			}
		}
		if match(f) {
			return f, nil
		}
		if f.Kind != "rpc" {
			return f, errors.New("unexpected parallel notice")
		}
		if e = h.serve(s, f); e != nil {
			return f, e
		}
	}
}
func (h *parallelHarness) startup(s *parallelSession) error {
	f, e := h.take(s, func(f parallelFrame) bool { return f.Kind == "notice" && f.Op == "startup" && f.ID == 0 })
	var stage string
	if e != nil || wire.Decode(f.Data, &stage) != nil || stage != "lease" || f.Error != "" {
		return fmt.Errorf("parallel serving startup: %s %s %v", stage, f.Error, e)
	}
	return nil
}
func (h *parallelHarness) command(s *parallelSession, op string, v any) (int, error) {
	b := &s.base.budget
	switch op {
	case "lease.request":
		b.Requests++
	case "lease.renew":
		b.Renewals++
	case "lease.release":
		b.Releases++
	default:
		return 0, errors.New("parallel command method")
	}
	if b.Requests > 3 || b.Renewals > 5 || b.Releases > 2 || b.Requests+b.Renewals+b.Releases > 8 || len(s.issued) >= 2 {
		return 0, errors.New("parallel call budget")
	}
	id, e := s.mux.command(op, v)
	raw, _ := wire.Encode(v)
	s.issued[id] = parallelFrame{ID: id, Op: op, Data: raw}
	return id, e
}
func (h *parallelHarness) result(s *parallelSession, id int, want, token string, generation uint64) (wire.LeaseResult, error) {
	for s.results[id].ID == 0 {
		f, e := h.take(s, func(f parallelFrame) bool { return f.Kind == "notice" })
		if e != nil {
			return wire.LeaseResult{}, e
		}
		cmd, ok := s.issued[f.ID]
		if !ok || s.finished[f.ID] || s.results[f.ID].ID != 0 || cmd.Op != f.Op {
			return wire.LeaseResult{}, errors.New("parallel duplicate/unknown result")
		}
		s.results[f.ID] = f
	}
	f := s.results[id]
	delete(s.results, id)
	cmd := s.issued[id]
	delete(s.issued, id)
	s.finished[id] = true
	var out parallelOutcome
	if wire.Decode(f.Data, &out) != nil || f.Error != want || want != "" && out != (parallelOutcome{}) {
		return out.Lease, fmt.Errorf("parallel exact outcome: want %s got %s", want, f.Error)
	}
	proof := parallelResult{Member: s.member, Method: cmd.Op, Command: id, Error: want, PolicyGeneration: out.PolicyGeneration}
	if cmd.Op == "lease.release" {
		var r wire.Release
		if wire.Decode(cmd.Data, &r) != nil {
			return out.Lease, errors.New("parallel release input")
		}
		proof.LeaseID = r.LeaseID
	}
	if cmd.Op == "lease.renew" {
		var r wire.Renew
		if wire.Decode(cmd.Data, &r) != nil {
			return out.Lease, errors.New("parallel renewal input")
		}
		proof.LeaseID = r.LeaseID
		proof.Rejected = r.RejectedSHA256
	}
	if want == "" && (cmd.Op == "lease.request" || cmd.Op == "lease.renew") {
		if e := lifecyclePublication(h.ledger.c.Root, out.Lease, token, generation); e != nil {
			return out.Lease, e
		}
		cp, _, _, e := h.ledger.records()
		b, x := os.ReadFile(filepath.Join(ownerAccountPath(h.ledger.c.Root), store.LeaseName(out.Lease.LeaseID)))
		var rec lease.Record
		if e != nil || x != nil || wire.Decode(b, &rec) != nil || out.PolicyGeneration != 1 {
			return out.Lease, errors.New("parallel publication records")
		}
		proof.LeaseID = out.Lease.LeaseID
		proof.Published = true
		proof.TokenDigest = lease.Digest(out.Lease.Payload.AccessToken)
		proof.TokenGeneration = cp.TokenGeneration
		proof.OfferedGeneration = rec.OfferedGeneration
		proof.ObservedGeneration = rec.ObservedGeneration
		if proof.TokenGeneration != generation || proof.OfferedGeneration != generation {
			return out.Lease, errors.New("token generation proof mismatch")
		}
	} else if want == "" && cmd.Op == "lease.release" && out.Release.State != "released" {
		return out.Lease, errors.New("parallel release missing")
	}
	h.fact.Parallel.Results = append(h.fact.Parallel.Results, proof)
	return out.Lease, h.ledger.audit.drain("owner")
}
func (h *parallelHarness) call(s *parallelSession, op string, v any, want, token string, generation uint64) (wire.LeaseResult, error) {
	id, e := h.command(s, op, v)
	if e != nil {
		return wire.LeaseResult{}, e
	}
	return h.result(s, id, want, token, generation)
}
func (h *parallelHarness) finish(s *parallelSession, crashed bool) error {
	if !crashed {
		if len(s.issued) != 0 {
			return errors.New("parallel calls still in flight")
		}
		if _, e := s.mux.command("close", nil); e != nil {
			return e
		}
		endWait := ownerDiagnosticWait(h.ctx, "normal join/"+ownerDiagnosticMember(s.member))
		select {
		case <-s.base.done:
			endWait(s.base.err)
		case <-h.ctx.Done():
			endWait(h.ctx.Err())
			s.base.cancel()
			<-s.base.done
			return h.ctx.Err()
		}
		if s.base.err != nil || s.base.waits != 1 || !s.base.execution.credit(false) {
			return errors.New("parallel normal join failed")
		}
	}
	s.mux.close()
	s.base.origin.Close()
	s.base.cancel()
	for _, f := range s.images {
		f.Close()
	}
	s.closed = true
	b := s.base
	origin := ownerEpochFact{Command: b.command, Image: b.image, Verified: b.execution.Handshake, Entered: b.execution.Started, Joined: b.execution.Joined, Exit: b.execution.CaseExit, Waits: b.waits}
	if crashed {
		cert := b.termination.Facts()
		if !cert.Valid() {
			return errors.New("parallel crash certificate")
		}
		origin.Verified = cert.Verified
		origin.Entered = cert.Entered
		origin.Exit = cert.Exit
		h.fact.Crashes = append(h.fact.Crashes, cert)
	}
	h.fact.Origins[s.index] = origin
	h.fact.Budgets[s.index] = b.budget
	h.fact.Parallel.Frames[s.index] = s.mux.frames()
	return nil
}
func (h *parallelHarness) lockHeld() error {
	path := filepath.Join(h.ledger.c.Root, "metadata", "owner.lock")
	fd, e := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Ino != h.ledger.audit.stable[path].Ino {
		return errors.New("parallel lock identity")
	}
	e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if e == nil {
		syscall.Flock(fd, syscall.LOCK_UN)
		return errors.New("winner real store lock not held")
	}
	if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
		return e
	}
	return nil
}
func parallelHistory(root string) (map[string]string, error) {
	dir := ownerAccountPath(root)
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, f := range entries {
		if len(f.Name()) > 14 && f.Name()[:14] == "owner-attempt-" {
			b, e := store.ReadProtected(filepath.Join(dir, f.Name()), uint32(os.Geteuid()))
			if e != nil {
				return nil, e
			}
			out[f.Name()] = qualificationHash(b)
		}
	}
	return out, nil
}
func parallelSameHistory(root string, before map[string]string) bool {
	after, e := parallelHistory(root)
	if e != nil || len(before) == 0 {
		return false
	}
	for p, digest := range before {
		if after[p] != digest {
			return false
		}
	}
	return true
}
func parallelPending(m *lifecycleModel) error {
	cp, is, es, e := m.records()
	if e != nil {
		return e
	}
	return lifecyclePending(cp, is, es)
}
