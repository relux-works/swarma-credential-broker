//go:build linux

package timeconf

import (
	"context"
	"math"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// WitnessHead is the independently retained monotonic checkpoint identity.
// A backend must durably acknowledge CAS before returning, reject generation
// reuse/wrap, and live outside every checkpoint restore domain.
type WitnessHead struct {
	Generation   uint64
	RecordDigest string
}

// RollbackWitness is deliberately local and narrow. Supplying an implementation
// does not qualify or activate consumption; no public injection path is shipped.
type RollbackWitness interface {
	Read(context.Context) (WitnessHead, error)
	CompareAndSwap(context.Context, WitnessHead, WitnessHead) error
}

// ClosedWitness is the only shipped production backend. It never manufactures
// a baseline, returns a cached head, or acknowledges an advancement.
type ClosedWitness struct{}

func (ClosedWitness) Read(context.Context) (WitnessHead, error) {
	return WitnessHead{}, &ActivationRefusal{Reason: "witness_unavailable"}
}
func (ClosedWitness) CompareAndSwap(context.Context, WitnessHead, WitnessHead) error {
	return &ActivationRefusal{Reason: "witness_unavailable"}
}

type checkpointHead struct {
	Generation   Generation `json:"generation"`
	RecordDigest string     `json:"record_digest"`
}

func wireHead(h WitnessHead) checkpointHead { return checkpointHead{gen(h.Generation), h.RecordDigest} }
func (h checkpointHead) value() (WitnessHead, error) {
	g, e := generation(h.Generation)
	if e != nil || !digestPattern.MatchString(h.RecordDigest) {
		return WitnessHead{}, ErrUnavailable
	}
	return WitnessHead{g, h.RecordDigest}, nil
}
func witnessBytes(h WitnessHead) []byte { b, _ := canonical(wireHead(h)); return b }

type savedClock struct {
	Boot      string      `json:"boot"`
	Wall      Nanoseconds `json:"wall"`
	Elapsed   Nanoseconds `json:"elapsed"`
	Reference Nanoseconds `json:"reference"`
}
type retainedObject struct {
	Digest string     `json:"digest"`
	Size   Generation `json:"size"`
}
type settlement struct {
	Version    string           `json:"version"`
	Binding    string           `json:"binding"`
	Generation Generation       `json:"generation"`
	Previous   string           `json:"previous"`
	HighWater  Nanoseconds      `json:"high_water"`
	Held       bool             `json:"held"`
	Hold       savedClock       `json:"hold"`
	Last       savedClock       `json:"last"`
	InFlight   bool             `json:"in_flight"`
	Operation  string           `json:"operation"`
	Challenge  string           `json:"challenge"`
	Facts      *Facts           `json:"facts"`
	Originals  []retainedObject `json:"originals"`
}
type settlementStore struct {
	root    string
	binding string
	witness RollbackWitness
	// fsync is an internal fixture fault point, never a production callback.
	syncFault func(string) error
}
type storeSession struct {
	*settlementStore
	dir *os.File
}

func (s *settlementStore) open() (*storeSession, error) {
	if pathProtected(s.root, uint32(os.Geteuid())) != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open(s.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "settlement")
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	info, ok := st.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != uint32(os.Geteuid()) || st.Mode() != (os.ModeDir|0700) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return &storeSession{s, f}, nil
}
func (s *storeSession) close() { _ = s.dir.Close() }
func (s *storeSession) read(name string, limit int) ([]byte, error) {
	fd, e := unix.Openat(int(s.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "settlement-object")
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, ErrUnavailable
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode() != 0600 || v.Uid != uint32(os.Geteuid()) || v.Nlink != 1 || st.Size() < 0 || st.Size() > int64(limit) {
		return nil, ErrUnavailable
	}
	b := make([]byte, int(st.Size()))
	n, e := f.ReadAt(b, 0)
	if n != len(b) || e != nil && len(b) != 0 {
		return nil, ErrUnavailable
	}
	return b, nil
}
func (s *storeSession) sync(f *os.File, point string) error {
	if e := f.Sync(); e != nil {
		return ErrUnavailable
	}
	if s.syncFault != nil && s.syncFault(point) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *storeSession) write(ctx context.Context, name string, b []byte, point string) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	fd, e := unix.Openat(int(s.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "settlement-object")
	n, e := f.Write(b)
	if e == nil && n == len(b) {
		e = s.sync(f, point+"-file")
	}
	ce := f.Close()
	if e != nil || ce != nil || n != len(b) || ctx.Err() != nil {
		return ErrUnavailable
	}
	if s.sync(s.dir, point+"-directory") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func objectName(prefix, digest string) string { return prefix + digest[len("sha256:"):] }
func (s *storeSession) retain(ctx context.Context, prefix string, b []byte, point string) error {
	name := objectName(prefix, sum(b))
	if old, e := s.read(name, len(b)); e == nil {
		if string(old) != string(b) {
			return ErrUnavailable
		}
		return nil
	}
	return s.write(ctx, name, b, point)
}
func (s *storeSession) publish(ctx context.Context, h WitnessHead) error {
	// Unique staging name: a failed prefix is never overwritten or interpreted as
	// enrollment. The next call must verify the witness and any pending begin.
	b := witnessBytes(h)
	name := "pointer-" + strconv.FormatUint(h.Generation, 10)
	if s.write(ctx, name, b, "pointer") != nil {
		return ErrUnavailable
	}
	if unix.Renameat(int(s.dir.Fd()), name, int(s.dir.Fd()), "current") != nil {
		return ErrUnavailable
	}
	if s.sync(s.dir, "current-directory") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *storeSession) record(h WitnessHead) (settlement, error) {
	b, e := s.read(objectName("record-", h.RecordDigest), receiptLimit)
	if e != nil || sum(b) != h.RecordDigest {
		return settlement{}, ErrUnavailable
	}
	var r settlement
	if strictRecord(b, &r, receiptLimit) != nil || r.Version != "qualified-time/settlement/1" || r.Binding != s.binding || r.Generation != gen(h.Generation) {
		return settlement{}, ErrUnavailable
	}
	if _, e := integer(r.HighWater); e != nil {
		return settlement{}, ErrUnavailable
	}
	if !bootValid(r.Last.Boot) {
		return settlement{}, ErrUnavailable
	}
	for _, n := range []Nanoseconds{r.Last.Wall, r.Last.Elapsed, r.Last.Reference, r.Hold.Wall, r.Hold.Elapsed, r.Hold.Reference} {
		if _, e := integer(n); e != nil {
			return settlement{}, ErrUnavailable
		}
	}
	elapsed, _ := integer(r.Last.Elapsed)
	if elapsed < 0 {
		return settlement{}, ErrUnavailable
	}
	if h.Generation == 0 {
		if r.Previous != "none" || r.InFlight || r.Facts != nil {
			return settlement{}, ErrUnavailable
		}
	} else if !digestPattern.MatchString(r.Previous) || !digestPattern.MatchString(r.Operation) || !randomPattern.MatchString(r.Challenge) {
		return settlement{}, ErrUnavailable
	}
	return r, nil
}
func (s *storeSession) load(ctx context.Context) (settlement, WitnessHead, error) {
	h, e := s.witness.Read(ctx)
	if e != nil {
		return settlement{}, h, e
	}
	if !digestPattern.MatchString(h.RecordDigest) {
		return settlement{}, h, ErrUnavailable
	}
	b, e := s.read("current", 512)
	var pointer checkpointHead
	if e != nil || strictRecord(b, &pointer, 512) != nil {
		return settlement{}, h, ErrUnavailable
	}
	old, e := pointer.value()
	if e != nil {
		return settlement{}, h, ErrUnavailable
	}
	r, e := s.record(h)
	if e != nil {
		return r, h, e
	}
	if old != h {
		if old.Generation == math.MaxUint64 || old.Generation+1 != h.Generation || r.Previous != old.RecordDigest {
			return r, h, ErrUnavailable
		}
		if _, e := s.record(old); e != nil {
			return r, h, e
		}
	}
	// Verify retained associations, evidence and the immutable ancestry. This is
	// bounded by the one request deadline; history is never pruned or reconstructed.
	walk, head := r, h
	for {
		if ctx.Err() != nil {
			return r, h, ErrUnavailable
		}
		total := 0
		if len(walk.Originals) > 60 {
			return r, h, ErrUnavailable
		}
		for _, o := range walk.Originals {
			n, e := generation(o.Size)
			if e != nil || n > 8<<20 || !digestPattern.MatchString(o.Digest) {
				return r, h, ErrUnavailable
			}
			b, e := s.read(objectName("evidence-", o.Digest), int(n))
			total += len(b)
			if e != nil || uint64(len(b)) != n || sum(b) != o.Digest || total > (8<<20)-4*receiptLimit {
				return r, h, ErrUnavailable
			}
		}
		if walk.Facts != nil {
			receipt, e := settledReceipt(walk, head)
			if e != nil {
				return r, h, e
			}
			raw, e := EncodeReceipt(receipt)
			if e != nil {
				return r, h, e
			}
			retained, e := s.read(objectName("receipt-", sum(raw)), receiptLimit)
			if e != nil || string(raw) != string(retained) {
				return r, h, ErrUnavailable
			}
		}
		if head.Generation == 0 {
			break
		}
		head = WitnessHead{head.Generation - 1, walk.Previous}
		walk, e = s.record(head)
		if e != nil {
			return r, h, e
		}
	}
	if old != h && s.publish(ctx, h) != nil {
		return r, h, ErrUnavailable
	}
	return r, h, nil
}
func (s *storeSession) commit(ctx context.Context, old WitnessHead, r settlement) (WitnessHead, error) {
	if ctx.Err() != nil || old.Generation == math.MaxUint64 {
		return old, ErrUnavailable
	}
	r.Generation = gen(old.Generation + 1)
	r.Previous = old.RecordDigest
	b, e := canonical(r)
	if e != nil || len(b) > receiptLimit {
		return old, ErrUnavailable
	}
	next := WitnessHead{old.Generation + 1, sum(b)}
	if s.write(ctx, objectName("record-", next.RecordDigest), b, "record") != nil {
		return old, ErrUnavailable
	}
	if ctx.Err() != nil || s.witness.CompareAndSwap(ctx, old, next) != nil {
		return old, ErrUnavailable
	}
	if s.publish(ctx, next) != nil {
		return next, ErrUnavailable
	}
	return next, nil
}
func settledReceipt(r settlement, h WitnessHead) (Receipt, error) {
	if r.Facts == nil || r.InFlight || r.Held {
		return Receipt{}, ErrUnavailable
	}
	f := *r.Facts
	enrollment := Enrollment{Authority: f.Authority, Adapter: f.Adapter, Policy: f.Policy, Scope: f.Scope, Store: f.Continuity.Store}
	enrollment.Scope.OperationDigest = ""
	binding, _ := canonical(enrollment)
	manifest, _ := canonical(r.Originals)
	if enrollment.validate() != nil || sum(binding) != r.Binding || f.Scope.OperationDigest != r.Operation || f.Sample.Challenge != r.Challenge || f.Clock.Boot != r.Last.Boot || f.Clock.ObservedNS != r.Last.Elapsed || f.Observed != r.Last.Wall || f.Evidence.Reference != r.Last.Reference || f.Continuity.HighWater != r.HighWater || f.Evidence.Digest != sum(manifest) || len(r.Originals) == 0 {
		return Receipt{}, ErrUnavailable
	}
	f.Continuity.Generation = gen(h.Generation)
	f.Sample.Generation = gen(h.Generation)
	f.Continuity.RecordDigest = h.RecordDigest
	f.Continuity.WitnessDigest = sum(witnessBytes(h))
	return Receipt{ReceiptVersion, f}, nil
}
