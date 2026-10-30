//go:build linux

package generationcas

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/relux-works/swarma-credential-broker/internal/freshstore"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

type testFixture struct {
	c          *Coordinator
	o          *Observer
	account    *store.Account
	path       string
	seed       []byte
	a, b, wide freshstore.Expected
}

func defaultLimits() Limits {
	return Limits{4096, 262144, 64, 2, 4, 2, 17, 2048, 1, 32, 32768, 8388608, 16777216, 8}
}
func wideLimits() Limits { l := defaultLimits(); l.Units = 3; l.Dependencies = 2; return l }
func prepare(t *testing.T, wide bool) testFixture {
	t.Helper()
	l := defaultLimits()
	if wide {
		l = wideLimits()
	}
	root := filepath.Join(t.TempDir(), "registry")
	s, e := store.Open(root, "i", uint32(os.Geteuid()), true, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	a, e := s.Account("content", true)
	if e != nil {
		t.Fatal(e)
	}
	fs, e := freshstore.NewFixture(a, l.content())
	if e != nil {
		t.Fatal(e)
	}
	binding := freshstore.Binding{Installation: "i", Scope: "s", Pin: strings.Repeat("0", 64), Previous: "g:" + strings.Repeat("1", 64)}
	first, e := fs.Retain(binding, []freshstore.Input{{Name: "a", Kind: "blob", Raw: []byte("x")}})
	if e != nil {
		t.Fatal(e)
	}
	ba := binding
	ba.Previous = "m:" + first.ManifestDigest
	second, e := fs.Retain(ba, []freshstore.Input{{Name: "a", Kind: "blob", Raw: []byte("y")}})
	if e != nil {
		t.Fatal(e)
	}
	f := testFixture{account: a, a: freshstore.Expected{Binding: binding, Schema: freshstore.Schema, ManifestDigest: first.ManifestDigest, Inventory: first.Inventory}, b: freshstore.Expected{Binding: ba, Schema: freshstore.Schema, ManifestDigest: second.ManifestDigest, Inventory: second.Inventory}, seed: []byte(literalSeed)}
	d := sha256.Sum256([]byte("content"))
	f.path = filepath.Join(root, "account-"+hex.EncodeToString(d[:]))
	ss, e := parseSeed(f.seed, l)
	if e != nil {
		t.Fatal(e)
	}
	if !equalUnit(ss.units[0], f.a) || !equalUnit(ss.units[1], f.b) {
		t.Fatal("immutable seed differs from retained content")
	}
	if wide {
		// A already exists. Append ONLY the independently frozen extra object
		// and complete manifest, then let the actual constructor ReadExact
		// validate their full inventory; duplicate Retain is intentionally illegal.
		e := a.AppendImmutableBounded([]store.EncodedImmutable{
			{Name: "owner-fresh-object-6b531e60bb6c16159c16fbb2c31cc3319ecd31942b7e7ab28e10da33b9ad8936.json", Bytes: []byte(literalWideObject)},
			{Name: "owner-fresh-manifest-3ef2705e33481d903e1696d805fd20af84e80a011c62eef512c180565900b705.json", Bytes: []byte(literalWideManifest)},
		}, store.ImmutableLimits{RecordBytes: l.RecordBytes, TotalBytes: l.RetainedBytes, TotalRecords: l.RetainedObjects, ReadBytes: l.ReadBytes})
		if e != nil {
			t.Fatal(e)
		}
		f.wide = copyUnit(f.a)
		f.wide.ManifestDigest = "3ef2705e33481d903e1696d805fd20af84e80a011c62eef512c180565900b705"
		f.wide.Inventory = append(f.wide.Inventory, freshstore.Ref{Digest: "6b531e60bb6c16159c16fbb2c31cc3319ecd31942b7e7ab28e10da33b9ad8936", Encoded: 300, Kind: "blob", Name: "b", Raw: 2, RawDigest: "68d617d6d2ee5715af77d9795566cfaba9a43a33d14cbbc95831c507c935bad1"})
		ss.units = append(ss.units, f.wide)
		sort.Slice(ss.units, func(i, j int) bool { return ss.units[i].ManifestDigest < ss.units[j].ManifestDigest })
		f.seed = seedBytes(ss, l)
	}
	return f
}
func seedBytes(s seed, l Limits) []byte {
	w := newWriter(l)
	w.put(`{"epoch":`)
	w.str(s.epoch)
	w.put(`,"generation":1,"initial_manifest":`)
	w.str(s.manifest)
	w.put(`,"installation":`)
	w.str(s.installation)
	w.put(`,"kind":"freshcas-initial/1","pin":`)
	w.str(s.pin)
	w.put(`,"schema":"freshcas/1","scope":`)
	w.str(s.scope)
	w.put(`,"units":[`)
	for i, u := range s.units {
		if i > 0 {
			w.put(`,`)
		}
		w.unit(u)
	}
	w.put(`]}`)
	if w.err != nil {
		panic(w.err)
	}
	return w.b
}
func newTestFixture(t *testing.T, l Limits, wide bool) testFixture {
	t.Helper()
	f := prepare(t, wide)
	var e error
	f.c, e = NewFixture(f.account, l, f.seed)
	if e != nil {
		t.Fatal(e)
	}
	f.o, e = f.c.OpenObserver()
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f testFixture) content(t *testing.T, name string) []byte {
	t.Helper()
	var manifest, object string
	if strings.HasPrefix(name, "A-") {
		manifest = f.a.ManifestDigest
		object = f.a.Inventory[0].Digest
	} else {
		manifest = f.b.ManifestDigest
		object = f.b.Inventory[0].Digest
	}
	n := "owner-fresh-object-" + object + ".json"
	if strings.HasSuffix(name, "manifest") {
		n = "owner-fresh-manifest-" + manifest + ".json"
	}
	b, e := os.ReadFile(filepath.Join(f.path, n))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func bind(t *testing.T, o *Observer, n byte, expected Token, u freshstore.Expected) Request {
	t.Helper()
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = n
	}
	r, e := o.Bind(nonce, expected, expected.Number()+1, u)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func submit(t *testing.T, o *Observer, r Request) Ticket {
	t.Helper()
	tk, e := o.Submit(r)
	if e != nil {
		t.Fatal(e)
	}
	return tk
}
func finishTest(t *testing.T, f testFixture, tk Ticket) Result {
	t.Helper()
	if e := f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	if e := f.c.RecordOutcome(tk); e != nil {
		t.Fatal(e)
	}
	if e := f.c.Deliver(tk); e != nil {
		t.Fatal(e)
	}
	r, e := f.o.Receive(tk)
	if e != nil || r.Outcome != Committed {
		t.Fatal(r, e)
	}
	return r
}
func assertCharge(t *testing.T, f testFixture, b, o, slots uint64) {
	t.Helper()
	snap, _, e := census(f.account, f.c.limits)
	if e != nil {
		t.Fatal(e)
	}
	bb, oo, ss, e := f.c.limits.charge(snap.Bytes, snap.Records, uint64(f.c.used))
	if e != nil || bb != b || oo != o || ss != slots {
		t.Fatalf("charge %d/%d/%d %v", bb, oo, ss, e)
	}
}
func observer2(t *testing.T, f testFixture) *Observer {
	t.Helper()
	o, e := f.c.OpenObserver()
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func requireUnknown(t *testing.T, r Result) {
	t.Helper()
	if r.Outcome != Unknown || r.Selection.Generation != (Token{}) || r.Selection.Unit.Inventory != nil || r.TerminalProof != ([32]byte{}) {
		t.Fatalf("not a closed unknown: %+v", r)
	}
}

// Claim: actual compare publishes once, O/F arise only at their transitions,
// output mutations do not alter canonical state, and old retries add no charge.
func TestCASExactPredecessor(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	root := f.c.root
	assertCharge(t, f, 15953, 14, 1)
	req := bind(t, f.o, 0xaa, root, f.b)
	tk := submit(t, f.o, req)
	assertCharge(t, f, 32337, 18, 5)
	j := &f.c.jobs[0]
	if len(j.slots[2]) != 0 || len(j.slots[3]) != 0 || f.c.root != root {
		t.Fatal("premature outcome/root")
	}
	// Mutate caller-owned inventory AFTER Submit. Canonical R/G are unaffected.
	req.Candidate.Inventory[0].Name = "bad"
	req = bind(t, f.o, 0xaa, root, f.b)
	got, e := f.o.Receive(tk)
	if e != nil {
		t.Fatal(e)
	}
	requireUnknown(t, got)
	if e = f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	selected := f.c.root
	if selected == root || selected.number != 2 || len(j.slots[2]) != 0 || len(j.slots[3]) != 0 || f.c.fence != 1 {
		t.Fatal("publication boundary")
	}
	if e = f.c.RecordOutcome(tk); e != nil {
		t.Fatal(e)
	}
	if len(j.slots[2]) == 0 || len(j.slots[3]) != 0 || f.c.fence != 1 {
		t.Fatal("outcome boundary")
	}
	if e = f.c.Deliver(tk); e != nil {
		t.Fatal(e)
	}
	got, e = f.o.Receive(tk)
	if e != nil || got.Outcome != Committed || !equalUnit(got.Selection.Unit, f.b) || got.TerminalProof == ([32]byte{}) || f.c.fence != 0 {
		t.Fatal(got, e)
	}
	got.Selection.Unit.Inventory[0].Name = "bad"
	cur, e := f.o.Current()
	if e != nil || !equalUnit(cur.Unit, f.b) || cur.Generation != selected {
		t.Fatal(cur, e)
	}
	again, e := f.o.Reconcile(req)
	if e != nil || again.Outcome != Committed || !equalUnit(again.Selection.Unit, f.b) {
		t.Fatal(again, e)
	}
	if tk2, e := f.o.Submit(req); e != nil || tk2 != tk {
		t.Fatal(tk2, e)
	}
	assertCharge(t, f, 32337, 18, 5)
}

// Claim: changing an admitted attempt's payload/nonce cannot escape its fence,
// while exact retries keep one ticket and reservation.
func TestCASAttemptCorrelation(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	tk := submit(t, f.o, r)
	r2 := r
	r2.Candidate = copyUnit(f.a)
	if _, e := f.o.Submit(r2); e != ErrInvalid {
		t.Fatal(e)
	}
	r2 = r
	r2.Nonce[0]++
	if _, e := f.o.Reconcile(r2); e != ErrInvalid {
		t.Fatal(e)
	}
	other := bind(t, f.o, 0xbb, f.c.root, f.a)
	if _, e := f.o.Submit(other); e != ErrFenced {
		t.Fatal(e)
	}
	same, e := f.o.Submit(r)
	if e != nil || same != tk {
		t.Fatal(e)
	}
	u, e := f.o.Reconcile(r)
	if e != nil {
		t.Fatal(e)
	}
	requireUnknown(t, u)
	if f.c.used != 1 || f.c.root != r.Expected || f.c.fence != 1 {
		t.Fatal("correlation changed effect")
	}
	finishTest(t, f, tk)
}

// Claim: Close/old root/pending observation cannot prove NoCommit; the same
// queued ticket still commits later and another real observer reconciles it.
func TestCASDelayedFence(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	tk := submit(t, f.o, r)
	o2 := observer2(t, f)
	if e := f.o.Close(); e != nil {
		t.Fatal(e)
	}
	cur, e := o2.Current()
	if e != nil || cur.Generation != r.Expected {
		t.Fatal(cur, e)
	}
	other := bind(t, o2, 0xdd, cur.Generation, f.b)
	if _, e = o2.Submit(other); e != ErrFenced {
		t.Fatal(e)
	}
	u, e := o2.Reconcile(r)
	if e != nil {
		t.Fatal(e)
	}
	requireUnknown(t, u)
	if e = f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	if e = f.c.RecordOutcome(tk); e != nil {
		t.Fatal(e)
	}
	if e = f.c.Deliver(tk); e != ErrDisconnected {
		t.Fatal(e)
	}
	u, e = o2.Reconcile(r)
	if e != nil || u.Outcome != Committed || f.c.used != 1 || f.c.fence != 0 {
		t.Fatal(u, e)
	}
	assertCharge(t, f, 32337, 18, 5)
}

// Claim: a lost sink reply AFTER actual selection retains true commit evidence,
// fence and charge; exact reconciliation recovers Committed, never NoCommit.
func TestCASLostReply(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	tk := submit(t, f.o, r)
	if e := f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	if e := f.c.RecordOutcome(tk); e != nil {
		t.Fatal(e)
	}
	root := f.c.root
	f.o.Close()
	o2 := observer2(t, f)
	e := f.c.Deliver(tk)
	if e != ErrDisconnected || f.c.root != root || f.c.fence != 1 || f.c.jobs[0].outcome != Committed || len(f.c.jobs[0].slots[3]) != 0 {
		t.Fatalf("lost reply changed committed truth/fence: %v state=%d outcome=%d fence=%d", e, f.c.jobs[0].state, f.c.jobs[0].outcome, f.c.fence)
	}
	got, e := o2.Reconcile(r)
	if e != nil || got.Outcome != Committed || got.Selection.Generation != root || f.c.used != 1 || f.c.fence != 0 {
		t.Fatal(got, e)
	}
	assertCharge(t, f, 32337, 18, 5)
}

// Claim: interruption before O and a real mailbox-capacity refusal after CAS
// preserve publication/charge. Neither is physical crash recovery.
func TestCASPostPublishFailure(t *testing.T) {
	for _, cut := range []string{"before-outcome", "full-mailbox"} {
		t.Run(cut, func(t *testing.T) {
			f := newTestFixture(t, defaultLimits(), false)
			r := bind(t, f.o, 0xaa, f.c.root, f.b)
			tk := submit(t, f.o, r)
			if cut == "full-mailbox" {
				if e := f.c.ComparePublish(tk); e != nil {
					t.Fatal(e)
				}
				if e := f.c.RecordOutcome(tk); e != nil {
					t.Fatal(e)
				}
				if e := f.c.Deliver(tk); e != nil {
					t.Fatal(e)
				} // Leave the real earlier delivery unconsumed.
				r = bind(t, f.o, 0xbb, f.c.root, f.a)
				tk = submit(t, f.o, r)
			}
			if e := f.c.ComparePublish(tk); e != nil {
				t.Fatal(e)
			}
			root := f.c.root
			j := &f.c.jobs[tk.slot-1]
			if cut == "before-outcome" {
				if len(j.slots[2]) != 0 || len(j.slots[3]) != 0 {
					t.Fatal("not pre-O cut")
				}
				u, e := f.c.CancelQueued(tk)
				if e != ErrPending {
					t.Fatal(e)
				}
				requireUnknown(t, u)
				f.o.Close()
			} else {
				if e := f.c.RecordOutcome(tk); e != nil {
					t.Fatal(e)
				}
				if e := f.c.Deliver(tk); e != ErrCapacity {
					t.Fatal(e)
				}
			}
			if f.c.root != root || j.state != published || f.c.fence != tk.slot {
				t.Fatal("postpublish rollback/refund")
			}
			o2 := observer2(t, f)
			got, e := o2.Reconcile(r)
			if e != nil || got.Outcome != Committed || got.Selection.Generation != root {
				t.Fatal(got, e)
			}
			if cut == "before-outcome" {
				assertCharge(t, f, 32337, 18, 5)
			} else {
				if !strings.Contains(string(f.c.jobs[0].slots[2]), `"job":1,`) || !strings.Contains(string(f.c.jobs[1].slots[2]), `"job":2,`) {
					t.Fatal("outcome ordinal does not follow actual admission")
				}
				assertCharge(t, f, 48721, 22, 9)
			}
		})
	}
}

// Claim: ConfirmedNoCommit is returned only after terminal revocation; a real
// delayed old ComparePublish cannot subsequently select its prepared G.
func TestCASCancelExcludesDelayed(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	root := f.c.root
	r := bind(t, f.o, 0xee, root, f.b)
	tk := submit(t, f.o, r)
	got, e := f.c.CancelQueued(tk)
	if e != nil || got.Outcome != ConfirmedNoCommit || got.Selection.Generation != root || !equalUnit(got.Selection.Unit, f.a) || f.c.fence != 0 || len(f.c.jobs[0].slots[3]) == 0 {
		t.Fatal(got, e)
	}
	e = f.c.ComparePublish(tk)
	if e != ErrTerminal || f.c.root != root {
		t.Fatalf("delayed selection after NoCommit: error=%v root=%d", e, f.c.root.number)
	}
	if e = f.c.RecordOutcome(tk); e != nil {
		t.Fatal(e)
	}
	again, e := f.o.Reconcile(r)
	if e != nil || !reflect.DeepEqual(got, again) {
		t.Fatal(again, e)
	}
	assertCharge(t, f, 32337, 18, 5)
	// Nearby genuine publication must NOT become NoCommit on cancellation.
	r = bind(t, f.o, 0xaa, root, f.b)
	tk = submit(t, f.o, r)
	if e = f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	u, e := f.c.CancelQueued(tk)
	if e != ErrPending {
		t.Fatal(e)
	}
	requireUnknown(t, u)
	if f.c.fence != tk.slot {
		t.Fatal("published cancel released fence")
	}
}

// Claim: valid retained A-B-A transitions advance monotonic generation tokens;
// a stale issued A token cannot become current because unit bytes match again.
func TestCASGenerationABA(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	initial := f.c.root
	ab := finishTest(t, f, submit(t, f.o, bind(t, f.o, 0xaa, initial, f.b)))
	ba := finishTest(t, f, submit(t, f.o, bind(t, f.o, 0xbb, ab.Selection.Generation, f.a)))
	if !equalUnit(ba.Selection.Unit, f.a) || ba.Selection.Generation.number != 3 || ba.Selection.Generation == initial {
		t.Fatal("valid ABA not reached")
	}
	stale := bind(t, f.o, 0xcc, initial, f.b)
	tk := submit(t, f.o, stale)
	e := f.c.ComparePublish(tk)
	if e != ErrTerminal || f.c.root != ba.Selection.Generation {
		t.Fatalf("stale ABA publication: %v root=%d", e, f.c.root.number)
	}
	got, e := f.o.Reconcile(stale)
	if e != nil || got.Outcome != ConfirmedNoCommit || got.Selection.Generation != ba.Selection.Generation {
		t.Fatal(got, e)
	}
	assertCharge(t, f, 65105, 26, 13)
}

// Claim: joined competitors serialize through ONE owner, including both finite
// winner directions and a barrier race. O/F ordinal and winner token are actual.
func TestCASSerializedCompetitors(t *testing.T) {
	for _, mode := range []string{"AB-first", "other-first", "barrier"} {
		t.Run(mode, func(t *testing.T) {
			f := newTestFixture(t, defaultLimits(), false)
			o2 := observer2(t, f)
			obs := []*Observer{f.o, o2}
			r := []Request{bind(t, f.o, 0xaa, f.c.root, f.b), bind(t, o2, 0xdd, f.c.root, f.b)}
			var tk [2]Ticket
			var er [2]error
			if mode == "barrier" {
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func(i int) { defer wg.Done(); <-start; tk[i], er[i] = obs[i].Submit(r[i]) }(i)
				}
				close(start)
				wg.Wait()
			} else {
				first := 0
				if mode == "other-first" {
					first = 1
				}
				tk[first], er[first] = obs[first].Submit(r[first])
				tk[1-first], er[1-first] = obs[1-first].Submit(r[1-first])
			}
			win := 0
			if er[0] == ErrFenced {
				win = 1
			}
			lose := 1 - win
			if er[win] != nil || er[lose] != ErrFenced || f.c.used != 1 || f.c.fence != 1 {
				t.Fatal(er)
			}
			if e := f.c.ComparePublish(tk[win]); e != nil {
				t.Fatal(e)
			}
			if e := f.c.RecordOutcome(tk[win]); e != nil {
				t.Fatal(e)
			}
			if e := f.c.Deliver(tk[win]); e != nil {
				t.Fatal(e)
			}
			winner, e := obs[win].Receive(tk[win])
			if e != nil || winner.Outcome != Committed {
				t.Fatal(winner, e)
			}
			tk[lose] = submit(t, obs[lose], r[lose])
			if tk[lose].slot != 2 {
				t.Fatal("ordinal")
			}
			if e = f.c.ComparePublish(tk[lose]); e != ErrTerminal {
				t.Fatal(e)
			}
			lost, e := obs[lose].Reconcile(r[lose])
			if e != nil || lost.Outcome != ConfirmedNoCommit || lost.Selection.Generation != winner.Selection.Generation || f.c.root != winner.Selection.Generation {
				t.Fatal(lost, e)
			}
			if !strings.Contains(string(f.c.jobs[0].slots[2]), `"job":1,`) || !strings.Contains(string(f.c.jobs[1].slots[2]), `"job":2,`) {
				t.Fatal("outcome ordinal does not follow actual admission")
			}
			assertCharge(t, f, 48721, 22, 9)
		})
	}
}

// Claim: genuine equal-byte tokens from another world are rejected by Bind;
// same-owner observer reconnects work and closed handle slots are not recycled.
func TestCASForeignOwnerBind(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	other := newTestFixture(t, defaultLimits(), false)
	if f.c.root.number != other.c.root.number || f.c.root.record != other.c.root.record {
		t.Fatal("not equal bytes")
	}
	if _, e := f.o.Bind([16]byte{}, other.c.root, 2, f.b); e != ErrForeign {
		t.Fatalf("foreign equal-token Bind admitted: %v", e)
	}
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	tk := submit(t, f.o, r)
	if _, e := other.c.CancelQueued(tk); e != ErrForeign {
		t.Fatal(e)
	}
}
func TestCASObserverRecovery(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	tk := submit(t, f.o, r)
	if e := f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	f.o.Close()
	o2 := observer2(t, f)
	got, e := o2.Reconcile(r)
	if e != nil || got.Outcome != Committed {
		t.Fatal(got, e)
	}
	o2.Close()
	if _, e = f.c.OpenObserver(); e != ErrCapacity {
		t.Fatal(e)
	}
	assertCharge(t, f, 32337, 18, 5)
}

// Claim: inclusive prepublication object/byte/slot capacity gates reserve all
// four slots, with exact adjacent refusals leaving root/jobs/fence unchanged.
func TestCASPrepublicationCapacity(t *testing.T) {
	for _, kind := range []string{"bytes", "objects", "slots"} {
		for _, positive := range []bool{true, false} {
			t.Run(kind+map[bool]string{true: "-equal", false: "-minus1"}[positive], func(t *testing.T) {
				l := defaultLimits()
				v := uint64(0)
				switch kind {
				case "bytes":
					v = 32337
					if !positive {
						v--
					}
					l.RetainedBytes = v
				case "objects":
					v = 18
					if !positive {
						v--
					}
					l.RetainedObjects = v
				case "slots":
					v = 5
					if !positive {
						v--
					}
					l.CoordinationRecords = v
				}
				f := newTestFixture(t, l, false)
				root := f.c.root
				r := bind(t, f.o, 0xaa, root, f.b)
				tk, e := f.o.Submit(r)
				if positive {
					if e != nil || tk.slot != 1 || f.c.used != 1 || f.c.fence != 1 || f.c.root != root {
						t.Fatal(tk, e)
					}
					assertCharge(t, f, 32337, 18, 5)
				} else {
					if e != ErrCapacity || tk != (Ticket{}) || f.c.used != 0 || f.c.fence != 0 || f.c.root != root {
						t.Fatalf("capacity admitted forbidden state: err=%v used=%d fence=%d", e, f.c.used, f.c.fence)
					}
					if _, e = f.o.Reconcile(r); e != ErrInvalid {
						t.Fatal("unreserved attempt invented outcome", e)
					}
				}
			})
		}
	}
}

// Claim: zero-byte and partial pending retained files remain charged; they are
// never selected or reclaimed to make a later reservation fit.
func TestCASPendingCharge(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, positive := range []bool{true, false} {
			t.Run(map[bool]string{true: "partial", false: "empty"}[partial]+map[bool]string{true: "-equal", false: "-minus1"}[positive], func(t *testing.T) {
				f := prepare(t, false)
				name := "owner-fresh-object-" + strings.Repeat("f", 64) + ".json"
				b := []byte{}
				if partial {
					name = "pending-owner-fresh-object-" + strings.Repeat("e", 64) + ".json"
					b = []byte("xx")
				}
				if e := os.WriteFile(filepath.Join(f.path, name), b, 0600); e != nil {
					t.Fatal(e)
				}
				l := defaultLimits()
				if partial {
					l.RetainedBytes = 32339
				} else {
					l.RetainedObjects = 19
				}
				if !positive {
					if partial {
						l.RetainedBytes--
					} else {
						l.RetainedObjects--
					}
				}
				var e error
				f.c, e = NewFixture(f.account, l, f.seed)
				if e != nil {
					t.Fatal(e)
				}
				f.o, e = f.c.OpenObserver()
				if e != nil {
					t.Fatal(e)
				}
				r := bind(t, f.o, 0xaa, f.c.root, f.b)
				tk, e := f.o.Submit(r)
				if positive {
					if e != nil {
						t.Fatal(e)
					}
					if _, e = f.c.CancelQueued(tk); e != nil {
						t.Fatal(e)
					}
				} else {
					if e != ErrCapacity || f.c.used != 0 || f.c.fence != 0 {
						t.Fatal(e)
					}
				}
				raw, e := os.ReadFile(filepath.Join(f.path, name))
				if e != nil || string(raw) != string(b) {
					t.Fatal("pending content reclaimed", e)
				}
			})
		}
	}
}

// Claim: protected descriptor/census boundaries reject these finite hostile
// fixture variants, paired with a valid actual Current. No mount qualification.
func TestCASRegistryBoundary(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink", "cycle", "mode", "missing-control"} {
		t.Run(kind, func(t *testing.T) {
			f := newTestFixture(t, defaultLimits(), false)
			root := f.c.root
			if _, e := f.o.Current(); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(f.path, "owner-fresh-object-"+f.a.Inventory[0].Digest+".json")
			switch kind {
			case "hardlink":
				if e := os.Link(p, filepath.Join(t.TempDir(), "alias")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				dst := filepath.Join(t.TempDir(), "payload")
				if e := os.Rename(p, dst); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(dst, p); e != nil {
					t.Fatal(e)
				}
			case "cycle":
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Base(p), p); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			case "missing-control":
				if e := os.Remove(filepath.Join(f.path, "identity.json")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.o.Current(); e != ErrUnavailable || f.c.root != root || f.c.used != 0 {
				t.Fatalf("protected variant accepted: %v", e)
			}
			if _, e := NewFixture(f.account, defaultLimits(), f.seed); e != ErrUnavailable {
				t.Fatal(e)
			}
		})
	}
	t.Run("changed-census", func(t *testing.T) {
		f := newTestFixture(t, defaultLimits(), false)
		r := bind(t, f.o, 0xaa, f.c.root, f.b)
		tk := submit(t, f.o, r)
		root := f.c.root
		p := filepath.Join(f.path, "owner-fresh-object-"+strings.Repeat("f", 64)+".json")
		if e := os.WriteFile(p, nil, 0600); e != nil {
			t.Fatal(e)
		}
		if e := f.c.ComparePublish(tk); e != ErrRegistryChanged || f.c.root != root || f.c.fence != 1 || f.c.jobs[0].state != queued {
			t.Fatal(e)
		}
		if _, e := f.o.Current(); e != ErrRegistryChanged {
			t.Fatal(e)
		}
	})
}

// Claim: refusal vocabulary is closed and results/tickets are zero on refusal;
// genuine pending/terminal/disconnected cases stay distinct from IO failures.
func TestCASRefusalClasses(t *testing.T) {
	var no *Observer
	if _, e := no.Current(); e != ErrInvalid {
		t.Fatal(e)
	}
	var nc *Coordinator
	if e := nc.ComparePublish(Ticket{}); e != ErrInvalid {
		t.Fatal(e)
	}
	f := newTestFixture(t, defaultLimits(), false)
	if _, e := f.c.CancelQueued(Ticket{}); e != ErrInvalid {
		t.Fatal(e)
	}
	if _, e := f.o.Reconcile(bind(t, f.o, 0xaa, f.c.root, f.b)); e != ErrInvalid {
		t.Fatal(e)
	}
	tk := submit(t, f.o, bind(t, f.o, 0xaa, f.c.root, f.b))
	if e := f.c.RecordOutcome(tk); e != ErrPending {
		t.Fatal(e)
	}
	if e := f.c.Deliver(tk); e != ErrPending {
		t.Fatal(e)
	}
	if e := f.c.ComparePublish(tk); e != nil {
		t.Fatal(e)
	}
	if e := f.c.ComparePublish(tk); e != ErrState {
		t.Fatal(e)
	}
	f.o.Close()
	if _, e := f.o.Current(); e != ErrDisconnected {
		t.Fatal(e)
	}
	t.Run("protected", func(t *testing.T) {
		g := newTestFixture(t, defaultLimits(), false)
		p := filepath.Join(g.path, "owner-fresh-object-"+g.a.Inventory[0].Digest+".json")
		if e := os.Chmod(p, 0644); e != nil {
			t.Fatal(e)
		}
		v, e := g.o.Current()
		if e != ErrUnavailable || !reflect.DeepEqual(v, Selection{}) {
			t.Fatalf("error surface leaked nonvocabulary error/result: %T %v %+v", e, e, v)
		}
		if strings.Contains(e.Error(), g.path) {
			t.Fatal("path leak")
		}
	})
}

// Claim: candidate generation is exactly checked successor, with ceiling
// refusal before admission; absent history never becomes accepting genesis.
func TestCASGenerationLimit(t *testing.T) {
	for _, max := range []uint64{1, 2} {
		l := defaultLimits()
		l.MaxGeneration = max
		f := newTestFixture(t, l, false)
		r, e := f.o.Bind([16]byte{}, f.c.root, 2, f.b)
		if max == 1 {
			if e != ErrCapacity || f.c.used != 0 {
				t.Fatal(e)
			}
		} else {
			if e != nil {
				t.Fatal(e)
			}
			finishTest(t, f, submit(t, f.o, r))
		}
	}
	f := newTestFixture(t, defaultLimits(), false)
	for _, next := range []uint64{0, 1, 3, ^uint64(0)} {
		if _, e := f.o.Bind([16]byte{}, f.c.root, next, f.b); e != ErrInvalid {
			t.Fatal(next, e)
		}
	}
	forged := f.c.root
	forged.number = ^uint64(0)
	if _, e := f.o.Bind([16]byte{}, forged, 1, f.b); e != ErrInvalid {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, {}, []byte(`{}`), []byte(strings.Replace(literalSeed, `"generation":1`, `"generation":2`, 1))} {
		if _, e := NewFixture(f.account, defaultLimits(), raw); e != ErrInvalid {
			t.Fatal(e)
		}
	}
	// Seed input and returned request/selection copies cannot mutate owned state.
	f.seed[0] = 'x'
	if string(f.c.initial) != literalSeed {
		t.Fatal("seed alias")
	}
	got, e := f.o.Current()
	if e != nil {
		t.Fatal(e)
	}
	got.Unit.Inventory[0].Name = "bad"
	again, e := f.o.Current()
	if e != nil || !equalUnit(again.Unit, f.a) {
		t.Fatal(again, e)
	}
}

const literalWideObject = `{"data":"eXo=","installation_id":"i","kind":"freshstore-object/1","name":"b","object_kind":"blob","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`
const literalWideManifest = `{"dependencies":[{"digest":"ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21","encoded":300,"kind":"blob","name":"a","raw":1,"raw_digest":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"},{"digest":"6b531e60bb6c16159c16fbb2c31cc3319ecd31942b7e7ab28e10da33b9ad8936","encoded":300,"kind":"blob","name":"b","raw":2,"raw_digest":"68d617d6d2ee5715af77d9795566cfaba9a43a33d14cbbc95831c507c935bad1"}],"installation_id":"i","kind":"freshstore-manifest/1","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`

// Claim: terminal cancellation never recycles the attempt pool or its slots;
// a fifth distinct attempt refuses while an exact old retry remains idempotent.
func TestCASRetainedAttempts(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	var first Request
	var firstTicket Ticket
	for i := byte(0); i < 4; i++ {
		r := bind(t, f.o, 0xaa+i, f.c.root, f.b)
		tk := submit(t, f.o, r)
		if i == 0 {
			first = r
			firstTicket = tk
		}
		got, e := f.c.CancelQueued(tk)
		if e != nil || got.Outcome != ConfirmedNoCommit {
			t.Fatal(got, e)
		}
	}
	assertCharge(t, f, 81489, 30, 17)
	root := f.c.root
	if _, e := f.o.Submit(bind(t, f.o, 0xee, root, f.b)); e != ErrCapacity || f.c.used != 4 || f.c.fence != 0 || f.c.root != root {
		t.Fatal(e)
	}
	if tk, e := f.o.Submit(first); e != nil || tk != firstTicket {
		t.Fatal(tk, e)
	}
	assertCharge(t, f, 81489, 30, 17)
}

// Claim: direct comparison/outcome recording bind canonical R AND G bytes to
// the actual admitted payload. A malformed stored reservation cannot produce
// selection or a committed record, including after the publication cut.
func TestCASJournalBinding(t *testing.T) {
	for _, cut := range []string{"before-compare", "after-publication"} {
		t.Run(cut, func(t *testing.T) {
			f := newTestFixture(t, defaultLimits(), false)
			r := bind(t, f.o, 0xaa, f.c.root, f.b)
			tk := submit(t, f.o, r)
			if cut == "after-publication" {
				if e := f.c.ComparePublish(tk); e != nil {
					t.Fatal(e)
				}
			}
			root := f.c.root
			j := &f.c.jobs[0]
			original := append([]byte(nil), j.slots[0]...)
			j.slots[0][0] = '['
			var e error
			if cut == "before-compare" {
				e = f.c.ComparePublish(tk)
			} else {
				e = f.c.RecordOutcome(tk)
			}
			if e != ErrState || f.c.root != root || f.c.fence != 1 || len(j.slots[2]) != 0 || len(j.slots[3]) != 0 {
				t.Fatal("unbound journal accepted", e)
			}
			copy(j.slots[0], original)
			got, e := f.o.Reconcile(r)
			if e != nil {
				t.Fatal(e)
			}
			if cut == "before-compare" {
				requireUnknown(t, got)
				finishTest(t, f, tk)
			} else {
				if got.Outcome != Committed || got.Selection.Generation != root {
					t.Fatal(got)
				}
			}
		})
	}
}
