//go:build linux

package generationcas

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/relux-works/swarma-credential-broker/internal/freshstore"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

const literalSeed = `{"epoch":"9999999999999999999999999999999999999999999999999999999999999999","generation":1,"initial_manifest":"8371a8459fdd568eb799ca504fdf21cf3a8ae2a7144b65b61e8f025f0cd82323","installation":"i","kind":"freshcas-initial/1","pin":"0000000000000000000000000000000000000000000000000000000000000000","schema":"freshcas/1","scope":"s","units":[{"binding":{"installation":"i","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","scope":"s"},"inventory":[{"digest":"ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21","encoded":300,"kind":"blob","name":"a","raw":1,"raw_digest":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}],"manifest":"8371a8459fdd568eb799ca504fdf21cf3a8ae2a7144b65b61e8f025f0cd82323","schema":"freshstore/1"},{"binding":{"installation":"i","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"m:8371a8459fdd568eb799ca504fdf21cf3a8ae2a7144b65b61e8f025f0cd82323","scope":"s"},"inventory":[{"digest":"f29b7c6ee4fd996f9a5525528a3720bdea4a7652d463c4158cc4d0848a2bb10c","encoded":300,"kind":"blob","name":"a","raw":1,"raw_digest":"a1fce4363854ff888cff4b8e7875d600c2682390412a8cf79b37d0b11148b0fa"}],"manifest":"bb212c3034d3b62de7f711be99d96577c7af1bce4fb171b507c304dbe82152e9","schema":"freshstore/1"}]}`

var frozenRecords = map[string]struct {
	size   int
	digest string
}{
	"A-object":                {300, "ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21"},
	"A-manifest":              {478, "8371a8459fdd568eb799ca504fdf21cf3a8ae2a7144b65b61e8f025f0cd82323"},
	"B-object":                {300, "f29b7c6ee4fd996f9a5525528a3720bdea4a7652d463c4158cc4d0848a2bb10c"},
	"B-manifest":              {478, "bb212c3034d3b62de7f711be99d96577c7af1bce4fb171b507c304dbe82152e9"},
	"S":                       {1379, "84db75026180d2abc4bc51e686a6e121c5d9b70d330d890954bb007070abdf25"},
	"AB-R":                    {1127, "3f35d080cfff243d07d8a88aed034176003a606213d27ce95d1dba1efc1fe33d"},
	"AB-G":                    {832, "30f422eca5c0c33380d301daaf430d850c23b0726726d28e5c181239cd55c72e"},
	"BA-R":                    {1127, "63432fe0b7e5e604d391d0bd298755143cb4409ce2fb2aeb478bc474d532ba84"},
	"BA-G":                    {832, "393bc8972ccdb595266f9d20c8d3cd5851b333ea720a85d0b23f30252c8784b6"},
	"stale-after-ABA-R":       {1127, "11f31cf44acdaa61e4f49fd6cf0b688383dd56db31dc65da6125787f9b0574ce"},
	"stale-after-ABA-G":       {832, "da171acf73a0db0efb202853d0c3d5234e8aa9438f0ee5a3f208b19fd0404bdd"},
	"competitor-R":            {1127, "8662f61c4067aaeff00468ec37c005d474f5a54045d85194486eccf2269e1696"},
	"competitor-G":            {832, "3a8dfcbd41ab3803d87def8013436a75f7da43df94d82c02c5d953407ce15348"},
	"cancel-R":                {1127, "9e2b83c8ee9bc7a43659c4a2095ec6a3cdf48fa3afc5cd7b1af180baa64994f8"},
	"cancel-G":                {832, "b60813783f9b03b2c166cf11b0ec100477b37e9d062d86cd874ffb86bf37df1a"},
	"AB-O-published":          {335, "38ab10e0f3202645013a5bc3eeff2ddbe8d6b07138b81899b022f83dfa6e6ed3"},
	"AB-F-published":          {278, "9ad720d54194dd3483059293e59c11c209be1892ad40143fc792cc494f3bc4eb"},
	"BA-O-published":          {335, "7a21196ac7cf874c48abcd1ae4df2c4ff3991bedb256046ad81c4d8b91f65423"},
	"BA-F-published":          {278, "c659e013dc6d21c9c1cd09a4f584ae5c2fb93535c625287647d9f7d52c53a240"},
	"stale-after-ABA-O-stale": {331, "2d1b75435a49013c18b43785465aac389bb0c28d1ee2d6c2d38ca01ef6215d0a"},
	"stale-after-ABA-F-stale": {278, "bcd4abd88c89bff4c444887f17da507b32b09c59d36b49b0e3ef5bfbc6a019c6"},
	"competitor-O-stale":      {331, "41c2338eef86d3778f0d1704c28befe26131d1fbe4555f0bf256aaad25efb908"},
	"competitor-F-stale":      {278, "0cd94224d088c10e3d5e955f494f3cc732e7014204935f2906f531303a2a53c5"},
	"cancel-O-cancelled":      {335, "403624c1cba28ec2ac7dfb4504c1f60129292be9a616f7e9f26b0dca0d03c8e4"},
	"cancel-F-cancelled":      {278, "45f8d9f580ef8dc3c400d28240e48fe4dba21b8366b973937a0cf19c9a832e6d"},
}

func golden(t *testing.T, name string, b []byte) {
	t.Helper()
	g, ok := frozenRecords[name]
	d := sha256.Sum256(b)
	if !ok || len(b) != g.size || hex.EncodeToString(d[:]) != g.digest {
		t.Fatalf("literal %s differs: len=%d sha=%x", name, len(b), d)
	}
}

// Claim: literal records from real owned operations match independent frozen
// sizes and hashes; selected generations and attempt domains are pinned too.
func TestCASFrozenRecords(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	golden(t, "S", f.c.initial)
	if hx(f.c.root.record) != "6dad1ac772766a3ab200810f632d787211880eb5ef716067f494b2f4b5ac82c1" {
		t.Fatal("initial token")
	}
	for _, name := range []string{"A-object", "A-manifest", "B-object", "B-manifest"} {
		b := f.content(t, name)
		golden(t, name, b)
	}
	r := bind(t, f.o, 0xaa, f.c.root, f.b)
	if hx(r.Attempt) != "889dc44c06f96ed567287d148a27b44cacb9b51b711ad5d364a11f36dd20bfb7" {
		t.Fatal("attempt domain")
	}
	tk := submit(t, f.o, r)
	golden(t, "AB-R", f.c.jobs[0].slots[0])
	golden(t, "AB-G", f.c.jobs[0].slots[1])
	ab := finishTest(t, f, tk)
	if hx(ab.Selection.Generation.record) != "058576b19a9d75a22b205b0c89a3b939ca2d00e685fafce2acda8ab0fd700fb9" || hx(ab.PayloadHash) != "4f38d96a13f52d7c268d6afe4ef6621cb48ffcb98c61615ffbfb2bb73decd44c" {
		t.Fatal("AB token/payload")
	}
	golden(t, "AB-O-published", f.c.jobs[0].slots[2])
	golden(t, "AB-F-published", f.c.jobs[0].slots[3])
	tk = submit(t, f.o, bind(t, f.o, 0xbb, ab.Selection.Generation, f.a))
	golden(t, "BA-R", f.c.jobs[1].slots[0])
	golden(t, "BA-G", f.c.jobs[1].slots[1])
	ba := finishTest(t, f, tk)
	if hx(ba.Selection.Generation.record) != "cb8904b365f3e05674144c950ca8ee489fe46649143c0e7a163fc77d64d1bf63" {
		t.Fatal("BA token")
	}
	golden(t, "BA-O-published", f.c.jobs[1].slots[2])
	golden(t, "BA-F-published", f.c.jobs[1].slots[3])
	tk = submit(t, f.o, bind(t, f.o, 0xcc, f.c.initialToken, f.b))
	golden(t, "stale-after-ABA-R", f.c.jobs[2].slots[0])
	golden(t, "stale-after-ABA-G", f.c.jobs[2].slots[1])
	if e := f.c.ComparePublish(tk); e != ErrTerminal {
		t.Fatal(e)
	}
	golden(t, "stale-after-ABA-O-stale", f.c.jobs[2].slots[2])
	golden(t, "stale-after-ABA-F-stale", f.c.jobs[2].slots[3])
	f = newTestFixture(t, defaultLimits(), false)
	tk = submit(t, f.o, bind(t, f.o, 0xaa, f.c.root, f.b))
	finishTest(t, f, tk)
	tk = submit(t, f.o, bind(t, f.o, 0xdd, f.c.initialToken, f.b))
	golden(t, "competitor-R", f.c.jobs[1].slots[0])
	golden(t, "competitor-G", f.c.jobs[1].slots[1])
	if e := f.c.ComparePublish(tk); e != ErrTerminal {
		t.Fatal(e)
	}
	golden(t, "competitor-O-stale", f.c.jobs[1].slots[2])
	golden(t, "competitor-F-stale", f.c.jobs[1].slots[3])
	f = newTestFixture(t, defaultLimits(), false)
	tk = submit(t, f.o, bind(t, f.o, 0xee, f.c.root, f.b))
	golden(t, "cancel-R", f.c.jobs[0].slots[0])
	golden(t, "cancel-G", f.c.jobs[0].slots[1])
	if r, e := f.c.CancelQueued(tk); e != nil || r.Outcome != ConfirmedNoCommit {
		t.Fatal(r, e)
	}
	golden(t, "cancel-O-cancelled", f.c.jobs[0].slots[2])
	golden(t, "cancel-F-cancelled", f.c.jobs[0].slots[3])
}

// Claim: the closed seed parser rejects noncanonical and absent history rather
// than initializing it. These codec checks do not qualify arbitrary JSON.
func TestCASClosedCodec(t *testing.T) {
	l := defaultLimits()
	if _, e := parseSeed([]byte(literalSeed), l); e != nil {
		t.Fatal(e)
	}
	cases := map[string]string{"LF": literalSeed + "\n", "BOM": "\xef\xbb\xbf" + literalSeed, "empty": "", "unknown": strings.Replace(literalSeed, `"generation":1`, `"extra":1,"generation":1`, 1), "duplicate": strings.Replace(literalSeed, `"generation":1`, `"generation":1,"generation":1`, 1), "leading-zero": strings.Replace(literalSeed, `"generation":1`, `"generation":01`, 1), "overflow": strings.Replace(literalSeed, `"generation":1`, `"generation":18446744073709551616`, 1), "schema": strings.Replace(literalSeed, `"schema":"freshcas/1"`, `"schema":"freshcas/2"`, 1), "missing-catalog": strings.Replace(literalSeed, `"units":[`, `"units":[] ,"extra":[`, 1)}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := parseSeed([]byte(b), l); e != ErrInvalid {
				t.Fatalf("accepted malformed seed: %v", e)
			}
		})
	}
	l.RecordBytes = uint64(len(literalSeed))
	if _, e := parseSeed([]byte(literalSeed), l); e != nil {
		t.Fatal(e)
	}
	l.RecordBytes--
	if _, e := parseSeed([]byte(literalSeed), l); e != ErrCapacity {
		t.Fatal(e)
	}
}

// Claim: positive effective logical bounds and inclusive adjacent refusals are
// enforced before construction, with fixed errors and checked arithmetic.
func TestCASReadAndCostBounds(t *testing.T) {
	l := defaultLimits()
	m, w, e := l.costs()
	if e != nil || m != 1020160 || w != 13332736 {
		t.Fatal(m, w, e)
	}
	base := prepare(t, false)
	for _, which := range []string{"memory", "work"} {
		p := l
		if which == "memory" {
			p.MemoryBytes = m
		} else {
			p.WorkBytes = w
		}
		if _, e := NewFixture(base.account, p, base.seed); e != nil {
			t.Fatal(e)
		}
		if which == "memory" {
			p.MemoryBytes--
		} else {
			p.WorkBytes--
		}
		if _, e := NewFixture(base.account, p, base.seed); e != ErrCapacity {
			t.Fatal(e)
		}
	}
	for i := 0; i < reflect.TypeOf(l).NumField(); i++ {
		p := l
		reflect.ValueOf(&p).Elem().Field(i).SetUint(0)
		if _, _, e := p.costs(); e != ErrInvalid {
			t.Fatalf("zero field%d: %v", i, e)
		}
	}
	p := l
	p.RecordBytes = (1 << 20) + 1
	if _, _, e := p.costs(); e != ErrInvalid {
		t.Fatal(e)
	}
	p = l
	p.RetainedBytes = 1<<40 + 1
	if _, _, e := p.costs(); e != ErrInvalid {
		t.Fatal(e)
	}
	if _, ok := add(^uint64(0), 1); ok {
		t.Fatal("add overflow")
	}
	if _, ok := mul(^uint64(0), 2); ok {
		t.Fatal("mul overflow")
	}
	if unsafe.Sizeof(job{}) > 1024 || unsafe.Sizeof(mailbox{}) > 1024 || unsafe.Sizeof(Coordinator{}) > 4096 {
		t.Fatal("fixed runtime residency")
	}
	// S plus512controls plus1256 selected B/predecessor bytes gives exact constructor read Q.
	p = l
	p.ReadBytes = uint64(len(base.seed)) + 512 + 1256
	if _, e := NewFixture(base.account, p, base.seed); e != nil {
		t.Fatal(e)
	}
	p.ReadBytes--
	if _, e := NewFixture(base.account, p, base.seed); e != ErrCapacity {
		t.Fatal(e)
	}
}

// Claim: catalog and dependency ordering are closed at the owned parser and
// public Bind. Wide has a distinct initial token; parser controls prove only
// that parser gate if unchanged downstream freshstore would also reject.
func TestCASInventoryOrder(t *testing.T) {
	f := newTestFixture(t, wideLimits(), true)
	if len(f.c.initial) != 2103 || hx(f.c.root.record) != "778f5e517c5e01f6ddae677a7106e742313e3a5d035f0f41c7fd3d8831deb3ed" {
		t.Fatal("wide seed identity")
	}
	want := copyUnit(f.wide)
	want.Inventory[0], want.Inventory[1] = want.Inventory[1], want.Inventory[0]
	t.Run("codec-reverse", func(t *testing.T) {
		w := newWriter(f.c.limits)
		w.unit(want)
		p := parser{b: w.b, l: f.c.limits}
		p.unit()
		if !p.err {
			t.Fatal("owned parser accepted reversed distinct pair")
		}
	})
	root := f.c.root
	if _, e := f.o.Bind([16]byte{}, root, 2, want); e != ErrInvalid || f.c.root != root || f.c.used != 0 {
		t.Fatal(e)
	}
	req := bind(t, f.o, 0xff, root, f.wide)
	if hx(req.Attempt) != "73290b5b2f2f7d7c43fa6ff961ae93066e03da5d0981066c5706f6238d5baeee" {
		t.Fatal("wide attempt")
	}
	tk := submit(t, f.o, req)
	got := finishTest(t, f, tk)
	if hx(got.Selection.Generation.record) != "660afd5ecbd117275d34839eca829e1d8ab220caab49b6eac47ece2db0995197" {
		t.Fatal("wide result")
	}
	assertCharge(t, f, 33320, 20, 5)
	m, w, e := f.c.limits.costs()
	if m != 1020416 || w != 15768576 || e != nil {
		t.Fatal(m, w, e)
	}
}

// Claim: full independent unit identity/scope/pin/schema/inventory are required;
// rejection preserves root, reservations, and the ability to admit a valid pair.
func TestCASBindingInventory(t *testing.T) {
	f := newTestFixture(t, defaultLimits(), false)
	root := f.c.root
	edits := []func(*freshstore.Expected){func(u *freshstore.Expected) { u.Scope = "t" }, func(u *freshstore.Expected) { u.Installation = "j" }, func(u *freshstore.Expected) { u.Pin = strings.Repeat("2", 64) }, func(u *freshstore.Expected) { u.Schema = "freshstore/2" }, func(u *freshstore.Expected) { u.Previous = "g:" + strings.Repeat("2", 64) }, func(u *freshstore.Expected) { u.Inventory = nil }, func(u *freshstore.Expected) { u.Inventory = append(u.Inventory, u.Inventory[0]) }, func(u *freshstore.Expected) { u.Inventory[0].Raw = 2 }, func(u *freshstore.Expected) { u.Inventory[0].Digest = strings.Repeat("f", 64) }, func(u *freshstore.Expected) { u.ManifestDigest = strings.Repeat("f", 64) }}
	for i, edit := range edits {
		u := copyUnit(f.b)
		edit(&u)
		_, e := f.o.Bind([16]byte{}, root, 2, u)
		if e != ErrInvalid {
			t.Fatalf("invalid%d: %v", i, e)
		}
		if f.c.root != root || f.c.used != 0 || f.c.fence != 0 {
			t.Fatal("rejection changed state")
		}
	}
	finishTest(t, f, submit(t, f.o, bind(t, f.o, 0xaa, root, f.b)))
}
