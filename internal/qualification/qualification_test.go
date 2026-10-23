//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type fixtureObserver struct {
	identity    Identity
	catalog     Catalog
	unavailable string
}

func (o *fixtureObserver) Version(context.Context) (string, error) {
	if o.unavailable == "version" {
		return "", ErrUnavailable
	}
	return o.identity.Version, nil
}
func (o *fixtureObserver) get(name string, m Measurement) (Measurement, error) {
	if o.unavailable == name {
		return Measurement{}, ErrUnavailable
	}
	return m, nil
}
func (o *fixtureObserver) Executable(context.Context) (Measurement, error) {
	return o.get("executable", o.identity.Executable)
}
func (o *fixtureObserver) Schema(context.Context) (Measurement, error) {
	return o.get("schema", o.identity.Schema)
}
func (o *fixtureObserver) Runner(context.Context) (Measurement, error) {
	return o.get("runner", o.identity.Runner)
}
func (o *fixtureObserver) Platform(context.Context) (Measurement, error) {
	return o.get("platform", o.identity.Platform)
}
func (o *fixtureObserver) Configuration(context.Context) (Measurement, error) {
	return o.get("configuration", o.identity.Configuration)
}
func (o *fixtureObserver) Properties(context.Context) (Measurement, error) {
	return o.get("properties", o.identity.Properties)
}
func (o *fixtureObserver) Catalog(context.Context) (Measurement, Catalog, error) {
	m, e := o.get("catalog", o.identity.Catalog)
	return m, o.catalog, e
}
func fixtureRepository(t *testing.T) (Repository, *fixtureObserver, Record) {
	t.Helper()
	catalog := Catalog{Models: []Model{{"fixture-model", []string{"medium"}}}}
	b, _ := wire.Encode(catalog)
	o := &fixtureObserver{catalog: catalog, identity: Identity{Version: "0.163.0", Executable: measure("executable", []byte("executable")), Schema: measure("schema", []byte("schema")), Runner: measure("runner", []byte("runner")), Platform: measure("platform", []byte("platform")), Configuration: measure("configuration", []byte("configuration")), Properties: measure("properties", []byte("properties")), Catalog: measure("catalog", b)}}
	r := Repository{Path: filepath.Join(t.TempDir(), "qualification"), UID: uint32(os.Geteuid()), Observer: o}
	rec := Pending(o.identity)
	rec.Mode = "live"
	rec.OperatorAccepted = true
	rec.AccountCheck = "matched"
	rec.Disposition = "accepted"
	ref, e := r.PutApproval(Approval{"qualification-approval/1", rec.Identity, "matched", true})
	check(t, e)
	rec.Approval = ref
	for n, c := range rec.Cases {
		for _, side := range []string{"positive", "negative"} {
			x := Control{Verdict: "passed", Executed: true, Command: CaseCommand(c.ID, side), ExitCode: 0, Artifacts: []string{}, DurationNS: 1, BoundNS: int64(time.Second)}
			ref, e := r.PutArtifact(Artifact{"qualification-case/1", rec.Identity, c.ID, side, x})
			check(t, e)
			x.Artifacts = []string{ref}
			if side == "positive" {
				rec.Cases[n].Positive = x
			} else {
				rec.Cases[n].Negative = x
			}
		}
	}
	return r, o, rec
}
func check(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatalf("fixture operation: %v", e)
	}
}
func reject(t *testing.T, r Repository) {
	t.Helper()
	if _, _, e := r.Read(context.Background()); !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrInvalid) {
		t.Fatalf("expected unqualified, got %v", e)
	}
}

// Claim: closed record fields reject missing/null/unknown/duplicate members and
// arbitrary material text at every string leaf; the adjacent typed record decodes.
func TestRecordStrictness(t *testing.T) {
	_, _, rec := fixtureRepository(t)
	raw, e := wire.Encode(rec)
	check(t, e)
	if _, e = DecodeRecord(raw); e != nil {
		t.Fatal("valid record refused")
	}
	var data map[string]any
	check(t, json.Unmarshal(raw, &data))
	for _, mode := range []string{"missing", "null", "unknown", "duplicate", "nested-null", "nested-extra"} {
		t.Run(mode, func(t *testing.T) {
			var m map[string]any
			check(t, json.Unmarshal(raw, &m))
			switch mode {
			case "missing":
				delete(m, "operator_accepted")
			case "null":
				m["cases"] = nil
			case "unknown":
				m["access_token"] = "fixture-material-canary"
			case "nested-null":
				m["identity"].(map[string]any)["schema"] = nil
			case "nested-extra":
				m["identity"].(map[string]any)["diagnostic"] = "fixture-material-canary"
			}
			b, _ := json.Marshal(m)
			if mode == "duplicate" {
				b = append([]byte(`{"kind":"qualification/1",`), b[1:]...)
			}
			if _, e := DecodeRecord(b); !errors.Is(e, ErrInvalid) {
				t.Fatal("invalid record accepted")
			}
		})
	}
	// A single traversal changes every string leaf independently, including
	// command args, observer names, digests, refs, timestamps and verdicts.
	var visit func(any)
	count := 0
	visit = func(v any) {
		switch m := v.(type) {
		case map[string]any:
			for k, x := range m {
				if _, ok := x.(string); ok {
					m[k] = "fixture-material-canary"
					b, _ := json.Marshal(data)
					if _, e := DecodeRecord(b); e == nil {
						t.Fatal("material string accepted")
					}
					m[k] = x
					count++
				} else {
					visit(x)
				}
			}
		case []any:
			for n, x := range m {
				if _, ok := x.(string); ok {
					m[n] = "fixture-material-canary"
					b, _ := json.Marshal(data)
					if _, e := DecodeRecord(b); e == nil {
						t.Fatal("material string accepted")
					}
					m[n] = x
					count++
				} else {
					visit(x)
				}
			}
		}
	}
	visit(data)
	if count < 100 {
		t.Fatal("canary traversal incomplete")
	}
}

// Claim: a syntactically valid hash cannot substitute material-derived bytes
// for a measured identity, typed approval or typed evidence artifact provenance.
func TestMaterialHashProvenance(t *testing.T) {
	r, o, rec := fixtureRepository(t)
	root, e := r.root(false)
	check(t, e)
	defer root.Close()
	check(t, r.verifySources(root, rec))
	materialHash := Hash([]byte("fixture-material-canary"))
	for _, kind := range []string{"executable", "configuration", "artifact", "approval"} {
		t.Run(kind, func(t *testing.T) {
			copy := rec
			copy.Cases = append([]Case(nil), rec.Cases...)
			switch kind {
			case "executable":
				copy.Identity.Executable.SHA256 = materialHash
			case "configuration":
				copy.Identity.Configuration.SHA256 = materialHash
			case "artifact":
				copy.Cases[0].Positive.Artifacts = []string{materialHash}
			case "approval":
				copy.Approval = materialHash
			}
			if copy.Identity == o.identity && r.verifySources(root, copy) == nil {
				t.Fatal("unbound material hash accepted")
			}
		})
	}
}

// Claim: evidence is durable before the list exists, and interruption at each
// publication stage leaves an admission fence, including after atomic rename.
func TestPublicationCrashOrdering(t *testing.T) {
	for _, stage := range []string{"before-evidence-flush", "after-evidence-flush", "after-list-replace", "after-list-directory-flush", "success"} {
		t.Run(stage, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			seen := []string{}
			r.Fault = func(at string) error {
				seen = append(seen, at)
				root, e := r.root(false)
				check(t, e)
				defer root.Close()
				if at == "before-evidence-flush" && exists(root, "qualified.json") {
					t.Error("list published before evidence flush")
				}
				if at != "before-evidence-flush" {
					b, _ := wire.Encode(rec)
					if !exists(root, "record-"+Hash(b)+".json") {
						t.Error("missing flushed evidence")
					}
				}
				if at == stage {
					return errors.New("injected crash")
				}
				return nil
			}
			e := r.Publish(context.Background(), rec)
			if stage == "success" {
				check(t, e)
				got, _, e := r.Read(context.Background())
				check(t, e)
				if !reflect.DeepEqual(got, rec) {
					t.Fatal("record changed")
				}
			} else {
				if e == nil {
					t.Fatal("crash did not interrupt")
				}
				reject(t, r)
			}
			if len(seen) == 0 {
				t.Fatal("fault control not applied")
			}
		})
	}
}

// Claim: pending/unexecuted/skipped rows, fake-only records and absent authority
// never publish; the green live-shaped synthetic fixture is the positive control.
func TestPublicationRequirements(t *testing.T) {
	for _, kind := range []string{"pending", "unexecuted", "skipped", "missing-row", "failed", "fake", "unaccepted", "account", "approval", "unavailable", "valid"} {
		t.Run(kind, func(t *testing.T) {
			r, o, rec := fixtureRepository(t)
			switch kind {
			case "pending":
				rec.Cases[0].Positive = Pending(rec.Identity).Cases[0].Positive
			case "unexecuted":
				rec.Cases[0].Positive.Executed = false
			case "skipped":
				rec.Cases[0].Positive.Verdict = "skipped"
			case "missing-row":
				rec.Cases = rec.Cases[1:]
			case "failed":
				rec.Cases[0].Positive.Verdict = "failed"
				rec.Cases[0].Positive.ExitCode = 1
			case "fake":
				rec.Mode = "fake"
				rec.Approval = ""
			case "unaccepted":
				rec.OperatorAccepted = false
			case "account":
				rec.AccountCheck = "mismatched"
			case "approval":
				rec.Approval = Hash([]byte("missing"))
			case "unavailable":
				o.unavailable = "schema"
			}
			e := r.Publish(context.Background(), rec)
			if kind == "valid" {
				check(t, e)
				_, _, e = r.Read(context.Background())
				check(t, e)
			} else {
				if e == nil {
					t.Fatal("unqualified record published")
				}
				reject(t, r)
			}
		})
	}
}

// Claim: each current input must match on every re-read; missing or substituted
// evidence, unsafe file protection, and unavailable observers close admission.
func TestReadInvalidation(t *testing.T) {
	for _, kind := range []string{"executable", "configuration", "platform", "schema", "runner", "properties", "catalog", "version", "missing-evidence", "missing-artifact", "mode", "symlink", "unavailable", "valid"} {
		t.Run(kind, func(t *testing.T) {
			r, o, rec := fixtureRepository(t)
			check(t, r.Publish(context.Background(), rec))
			old := o.identity
			switch kind {
			case "executable":
				o.identity.Executable.SHA256 = Hash([]byte("new"))
			case "configuration":
				o.identity.Configuration.SHA256 = Hash([]byte("new"))
			case "platform":
				o.identity.Platform.SHA256 = Hash([]byte("new"))
			case "schema":
				o.identity.Schema.SHA256 = Hash([]byte("new"))
			case "runner":
				o.identity.Runner.SHA256 = Hash([]byte("new"))
			case "properties":
				o.identity.Properties.SHA256 = Hash([]byte("new"))
			case "catalog":
				o.identity.Catalog.SHA256 = Hash([]byte("new"))
			case "version":
				o.identity.Version = "0.162.0"
			case "missing-evidence":
				b, _ := wire.Encode(rec)
				check(t, os.Remove(filepath.Join(r.Path, "record-"+Hash(b)+".json")))
			case "missing-artifact":
				check(t, os.Remove(filepath.Join(r.Path, "artifact-"+rec.Cases[0].Positive.Artifacts[0]+".json")))
			case "mode":
				check(t, os.Chmod(filepath.Join(r.Path, "qualified.json"), 0644))
			case "symlink":
				p := filepath.Join(r.Path, "qualified.json")
				check(t, os.Rename(p, p+".saved"))
				check(t, os.Symlink(p+".saved", p))
			case "unavailable":
				o.unavailable = "schema"
			}
			if kind == "valid" {
				_, _, e := r.Read(context.Background())
				check(t, e)
			} else {
				reject(t, r)
			}
			o.identity = old
		})
	}
}

// Claim: the entire list is validated before matching an entry; a malformed or
// duplicate trailing entry cannot hide behind an otherwise valid first entry.
func TestPublishedListStrictness(t *testing.T) {
	for _, kind := range []string{"invalid-tail", "duplicate-tail", "valid"} {
		t.Run(kind, func(t *testing.T) {
			r, _, rec := fixtureRepository(t)
			check(t, r.Publish(context.Background(), rec))
			path := filepath.Join(r.Path, "qualified.json")
			b, e := os.ReadFile(path)
			check(t, e)
			var list List
			check(t, wire.Decode(b, &list))
			switch kind {
			case "invalid-tail":
				list.Entries = append(list.Entries, Entry{})
			case "duplicate-tail":
				list.Entries = append(list.Entries, list.Entries[0])
			}
			b, e = wire.Encode(list)
			check(t, e)
			check(t, os.WriteFile(path, b, 0600))
			if kind == "valid" {
				_, _, e = r.Read(context.Background())
				check(t, e)
			} else {
				reject(t, r)
			}
		})
	}
}

// Claim: native observers measure protected executable/current runner/platform
// without executing the candidate; unavailable schema/version/properties/catalog
// cannot be replaced by a historical hash. Canonical static identity ignores
// launch paths because no per-launch inputs enter this observer.
func TestNativeObservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate")
	check(t, os.WriteFile(path, []byte("fixture executable; never executed"), 0700))
	raw, _ := wire.Encode(map[string]any{"policy_generation": 1, "profile": "example"})
	o := NativeObserver{ExecutablePath: path, StaticPolicy: raw}
	m, e := o.Executable(context.Background())
	check(t, e)
	if m.SHA256 != Hash([]byte("fixture executable; never executed")) {
		t.Fatal("wrong executable digest")
	}
	first, e := o.Configuration(context.Background())
	check(t, e)
	again, e := o.Configuration(context.Background())
	check(t, e)
	if first != again {
		t.Fatal("unstable configuration")
	}
	o.StaticPolicy, _ = wire.Encode(map[string]any{"policy_generation": 2, "profile": "example"})
	changed, e := o.Configuration(context.Background())
	check(t, e)
	if changed == first {
		t.Fatal("policy change not bound")
	}
	if _, e := o.Runner(context.Background()); e != nil {
		t.Fatal("current runner unavailable")
	}
	if _, e := o.Platform(context.Background()); e != nil {
		t.Fatal("current platform unavailable")
	}
	_, _, missing := Observe(context.Background(), o)
	for _, name := range []string{"version/1", "schema/1", "properties/1", "catalog/1"} {
		if !strings.Contains(strings.Join(missing, ","), name) {
			t.Fatal("missing unavailable observer")
		}
	}
	check(t, os.Chmod(path, 0777))
	if _, e := o.Executable(context.Background()); e == nil {
		t.Fatal("writable executable admitted")
	}
	link := path + ".link"
	check(t, os.Symlink(path, link))
	o.ExecutablePath = link
	if _, e := o.Executable(context.Background()); e == nil {
		t.Fatal("symlink executable admitted")
	}
	if bytes.Contains(raw, []byte("fixture executable")) {
		t.Fatal("unexpected fixture binding")
	}
}

// Claim: the row gate itself rejects a structurally valid pending control;
// provenance checks are additional defenses, not a replacement for this gate.
func TestPublishableRows(t *testing.T) {
	_, _, rec := fixtureRepository(t)
	check(t, rec.Publishable())
	rec.Cases[0].Positive = Pending(rec.Identity).Cases[0].Positive
	check(t, rec.Validate())
	if rec.Publishable() == nil {
		t.Fatal("pending row accepted as green")
	}
}
