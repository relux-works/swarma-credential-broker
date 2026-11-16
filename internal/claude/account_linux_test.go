//go:build linux

package claude

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const fakeToken = "FAKE_CLAUDE_TOKEN_NOT_A_CREDENTIAL_a1"
const installation = "fixture-claude"
const label = "owner/claude/test"

type fixture struct {
	s       *store.Store
	a       *Account
	records *store.Account
	root    string
	dir     string
}

func newFixture(t *testing.T, hook store.Durability) fixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "store")
	s, err := store.Open(root, installation, uint32(os.Geteuid()), true, hook)
	if err != nil {
		t.Fatal("store setup failed")
	}
	t.Cleanup(func() { s.Close() })
	r, err := s.Account(label, true)
	if err != nil {
		t.Fatal("account setup failed")
	}
	a, err := NewAccount(r, installation, label)
	if err != nil {
		t.Fatal("custody setup failed")
	}
	h := sha256.Sum256([]byte(label))
	return fixture{s, a, r, root, filepath.Join(root, "account-"+hex.EncodeToString(h[:]))}
}

func enroll(t *testing.T, a *Account) {
	t.Helper()
	if a.Enroll([]byte(fakeToken), nil) != nil {
		t.Fatal("valid enrollment refused")
	}
}

func safeOutput(t *testing.T, b []byte) {
	t.Helper()
	h := sha256.Sum256([]byte(fakeToken))
	for _, v := range []string{fakeToken, base64.StdEncoding.EncodeToString([]byte(fakeToken)), hex.EncodeToString([]byte(fakeToken)), hex.EncodeToString(h[:])} {
		if bytes.Contains(b, []byte(v)) {
			t.Fatal("fixture material escaped metadata boundary")
		}
	}
}

// Invalid material/expiry is rejected before a store write; each neighbor can
// still enroll valid inert material. These are custody checks, not lease checks.
func TestEnrollmentRefusalBeforeWrite(t *testing.T) {
	offset := time.Date(2030, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
	fraction := time.Date(2030, 1, 1, 0, 0, 0, 1, time.UTC)
	zero := time.Time{}
	for _, tc := range []struct {
		name   string
		token  []byte
		expiry *time.Time
	}{
		{"empty", nil, nil},
		{"space", []byte("FAKE invalid"), nil},
		{"newline", []byte("FAKE\ninvalid"), nil},
		{"nul", []byte("FAKE\x00invalid"), nil},
		{"oversize", bytes.Repeat([]byte("F"), 4097), nil},
		{"offset-expiry", []byte(fakeToken), &offset},
		{"fractional-expiry", []byte(fakeToken), &fraction},
		{"zero-expiry", []byte(fakeToken), &zero},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			f := newFixture(t, func(string) error { writes++; return nil })
			writes = 0
			err := f.a.Enroll(tc.token, tc.expiry)
			if !errors.Is(err, ErrInvalid) || writes != 0 {
				t.Fatal("invalid enrollment reached persistence")
			}
			safeOutput(t, []byte(err.Error()))
			r, err := f.records.Records()
			if err != nil || len(r) != 0 {
				t.Fatal("refusal left account records")
			}
			enroll(t, f.a)
			s, err := f.a.Status()
			if err != nil || s.State != "enrolled" || s.TokenExpiresAt != nil || s.Refreshable {
				t.Fatal("valid control failed or invented lifetime/refresh")
			}
		})
	}
}

// Status opens only metadata, even when material is an unreadable symlink.
// It reports recorded custody, never material health or permission to lease.
func TestStatusNeverOpensMaterial(t *testing.T) {
	f := newFixture(t, nil)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if f.a.Enroll([]byte(fakeToken), &expiry) != nil {
		t.Fatal("known-expiry control failed")
	}
	expiry = expiry.Add(time.Hour)
	before, err := f.a.Status()
	if err != nil || before.Account != label || before.Kind != Kind || before.Mode != Mode || before.State != "enrolled" || before.TokenExpiresAt.Hour() != 0 || before.Refreshable {
		t.Fatal("status metadata control failed")
	}
	raw, err := wire.Encode(before)
	if err != nil {
		t.Fatal("status encoding failed")
	}
	safeOutput(t, raw)
	secret := filepath.Join(f.dir, materialName)
	st, err := os.Lstat(secret)
	if err != nil || st.Mode() != 0600 {
		t.Fatal("material protection mismatch")
	}
	if os.Remove(secret) != nil || os.Symlink(filepath.Join(f.root, "absent"), secret) != nil {
		t.Fatal("material no-open witness setup failed")
	}
	after, err := f.a.Status()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("metadata lookup touched material")
	}
}

// A duplicate enrollment refuses before any material write, preserves the
// original bytes and cannot clear a hold. The first enrollment is the control.
func TestEnrollmentCannotReplaceOrLiftHold(t *testing.T) {
	var writes int
	f := newFixture(t, func(string) error { writes++; return nil })
	enroll(t, f.a)
	before, err := os.ReadFile(filepath.Join(f.dir, materialName))
	if err != nil {
		t.Fatal("material control unavailable")
	}
	if f.a.Hold() != nil {
		t.Fatal("hold control failed")
	}
	writes = 0
	err = f.a.Enroll([]byte("FAKE_CLAUDE_REPLACEMENT_NOT_A_CREDENTIAL"), nil)
	if !errors.Is(err, ErrExists) || writes != 0 {
		t.Fatal("duplicate enrollment reached material persistence")
	}
	safeOutput(t, []byte(err.Error()))
	after, err := os.ReadFile(filepath.Join(f.dir, materialName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("duplicate enrollment replaced material")
	}
	s, err := f.a.Status()
	if err != nil || s.State != "held" {
		t.Fatal("enrollment cleared hold")
	}
}

// An already recorded account refuses a duplicate using metadata before any
// material read. A broken material target cannot change that precise refusal;
// the nearby original enrollment/status is the valid custody control.
func TestDuplicateRefusalDoesNotReadMaterial(t *testing.T) {
	f := newFixture(t, nil)
	enroll(t, f.a)
	if _, err := f.a.Status(); err != nil {
		t.Fatal("metadata control failed")
	}
	secret := filepath.Join(f.dir, materialName)
	if os.Remove(secret) != nil || os.Symlink(filepath.Join(f.root, "absent"), secret) != nil {
		t.Fatal("no-open refusal witness setup failed")
	}
	if err := f.a.Enroll([]byte(fakeToken), nil); !errors.Is(err, ErrExists) {
		t.Fatal("duplicate refusal opened material first")
	}
}

// Durable account hold survives reopen and a fresh wrapper; another account
// remains unaffected. This does not prove service-use closure or vendor revoke.
func TestHoldPersistsAcrossReopen(t *testing.T) {
	f := newFixture(t, nil)
	enroll(t, f.a)
	r, err := f.s.Account("owner/claude/other", true)
	if err != nil {
		t.Fatal("unrelated account setup failed")
	}
	other, err := NewAccount(r, installation, "owner/claude/other")
	if err != nil {
		t.Fatal("unrelated custody setup failed")
	}
	enroll(t, other)
	if f.a.Hold() != nil || f.a.Hold() != nil {
		t.Fatal("idempotent hold failed")
	}
	s, err := other.Status()
	if err != nil || s.State != "enrolled" {
		t.Fatal("hold affected unrelated account")
	}
	f.s.Close()
	reopened, err := store.Open(f.root, installation, uint32(os.Geteuid()), false, nil)
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer reopened.Close()
	r, err = reopened.Account(label, false)
	if err != nil {
		t.Fatal("account reopen failed")
	}
	a, err := NewAccount(r, installation, label)
	if err != nil {
		t.Fatal("wrapper reopen failed")
	}
	s, err = a.Status()
	if err != nil || s.State != "held" {
		t.Fatal("restart cleared hold")
	}
}

// A hold acknowledges only after all durability stages. Any injected failure
// yields UNKNOWN and closes this object, even if a rename already took effect.
func TestHoldDurabilityFailures(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			armed := false
			f := newFixture(t, func(s string) error {
				if armed && s == stage {
					return errors.New("inert persistence failure")
				}
				return nil
			})
			enroll(t, f.a)
			armed = true
			if !errors.Is(f.a.Hold(), ErrUnavailable) {
				t.Fatal("failed hold acknowledged")
			}
			if s, err := f.a.Status(); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(s, Status{}) {
				t.Fatal("unknown persistence reported as known status")
			}
			control := newFixture(t, nil)
			enroll(t, control.a)
			if control.a.Hold() != nil {
				t.Fatal("durable hold control failed")
			}
		})
	}
}

// A fresh wrapper cannot convert a prior rename-without-directory-sync into a
// durable acknowledgment. Its retry must also flush; a resolved write controls.
func TestHoldRetryReestablishesDurability(t *testing.T) {
	armed := false
	f := newFixture(t, func(stage string) error {
		if armed && stage == "directory-sync" {
			return errors.New("inert directory sync failure")
		}
		return nil
	})
	enroll(t, f.a)
	armed = true
	if !errors.Is(f.a.Hold(), ErrUnavailable) {
		t.Fatal("uncertain hold acknowledged")
	}
	retry, err := NewAccount(f.records, installation, label)
	if err != nil {
		t.Fatal("retry wrapper setup failed")
	}
	if !errors.Is(retry.Hold(), ErrUnavailable) {
		t.Fatal("observed record substituted for durable acknowledgment")
	}
	armed = false
	control, err := NewAccount(f.records, installation, label)
	if err != nil || control.Hold() != nil {
		t.Fatal("durable retry control failed")
	}
	if s, err := control.Status(); err != nil || s.State != "held" {
		t.Fatal("durable retry lost hold")
	}
}

// A terminal local revision cannot acknowledge a hold whose successor would
// fail metadata admission. Normal revision space remains writable.
func TestHoldRevisionBoundary(t *testing.T) {
	writes := 0
	f := newFixture(t, func(string) error { writes++; return nil })
	enroll(t, f.a)
	b, err := f.records.Read(metadataName)
	var m metadata
	if err != nil || wire.Decode(b, &m) != nil {
		t.Fatal("revision fixture unavailable")
	}
	m.Revision = 9007199254740990
	b, err = wire.Encode(m)
	if err != nil || os.WriteFile(filepath.Join(f.dir, metadataName), b, 0600) != nil {
		t.Fatal("revision plant failed")
	}
	if _, err := f.a.Status(); err != nil {
		t.Fatal("readable boundary refused")
	}
	writes = 0
	if !errors.Is(f.a.Hold(), ErrUnavailable) || writes != 0 {
		t.Fatal("unreadable successor acknowledged")
	}
	control := newFixture(t, nil)
	enroll(t, control.a)
	if control.a.Hold() != nil {
		t.Fatal("revision control failed")
	}
}

// Interrupted enrollment retains its material orphan without adopting or
// replacing it on retry; fully durable enrollment is the adjacent control.
func TestEnrollmentOrphanRefusesRetry(t *testing.T) {
	writes, armed := 0, false
	f := newFixture(t, func(stage string) error {
		if armed && stage == "write" {
			writes++
			if writes == 2 {
				return errors.New("inert metadata failure")
			}
		}
		return nil
	})
	armed = true
	if !errors.Is(f.a.Enroll([]byte(fakeToken), nil), ErrUnavailable) {
		t.Fatal("interrupted enrollment acknowledged")
	}
	original, err := os.ReadFile(filepath.Join(f.dir, materialName))
	if err != nil {
		t.Fatal("orphan not retained")
	}
	armed = false
	retry, err := NewAccount(f.records, installation, label)
	if err != nil {
		t.Fatal("retry wrapper setup failed")
	}
	if !errors.Is(retry.Enroll([]byte("FAKE_CLAUDE_ORPHAN_REPLACEMENT"), nil), ErrUnavailable) {
		t.Fatal("orphan silently adopted")
	}
	if _, err = retry.Status(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("orphan reported as enrolled")
	}
	after, err := os.ReadFile(filepath.Join(f.dir, materialName))
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("orphan overwritten")
	}
	control := newFixture(t, nil)
	enroll(t, control.a)
}

// Semantically invalid or widened metadata never produces a status/hold result;
// each case starts from valid enrolled metadata and checks the fixed error.
func TestMetadataRefusals(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*metadata)
	}{
		{"record-kind", func(m *metadata) { m.Kind = "unknown/1" }},
		{"installation", func(m *metadata) { m.Installation = "other" }},
		{"revision", func(m *metadata) { m.Revision = 0 }},
		{"overflow", func(m *metadata) { m.Revision = 9007199254740991 }},
		{"account", func(m *metadata) { m.Status.Account = "other" }},
		{"credential-kind", func(m *metadata) { m.Status.Kind = "api-key" }},
		{"exposed-mode", func(m *metadata) { m.Status.Mode = "exposed" }},
		{"refresh", func(m *metadata) { m.Status.Refreshable = true }},
		{"state", func(m *metadata) { m.Status.State = "active" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			f := newFixture(t, nil)
			enroll(t, f.a)
			if _, err := f.a.Status(); err != nil {
				t.Fatal("valid status control failed")
			}
			b, err := f.records.Read(metadataName)
			var m metadata
			if err != nil || wire.Decode(b, &m) != nil {
				t.Fatal("metadata fixture unavailable")
			}
			mutate.apply(&m)
			b, err = wire.Encode(m)
			if err != nil || os.WriteFile(filepath.Join(f.dir, metadataName), b, 0600) != nil {
				t.Fatal("corruption plant failed")
			}
			if s, err := f.a.Status(); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(s, Status{}) {
				t.Fatal("invalid metadata accepted")
			}
			if !errors.Is(f.a.Hold(), ErrUnavailable) {
				t.Fatal("invalid metadata changed")
			}
		})
	}
}

// Concurrent wrappers serialize enrollment through immutable material/CAS;
// after a successful hold all fresh wrappers observe held metadata.
func TestConcurrentCustodyAndHold(t *testing.T) {
	f := newFixture(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			a, err := NewAccount(f.records, installation, label)
			if err == nil {
				err = a.Enroll([]byte(fakeToken), nil)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrExists) && !errors.Is(err, ErrUnavailable) {
			t.Fatal("unexpected concurrent result")
		}
	}
	if successes != 1 {
		t.Fatal("enrollment did not have one winner")
	}
	if f.a.Hold() != nil {
		t.Fatal("hold control failed")
	}
	for range 8 {
		a, err := NewAccount(f.records, installation, label)
		if err != nil {
			t.Fatal("fresh wrapper failed")
		}
		if s, err := a.Status(); err != nil || s.State != "held" {
			t.Fatal("fresh wrapper bypassed hold")
		}
	}
}

// Empty/invalid constructor and zero-value calls cannot create custody or hold
// authority; a genuine protected store account is the positive control.
func TestAccountConstructionNeighbors(t *testing.T) {
	f := newFixture(t, nil)
	for _, tc := range []struct {
		store               *store.Account
		installation, label string
	}{
		{nil, installation, label},
		{&store.Account{}, installation, label},
		{f.records, "", label},
		{f.records, installation, ""},
		{f.records, installation, "invalid\nlabel"},
	} {
		if a, err := NewAccount(tc.store, tc.installation, tc.label); !errors.Is(err, ErrInvalid) || a != nil {
			t.Fatal("invalid constructor admitted")
		}
	}
	if _, err := f.a.Status(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("absent metadata accepted")
	}
	if !errors.Is(f.a.Hold(), ErrUnavailable) {
		t.Fatal("absent metadata held")
	}
	enroll(t, f.a)
	if _, err := f.a.Status(); err != nil {
		t.Fatal("valid control refused")
	}
	var zero *Account
	if !errors.Is(zero.Enroll([]byte(fakeToken), nil), ErrInvalid) {
		t.Fatal("nil enrollment admitted")
	}
	if _, err := zero.Status(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil status admitted")
	}
	if !errors.Is(zero.Hold(), ErrUnavailable) {
		t.Fatal("nil hold admitted")
	}
}
