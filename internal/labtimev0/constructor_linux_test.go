//go:build linux && broker_lab

package labtimev0

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

func constructionRuntimeCalls(test *testing.T) *int {
	test.Helper()
	calls := 0
	previous := labRuntimeFor
	labRuntimeFor = func(inventory string) labRuntime {
		calls++
		return previous(inventory)
	}
	test.Cleanup(func() { labRuntimeFor = previous })
	return &calls
}

func constructorUnspent(test *testing.T, fixture *publicFixture, start *Start, before []byte) {
	test.Helper()
	for _, name := range []string{"lab-burned", "lab-start-" + strconv.FormatUint(start.Generation(), 10)} {
		if _, err := os.Stat(filepath.Join(fixture.clock.root, name)); !errors.Is(err, os.ErrNotExist) {
			test.Fatal("refused constructor mutated installation", name, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
	if err != nil || !bytes.Equal(before, after) {
		test.Fatal("refused constructor changed floor", err)
	}
}

func constructorUseControl(test *testing.T, fixture *publicFixture, start *Start, heads Heads) *LabConsumer {
	test.Helper()
	lab, err := fixture.construct(start)
	if err != nil || lab == nil {
		test.Fatal("constructor adjacent control", err)
	}
	fixture.clock.setTime(250, fixtureBoot)
	raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("a", 32)), fixture.journal, heads.Manager)
	if err != nil || len(raw) == 0 {
		test.Fatal("constructor public use control", err)
	}
	receipt, err := timeconf.DecodeReceipt(raw)
	if err != nil || receipt.Facts.Authority.QualificationDigest != start.DecisionDigest() {
		test.Fatal("control receipt decision join", err)
	}
	return lab
}

// Claim: every public enrollment/start field join refuses before runtime selection, burn or marker writes; a D1 enrollment cannot use a later D2 start, beside restored construction/use controls.
func TestLabPublicConstructorEnrollmentJoins(test *testing.T) {
	for _, fault := range []string{"authority-id", "authority-version", "trust-root", "decision-pin", "machine", "consumer", "purpose", "continuity-scope"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			fixture.decision.Approval.Expires = time.Unix(300, 0).UTC().Format(time.RFC3339Nano)
			fixture.decisionRaw = seal(test, &fixture.decision)
			fixture.clock.enrollment.Authority.QualificationDigest = sum(fixture.decisionRaw)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal("join prepare control", err)
			}
			originalDecision := append([]byte(nil), fixture.decisionRaw...)
			enrollment := fixture.clock.enrollment
			switch fault {
			case "authority-id":
				enrollment.Authority.ID = "other-lab-authority"
			case "authority-version":
				enrollment.Authority.Version = "2"
			case "trust-root":
				enrollment.Authority.TrustRootDigest = sum([]byte("other amendment"))
			case "decision-pin":
				fixture.decision.Approval.Expires = time.Unix(600, 0).UTC().Format(time.RFC3339Nano)
				fixture.decisionRaw = seal(test, &fixture.decision)
			case "machine":
				enrollment.Scope.Machine = "other-machine"
			case "consumer":
				enrollment.Scope.Consumer = "other-consumer"
			case "purpose":
				enrollment.Scope.Purpose = "other-purpose"
			case "continuity-scope":
				enrollment.Scope.ContinuityScope = "other-continuity"
			}
			start := fixture.start(test, heads, nil)
			before, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
			if err != nil {
				test.Fatal(err)
			}
			calls := constructionRuntimeCalls(test)
			lab, err := NewLabConsumer(context.Background(), start, enrollment, fixture.clock.policy, fixture.clock.root, fixture.witness, fixture.inventory)
			if !errors.Is(err, ErrUnavailable) || lab != nil || *calls != 0 {
				test.Fatal("constructor enrollment join bypass", fault, err, *calls)
			}
			constructorUnspent(test, fixture, start, before)
			fixture.decisionRaw = originalDecision
			start = fixture.start(test, heads, nil)
			constructorUseControl(test, fixture, start, heads)
			if *calls != 1 {
				test.Fatal("control did not select runtime")
			}
		})
	}
}

// Claim: malformed, absent or canonical same-length reissued fences refuse public construction without spending the generation; restoring exact loaded bytes permits construction/use.
func TestLabPublicConstructorCurrentJoin(test *testing.T) {
	for _, fault := range []string{"replaced", "removed", "reissued"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal(err)
			}
			start := fixture.start(test, heads, nil)
			before, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
			if err != nil {
				test.Fatal(err)
			}
			switch fault {
			case "replaced":
				err = os.WriteFile(fixture.path, []byte("{}"), 0644)
			case "removed":
				err = os.Remove(fixture.path)
			case "reissued":
				err = os.WriteFile(fixture.path, reissuedFence(test, start), 0644)
			}
			if err != nil {
				test.Fatal(err)
			}
			if lab, err := fixture.construct(start); !errors.Is(err, ErrUnavailable) || lab != nil {
				test.Fatal("constructor currentness join bypass", fault, err)
			}
			constructorUnspent(test, fixture, start, before)
			if os.WriteFile(fixture.path, start.raw, 0644) != nil || os.Chmod(fixture.path, 0644) != nil {
				test.Fatal("restore fence fixture")
			}
			constructorUseControl(test, fixture, start, heads)
		})
	}
}

func reissuedFence(test *testing.T, start *Start) []byte {
	test.Helper()
	var fence Fence
	if err := Decode(start.raw, &fence); err != nil {
		test.Fatal("decode loaded fence fixture", err)
	}
	fence.ApprovalDigest = sum([]byte("reissued fence approval"))
	raw := encoded(test, fence)
	var replacement Fence
	if err := Decode(raw, &replacement); err != nil || replacement != fence || !replacement.Consumed || replacement.Generation != start.Generation() || replacement.Context != start.Context() || len(raw) != len(start.raw) || bytes.Equal(raw, start.raw) {
		test.Fatal("canonical same-length replacement fixture", err)
	}
	return raw
}

// Claim: a canonical same-length fence with a different approval identity closes public use without burn or floor changes, beside unchanged-byte use controls before and after replacement.
func TestLabPublicUseCurrentJoin(test *testing.T) {
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	start := fixture.start(test, heads, nil)
	lab := constructorUseControl(test, fixture, start, heads)
	before, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
	if err != nil {
		test.Fatal(err)
	}
	if os.WriteFile(fixture.path, reissuedFence(test, start), 0644) != nil {
		test.Fatal("replace fence fixture")
	}
	fixture.clock.setTime(270, fixtureBoot)
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("b", 32)), fixture.journal, heads.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
		test.Fatal("well-formed replacement admitted at use", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-burned")); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("reissued fence burned installation", err)
	}
	after, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
	if err != nil || !bytes.Equal(before, after) {
		test.Fatal("reissued fence changed floor", err)
	}
	if os.WriteFile(fixture.path, start.raw, 0644) != nil || os.Chmod(fixture.path, 0644) != nil {
		test.Fatal("restore fence fixture")
	}
	fixture.clock.setTime(290, fixtureBoot)
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("c", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
		test.Fatal("restored fence public use control", err)
	}
}

// Claim: public construction rejects non-NTS/non-operator policy, overlapping roots and malformed inventory before runtime selection, with a matching construction/use control; nil Start also refuses.
func TestLabPublicConstructorInputJoins(test *testing.T) {
	for _, fault := range []string{"source", "resync", "roots", "inventory", "nil-start"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal(err)
			}
			start := fixture.start(test, heads, nil)
			enrollment, policy, witness, inventory := fixture.clock.enrollment, fixture.clock.policy, fixture.witness, fixture.inventory
			badStart := start
			switch fault {
			case "source":
				policy.Source = NTSConfig
			case "resync":
				policy.Resync = "new-authenticated-sync"
			case "roots":
				witness = fixture.clock.root
			case "inventory":
				inventory = "not-a-digest"
			case "nil-start":
				badStart = nil
			}
			enrollment.Policy.EffectiveDigest, err = timeconf.EffectivePolicyDigest(policy, enrollment.Policy.SharedDigest, enrollment.Policy.ServiceDigest)
			if err != nil {
				test.Fatal("valid alternative policy fixture", err)
			}
			before, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
			if err != nil {
				test.Fatal(err)
			}
			calls := constructionRuntimeCalls(test)
			lab, err := NewLabConsumer(context.Background(), badStart, enrollment, policy, fixture.clock.root, witness, inventory)
			if !errors.Is(err, ErrUnavailable) || lab != nil || *calls != 0 {
				test.Fatal("constructor input join bypass", fault, err, *calls)
			}
			constructorUnspent(test, fixture, start, before)
			constructorUseControl(test, fixture, start, heads)
		})
	}
}

// Claim: a valid but different caller inventory refuses without burning or spending Start, then the provisioned inventory admits through the public constructor and use path.
func TestLabPublicConstructorInventoryRefusal(test *testing.T) {
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	start := fixture.start(test, heads, nil)
	before, err := os.ReadFile(filepath.Join(fixture.clock.root, "lab-floor"))
	if err != nil {
		test.Fatal(err)
	}
	if lab, err := NewLabConsumer(context.Background(), start, fixture.clock.enrollment, fixture.clock.policy, fixture.clock.root, fixture.witness, sum([]byte("different inventory"))); !errors.Is(err, ErrUnavailable) || lab != nil {
		test.Fatal("constructor inventory join bypass", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-burned")); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("caller inventory burned installation", err)
	}
	constructorUnspent(test, fixture, start, before)
	constructorUseControl(test, fixture, start, heads)
}

// Claim: replay after a successful public use refuses by the spent marker without burning; the original consumer remains usable at a fresh later interval.
func TestLabPublicConstructorSpentStart(test *testing.T) {
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	start := fixture.start(test, heads, nil)
	lab := constructorUseControl(test, fixture, start, heads)
	if replay, err := fixture.construct(start); !errors.Is(err, ErrUnavailable) || replay != nil {
		test.Fatal("spent constructor replay admitted", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-burned")); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("spent start replay burned installation", err)
	}
	next, err := lab.Heads(context.Background())
	if err != nil {
		test.Fatal("replay closed original consumer", err)
	}
	fixture.clock.setTime(270, fixtureBoot)
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("b", 32)), fixture.journal, next.Manager); err != nil || len(raw) == 0 {
		test.Fatal("original consumer after replay control", err)
	}
}

// Claim: public prepare rejects unverified journals before genesis writes, leaving both roots empty for a later complete-history provisioning/use control.
func TestLabPublicPrepareJournalJoin(test *testing.T) {
	for _, fault := range []string{"missing", "partial", "invalid"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			valid := fixture.journal
			switch fault {
			case "missing":
				fixture.journal = nil
			case "partial":
				fixture.journal = valid[:len(valid)-1]
			case "invalid":
				fixture.journal = []byte("{}\n")
			}
			if _, err := fixture.prepare(); !errors.Is(err, ErrUnavailable) {
				test.Fatal("unverified prepare journal admitted", err)
			}
			for _, root := range []string{fixture.clock.root, fixture.witness} {
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 {
					test.Fatal("unverified prepare wrote genesis", err)
				}
			}
			fixture.journal = valid
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal("complete prepare retry control", err)
			}
			constructorUseControl(test, fixture, fixture.start(test, heads, nil), heads)
		})
	}
}
