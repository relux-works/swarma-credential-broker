//go:build linux && broker_lab

package labtimev0

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

type publicFixture struct {
	clock                          *settlementFixture
	decision                       Decision
	approval                       OffVM
	fence                          Fence
	pins                           StartPins
	decisionRaw                    []byte
	journal                        []byte
	witness, home, path, inventory string
}

func publicSetup(test *testing.T) *publicFixture {
	test.Helper()
	decision, approval, fence, pins := startFixture(test)
	scope := decision.Context
	scope.Machine = fixtureBoot
	decision.Context, approval.Context, fence.Context, pins.Context = scope, scope, scope, scope
	decision.Recorded = time.Unix(60, 0).UTC().Format(time.RFC3339Nano)
	decision.Approval.At, approval.Approval.At = decision.Recorded, decision.Recorded
	decision.Approval.Expires = time.Unix(600, 0).UTC().Format(time.RFC3339Nano)
	approval.Approval.Expires = decision.Approval.Expires
	clock := &settlementFixture{root: protectedTemp(test), policy: testPolicy()}
	clock.setTime(151, fixtureBoot)
	digest := sum([]byte("public pipeline enrollment"))
	decisionRaw := seal(test, &decision)
	clock.enrollment = Enrollment{Authority: timeconf.AuthorityFact{ID: LabAuthority, Version: "1", TrustRootDigest: AmendmentDigest, QualificationDigest: sum(decisionRaw)}, Adapter: timeconf.AdapterFact{Revision: strings.Repeat("a", 40), CollectorEntry: "timeconf.CollectorEntry", ImageDigest: digest, ChronycDigest: digest, ClosureDigest: digest}, Policy: timeconf.PolicyFact{SharedDigest: digest, ServiceDigest: "none", EffectiveDigest: ""}, Scope: timeconf.ScopeFact{Machine: scope.Machine, Consumer: scope.Installation, Purpose: "broker-lab", ContinuityScope: scope.Installation}, Store: "continuity"}
	clock.enrollment.Policy.EffectiveDigest, _ = timeconf.EffectivePolicyDigest(clock.policy, digest, "none")
	old := labRuntimeFor
	labRuntimeFor = func(string) labRuntime { return labRuntime{clock, clock} }
	test.Cleanup(func() { labRuntimeFor = old })
	_, journal, _ := managerJournal(test)
	home := protectedTemp(test)
	path := filepath.Join(protectedTemp(test), "fence.json")
	return &publicFixture{clock: clock, decision: decision, approval: approval, fence: fence, pins: pins, decisionRaw: decisionRaw, journal: journal, witness: protectedTemp(test), home: home, path: path, inventory: sum([]byte("public NTS inventory"))}
}

func (fixture *publicFixture) prepare() (Heads, error) {
	return PrepareLabTime(context.Background(), fixture.decisionRaw, fixture.decision.Context, fixture.clock.enrollment, fixture.clock.policy, fixture.clock.root, fixture.witness, fixture.inventory, fixture.clock.request(strings.Repeat("0", 32)), fixture.journal)
}

func (fixture *publicFixture) start(test *testing.T, heads Heads, previous *Fence, floors ...time.Time) *Start {
	test.Helper()
	fixture.clock.setTime(211+int64(fixture.pins.Generation-1)*40, fixtureBoot)
	heads.Authority, heads.Service, heads.Revocation = fixture.approval.Heads.Authority, fixture.approval.Heads.Service, fixture.approval.Heads.Revocation
	fixture.approval.Heads = heads
	fixture.approval.Generation = fixture.pins.Generation
	fixture.approval.Now = fixture.clock.now.UTC().Format(time.RFC3339Nano)
	approvalRaw := seal(test, &fixture.approval)
	fixture.pins.Now, fixture.pins.Heads = fixture.clock.now, heads
	fixture.pins.DecisionDigest, fixture.pins.ApprovalDigest = sum(fixture.decisionRaw), sum(approvalRaw)
	fixture.pins.RefusalFloors = floors
	fixture.fence.Heads, fixture.fence.Context, fixture.fence.ApprovalDigest = heads, fixture.pins.Context, fixture.pins.ApprovalDigest
	fixture.fence.Generation, fixture.fence.Consumed = fixture.pins.Generation, false
	if previous != nil {
		fixture.fence.State = "orderly-stop"
	}
	if os.WriteFile(fixture.path, encoded(test, fixture.fence), 0644) != nil || os.Chmod(fixture.path, 0644) != nil {
		test.Fatal("fence fixture")
	}
	owner, group := uint32(os.Geteuid()), uint32(os.Getegid())
	if consumeStartFence(context.Background(), fixture.path, fixture.home, fixture.decisionRaw, approvalRaw, previous, fixture.pins, owner, group) != nil {
		test.Fatal("consume fixture fence")
	}
	start, err := loadStart(context.Background(), fixture.path, fixture.home, fixture.decisionRaw, approvalRaw, previous, fixture.pins, owner, group)
	if err != nil {
		test.Fatal("load fixture fence", err)
	}
	return start
}

func (fixture *publicFixture) construct(start *Start) (*LabConsumer, error) {
	return NewLabConsumer(context.Background(), start, fixture.clock.enrollment, fixture.clock.policy, fixture.clock.root, fixture.witness, fixture.inventory)
}

// Claim: public genesis and two acknowledged generations advance time/floor heads, W and manager prefix; replay and changed/removed fences refuse with synthetic ownership.
func TestLabPublicLifecycle(test *testing.T) {
	fixture := publicSetup(test)
	fullJournal := fixture.journal
	first, _, _ := managerJournal(test)
	fixture.journal = first
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal("public prepare control", err)
	}
	fixture.journal = fullJournal
	start := fixture.start(test, heads, nil)
	lab, err := fixture.construct(start)
	if err != nil {
		test.Fatal("public construction control", err)
	}
	if _, err := fixture.construct(start); err == nil {
		test.Fatal("per-start replay admitted")
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("1", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
		test.Fatal("public use control", err)
	}
	next, err := lab.Heads(context.Background())
	if err != nil || next.Time == heads.Time || next.Floor == heads.Floor || next.Manager.Sequence != heads.Manager.Sequence+1 {
		test.Fatal("public advancing heads", err)
	}
	previous := fixture.fence
	previous.Consumed, previous.State, previous.Heads = true, "orderly-stop", start.Heads()
	previous.Heads.Time, previous.Heads.Floor, previous.Heads.Manager = next.Time, next.Floor, next.Manager
	previousRaw := encoded(test, previous)
	if Decode(previousRaw, &previous) != nil {
		test.Fatal("canonical stop fixture")
	}
	fixture.pins.Generation++
	start = fixture.start(test, next, &previous)
	lab, err = fixture.construct(start)
	if err != nil {
		test.Fatal("acknowledged restart control", err)
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("2", 32)), fixture.journal, next.Manager); err != nil || len(raw) == 0 {
		test.Fatal("restart public use control", err)
	}
	fixture.clock.setTime(270, fixtureBoot)
	if os.WriteFile(fixture.path, []byte("{}"), 0644) != nil {
		test.Fatal("replace fence")
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("3", 32)), fixture.journal, next.Manager); err == nil || len(raw) != 0 {
		test.Fatal("changed fence admitted")
	}
	if os.Remove(fixture.path) != nil {
		test.Fatal("remove fence")
	}
	fixture.clock.setTime(290, fixtureBoot)
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("4", 32)), fixture.journal, next.Manager); err == nil || len(raw) != 0 {
		test.Fatal("removed fence admitted")
	}
}

// Claim: public provisioning never adopts occupied roots or a wrong/unaccepted decision, and rechecks both settled consent bounds before publishing a floor.
func TestLabPublicProvisionRefusals(test *testing.T) {
	for _, fault := range []string{"occupied-store", "occupied-witness", "decision-pin", "decision-role", "settled-before-approval", "settled-expiry"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			switch fault {
			case "occupied-store", "occupied-witness":
				root := fixture.clock.root
				if fault == "occupied-witness" {
					root = fixture.witness
				}
				if os.WriteFile(filepath.Join(root, "foreign"), []byte("untouched"), 0600) != nil {
					test.Fatal("occupied root fixture")
				}
			case "decision-pin":
				fixture.clock.enrollment.Authority.QualificationDigest = sum([]byte("wrong decision"))
			case "decision-role":
				fixture.decision.Roles[0].Accepted = false
				fixture.decisionRaw = seal(test, &fixture.decision)
				fixture.clock.enrollment.Authority.QualificationDigest = sum(fixture.decisionRaw)
			case "settled-expiry":
				fixture.decision.Approval.Expires = fixture.clock.now.Add(time.Nanosecond).Format(time.RFC3339Nano)
				fixture.decisionRaw = seal(test, &fixture.decision)
				fixture.clock.enrollment.Authority.QualificationDigest = sum(fixture.decisionRaw)
			case "settled-before-approval":
				fixture.decision.Approval.At = fixture.clock.now.Format(time.RFC3339Nano)
				fixture.decisionRaw = seal(test, &fixture.decision)
				fixture.clock.enrollment.Authority.QualificationDigest = sum(fixture.decisionRaw)
			}
			if _, err := fixture.prepare(); err == nil {
				test.Fatal("invalid public provision admitted", fault)
			}
			if fault != "settled-expiry" && fault != "settled-before-approval" {
				if _, err := os.Stat(filepath.Join(fixture.clock.root, "current")); !errors.Is(err, os.ErrNotExist) {
					test.Fatal("refused provisioning wrote genesis", err)
				}
			}
			if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-floor")); !errors.Is(err, os.ErrNotExist) {
				test.Fatal("refused provisioning published floor", err)
			}
			control := publicSetup(test)
			if _, err := control.prepare(); err != nil {
				test.Fatal("public prepare adjacent control", err)
			}
		})
	}
}

// Claim: each use checks both exclusive approval expiries against fresh settled upper/W, including equality; valid earlier uses and the exposed deadline remain bounded.
func TestLabPublicApprovalExpiry(test *testing.T) {
	for _, owner := range []bool{true, false} {
		for _, seconds := range []int64{299, 400} {
			test.Run(time.Unix(seconds, 0).Format(time.RFC3339)+map[bool]string{true: "owner", false: "offvm"}[owner], func(test *testing.T) {
				fixture := publicSetup(test)
				expiry := time.Unix(300, 0).UTC()
				if owner {
					fixture.decision.Approval.Expires = expiry.Format(time.RFC3339Nano)
					fixture.decisionRaw = seal(test, &fixture.decision)
					fixture.clock.enrollment.Authority.QualificationDigest = sum(fixture.decisionRaw)
				} else {
					fixture.approval.Approval.Expires = expiry.Format(time.RFC3339Nano)
				}
				heads, err := fixture.prepare()
				if err != nil {
					test.Fatal("expiry prepare", err)
				}
				start := fixture.start(test, heads, nil)
				if !start.Deadline().Equal(expiry) {
					test.Fatal("exclusive approval deadline missing")
				}
				lab, err := fixture.construct(start)
				if err != nil {
					test.Fatal("expiry construction", err)
				}
				if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("5", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
					test.Fatal("unexpired public use control", err)
				}
				before := readLabFloor(test, lab)
				checkpointRaw, err := os.ReadFile(filepath.Join(lab.root, objectName("lab-checkpoint-", before.Checkpoint)))
				var checkpoint Checkpoint
				if err != nil || Decode(checkpointRaw, &checkpoint) != nil {
					test.Fatal("deadline checkpoint", err)
				}
				if deadline, err := Deadline(checkpoint, fixture.clock.now, 900, start.Deadline()); err != nil || !deadline.Equal(expiry) {
					test.Fatal("approval deadline not exposed to issuance", err)
				}
				fixture.clock.setTime(seconds, fixtureBoot)
				if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("6", 32)), fixture.journal, before.Manager); err == nil || len(raw) != 0 {
					test.Fatal("expired approval released receipt")
				}
				if after := readLabFloor(test, lab); after.Checkpoint != before.Checkpoint {
					test.Fatal("expiry widened lab floor")
				}
				if _, err := lab.Heads(context.Background()); err == nil {
					test.Fatal("failed use exported seal heads")
				}
			})
		}
	}
}

// Claim: public use folds every C1 refusal floor; a floor below fresh NTS lower admits, equality or later refuses without releasing a receipt.
func TestLabPublicRefusalFloors(test *testing.T) {
	for _, seconds := range []int64{200, 210, 230} {
		test.Run(time.Unix(seconds, 0).Format(time.RFC3339), func(test *testing.T) {
			fixture := publicSetup(test)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal(err)
			}
			start := fixture.start(test, heads, nil, time.Unix(190, 0), time.Unix(seconds, 0))
			lab, err := fixture.construct(start)
			if err != nil {
				test.Fatal(err)
			}
			raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("7", 32)), fixture.journal, heads.Manager)
			if seconds == 200 {
				if err != nil || len(raw) == 0 {
					test.Fatal("below-floor control", err)
				}
			} else {
				var refusal *timeconf.ConsumptionRefusal
				if !errors.As(err, &refusal) || refusal.Code != "interval" || len(raw) != 0 {
					test.Fatal("C1 refusal floor bypass", err)
				}
			}
		})
	}
}

// Claim: the public start join burns decoded off-VM head mismatches, but lock, I/O, missing/corrupt metadata and cancellation refuse without burn and permit the restored matching control.
func TestLabPublicStartTransientRefusal(test *testing.T) {
	for _, fault := range []string{"witness-lock", "store-lock", "cancel", "missing-floor", "corrupt-floor", "unreadable-floor", "missing-checkpoint"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal(err)
			}
			start := fixture.start(test, heads, nil)
			var locked *os.File
			var restorePath string
			var restore []byte
			ctx := context.Background()
			switch fault {
			case "witness-lock", "store-lock":
				root := fixture.witness
				if fault == "store-lock" {
					root = fixture.clock.root
				}
				locked, err = os.Open(root)
				if err != nil || unix.Flock(int(locked.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
					test.Fatal("lock fixture", err)
				}
				test.Cleanup(func() { locked.Close() })
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-floor", "corrupt-floor", "unreadable-floor", "missing-checkpoint":
				restorePath = filepath.Join(fixture.clock.root, "lab-floor")
				if fault == "missing-checkpoint" {
					floorRaw, _ := os.ReadFile(restorePath)
					var floor Floor
					if Decode(floorRaw, &floor) != nil {
						test.Fatal("floor fixture")
					}
					restorePath = filepath.Join(fixture.clock.root, objectName("lab-checkpoint-", floor.Checkpoint))
				}
				restore, err = os.ReadFile(restorePath)
				if err != nil {
					test.Fatal(err)
				}
				if fault == "unreadable-floor" {
					err = os.Chmod(restorePath, 0000)
				} else if fault == "corrupt-floor" {
					err = os.WriteFile(restorePath, []byte("{}"), 0600)
				} else {
					err = os.Remove(restorePath)
				}
				if err != nil {
					test.Fatal(err)
				}
			}
			if _, err := NewLabConsumer(ctx, start, fixture.clock.enrollment, fixture.clock.policy, fixture.clock.root, fixture.witness, fixture.inventory); !errors.Is(err, ErrUnavailable) {
				test.Fatal("transient start did not refuse", err)
			}
			if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-burned")); !errors.Is(err, os.ErrNotExist) {
				test.Fatal("transient start burned installation", err)
			}
			if locked != nil {
				if unix.Flock(int(locked.Fd()), unix.LOCK_UN) != nil {
					test.Fatal("unlock")
				}
			}
			if restorePath != "" {
				if os.Chmod(restorePath, 0600) != nil && fault == "unreadable-floor" {
					test.Fatal("restore fixture permissions")
				}
				if os.WriteFile(restorePath, restore, 0600) != nil {
					test.Fatal("restore fixture bytes")
				}
			}
			lab, err := fixture.construct(start)
			if err != nil {
				test.Fatal("matching start after transient control", err)
			}
			if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("8", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
				test.Fatal("matching use after transient control", err)
			}
		})
	}
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	wrong := heads
	wrong.Time.Sequence++
	start := fixture.start(test, wrong, nil)
	if _, err := fixture.construct(start); err == nil {
		test.Fatal("public off-VM mismatch admitted")
	}
	if _, err := os.Stat(filepath.Join(fixture.clock.root, "lab-burned")); err != nil {
		test.Fatal("verified public mismatch not burned", err)
	}
}

// Claim: incomplete/unverified journals refuse without changing floor or burning; complete later history admits through the same public consumer.
func TestLabUnverifiedJournalRefusal(test *testing.T) {
	for _, fault := range []string{"missing", "partial", "invalid", "fork-partial"} {
		test.Run(fault, func(test *testing.T) {
			fixture := publicSetup(test)
			heads, err := fixture.prepare()
			if err != nil {
				test.Fatal(err)
			}
			start := fixture.start(test, heads, nil)
			lab, err := fixture.construct(start)
			if err != nil {
				test.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(lab.root, "lab-floor"))
			bad := fixture.journal
			switch fault {
			case "missing":
				bad = nil
			case "partial":
				bad = bad[:len(bad)-1]
			case "invalid":
				bad = bytes.ReplaceAll(bad, []byte("creating"), []byte("unknown!"))
			case "fork-partial":
				bad = append(forkJournal(test, fixture.journal), byte(123))
			}
			if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("9", 32)), bad, heads.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
				test.Fatal("unverified journal not refused", err)
			}
			if _, err := os.Stat(filepath.Join(lab.root, "lab-burned")); !errors.Is(err, os.ErrNotExist) {
				test.Fatal("unverified journal burned installation", err)
			}
			after, _ := os.ReadFile(filepath.Join(lab.root, "lab-floor"))
			if !bytes.Equal(before, after) {
				test.Fatal("unverified journal changed floor")
			}
			if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("a", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
				test.Fatal("complete journal retry control", err)
			}
		})
	}
}

func forkJournal(test *testing.T, raw []byte) []byte {
	test.Helper()
	var result []byte
	previous := genjournal.ZeroHash
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{10}), []byte{10}) {
		record, err := genjournal.DecodeRecordBytes(append(append([]byte(nil), line...), byte(10)))
		if err != nil {
			test.Fatal("fork fixture decode", err)
		}
		record.UID, record.Prev = 2002, previous
		encoded, err := genjournal.Encode(record)
		if err != nil {
			test.Fatal("fork fixture encode", err)
		}
		previous = genjournal.Digest(encoded)
		result = append(result, encoded...)
	}
	return result
}

// Claim: a complete verified public manager fork burns durably; a later correct journal and reconstructed consumer cannot reopen it.
func TestLabPublicVerifiedForkBurn(test *testing.T) {
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	start := fixture.start(test, heads, nil)
	lab, err := fixture.construct(start)
	if err != nil {
		test.Fatal(err)
	}
	if control, err := lab.Heads(context.Background()); err != nil || control != heads {
		test.Fatal("unburned heads control", err)
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("b", 32)), forkJournal(test, fixture.journal), heads.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
		test.Fatal("verified fork not refused", err)
	}
	if _, err := os.Stat(filepath.Join(lab.root, "lab-burned")); err != nil {
		test.Fatal("verified fork not burned", err)
	}
	lab.failed = false
	if _, err := lab.Heads(context.Background()); !errors.Is(err, ErrUnavailable) {
		test.Fatal("burned heads exported", err)
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("c", 32)), fixture.journal, heads.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
		test.Fatal("burned public scope reopened", err)
	}
	if _, err := fixture.construct(start); !errors.Is(err, ErrUnavailable) {
		test.Fatal("burned public construction admitted", err)
	}
}

// Claim: a verified mismatch still refuses when burn persistence fails, and the persistence uncertainty is returned rather than silently discarded.
func TestLabBurnPersistenceRefusal(test *testing.T) {
	lab, _, _, _ := labFixture(test)
	heads, err := lab.Heads(context.Background())
	if err != nil {
		test.Fatal(err)
	}
	heads.Time.Sequence++
	lab.consumer.LabStore().LabSyncFault(func(stage string) error {
		if stage == "lab-burned-file" {
			return ErrUnavailable
		}
		return nil
	})
	err = lab.checkStartHeads(context.Background(), heads)
	if !errors.Is(err, errBurnPersistence) || !errors.Is(err, ErrUnavailable) || !lab.failed {
		test.Fatal("burn persistence error hidden", err)
	}
}

// Claim: public use persists a clock-step hold across acknowledged restart; later good NTS and another start never clear the held floor or lower W.
func TestLabPublicStickyRestart(test *testing.T) {
	fixture := publicSetup(test)
	heads, err := fixture.prepare()
	if err != nil {
		test.Fatal(err)
	}
	start := fixture.start(test, heads, nil)
	lab, err := fixture.construct(start)
	if err != nil {
		test.Fatal(err)
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("d", 32)), fixture.journal, heads.Manager); err != nil || len(raw) == 0 {
		test.Fatal("pre-hold public control", err)
	}
	before := readLabFloor(test, lab)
	fixture.clock.setTime(230, fixtureBoot)
	fixture.clock.after.Now = fixture.clock.after.Now.Add(-3 * time.Second)
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("e", 32)), fixture.journal, before.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
		test.Fatal("public clock step admitted", err)
	}
	held := readLabFloor(test, lab)
	if len(held.Holds) == 0 || held.Watermark != before.Watermark {
		test.Fatal("public hold/W not retained")
	}
	next, err := lab.Heads(context.Background())
	if err != nil {
		test.Fatal("held heads fixture", err)
	}
	previous := fixture.fence
	previous.Consumed, previous.State, previous.Heads = true, "orderly-stop", start.Heads()
	previous.Heads.Time, previous.Heads.Floor, previous.Heads.Manager = next.Time, next.Floor, next.Manager
	fixture.pins.Generation++
	start = fixture.start(test, next, &previous)
	lab, err = fixture.construct(start)
	if err != nil {
		test.Fatal("held reconstruction fixture", err)
	}
	if raw, err := lab.ConsumeWithManager(context.Background(), fixture.clock.request(strings.Repeat("f", 32)), fixture.journal, next.Manager); !errors.Is(err, ErrUnavailable) || len(raw) != 0 {
		test.Fatal("public restart cleared sticky hold", err)
	}
	if after := readLabFloor(test, lab); after.Watermark != held.Watermark || !bytes.Equal(mustLabBytes(after.Holds), mustLabBytes(held.Holds)) {
		test.Fatal("restart changed held continuity")
	}
}
