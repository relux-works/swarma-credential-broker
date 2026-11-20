//go:build linux && broker_lab

package timeconf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/labtimev0"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func labFixture(test *testing.T) (*LabConsumer, *settlementFixture, []byte, labtimev0.Floor) {
	test.Helper()
	fixture := newSettlementFixture(test)
	fixture.policy.Source = NTSAuthData
	fixture.consumer.policy = fixture.policy
	fixture.enrollment.Authority.ID = LabAuthority
	fixture.enrollment.Policy.EffectiveDigest, _ = EffectivePolicyDigest(fixture.policy, fixture.enrollment.Policy.SharedDigest, "none")
	fixture.consumer.enrollment = fixture.enrollment
	encoded, _ := canonical(fixture.enrollment)
	fixture.consumer.store.binding = sum(encoded)
	fixture.seed(test, 140, 140, fixtureBoot)
	fixture.collection.evidence.Authentication = Authentication{Addresses: map[string]bool{"192.0.2.1": true}}
	witnessRoot := protectedTemp(test)
	witness := &labWitness{root: witnessRoot}
	session, err := witness.session()
	if err != nil {
		test.Fatal(err)
	}
	if err = session.write(context.Background(), "head", witnessBytes(fixture.witness.head), "fixture-witness"); err != nil {
		test.Fatal(err)
	}
	session.close()
	fixture.consumer.store.witness = witness
	scope := labtimev0.Context{Account: "lab/anthropic", Installation: "synthetic-installation", Machine: fixtureBoot, VM: sum([]byte("synthetic VM evidence")), Revision: "synthetic-revision", Expires: "2030-01-01T00:00:00Z"}
	lab := &LabConsumer{consumer: fixture.consumer, context: scope, inventory: sum([]byte("synthetic NTS inventory")), root: fixture.root}
	checkpoint := labtimev0.Checkpoint{Format: labtimev0.CheckpointFormat, Context: scope, Boot: fixtureBoot, Scope: scope.Installation, Incident: "none", Inventory: lab.inventory, Settled: true, Holds: []string{}, Lower: time.Unix(139, 0).UTC().Format(time.RFC3339Nano), Upper: time.Unix(140, 0).UTC().Format(time.RFC3339Nano), Watermark: time.Unix(140, 0).UTC().Format(time.RFC3339Nano), Previous: labtimev0.Head{SHA256: fixture.witness.head.RecordDigest}, Monotonic: 140 * uint64(time.Second)}
	checkpointRaw := mustLabBytes(checkpoint)
	manager := labtimev0.Head{SHA256: "sha256:" + genjournal.ZeroHash}
	floor := labtimev0.Floor{Format: labtimev0.FloorFormat, Context: scope, Holds: []string{}, Manager: manager, Previous: manager, Persisted: true, Checkpoint: sum(checkpointRaw), Watermark: checkpoint.Watermark}
	if err := os.WriteFile(filepath.Join(lab.root, "lab-floor"), mustLabBytes(floor), 0600); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab.root, "lab-floor-head"), witnessBytes(WitnessHead{0, sum(mustLabBytes(floor))}), 0600); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab.root, objectName("lab-checkpoint-", floor.Checkpoint)), checkpointRaw, 0600); err != nil {
		test.Fatal(err)
	}
	first, err := genjournal.Encode(genjournal.Record{Seq: 1, Prev: genjournal.ZeroHash, UID: 2001, Generation: strings.Repeat("1", 32), State: "creating", Writer: "user-manager", Time: "2026-11-20T08:00:00Z"})
	if err != nil {
		test.Fatal(err)
	}
	second, err := genjournal.Encode(genjournal.Record{Seq: 2, Prev: strings.TrimPrefix(sum(first), "sha256:"), UID: 2001, Generation: strings.Repeat("1", 32), State: "active", Writer: "user-manager", Time: "2026-11-20T08:00:01Z"})
	if err != nil {
		test.Fatal(err)
	}
	return lab, fixture, append(first, second...), floor
}

func readLabFloor(test *testing.T, lab *LabConsumer) labtimev0.Floor {
	test.Helper()
	raw, err := os.ReadFile(filepath.Join(lab.root, "lab-floor"))
	var floor labtimev0.Floor
	if err != nil || labtimev0.Decode(raw, &floor) != nil {
		test.Fatal("floor read", err)
	}
	return floor
}

func labAdvance(fixture *settlementFixture, seconds int64) {
	fixture.setTime(seconds, fixtureBoot)
	fixture.collection.evidence.Authentication = Authentication{Addresses: map[string]bool{"192.0.2.1": true}}
}

// Claim: the lab witness acknowledges durable exact CAS across reopen and refuses wrong prior, skipped generation, corrupt head and symlink substitution.
func TestLabWitnessDurableCAS(test *testing.T) {
	lab, _, _, _ := labFixture(test)
	witness := lab.consumer.store.witness.(*labWitness)
	old, err := witness.Read(context.Background())
	if err != nil {
		test.Fatal(err)
	}
	next := WitnessHead{old.Generation + 1, sum([]byte("next settled object"))}
	if witness.CompareAndSwap(context.Background(), old, next) != nil {
		test.Fatal("valid CAS")
	}
	reopened := &labWitness{witness.root}
	got, err := reopened.Read(context.Background())
	if err != nil || got != next {
		test.Fatal("durable CAS reopen", err)
	}
	for _, candidate := range []WitnessHead{{next.Generation + 2, next.RecordDigest}, {next.Generation, next.RecordDigest}} {
		if witness.CompareAndSwap(context.Background(), next, candidate) == nil {
			test.Fatal("invalid generation CAS")
		}
	}
	if witness.CompareAndSwap(context.Background(), old, WitnessHead{old.Generation + 1, sum([]byte("different settled object"))}) == nil {
		test.Fatal("stale CAS")
	}
	if got, err = reopened.Read(context.Background()); err != nil || got != next {
		test.Fatal("negative CAS mutated head")
	}
	path := filepath.Join(witness.root, "head")
	if os.Rename(path, path+".saved") != nil || os.Symlink(path+".saved", path) != nil {
		test.Fatal("link fixture")
	}
	if _, err := reopened.Read(context.Background()); err == nil {
		test.Fatal("linked witness")
	}
}

// Claim: a settled authenticated NTS receipt publishes only after the exact manager-prefix floor and checkpoint are durable; a missing/forked floor refuses.
func TestLabConsumerSettlementAndFloor(test *testing.T) {
	for _, fault := range []string{"missing", "malformed", "forked", "unpersisted", "stale-expected", "checkpoint-missing", "head-missing"} {
		test.Run(fault, func(test *testing.T) {
			lab, fixture, journal, floor := labFixture(test)
			raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("1", 32)), journal, floor.Manager)
			if err != nil || len(raw) == 0 {
				test.Fatal("settled positive", err)
			}
			next := readLabFloor(test, lab)
			if !next.Persisted || next.Manager.Sequence != 2 || next.Previous != floor.Manager || next.Watermark == floor.Watermark {
				test.Fatal("floor not advanced")
			}
			checkpointRaw, err := os.ReadFile(filepath.Join(lab.root, objectName("lab-checkpoint-", next.Checkpoint)))
			if err != nil || sum(checkpointRaw) != next.Checkpoint {
				test.Fatal("checkpoint not retained")
			}
			labAdvance(fixture, 230)
			expected := next.Manager
			path := filepath.Join(lab.root, "lab-floor")
			switch fault {
			case "missing":
				err = os.Remove(path)
			case "malformed":
				err = os.WriteFile(path, []byte("{}"), 0600)
			case "forked":
				journal = []byte(strings.ReplaceAll(string(journal), "2001", "2002"))
			case "unpersisted":
				next.Persisted = false
				err = os.WriteFile(path, mustLabBytes(next), 0600)
			case "stale-expected":
				expected = floor.Manager
			case "checkpoint-missing":
				err = os.Remove(filepath.Join(lab.root, objectName("lab-checkpoint-", next.Checkpoint)))
			case "head-missing":
				err = os.Remove(filepath.Join(lab.root, "lab-floor-head"))
			}
			if err != nil {
				test.Fatal("fault setup", err)
			}
			raw, err = lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("2", 32)), journal, expected)
			if err == nil || len(raw) != 0 {
				test.Fatal("floor fault released receipt")
			}
		})
	}
}

// Claim: each checkpoint/floor durability boundary fails closed after its real fault point; no unacknowledged receipt is returned.
func TestLabFloorDurabilityFaults(test *testing.T) {
	for _, point := range []string{"lab-checkpoint-file", "lab-checkpoint-directory", "lab-floor-file", "lab-floor-directory", "lab-floor-pointer-file", "lab-floor-pointer-directory", "lab-floor-current"} {
		test.Run(point, func(test *testing.T) {
			lab, fixture, journal, floor := labFixture(test)
			if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("3", 32)), journal, floor.Manager); err != nil || len(raw) == 0 {
				test.Fatal("valid durability control", err)
			}
			floor = readLabFloor(test, lab)
			labAdvance(fixture, 230)
			triggered := false
			lab.consumer.store.syncFault = func(stage string) error {
				if stage == point {
					triggered = true
					return ErrUnavailable
				}
				return nil
			}
			raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("4", 32)), journal, floor.Manager)
			if !triggered || err == nil || len(raw) != 0 {
				test.Fatal("durability fault not enforced", triggered, err)
			}
		})
	}
}

// Claim: a persisted settlement hold survives witness/consumer reconstruction and a later good authenticated report cannot clear it.
func TestLabConsumerStickyRestart(test *testing.T) {
	lab, fixture, journal, floor := labFixture(test)
	if _, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("5", 32)), journal, floor.Manager); err != nil {
		test.Fatal("valid before incident", err)
	}
	floor = readLabFloor(test, lab)
	labAdvance(fixture, 230)
	fixture.after.Now = fixture.after.Now.Add(-3 * time.Second)
	if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("6", 32)), journal, floor.Manager); err == nil || len(raw) != 0 {
		test.Fatal("clock step used")
	}
	session, err := lab.consumer.store.open()
	if err != nil {
		test.Fatal(err)
	}
	record, _, err := session.load(context.Background())
	session.close()
	if err != nil || !record.Held {
		test.Fatal("hold not durable", err)
	}
	held := readLabFloor(test, lab)
	if len(held.Holds) == 0 {
		test.Fatal("C0 floor omitted sticky incident")
	}
	reopened, err := NewConsumer(fixture.enrollment, fixture.policy, lab.root)
	if err != nil {
		test.Fatal(err)
	}
	reopened.store.witness = &labWitness{lab.consumer.store.witness.(*labWitness).root}
	reopened.timePath = lab.consumer.timePath
	reopened.clock, reopened.collector = fixture, lab.consumer.collector
	lab.consumer = reopened
	labAdvance(fixture, 250)
	if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("7", 32)), journal, floor.Manager); err == nil || len(raw) != 0 {
		test.Fatal("restart cleared hold")
	}
}

// Claim: a manager regression burns persistently and reconstructed state cannot reopen through a later matching history.
func TestLabBurnPersists(test *testing.T) {
	lab, fixture, journal, floor := labFixture(test)
	if _, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("8", 32)), journal, floor.Manager); err != nil {
		test.Fatal("valid control", err)
	}
	floor = readLabFloor(test, lab)
	labAdvance(fixture, 230)
	if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("9", 32)), nil, floor.Manager); err == nil || len(raw) != 0 {
		test.Fatal("regressed history")
	}
	raw, err := os.ReadFile(filepath.Join(lab.root, "lab-burned"))
	var burned labtimev0.Checkpoint
	if err != nil || labtimev0.Decode(raw, &burned) != nil || burned.Incident != "burned" || burned.Settled {
		test.Fatal("burn not durable", err)
	}
	lab.failed = false
	if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("a", 32)), journal, floor.Manager); err == nil || len(raw) != 0 {
		test.Fatal("burned scope reopened")
	}
}

// Claim: a matching persisted start admits; mismatched off-VM heads or missing local metadata permanently burn, never infer a replacement baseline.
func TestLabStartContinuityBurn(test *testing.T) {
	for _, fault := range []string{"time", "floor", "manager", "missing-floor", "missing-checkpoint"} {
		test.Run(fault, func(test *testing.T) {
			lab, _, _, floor := labFixture(test)
			heads, err := lab.Heads(context.Background())
			if err != nil || lab.checkStartHeads(context.Background(), heads) != nil {
				test.Fatal("valid persisted start", err)
			}
			candidate := heads
			switch fault {
			case "time":
				candidate.Time.Sequence++
			case "floor":
				candidate.Floor.Sequence++
			case "manager":
				candidate.Manager.Sequence++
			case "missing-floor":
				if err := os.Remove(filepath.Join(lab.root, "lab-floor")); err != nil {
					test.Fatal(err)
				}
			case "missing-checkpoint":
				if err := os.Remove(filepath.Join(lab.root, objectName("lab-checkpoint-", floor.Checkpoint))); err != nil {
					test.Fatal(err)
				}
			}
			if lab.checkStartHeads(context.Background(), candidate) == nil {
				test.Fatal("mismatch admitted")
			}
			if _, err := os.Stat(filepath.Join(lab.root, "lab-burned")); err != nil {
				test.Fatal("missing durable burn", err)
			}
			lab.failed = false
			if lab.checkStartHeads(context.Background(), heads) == nil {
				test.Fatal("matching state reopened burned install")
			}
		})
	}
}

// Claim: default construction stays ClosedWitness; the lab factory and public consume path refuse a missing consumed-start capability before collection.
func TestLabProductionConstructionClosed(test *testing.T) {
	lab, fixture, _, _ := labFixture(test)
	ordinary, err := NewConsumer(fixture.enrollment, fixture.policy, lab.root)
	if err != nil {
		test.Fatal(err)
	}
	if _, ok := ordinary.store.witness.(ClosedWitness); !ok {
		test.Fatal("production witness changed")
	}
	raw, err := ordinary.ConsumeBeforePin(context.Background(), fixture.request(strings.Repeat("b", 32)))
	var inactive *ActivationRefusal
	if len(raw) != 0 || !errors.As(err, &inactive) || inactive.Reason != "path_unqualified" {
		test.Fatal("production opened", err)
	}
	if _, err := NewLabConsumer(context.Background(), nil, fixture.enrollment, fixture.policy, lab.root, lab.consumer.store.witness.(*labWitness).root, lab.inventory); err == nil {
		test.Fatal("nil start selected lab")
	}
	if _, err := lab.ConsumeWithManager(context.Background(), fixture.request(strings.Repeat("c", 32)), nil, labtimev0.Head{}); err == nil {
		test.Fatal("fixture selected native lab authority")
	}
}

// Claim: actual production receipt decoding and lab checkpoint decoding refuse each others bytes beside their own-format controls.
func TestLabProductionCrossReadTime(test *testing.T) {
	lab, fixture, journal, floor := labFixture(test)
	raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("d", 32)), journal, floor.Manager)
	if err != nil {
		test.Fatal(err)
	}
	if _, err := DecodeReceipt(raw); err != nil {
		test.Fatal("production codec control", err)
	}
	floor = readLabFloor(test, lab)
	checkpointRaw, err := os.ReadFile(filepath.Join(lab.root, objectName("lab-checkpoint-", floor.Checkpoint)))
	if err != nil {
		test.Fatal(err)
	}
	if labtimev0.Decode(checkpointRaw, &labtimev0.Checkpoint{}) != nil {
		test.Fatal("lab codec control")
	}
	if _, err := DecodeReceipt(checkpointRaw); err == nil {
		test.Fatal("production accepted lab checkpoint")
	}
	if labtimev0.Decode(raw, &labtimev0.Checkpoint{}) == nil {
		test.Fatal("lab accepted production receipt")
	}
	for _, format := range []string{labtimev0.FenceFormat, labtimev0.FloorFormat, labtimev0.CheckpointFormat} {
		if bytes.Contains(raw, []byte(format)) {
			test.Fatal("production receipt format changed")
		}
	}
}

// Claim: the real settlement predicate requires fresh, selected, authenticated NTS; plain NTP, absent auth and stale or unlisted sources cannot publish a receipt.
func TestLabConsumerAuthenticatedNTS(test *testing.T) {
	for _, fault := range []string{"plain-ntp", "missing-auth", "stale", "unlisted"} {
		test.Run(fault, func(test *testing.T) {
			lab, fixture, journal, floor := labFixture(test)
			if raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("e", 32)), journal, floor.Manager); err != nil || len(raw) == 0 {
				test.Fatal("valid NTS control", err)
			}
			floor = readLabFloor(test, lab)
			labAdvance(fixture, 230)
			switch fault {
			case "plain-ntp":
				fixture.collection.evidence.Sources.AllNTS = false
			case "missing-auth":
				fixture.collection.evidence.Authentication.Addresses = map[string]bool{}
			case "stale":
				fixture.collection.evidence.Tracking.Reference = fixture.now.Add(-fixture.policy.MaxSyncAge)
			case "unlisted":
				fixture.collection.evidence.Tracking.Address = "192.0.2.2"
			}
			raw, err := lab.consumeWithManager(context.Background(), fixture.request(strings.Repeat("f", 32)), journal, floor.Manager)
			if err == nil || len(raw) != 0 {
				test.Fatal("unqualified source admitted")
			}
		})
	}
}

// Claim: the lab inventory pins complete explicit NTS configuration bytes and applied policy; changed sources, plain NTP, expansion and disabled modes refuse.
func TestLabNTSInventory(test *testing.T) {
	root := protectedTemp(test)
	path := filepath.Join(root, "source.conf")
	policy := testPolicy()
	policy.Source = NTSAuthData
	policy.SourceFiles = []string{path}
	policy.Resync = "operator"
	valid := []byte("server 192.0.2.1 nts\n")
	for _, candidate := range []string{"server 192.0.2.1\n", "sourcedir /unapproved\n", "confdir /unapproved\n"} {
		if os.WriteFile(path, valid, 0600) != nil {
			test.Fatal("valid config")
		}
		if digest, err := LabInventoryDigest(context.Background(), policy); err != nil || !digestPattern.MatchString(digest) {
			test.Fatal("valid inventory", err)
		}
		if os.WriteFile(path, []byte(candidate), 0600) != nil {
			test.Fatal("negative config")
		}
		if _, err := LabInventoryDigest(context.Background(), policy); err == nil {
			test.Fatal("unqualified inventory")
		}
	}
	if os.WriteFile(path, valid, 0600) != nil {
		test.Fatal("valid config")
	}
	digest, err := LabInventoryDigest(context.Background(), policy)
	if err != nil {
		test.Fatal(err)
	}
	if os.WriteFile(path, []byte("server 192.0.2.2 nts\n"), 0600) != nil {
		test.Fatal("changed config")
	}
	if _, err := (labSource{inventory: digest}).collect(context.Background(), policy); err == nil {
		test.Fatal("changed approved inventory collected")
	}
	policy.Source = NTSConfig
	if _, err := LabInventoryDigest(context.Background(), policy); err == nil {
		test.Fatal("config-only source selected lab")
	}
}
