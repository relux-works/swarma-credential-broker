//go:build linux && broker_lab

package timeconf

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/labtimev0"
	"golang.org/x/sys/unix"
)

const LabAuthority = "swarma-broker-lab-C-1"

type labWitness struct{ root string }

func (witness *labWitness) session() (*storeSession, error) {
	return (&settlementStore{root: witness.root}).open()
}

func labWitnessHead(session *storeSession) (WitnessHead, error) {
	raw, err := session.read("head", 512)
	var encoded checkpointHead
	if err != nil || strictRecord(raw, &encoded, 512) != nil {
		return WitnessHead{}, ErrUnavailable
	}
	return encoded.value()
}

func (witness *labWitness) Read(ctx context.Context) (WitnessHead, error) {
	if ctx.Err() != nil {
		return WitnessHead{}, ErrUnavailable
	}
	session, err := witness.session()
	if err != nil {
		return WitnessHead{}, err
	}
	defer session.close()
	head, err := labWitnessHead(session)
	if err != nil || ctx.Err() != nil {
		return WitnessHead{}, ErrUnavailable
	}
	return head, nil
}

func (witness *labWitness) CompareAndSwap(ctx context.Context, old, next WitnessHead) error {
	session, err := witness.session()
	if err != nil {
		return err
	}
	defer session.close()
	current, err := labWitnessHead(session)
	if err != nil || current != old || old.Generation >= 9007199254740991 || next.Generation != old.Generation+1 || next.RecordDigest == old.RecordDigest || !digestPattern.MatchString(next.RecordDigest) {
		return ErrUnavailable
	}
	name := "advance-" + strconv.FormatUint(next.Generation, 10)
	if session.write(ctx, name, witnessBytes(next), "lab-witness") != nil {
		return ErrUnavailable
	}
	if unix.Renameat(int(session.dir.Fd()), name, int(session.dir.Fd()), "head") != nil || session.sync(session.dir, "lab-witness-head") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

type labCollector struct{ raw [][]byte }

func (runner *labCollector) Run(ctx context.Context, path string, args []string, timeout time.Duration, limit int) ([]byte, error) {
	raw, err := (SystemRunner{}).Run(ctx, path, args, timeout, limit)
	if err == nil {
		runner.raw = append(runner.raw, append([]byte(nil), raw...))
	}
	return raw, err
}

type labSource struct{ inventory string }

func LabInventoryDigest(ctx context.Context, policy Policy) (string, error) {
	if policy.Validate() != nil || policy.Source != NTSAuthData || policy.Resync != "operator" {
		return "", ErrUnavailable
	}
	files := make([]map[string]string, 0, len(policy.SourceFiles))
	for _, path := range policy.SourceFiles {
		raw, err := protectedRead(path, uint32(os.Geteuid()), policy.MaxOutputBytes, false)
		if err != nil {
			return "", ErrUnavailable
		}
		if _, err := parseSources(raw, false, nil); err != nil {
			return "", ErrUnavailable
		}
		files = append(files, map[string]string{"path": path, "sha256": sum(raw)})
	}
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	raw, err := labtimev0.Encode(map[string]any{"policy": policy, "source_files": files})
	if err != nil {
		return "", ErrUnavailable
	}
	return sum(raw), nil
}

func (source labSource) collect(ctx context.Context, policy Policy) (localCollection, error) {
	inventory, err := LabInventoryDigest(ctx, policy)
	if err != nil || inventory != source.inventory {
		return localCollection{}, ErrUnavailable
	}
	var originals [][]byte
	for _, path := range policy.SourceFiles {
		raw, err := protectedRead(path, uint32(os.Geteuid()), policy.MaxOutputBytes, false)
		if err != nil {
			return localCollection{}, ErrUnavailable
		}
		if _, err := parseSources(raw, false, nil); err != nil {
			return localCollection{}, ErrUnavailable
		}
		originals = append(originals, raw)
	}
	runner := &labCollector{}
	evidence, err := (SystemCollector{Runner: runner}).Collect(ctx, policy)
	if err != nil {
		return localCollection{}, err
	}
	for index, path := range policy.SourceFiles {
		raw, readErr := protectedRead(path, uint32(os.Geteuid()), policy.MaxOutputBytes, false)
		if readErr != nil || !bytes.Equal(raw, originals[index]) {
			return localCollection{}, ErrUnavailable
		}
		runner.raw = append(runner.raw, raw)
	}
	return localCollection{evidence, runner.raw, true, true}, nil
}

type LabConsumer struct {
	mu        sync.Mutex
	consumer  *Consumer
	start     *labtimev0.Start
	context   labtimev0.Context
	inventory string
	root      string
	failed    bool
}

func PrepareLabTime(ctx context.Context, decisionRaw []byte, scope labtimev0.Context, enrollment Enrollment, policy Policy, root, witnessRoot, inventory string, request ConsumptionRequest, journal []byte) (labtimev0.Heads, error) {
	if labtimev0.CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, time.Now()) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.TrustRootDigest != labtimev0.AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.ContinuityScope != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || !digestPattern.MatchString(inventory) || !separateLabRoots(root, witnessRoot) {
		return labtimev0.Heads{}, ErrUnavailable
	}
	consumer, err := NewConsumer(enrollment, policy, root)
	if err != nil {
		return labtimev0.Heads{}, err
	}
	consumer.store.witness = &labWitness{witnessRoot}
	consumer.clock, consumer.collector = SystemClock{}, labSource{inventory}
	consumer.timePath = &pathQualification{reserve: time.Second, budget: 500 * time.Millisecond, handoff: time.Millisecond, reboot: true}
	lab := &LabConsumer{consumer: consumer, context: scope, inventory: inventory, root: root}
	if err := lab.provision(ctx, witnessRoot); err != nil {
		return labtimev0.Heads{}, err
	}
	manager, err := labtimev0.ManagerExtension(journal, labtimev0.Head{SHA256: "sha256:" + strings.Repeat("0", 64)})
	if err != nil {
		return labtimev0.Heads{}, ErrUnavailable
	}
	raw, err := consumer.ConsumeBeforePin(ctx, request)
	if err != nil {
		return labtimev0.Heads{}, err
	}
	checkpoint, err := lab.checkpoint(raw)
	if err != nil {
		return labtimev0.Heads{}, err
	}
	checkpointRaw, _ := labtimev0.Encode(checkpoint)
	floor := labtimev0.Floor{Format: labtimev0.FloorFormat, Context: scope, Holds: []string{}, Manager: manager, Previous: manager, Persisted: true, Checkpoint: labtimev0.Digest(checkpointRaw), Watermark: checkpoint.Watermark}
	floorRaw, _ := labtimev0.Encode(floor)
	session, err := consumer.store.open()
	if err != nil {
		return labtimev0.Heads{}, err
	}
	defer session.close()
	if session.retain(ctx, "lab-checkpoint-", checkpointRaw, "lab-checkpoint") != nil || session.write(ctx, "lab-floor", floorRaw, "lab-floor-genesis") != nil || session.write(ctx, "lab-floor-head", witnessBytes(WitnessHead{0, sum(floorRaw)}), "lab-floor-head-genesis") != nil {
		return labtimev0.Heads{}, ErrUnavailable
	}
	head, err := consumer.store.witness.Read(ctx)
	if err != nil {
		return labtimev0.Heads{}, err
	}
	return labtimev0.Heads{Manager: manager, Time: labtimev0.Head{Sequence: head.Generation, SHA256: head.RecordDigest}, Floor: labtimev0.Head{Sequence: 0, SHA256: labtimev0.Digest(floorRaw)}}, nil
}

func separateLabRoots(root, witness string) bool {
	return cleanPath(root) && cleanPath(witness) && root != witness && !strings.HasPrefix(root, witness+"/") && !strings.HasPrefix(witness, root+"/")
}

func NewLabConsumer(ctx context.Context, start *labtimev0.Start, enrollment Enrollment, policy Policy, root, witnessRoot, inventoryDigest string) (*LabConsumer, error) {
	if start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {
		return nil, ErrUnavailable
	}
	scope := start.Context()
	if enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != labtimev0.AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {
		return nil, ErrUnavailable
	}
	consumer, err := NewConsumer(enrollment, policy, root)
	if err != nil {
		return nil, err
	}
	consumer.store.witness = &labWitness{witnessRoot}
	consumer.clock, consumer.collector = SystemClock{}, labSource{inventoryDigest}
	consumer.timePath = &pathQualification{reserve: time.Second, budget: 500 * time.Millisecond, handoff: time.Millisecond, reboot: true}
	lab := &LabConsumer{consumer: consumer, start: start, context: scope, inventory: inventoryDigest, root: root}
	if lab.checkStartHeads(ctx, start.Heads()) != nil {
		return nil, ErrUnavailable
	}
	session, err := consumer.store.open()
	if err != nil {
		return nil, err
	}
	defer session.close()
	name := "lab-start-" + strconv.FormatUint(start.Generation(), 10)
	if session.write(ctx, name, []byte(labtimev0.FenceFormat), "lab-start") != nil {
		return nil, ErrUnavailable
	}
	return lab, nil
}

func (lab *LabConsumer) checkStartHeads(ctx context.Context, expected labtimev0.Heads) error {
	session, err := lab.consumer.store.open()
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if unix.Fstatat(int(session.dir.Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		session.close()
		return ErrUnavailable
	}
	_, head, err := session.load(ctx)
	floorRaw, floorErr := session.read("lab-floor", receiptLimit)
	floorHead, headErr := labFloorHead(session, floorRaw)
	var floor labtimev0.Floor
	floorDecodeErr := labtimev0.Decode(floorRaw, &floor)
	var checkpointRaw []byte
	checkpointErr := ErrUnavailable
	if floorErr == nil && floorDecodeErr == nil {
		checkpointRaw, checkpointErr = session.read(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	}
	var checkpoint labtimev0.Checkpoint
	session.close()
	if err != nil || floorErr != nil || headErr != nil || floorDecodeErr != nil || checkpointErr != nil || labtimev0.Decode(checkpointRaw, &checkpoint) != nil || sum(checkpointRaw) != floor.Checkpoint || checkpoint.Context != lab.context || checkpoint.Scope != lab.context.Installation || checkpoint.Inventory != lab.inventory || checkpoint.Watermark != floor.Watermark || floor.Context != lab.context || !floor.Persisted || (labtimev0.Head{Sequence: head.Generation, SHA256: head.RecordDigest}) != expected.Time || floorHead != expected.Floor || floor.Manager != expected.Manager {
		lab.burn(ctx)
		return ErrUnavailable
	}
	return nil
}

func (lab *LabConsumer) provision(ctx context.Context, witnessRoot string) error {
	for _, root := range []string{lab.root, witnessRoot} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			return ErrUnavailable
		}
	}
	clock, err := lab.consumer.clock.Read(ctx)
	if err != nil {
		return err
	}
	last, err := point(clock)
	if err != nil {
		return err
	}
	last.Reference = "0"
	genesis := settlement{Version: "qualified-time/settlement/1", Binding: lab.consumer.store.binding, Generation: "0", Previous: "none", HighWater: "0", Last: last, Hold: savedClock{Wall: "0", Elapsed: "0", Reference: "0"}}
	raw, err := canonical(genesis)
	if err != nil {
		return err
	}
	head := WitnessHead{0, sum(raw)}
	session, err := lab.consumer.store.open()
	if err != nil {
		return err
	}
	defer session.close()
	if session.write(ctx, objectName("record-", head.RecordDigest), raw, "lab-genesis") != nil {
		return ErrUnavailable
	}
	witness, err := (&labWitness{witnessRoot}).session()
	if err != nil {
		return err
	}
	err = witness.write(ctx, "head", witnessBytes(head), "lab-witness-genesis")
	witness.close()
	if err != nil || session.write(ctx, "current", witnessBytes(head), "lab-genesis-pointer") != nil {
		return ErrUnavailable
	}
	return nil
}

func (lab *LabConsumer) ConsumeWithManager(ctx context.Context, request ConsumptionRequest, journal []byte, expectedFloor labtimev0.Head) ([]byte, error) {
	if lab == nil {
		return nil, ErrUnavailable
	}
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if lab.failed || lab.start == nil || lab.start.Current(ctx) != nil {
		return nil, ErrUnavailable
	}
	for _, floor := range lab.start.RefusalFloors() {
		if floor.IsZero() {
			return nil, ErrUnavailable
		}
		request.JournalFloor = max(request.JournalFloor, floor.UnixNano())
	}
	return lab.consumeWithManager(ctx, request, journal, expectedFloor)
}

func (lab *LabConsumer) consumeWithManager(ctx context.Context, request ConsumptionRequest, journal []byte, expectedFloor labtimev0.Head) ([]byte, error) {
	if lab.failed {
		return nil, ErrUnavailable
	}
	session, err := lab.consumer.store.open()
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Fstatat(int(session.dir.Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		session.close()
		return nil, ErrUnavailable
	}
	floorRaw, err := session.read("lab-floor", receiptLimit)
	floorHead, headErr := labFloorHead(session, floorRaw)
	var floor labtimev0.Floor
	if err != nil || headErr != nil || labtimev0.Decode(floorRaw, &floor) != nil || !floor.Persisted || floor.Context != lab.context || floor.Manager != expectedFloor || len(floor.Holds) != 0 {
		session.close()
		return nil, ErrUnavailable
	}
	checkpointRaw, checkpointErr := session.read(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	var checkpoint labtimev0.Checkpoint
	if checkpointErr != nil || sum(checkpointRaw) != floor.Checkpoint || labtimev0.Decode(checkpointRaw, &checkpoint) != nil || checkpoint.Context != lab.context || checkpoint.Watermark != floor.Watermark || checkpoint.Inventory != lab.inventory || !checkpoint.Settled || checkpoint.Incident != "none" || len(checkpoint.Holds) != 0 {
		session.close()
		return nil, ErrUnavailable
	}
	manager, err := labtimev0.ManagerExtension(journal, floor.Manager)
	if err != nil {
		session.close()
		lab.burn(ctx)
		return nil, ErrUnavailable
	}
	watermark, err := time.Parse(time.RFC3339Nano, floor.Watermark)
	if err != nil || watermark.UnixNano() < 0 {
		session.close()
		return nil, ErrUnavailable
	}
	request.JournalFloor = max(request.JournalFloor, watermark.UnixNano())
	session.close()
	raw, err := lab.consumer.ConsumeBeforePin(ctx, request)
	if err != nil {
		lab.retainIncident(ctx)
		return nil, err
	}
	nextCheckpoint, err := lab.checkpoint(raw)
	if err != nil {
		lab.failed = true
		return nil, err
	}
	nextCheckpoint.Previous = labtimev0.Head{Sequence: checkpoint.Previous.Sequence + 1, SHA256: sum(checkpointRaw)}
	if labtimev0.CheckCheckpoint(checkpoint, nextCheckpoint.Previous, nextCheckpoint, true) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	checkpointRaw, err = labtimev0.Encode(nextCheckpoint)
	if err != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	nextFloor := floor
	nextFloor.Previous, nextFloor.Manager = floor.Manager, manager
	nextFloor.Checkpoint, nextFloor.Watermark = labtimev0.Digest(checkpointRaw), nextCheckpoint.Watermark
	if labtimev0.CheckFloor(floor, nextFloor, checkpointRaw, journal) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	nextRaw, err := labtimev0.Encode(nextFloor)
	if err != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	session, err = lab.consumer.store.open()
	if err != nil {
		lab.failed = true
		return nil, err
	}
	defer session.close()
	current, err := session.read("lab-floor", receiptLimit)
	if err != nil || !bytes.Equal(current, floorRaw) || session.retain(ctx, "lab-checkpoint-", checkpointRaw, "lab-checkpoint") != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	if commitLabFloor(ctx, session, floorHead, nextRaw) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	return raw, nil
}

func (lab *LabConsumer) checkpoint(raw []byte) (labtimev0.Checkpoint, error) {
	receipt, err := DecodeReceipt(raw)
	if err != nil {
		return labtimev0.Checkpoint{}, ErrUnavailable
	}
	observed, _ := integer(receipt.Facts.Observed)
	uncertainty, _ := integer(receipt.Facts.Uncertainty)
	upper := time.Unix(0, observed+uncertainty).UTC()
	expires, _ := time.Parse(time.RFC3339Nano, lab.context.Expires)
	if !upper.Before(expires) || receipt.Facts.Authority.ID != LabAuthority || receipt.Facts.Evidence.Source != NTSAuthData || receipt.Facts.Evidence.NTSAssociation != "verified" {
		return labtimev0.Checkpoint{}, ErrUnavailable
	}
	monotonic, _ := integer(receipt.Facts.Clock.ObservedNS)
	checkpoint := labtimev0.Checkpoint{Format: labtimev0.CheckpointFormat, Context: lab.context, Boot: receipt.Facts.Clock.Boot, Scope: lab.context.Installation, Incident: "none", Inventory: lab.inventory, Settled: true, Holds: []string{}, Lower: time.Unix(0, observed-uncertainty).UTC().Format(time.RFC3339Nano), Upper: upper.Format(time.RFC3339Nano), Watermark: upper.Format(time.RFC3339Nano), Monotonic: uint64(monotonic), Previous: labtimev0.Head{Sequence: 0, SHA256: lab.consumer.store.binding}}
	if labtimev0.Decode(mustLabBytes(checkpoint), &labtimev0.Checkpoint{}) != nil {
		return labtimev0.Checkpoint{}, ErrUnavailable
	}
	return checkpoint, nil
}

func mustLabBytes(value any) []byte { raw, _ := labtimev0.Encode(value); return raw }

func (lab *LabConsumer) burn(ctx context.Context) {
	lab.failed = true
	session, err := lab.consumer.store.open()
	if err != nil {
		return
	}
	defer session.close()
	marker := []byte("burned")
	defer func() { _ = session.write(ctx, "lab-burned", marker, "lab-burned") }()
	floorRaw, err := session.read("lab-floor", receiptLimit)
	var floor labtimev0.Floor
	if err != nil || labtimev0.Decode(floorRaw, &floor) != nil {
		return
	}
	checkpointRaw, err := session.read(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	var checkpoint labtimev0.Checkpoint
	if err != nil || labtimev0.Decode(checkpointRaw, &checkpoint) != nil {
		return
	}
	checkpoint.Incident, checkpoint.Settled = "burned", false
	marker = mustLabBytes(checkpoint)
}

func (lab *LabConsumer) retainIncident(ctx context.Context) {
	session, err := lab.consumer.store.open()
	if err != nil {
		return
	}
	defer session.close()
	record, _, err := session.load(ctx)
	if err != nil || !record.Held && !record.InFlight {
		return
	}
	floorRaw, err := session.read("lab-floor", receiptLimit)
	var floor labtimev0.Floor
	if err != nil || labtimev0.Decode(floorRaw, &floor) != nil {
		return
	}
	checkpointRaw, err := session.read(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	var checkpoint labtimev0.Checkpoint
	if err != nil || labtimev0.Decode(checkpointRaw, &checkpoint) != nil {
		return
	}
	checkpoint.Incident, checkpoint.Settled = "held", false
	checkpoint.Previous = labtimev0.Head{Sequence: checkpoint.Previous.Sequence + 1, SHA256: sum(checkpointRaw)}
	if len(checkpoint.Holds) == 0 {
		checkpoint.Holds = []string{"time-incident"}
	}
	checkpointRaw = mustLabBytes(checkpoint)
	floor.Holds, floor.Checkpoint = append([]string(nil), checkpoint.Holds...), sum(checkpointRaw)
	floorHead, err := labFloorHead(session, floorRaw)
	if err != nil || session.retain(ctx, "lab-checkpoint-", checkpointRaw, "lab-incident-checkpoint") != nil || commitLabFloor(ctx, session, floorHead, mustLabBytes(floor)) != nil {
		lab.failed = true
	}
}

func (lab *LabConsumer) Heads(ctx context.Context) (labtimev0.Heads, error) {
	if lab == nil {
		return labtimev0.Heads{}, ErrUnavailable
	}
	lab.mu.Lock()
	defer lab.mu.Unlock()
	session, err := lab.consumer.store.open()
	if err != nil {
		return labtimev0.Heads{}, err
	}
	defer session.close()
	_, head, err := session.load(ctx)
	raw, readErr := session.read("lab-floor", receiptLimit)
	var floor labtimev0.Floor
	floorHead, headErr := labFloorHead(session, raw)
	if err != nil || readErr != nil || headErr != nil || labtimev0.Decode(raw, &floor) != nil || floor.Context != lab.context {
		return labtimev0.Heads{}, ErrUnavailable
	}
	return labtimev0.Heads{Manager: floor.Manager, Time: labtimev0.Head{Sequence: head.Generation, SHA256: head.RecordDigest}, Floor: floorHead}, nil
}

func labFloorHead(session *storeSession, raw []byte) (labtimev0.Head, error) {
	encoded, err := session.read("lab-floor-head", 512)
	var pointer checkpointHead
	if err != nil || strictRecord(encoded, &pointer, 512) != nil {
		return labtimev0.Head{}, ErrUnavailable
	}
	head, err := pointer.value()
	if err != nil || head.RecordDigest != sum(raw) || head.Generation > 9007199254740991 {
		return labtimev0.Head{}, ErrUnavailable
	}
	return labtimev0.Head{Sequence: head.Generation, SHA256: head.RecordDigest}, nil
}

func commitLabFloor(ctx context.Context, session *storeSession, prior labtimev0.Head, raw []byte) error {
	current, err := session.read("lab-floor", receiptLimit)
	head, headErr := labFloorHead(session, current)
	if err != nil || headErr != nil || head != prior || prior.Sequence >= 9007199254740991 {
		return ErrUnavailable
	}
	name := "lab-floor-" + strconv.FormatUint(prior.Sequence+1, 10)
	pointer := name + "-head"
	if session.retain(ctx, "lab-floor-record-", current, "lab-floor-retain") != nil || session.write(ctx, name, raw, "lab-floor") != nil || session.write(ctx, pointer, witnessBytes(WitnessHead{prior.Sequence + 1, sum(raw)}), "lab-floor-pointer") != nil {
		return ErrUnavailable
	}
	if unix.Renameat(int(session.dir.Fd()), name, int(session.dir.Fd()), "lab-floor") != nil || unix.Renameat(int(session.dir.Fd()), pointer, int(session.dir.Fd()), "lab-floor-head") != nil || session.sync(session.dir, "lab-floor-current") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
