//go:build linux && broker_lab

package labtimev0

import (
	"bytes"
	"context"
	"errors"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const LabAuthority = "swarma-broker-lab-C-1"

type labWitness struct{ root string }

func (witness *labWitness) session() (*storeSession, error) {
	return openLabStore(witness.root)
}

func labWitnessHead(session *storeSession) (WitnessHead, error) {
	raw, err := session.LabRead("head", 512)
	var encoded checkpointHead
	if err != nil || strictRecord(raw, &encoded, 512) != nil {
		return WitnessHead{}, ErrUnavailable
	}
	return encoded.LabValue()
}

func (witness *labWitness) Read(ctx context.Context) (WitnessHead, error) {
	if ctx.Err() != nil {
		return WitnessHead{}, ErrUnavailable
	}
	session, err := witness.session()
	if err != nil {
		return WitnessHead{}, err
	}
	defer session.LabClose()
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
	defer session.LabClose()
	current, err := labWitnessHead(session)
	if err != nil || current != old || old.Generation >= 9007199254740991 || next.Generation != old.Generation+1 || next.RecordDigest == old.RecordDigest || !digestPattern.MatchString(next.RecordDigest) {
		return ErrUnavailable
	}
	name := "advance-" + strconv.FormatUint(next.Generation, 10)
	if session.LabWrite(ctx, name, witnessBytes(next), "lab-witness") != nil {
		return ErrUnavailable
	}
	if unix.Renameat(int(session.LabDir().Fd()), name, int(session.LabDir().Fd()), "head") != nil || session.LabSync(session.LabDir(), "lab-witness-head") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

type labCollector struct{ raw [][]byte }

func (runner *labCollector) Run(ctx context.Context, path string, args []string, timeout time.Duration, limit int) ([]byte, error) {
	raw, err := (timeconf.SystemRunner{}).Run(ctx, path, args, timeout, limit)
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
		if _, err := timeconf.LabParseSources(raw); err != nil {
			return "", ErrUnavailable
		}
		files = append(files, map[string]string{"path": path, "sha256": sum(raw)})
	}
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	raw, err := Encode(map[string]any{"policy": policy, "source_files": files})
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
		if _, err := timeconf.LabParseSources(raw); err != nil {
			return localCollection{}, ErrUnavailable
		}
		originals = append(originals, raw)
	}
	runner := &labCollector{}
	evidence, err := (timeconf.SystemCollector{Runner: runner}).Collect(ctx, policy)
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
	return localCollection{Evidence: evidence, Originals: runner.raw, Terminal: true, Drained: true}, nil
}

type LabConsumer struct {
	mu        sync.Mutex
	consumer  *Consumer
	start     *Start
	context   Context
	inventory string
	root      string
	runtime   labRuntime
	failed    bool
}

func PrepareLabTime(ctx context.Context, decisionRaw []byte, scope Context, enrollment Enrollment, policy Policy, root, witnessRoot, inventory string, request ConsumptionRequest, journal []byte) (Heads, error) {
	runtime := labRuntimeFor(inventory)
	clock, clockErr := runtime.clock.Read(ctx)
	if clockErr != nil || CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, clock.Now) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.ContinuityScope != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || !digestPattern.MatchString(inventory) || !separateLabRoots(root, witnessRoot) {
		return Heads{}, ErrUnavailable
	}
	consumer, err := timeconf.NewConsumer(enrollment, policy, root)
	if err != nil {
		return Heads{}, err
	}
	configureLab(consumer, &labWitness{witnessRoot}, runtime)
	lab := &LabConsumer{consumer: consumer, context: scope, inventory: inventory, root: root, runtime: runtime}
	manager, err := ManagerExtension(journal, Head{SHA256: "sha256:" + strings.Repeat("0", 64)})
	if err != nil {
		return Heads{}, ErrUnavailable
	}
	if err := lab.provision(ctx, witnessRoot); err != nil {
		return Heads{}, err
	}
	raw, err := consumer.ConsumeBeforePin(ctx, request)
	if err != nil {
		return Heads{}, err
	}
	checkpoint, err := lab.checkpoint(raw)
	if err != nil || CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, instant(checkpoint.Lower)) != nil || CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, instant(checkpoint.Upper)) != nil {
		return Heads{}, ErrUnavailable
	}
	checkpointRaw, _ := Encode(checkpoint)
	floor := Floor{Format: FloorFormat, Context: scope, Holds: []string{}, Manager: manager, Previous: manager, Persisted: true, Checkpoint: Digest(checkpointRaw), Watermark: checkpoint.Watermark}
	floorRaw, _ := Encode(floor)
	session, err := consumer.LabStore().LabOpen()
	if err != nil {
		return Heads{}, err
	}
	defer session.LabClose()
	if session.LabRetain(ctx, "lab-checkpoint-", checkpointRaw, "lab-checkpoint") != nil || session.LabWrite(ctx, "lab-floor", floorRaw, "lab-floor-genesis") != nil || session.LabWrite(ctx, "lab-floor-head", witnessBytes(WitnessHead{Generation: 0, RecordDigest: sum(floorRaw)}), "lab-floor-head-genesis") != nil {
		return Heads{}, ErrUnavailable
	}
	head, err := consumer.LabStore().LabWitness().Read(ctx)
	if err != nil {
		return Heads{}, err
	}
	return Heads{Manager: manager, Time: Head{Sequence: head.Generation, SHA256: head.RecordDigest}, Floor: Head{Sequence: 0, SHA256: Digest(floorRaw)}}, nil
}

func separateLabRoots(root, witness string) bool {
	return cleanPath(root) && cleanPath(witness) && root != witness && !strings.HasPrefix(root, witness+"/") && !strings.HasPrefix(witness, root+"/")
}

func NewLabConsumer(ctx context.Context, start *Start, enrollment Enrollment, policy Policy, root, witnessRoot, inventoryDigest string) (*LabConsumer, error) {
	if start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {
		return nil, ErrUnavailable
	}
	scope := start.Context()
	if enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {
		return nil, ErrUnavailable
	}
	consumer, err := timeconf.NewConsumer(enrollment, policy, root)
	if err != nil {
		return nil, err
	}
	runtime := labRuntimeFor(inventoryDigest)
	configureLab(consumer, &labWitness{witnessRoot}, runtime)
	lab := &LabConsumer{consumer: consumer, start: start, context: scope, inventory: inventoryDigest, root: root, runtime: runtime}
	marker, err := consumer.LabStore().LabOpen()
	if err != nil {
		return nil, err
	}
	name := "lab-start-" + strconv.FormatUint(start.Generation(), 10)
	var stat unix.Stat_t
	markerErr := unix.Fstatat(int(marker.LabDir().Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	marker.LabClose()
	if markerErr != unix.ENOENT {
		return nil, ErrUnavailable
	}
	if err := lab.checkStartHeads(ctx, start.Heads()); err != nil {
		return nil, err
	}
	session, err := consumer.LabStore().LabOpen()
	if err != nil {
		return nil, err
	}
	defer session.LabClose()
	if session.LabWrite(ctx, name, []byte(FenceFormat), "lab-start") != nil {
		return nil, ErrUnavailable
	}
	return lab, nil
}

func (lab *LabConsumer) checkStartHeads(ctx context.Context, expected Heads) error {
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if unix.Fstatat(int(session.LabDir().Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		session.LabClose()
		return ErrUnavailable
	}
	_, head, err := session.LabLoad(ctx)
	floorRaw, floorErr := session.LabRead("lab-floor", receiptLimit)
	floorHead, headErr := labFloorHead(session, floorRaw)
	var floor Floor
	floorDecodeErr := Decode(floorRaw, &floor)
	var checkpointRaw []byte
	checkpointErr := ErrUnavailable
	if floorErr == nil && floorDecodeErr == nil {
		checkpointRaw, checkpointErr = session.LabRead(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	}
	var checkpoint Checkpoint
	session.LabClose()
	if err != nil || floorErr != nil || headErr != nil || floorDecodeErr != nil || checkpointErr != nil || Decode(checkpointRaw, &checkpoint) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if checkpoint.Inventory != lab.inventory {
		return ErrUnavailable
	}
	if sum(checkpointRaw) != floor.Checkpoint || checkpoint.Context != lab.context || checkpoint.Scope != lab.context.Installation || checkpoint.Watermark != floor.Watermark || floor.Context != lab.context || !floor.Persisted || (Head{Sequence: head.Generation, SHA256: head.RecordDigest}) != expected.Time || floorHead != expected.Floor || floor.Manager != expected.Manager {
		return lab.burn(ctx)
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
	clock, err := lab.runtime.clock.Read(ctx)
	if err != nil {
		return err
	}
	last, err := point(clock)
	if err != nil {
		return err
	}
	last.Reference = "0"
	genesis := settlement{Version: "qualified-time/settlement/1", Binding: lab.consumer.LabStore().LabBinding(), Generation: "0", Previous: "none", HighWater: "0", Last: last, Hold: savedClock{Wall: "0", Elapsed: "0", Reference: "0"}}
	raw, err := canonical(genesis)
	if err != nil {
		return err
	}
	head := WitnessHead{Generation: 0, RecordDigest: sum(raw)}
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return err
	}
	defer session.LabClose()
	if session.LabWrite(ctx, objectName("record-", head.RecordDigest), raw, "lab-genesis") != nil {
		return ErrUnavailable
	}
	witness, err := (&labWitness{witnessRoot}).session()
	if err != nil {
		return err
	}
	err = witness.LabWrite(ctx, "head", witnessBytes(head), "lab-witness-genesis")
	witness.LabClose()
	if err != nil || session.LabWrite(ctx, "current", witnessBytes(head), "lab-genesis-pointer") != nil {
		return ErrUnavailable
	}
	return nil
}

func (lab *LabConsumer) ConsumeWithManager(ctx context.Context, request ConsumptionRequest, journal []byte, expectedFloor Head) ([]byte, error) {
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

func (lab *LabConsumer) consumeWithManager(ctx context.Context, request ConsumptionRequest, journal []byte, expectedFloor Head) ([]byte, error) {
	if lab.failed {
		return nil, ErrUnavailable
	}
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Fstatat(int(session.LabDir().Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		session.LabClose()
		return nil, ErrUnavailable
	}
	floorRaw, err := session.LabRead("lab-floor", receiptLimit)
	floorHead, headErr := labFloorHead(session, floorRaw)
	var floor Floor
	if err != nil || headErr != nil || Decode(floorRaw, &floor) != nil || !floor.Persisted || floor.Context != lab.context || floor.Manager != expectedFloor || len(floor.Holds) != 0 {
		session.LabClose()
		return nil, ErrUnavailable
	}
	checkpointRaw, checkpointErr := session.LabRead(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	var checkpoint Checkpoint
	if checkpointErr != nil || sum(checkpointRaw) != floor.Checkpoint || Decode(checkpointRaw, &checkpoint) != nil || checkpoint.Context != lab.context || checkpoint.Watermark != floor.Watermark || checkpoint.Inventory != lab.inventory || !checkpoint.Settled || checkpoint.Incident != "none" || len(checkpoint.Holds) != 0 {
		session.LabClose()
		return nil, ErrUnavailable
	}
	manager, err := ManagerExtension(journal, floor.Manager)
	if err != nil {
		session.LabClose()
		if errors.Is(err, ErrRegression) {
			return nil, lab.burn(ctx)
		}
		return nil, ErrUnavailable
	}
	watermark, err := time.Parse(time.RFC3339Nano, floor.Watermark)
	if err != nil || watermark.UnixNano() < 0 {
		session.LabClose()
		return nil, ErrUnavailable
	}
	request.JournalFloor = max(request.JournalFloor, watermark.UnixNano())
	session.LabClose()
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
	nextCheckpoint.Previous = Head{Sequence: checkpoint.Previous.Sequence + 1, SHA256: sum(checkpointRaw)}
	if CheckCheckpoint(checkpoint, nextCheckpoint.Previous, nextCheckpoint, true) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	checkpointRaw, err = Encode(nextCheckpoint)
	if err != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	nextFloor := floor
	nextFloor.Previous, nextFloor.Manager = floor.Manager, manager
	nextFloor.Checkpoint, nextFloor.Watermark = Digest(checkpointRaw), nextCheckpoint.Watermark
	if CheckFloor(floor, nextFloor, checkpointRaw, journal) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	nextRaw, err := Encode(nextFloor)
	if err != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	session, err = lab.consumer.LabStore().LabOpen()
	if err != nil {
		lab.failed = true
		return nil, err
	}
	defer session.LabClose()
	current, err := session.LabRead("lab-floor", receiptLimit)
	if err != nil || !bytes.Equal(current, floorRaw) || session.LabRetain(ctx, "lab-checkpoint-", checkpointRaw, "lab-checkpoint") != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	if commitLabFloor(ctx, session, floorHead, nextRaw) != nil {
		lab.failed = true
		return nil, ErrUnavailable
	}
	return raw, nil
}

func (lab *LabConsumer) checkpoint(raw []byte) (Checkpoint, error) {
	receipt, err := timeconf.DecodeReceipt(raw)
	if err != nil {
		return Checkpoint{}, ErrUnavailable
	}
	observed, _ := integer(receipt.Facts.Observed)
	uncertainty, _ := integer(receipt.Facts.Uncertainty)
	upper := time.Unix(0, observed+uncertainty).UTC()
	expires, _ := time.Parse(time.RFC3339Nano, lab.context.Expires)
	if !upper.Before(expires) || lab.start != nil && !upper.Before(lab.start.Deadline()) || receipt.Facts.Authority.ID != LabAuthority || receipt.Facts.Evidence.Source != NTSAuthData || receipt.Facts.Evidence.NTSAssociation != "verified" {
		return Checkpoint{}, ErrUnavailable
	}
	monotonic, _ := integer(receipt.Facts.Clock.ObservedNS)
	checkpoint := Checkpoint{Format: CheckpointFormat, Context: lab.context, Boot: receipt.Facts.Clock.Boot, Scope: lab.context.Installation, Incident: "none", Inventory: lab.inventory, Settled: true, Holds: []string{}, Lower: time.Unix(0, observed-uncertainty).UTC().Format(time.RFC3339Nano), Upper: upper.Format(time.RFC3339Nano), Watermark: upper.Format(time.RFC3339Nano), Monotonic: uint64(monotonic), Previous: Head{Sequence: 0, SHA256: lab.consumer.LabStore().LabBinding()}}
	if Decode(mustLabBytes(checkpoint), &Checkpoint{}) != nil {
		return Checkpoint{}, ErrUnavailable
	}
	return checkpoint, nil
}

func mustLabBytes(value any) []byte { raw, _ := Encode(value); return raw }

func (lab *LabConsumer) burn(ctx context.Context) error {
	lab.failed = true
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return errors.Join(ErrUnavailable, errBurnPersistence)
	}
	defer session.LabClose()
	marker := []byte("burned")
	floorRaw, err := session.LabRead("lab-floor", receiptLimit)
	var floor Floor
	if err == nil && Decode(floorRaw, &floor) == nil {
		checkpointRaw, readErr := session.LabRead(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
		var checkpoint Checkpoint
		if readErr == nil && Decode(checkpointRaw, &checkpoint) == nil {
			checkpoint.Incident, checkpoint.Settled = "burned", false
			marker = mustLabBytes(checkpoint)
		}
	}
	if session.LabWrite(ctx, "lab-burned", marker, "lab-burned") != nil {
		return errors.Join(ErrUnavailable, errBurnPersistence)
	}
	return ErrUnavailable
}

var errBurnPersistence = errors.New("lab_burn_persistence_unknown")

func (lab *LabConsumer) retainIncident(ctx context.Context) {
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return
	}
	defer session.LabClose()
	record, _, err := session.LabLoad(ctx)
	if err != nil || !record.Held && !record.InFlight {
		return
	}
	floorRaw, err := session.LabRead("lab-floor", receiptLimit)
	var floor Floor
	if err != nil || Decode(floorRaw, &floor) != nil {
		return
	}
	checkpointRaw, err := session.LabRead(objectName("lab-checkpoint-", floor.Checkpoint), receiptLimit)
	var checkpoint Checkpoint
	if err != nil || Decode(checkpointRaw, &checkpoint) != nil {
		return
	}
	checkpoint.Incident, checkpoint.Settled = "held", false
	checkpoint.Previous = Head{Sequence: checkpoint.Previous.Sequence + 1, SHA256: sum(checkpointRaw)}
	if len(checkpoint.Holds) == 0 {
		checkpoint.Holds = []string{"time-incident"}
	}
	checkpointRaw = mustLabBytes(checkpoint)
	floor.Holds, floor.Checkpoint = append([]string(nil), checkpoint.Holds...), sum(checkpointRaw)
	floorHead, err := labFloorHead(session, floorRaw)
	if err != nil || session.LabRetain(ctx, "lab-checkpoint-", checkpointRaw, "lab-incident-checkpoint") != nil || commitLabFloor(ctx, session, floorHead, mustLabBytes(floor)) != nil {
		lab.failed = true
	}
}

func (lab *LabConsumer) Heads(ctx context.Context) (Heads, error) {
	if lab == nil {
		return Heads{}, ErrUnavailable
	}
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if lab.failed {
		return Heads{}, ErrUnavailable
	}
	session, err := lab.consumer.LabStore().LabOpen()
	if err != nil {
		return Heads{}, err
	}
	defer session.LabClose()
	var stat unix.Stat_t
	if unix.Fstatat(int(session.LabDir().Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return Heads{}, ErrUnavailable
	}
	_, head, err := session.LabLoad(ctx)
	raw, readErr := session.LabRead("lab-floor", receiptLimit)
	var floor Floor
	floorHead, headErr := labFloorHead(session, raw)
	if err != nil || readErr != nil || headErr != nil || Decode(raw, &floor) != nil || floor.Context != lab.context {
		return Heads{}, ErrUnavailable
	}
	return Heads{Manager: floor.Manager, Time: Head{Sequence: head.Generation, SHA256: head.RecordDigest}, Floor: floorHead}, nil
}

func labFloorHead(session *storeSession, raw []byte) (Head, error) {
	encoded, err := session.LabRead("lab-floor-head", 512)
	var pointer checkpointHead
	if err != nil || strictRecord(encoded, &pointer, 512) != nil {
		return Head{}, ErrUnavailable
	}
	head, err := pointer.LabValue()
	if err != nil || head.RecordDigest != sum(raw) || head.Generation > 9007199254740991 {
		return Head{}, ErrUnavailable
	}
	return Head{Sequence: head.Generation, SHA256: head.RecordDigest}, nil
}

func commitLabFloor(ctx context.Context, session *storeSession, prior Head, raw []byte) error {
	current, err := session.LabRead("lab-floor", receiptLimit)
	head, headErr := labFloorHead(session, current)
	if err != nil || headErr != nil || head != prior || prior.Sequence >= 9007199254740991 {
		return ErrUnavailable
	}
	name := "lab-floor-" + strconv.FormatUint(prior.Sequence+1, 10)
	pointer := name + "-head"
	if session.LabRetain(ctx, "lab-floor-record-", current, "lab-floor-retain") != nil || session.LabWrite(ctx, name, raw, "lab-floor") != nil || session.LabWrite(ctx, pointer, witnessBytes(WitnessHead{Generation: prior.Sequence + 1, RecordDigest: sum(raw)}), "lab-floor-pointer") != nil {
		return ErrUnavailable
	}
	if unix.Renameat(int(session.LabDir().Fd()), name, int(session.LabDir().Fd()), "lab-floor") != nil || unix.Renameat(int(session.LabDir().Fd()), pointer, int(session.LabDir().Fd()), "lab-floor-head") != nil || session.LabSync(session.LabDir(), "lab-floor-current") != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
