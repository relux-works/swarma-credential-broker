//go:build linux && broker_lab

package timeconf

import (
	"context"
	"os"
	"time"
)

type LabCollection struct {
	Evidence  Evidence
	Originals [][]byte
	Terminal  bool
	Drained   bool
}

type labCollectionAdapter struct {
	collectFn func(context.Context, Policy) (LabCollection, error)
}

func (adapter labCollectionAdapter) collect(ctx context.Context, policy Policy) (localCollection, error) {
	result, err := adapter.collectFn(ctx, policy)
	return localCollection{result.Evidence, result.Originals, result.Terminal, result.Drained}, err
}

func (consumer *Consumer) LabConfigure(witness RollbackWitness, clock Clock, collect func(context.Context, Policy) (LabCollection, error)) {
	consumer.store.witness = witness
	consumer.clock = clock
	consumer.collector = labCollectionAdapter{collect}
	consumer.timePath = &pathQualification{reserve: time.Second, budget: 500 * time.Millisecond, handoff: time.Millisecond, reboot: true}
}

type LabStore = settlementStore
type LabSession = storeSession
type LabPointer = checkpointHead
type LabSettlement = settlement
type LabSavedClock = savedClock

func (consumer *Consumer) LabStore() *LabStore                       { return &consumer.store }
func LabOpenStore(root string) (*LabSession, error)                  { return (&settlementStore{root: root}).open() }
func (store *settlementStore) LabOpen() (*LabSession, error)         { return store.open() }
func (store *settlementStore) LabBinding() string                    { return store.binding }
func (store *settlementStore) LabWitness() RollbackWitness           { return store.witness }
func (store *settlementStore) LabSyncFault(fault func(string) error) { store.syncFault = fault }
func (session *storeSession) LabClose()                              { session.close() }
func (session *storeSession) LabDir() *os.File                       { return session.dir }
func (session *storeSession) LabRead(name string, limit int) ([]byte, error) {
	return session.read(name, limit)
}
func (session *storeSession) LabWrite(ctx context.Context, name string, raw []byte, stage string) error {
	return session.write(ctx, name, raw, stage)
}
func (session *storeSession) LabRetain(ctx context.Context, prefix string, raw []byte, stage string) error {
	return session.retain(ctx, prefix, raw, stage)
}
func (session *storeSession) LabSync(file *os.File, stage string) error {
	return session.sync(file, stage)
}
func (session *storeSession) LabLoad(ctx context.Context) (LabSettlement, WitnessHead, error) {
	return session.load(ctx)
}
func (pointer checkpointHead) LabValue() (WitnessHead, error) { return pointer.value() }
func LabCanonical(value any) ([]byte, error)                  { return canonical(value) }
func LabStrictRecord(raw []byte, value any, limit int) error  { return strictRecord(raw, value, limit) }
func LabWitnessBytes(head WitnessHead) []byte                 { return witnessBytes(head) }
func LabObjectName(prefix, digest string) string              { return objectName(prefix, digest) }
func LabPoint(clock ClockPoint) (LabSavedClock, error)        { return point(clock) }
func LabInteger(value Nanoseconds) (int64, error)             { return integer(value) }
func LabProtectedRead(path string, owner uint32, limit int, directory bool) ([]byte, error) {
	return protectedRead(path, owner, limit, directory)
}
func LabParseSources(raw []byte) (Sources, error) { return parseSources(raw, false, nil) }
