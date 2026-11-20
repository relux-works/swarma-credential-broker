//go:build linux && broker_lab

package labv0

import (
	"context"
	"sync"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const periodicDelay = 500 * time.Millisecond
const schedulerMargin = 50 * time.Millisecond
const nativeAge = 1200 * time.Millisecond
const nativeArm = 1150 * time.Millisecond
const pairBudget = 1250 * time.Millisecond

func validObservationRecovery(records []any) bool {
	if len(records) == 0 {
		return true
	}
	if len(records) != 1 {
		return false
	}
	record := records[0].(map[string]any)
	baseline := record["baseline"].(map[string]any)
	encoded, err := wire.Encode(baseline)
	if err != nil || len(encoded) > 65536 {
		return false
	}
	return record["seen"].(int64) >= record["floor"].(int64) && baseline["sequence"] == record["floor"] && record["store_generation"] == baseline["sequence_generation"] && record["store_generation"] == baseline["store"].(map[string]any)["generation"] && record["observed_monotonic_ms"].(int64) >= baseline["observed_monotonic_ms"].(int64) && record["observed_monotonic_ms"].(int64) <= record["receipt_monotonic_ms"].(int64)
}

func sameNative(first, second map[string]any) bool {
	left, leftErr := object(first)
	right, rightErr := object(second)
	delete(left, "sequence")
	delete(right, "sequence")
	delete(left, "observed_monotonic_ms")
	delete(right, "observed_monotonic_ms")
	return leftErr == nil && rightErr == nil && labcontract.Equal(left, right)
}

type continuedUse struct {
	mu       sync.Mutex
	serial   chan struct{}
	account  *Account
	client   *observationClient
	record   map[string]any
	open     bool
	epoch    uint64
	closeUse func()
}

func newContinuedUse(account *Account, client *observationClient, closeUse func()) (*continuedUse, error) {
	if account == nil || client == nil || closeUse == nil {
		return nil, ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if _, _, err := account.load(); err != nil {
		return nil, ErrUnknown
	}
	use := &continuedUse{account: account, client: client, serial: make(chan struct{}, 1), closeUse: closeUse}
	use.serial <- struct{}{}
	if len(account.observation) == 1 {
		use.record, _ = object(account.observation[0])
		if use.record["store_generation"] != client.pins.storeGeneration {
			return nil, ErrUnknown
		}
	}
	return use, nil
}

func (use *continuedUse) fence() {
	use.mu.Lock()
	wasOpen := use.open
	use.open = false
	use.epoch++
	use.mu.Unlock()
	if wasOpen {
		use.closeUse()
	}
}

func (use *continuedUse) current() error {
	now, err := bootNanos()
	use.mu.Lock()
	valid := err == nil && use.open && use.record != nil
	if valid {
		observed := use.record["observed_monotonic_ms"].(int64) * int64(time.Millisecond)
		valid = now >= observed && now-observed < int64(nativeAge)
	}
	use.mu.Unlock()
	if !valid {
		use.fence()
		return ErrUnknown
	}
	return nil
}

func (use *continuedUse) enter() bool {
	select {
	case <-use.serial:
		return true
	default:
		use.fence()
		return false
	}
}

func (use *continuedUse) publication(ctx context.Context, kind string, publish func() error) error {
	return use.publicationFor(ctx, observationPurpose{kind: kind}, publish)
}

func (use *continuedUse) publicationFor(ctx context.Context, purpose observationPurpose, publish func() error) error {
	use.fence()
	kind := purpose.kind
	if ctx == nil || ctx.Err() != nil || publish == nil || (kind != "start" && kind != "commit" && kind != "debit" && kind != "stop" && kind != "invalidation") || !use.enter() {
		return ErrUnknown
	}
	defer func() { use.serial <- struct{}{} }()
	ctx, cancel := context.WithTimeout(ctx, pairBudget)
	defer cancel()
	entered, err := bootNanos()
	if err != nil {
		return ErrUnknown
	}
	use.mu.Lock()
	publicationEpoch := use.epoch
	use.mu.Unlock()
	envelope, seen, receipt, err := use.prepare(entered)
	if err != nil {
		return ErrUnknown
	}
	if err := waitObservationCooldown(ctx, receipt+int64(observationWindow)); err != nil {
		return ErrUnknown
	}
	first, err := use.client.collectFor(ctx, seen, purpose)
	if err != nil || first.before < receipt+int64(observationWindow) || first.before >= receipt+int64(observationWindow+schedulerMargin) {
		return ErrUnknown
	}
	if err := waitObservationCooldown(ctx, first.after+int64(observationWindow)); err != nil {
		return ErrUnknown
	}
	final, err := use.client.collectFor(ctx, first.record["sequence"].(int64), purpose)
	if err != nil || final.before >= first.after+int64(observationWindow+schedulerMargin) || !sameNative(first.record, final.record) {
		return ErrUnknown
	}
	if !use.account.mu.TryLock() {
		return ErrUnknown
	}
	defer use.account.mu.Unlock()
	use.mu.Lock()
	unchanged := use.epoch == publicationEpoch
	use.mu.Unlock()
	if !unchanged {
		return ErrUnknown
	}
	result := map[string]any{"kind": kind, "operation_id": use.client.pins.start["operation_id"], "start_id": use.client.pins.start["start_id"], "effect_id": purpose.effectID}
	updated := map[string]any{"store_generation": use.client.pins.storeGeneration, "floor": final.record["sequence"], "seen": final.record["sequence"], "baseline": final.record, "observed_monotonic_ms": final.record["observed_monotonic_ms"], "receipt_monotonic_ms": final.after / int64(time.Millisecond), "publication": kind, "result_sha256": digest(result)}
	if err := use.commit(ctx, envelope, updated, final.deadline, entered+int64(pairBudget)); err != nil {
		return ErrUnknown
	}
	use.mu.Lock()
	unchanged = use.epoch == publicationEpoch
	use.mu.Unlock()
	if !unchanged {
		return ErrUnknown
	}
	if err := publish(); err != nil {
		return ErrUnknown
	}
	now, clockErr := bootNanos()
	if clockErr != nil || ctx.Err() != nil || now >= final.deadline || now >= entered+int64(pairBudget) {
		return ErrUnknown
	}
	use.mu.Lock()
	if use.epoch != publicationEpoch {
		use.mu.Unlock()
		return ErrUnknown
	}
	use.record = updated
	use.open = kind != "stop" && kind != "invalidation"
	use.epoch++
	epoch := use.epoch
	use.mu.Unlock()
	go use.guard(epoch)
	return nil
}

func (use *continuedUse) prepare(entered int64) (map[string]any, int64, int64, error) {
	if !use.account.mu.TryLock() {
		return nil, 0, 0, ErrUnknown
	}
	defer use.account.mu.Unlock()
	if _, _, err := use.account.load(); err != nil {
		return nil, 0, 0, ErrUnknown
	}
	raw, err := use.account.records.Read(stateName)
	if err != nil {
		return nil, 0, 0, ErrUnknown
	}
	envelope, err := labcontract.ReadRecovery(raw)
	if err != nil {
		return nil, 0, 0, ErrUnknown
	}
	seen, receipt := int64(0), entered
	if len(use.account.observation) == 1 {
		record := use.account.observation[0].(map[string]any)
		seen = record["seen"].(int64)
		receipt = max(receipt, record["receipt_monotonic_ms"].(int64)*int64(time.Millisecond))
	}
	return envelope, seen, receipt, nil
}

func (use *continuedUse) guard(epoch uint64) {
	for {
		use.mu.Lock()
		if !use.open || use.epoch != epoch {
			use.mu.Unlock()
			return
		}
		observed := use.record["observed_monotonic_ms"].(int64) * int64(time.Millisecond)
		use.mu.Unlock()
		now, err := bootNanos()
		if err != nil || now >= observed+int64(nativeArm) {
			use.mu.Lock()
			if use.open && use.epoch == epoch {
				use.open = false
				use.epoch++
				use.mu.Unlock()
				use.closeUse()
				return
			}
			use.mu.Unlock()
			return
		}
		time.Sleep(time.Duration(min(int64(25*time.Millisecond), observed+int64(nativeArm)-now)))
	}
}

func (use *continuedUse) commit(ctx context.Context, envelope, updated map[string]any, deadlines ...int64) error {
	if use.account.unknown {
		return ErrUnknown
	}
	now, err := bootNanos()
	if err != nil || ctx.Err() != nil || !validObservationRecovery([]any{updated}) {
		return ErrUnknown
	}
	for _, deadline := range deadlines {
		if now >= deadline {
			return ErrUnknown
		}
	}
	revision := envelope["revision"].(int64)
	reserve := envelope["external"].(map[string]any)["narrowing_reserve"].(int64)
	if revision >= 9007199254740990-reserve {
		return ErrUnknown
	}
	envelope["previous_revision"], envelope["revision"] = revision, revision+1
	envelope["observation"] = []any{updated}
	raw, err := wire.Encode(envelope)
	if err != nil {
		return ErrUnknown
	}
	if _, _, err := readRecovery(raw, use.account.installation); err != nil {
		return ErrUnknown
	}
	use.account.unknown = true
	if use.account.records.Put(stateName, uint64(revision), envelope) != nil {
		return ErrUnknown
	}
	now, err = bootNanos()
	if err != nil || ctx.Err() != nil {
		return ErrUnknown
	}
	for _, deadline := range deadlines {
		if now >= deadline {
			return ErrUnknown
		}
	}
	use.account.unknown = false
	return nil
}

func (use *continuedUse) periodic(ctx context.Context) error {
	if use.current() != nil || !use.enter() {
		return ErrUnknown
	}
	defer func() { use.serial <- struct{}{} }()
	failed := true
	defer func() {
		if failed {
			use.fence()
		}
	}()
	use.mu.Lock()
	previous, err := object(use.record)
	use.mu.Unlock()
	if err != nil {
		return ErrUnknown
	}
	receipt := previous["receipt_monotonic_ms"].(int64) * int64(time.Millisecond)
	if waitObservationCooldown(ctx, receipt+int64(periodicDelay)) != nil {
		return ErrUnknown
	}
	if !use.account.mu.TryLock() {
		return ErrUnknown
	}
	prior, err := use.account.records.Read(stateName)
	use.account.mu.Unlock()
	if err != nil {
		return ErrUnknown
	}
	envelope, err := labcontract.ReadRecovery(prior)
	if err != nil || !labcontract.Equal(envelope["observation"], []any{previous}) {
		return ErrUnknown
	}
	next, err := use.client.collect(ctx, previous["seen"].(int64))
	if err != nil || next.before < receipt+int64(periodicDelay) || next.before >= receipt+int64(periodicDelay+schedulerMargin) || !sameNative(previous["baseline"].(map[string]any), next.record) {
		return ErrUnknown
	}
	updated, _ := object(previous)
	updated["seen"] = next.record["sequence"]
	updated["observed_monotonic_ms"] = next.record["observed_monotonic_ms"]
	updated["receipt_monotonic_ms"] = next.after / int64(time.Millisecond)
	if !use.account.mu.TryLock() {
		return ErrUnknown
	}
	defer use.account.mu.Unlock()
	if use.current() != nil {
		return ErrUnknown
	}
	if err := use.commit(ctx, envelope, updated, next.deadline, previous["observed_monotonic_ms"].(int64)*int64(time.Millisecond)+int64(nativeAge)); err != nil {
		return ErrUnknown
	}
	use.mu.Lock()
	if !use.open {
		use.mu.Unlock()
		return ErrUnknown
	}
	use.record = updated
	use.mu.Unlock()
	failed = false
	return nil
}

func (use *continuedUse) watch(ctx context.Context) error {
	for {
		if ctx.Err() != nil || use.current() != nil {
			use.fence()
			return ErrUnknown
		}
		use.mu.Lock()
		receipt := use.record["receipt_monotonic_ms"].(int64) * int64(time.Millisecond)
		observed := use.record["observed_monotonic_ms"].(int64) * int64(time.Millisecond)
		use.mu.Unlock()
		if waitObservationCooldown(ctx, min(receipt+int64(periodicDelay), observed+int64(nativeArm))) != nil {
			use.fence()
			return ErrUnknown
		}
		now, err := bootNanos()
		if err != nil || now >= observed+int64(nativeArm) || use.periodic(ctx) != nil {
			use.fence()
			return ErrUnknown
		}
	}
}

type continuedAuthority struct {
	base service.Authority
	use  *continuedUse
}

func (authority continuedAuthority) WithIdentity(ctx context.Context, callback func(service.View) error) error {
	return authority.base.WithIdentity(ctx, callback)
}
func (authority continuedAuthority) WithCurrent(ctx context.Context, callback func(service.View) error) error {
	if authority.use.current() != nil {
		return ErrUnknown
	}
	return authority.base.WithCurrent(ctx, func(view service.View) error {
		if authority.use.current() != nil {
			return ErrUnknown
		}
		return callback(view)
	})
}
