//go:build linux && broker_lab

package labv0

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var ErrUnknown = errors.New("lab state UNKNOWN")
var ErrReserve = errors.New("lab narrowing reserve exhausted")

const accountLabel = "lab/anthropic"

type Account struct {
	mu           sync.Mutex
	records      *store.Account
	installation string
	context      map[string]any
	project      func(wire.ServiceState, map[string]any) (map[string]any, error)
	unknown      bool
}

func newAccount(records *store.Account, approvedContext map[string]any, project func(wire.ServiceState, map[string]any) (map[string]any, error)) (*Account, error) {
	if records == nil || project == nil {
		return nil, ErrUnknown
	}
	installation, ok := approvedContext["installation_id"].(string)
	storedInstallation, storeErr := records.LabInstallation()
	if storeErr != nil || storedInstallation != installation || !ok || !wire.ASCII(installation, 128) || approvedContext["account"] != accountLabel {
		return nil, ErrUnknown
	}
	copy, err := object(approvedContext)
	if err != nil {
		return nil, ErrUnknown
	}
	return &Account{records: records, installation: installation, context: copy, project: project, unknown: true}, nil
}

func (account *Account) bootstrap(custody, metadata, journal map[string]any, now time.Time) error {
	account.mu.Lock()
	defer account.mu.Unlock()
	occupied, err := account.records.HasRecords()
	if err != nil || occupied || now.IsZero() {
		return ErrUnknown
	}
	for _, record := range []map[string]any{custody, metadata} {
		raw, err := wire.Encode(record)
		if err != nil {
			return ErrUnknown
		}
		format, _ := record["format"].(string)
		_, err = labcontract.Read(format, raw)
		clear(raw)
		if err != nil || !labcontract.Equal(record["context"], account.context) {
			return ErrUnknown
		}
	}
	if custody["format"] != "swarma-broker-lab-custody/1" || metadata["format"] != "swarma-broker-lab-account/1" || custody["store_object_id"] != metadata["custody_object_id"] || custody["state"] != "enrolled" || metadata["status"] != "enrolled" || !labcontract.Equal(journal["context"], account.context) {
		return ErrUnknown
	}
	state := wire.ServiceState{Kind: stateFormat, Installation: account.installation, Revision: 1, Watermark: now.UTC()}
	raw, err := encodeRecovery(state, journal)
	if err != nil {
		return ErrUnknown
	}
	if _, _, err = readRecovery(raw, account.installation); err != nil {
		return ErrUnknown
	}
	if !labcontract.Equal(metadata["service_journal_head"], journal["head"]) || len(journal["entries"].([]any)) != 0 {
		return ErrUnknown
	}
	account.unknown = true
	for _, record := range []map[string]any{custody, metadata} {
		encoded, err := wire.Encode(record)
		if err != nil {
			return ErrUnknown
		}
		err = account.records.AppendLabRecord(encoded)
		clear(encoded)
		if err != nil {
			return ErrUnknown
		}
	}
	envelope, err := wire.Parse(raw)
	if err != nil || account.records.Put(stateName, 0, envelope) != nil {
		return ErrUnknown
	}
	account.unknown = false
	return nil
}

func (account *Account) load() (wire.ServiceState, map[string]any, error) {
	if account == nil || account.records == nil {
		return wire.ServiceState{}, nil, ErrUnknown
	}
	raw, err := account.records.Read(stateName)
	if err != nil {
		return wire.ServiceState{}, nil, ErrUnknown
	}
	state, external, err := readRecovery(raw, account.installation)
	if err != nil || !labcontract.Equal(external["context"], account.context) {
		return wire.ServiceState{}, nil, ErrUnknown
	}
	metadata, err := account.readMetadata()
	if err != nil || metadata["status"] != "enrolled" || metadata["context"] == nil {
		return wire.ServiceState{}, nil, ErrUnknown
	}
	return state, external, nil
}

func (account *Account) readMetadata() (map[string]any, error) {
	raw, err := account.records.Read("owner-lab-account.json")
	if err != nil {
		return nil, ErrUnknown
	}
	metadata, err := labcontract.Read("swarma-broker-lab-account/1", raw)
	if err != nil || !labcontract.Equal(metadata["context"], account.context) {
		return nil, ErrUnknown
	}
	return metadata, nil
}

func (account *Account) LoadServiceState() (wire.ServiceState, error) {
	if account == nil {
		return wire.ServiceState{}, ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	state, _, err := account.load()
	return state, err
}

func (account *Account) StoreServiceState(candidate wire.ServiceState) error {
	if account == nil {
		return ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	previous, external, err := account.load()
	if err != nil || candidate.Revision != previous.Revision+1 || candidate.Installation != account.installation || candidate.Watermark.Before(previous.Watermark) || len(candidate.Operations) < len(previous.Operations) || len(candidate.Operations) > len(previous.Operations)+1 {
		account.unknown = true
		return ErrUnknown
	}
	for position, operation := range previous.Operations {
		if !labcontract.Equal(operation, candidate.Operations[position]) {
			account.unknown = true
			return ErrUnknown
		}
	}
	limit, reserve := external["operation_limit"], external["narrowing_reserve"]
	if len(candidate.Operations) == len(previous.Operations) {
		confirmed, expected := candidate, previous
		confirmed.Revision = expected.Revision
		if !labcontract.Equal(confirmed, expected) {
			account.unknown = true
			return ErrUnknown
		}
	} else {
		external, err = account.project(candidate, external)
		if err != nil {
			account.unknown = true
			return ErrUnknown
		}
		if external["operation_limit"] != limit || external["narrowing_reserve"] != reserve {
			account.unknown = true
			return ErrUnknown
		}
	}
	encoded, err := encodeRecovery(candidate, external)
	if err != nil {
		account.unknown = true
		return ErrUnknown
	}
	state, joined, err := readRecovery(encoded, account.installation)
	if err != nil || !labcontract.Equal(joined["context"], account.context) {
		account.unknown = true
		return ErrUnknown
	}
	if len(candidate.Operations) > len(previous.Operations) {
		method := candidate.Operations[len(candidate.Operations)-1].Method
		if !terminalMethod(method) && !reserveFits(state, joined, len(encoded)) {
			return ErrReserve
		}
	}
	envelope, err := wire.Parse(encoded)
	if err != nil {
		return ErrUnknown
	}
	account.unknown = true
	if account.records.Put(stateName, previous.Revision, envelope) != nil {
		return ErrUnknown
	}
	account.unknown = false
	return nil
}

func reserveFits(state wire.ServiceState, external map[string]any, encodedBytes int) bool {
	liabilities := 2
	for _, binding := range state.Bindings {
		if binding.State == "active" {
			liabilities++
		}
	}
	for _, lease := range state.Leases {
		if lease.State == "active" {
			liabilities++
		}
	}
	reserve := int(external["narrowing_reserve"].(int64))
	remaining := int(external["operation_limit"].(int64)) - len(state.Operations)
	public, err := wire.Encode(external)
	return err == nil && reserve >= liabilities && remaining >= reserve && state.Revision <= 9007199254740990-uint64(reserve) && encodedBytes+reserve*8192 <= 524288 && len(public)+reserve*2048 <= 65536
}

func (account *Account) Snapshot() ([]byte, error) {
	if account == nil {
		return nil, ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if account.unknown {
		return nil, ErrUnknown
	}
	_, external, err := account.load()
	if err != nil {
		return nil, ErrUnknown
	}
	return wire.Encode(external)
}

func (account *Account) ExpiresAt() (*time.Time, error) {
	if account == nil {
		return nil, ErrUnknown
	}
	return nil, nil
}

func (account *Account) ServiceAccount() (wire.ServiceAccount, error) {
	if account == nil {
		return wire.ServiceAccount{}, ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if account.unknown {
		return wire.ServiceAccount{}, ErrUnknown
	}
	_, _, err := account.load()
	if err != nil {
		return wire.ServiceAccount{}, ErrUnknown
	}
	return wire.ServiceAccount{Account: accountLabel, Harness: "claude_code", Kind: service.LabKind, State: "active"}, nil
}

func (account *Account) Publish(ctx context.Context, until time.Time, trustedNow func() time.Time, deliver func([]byte) error) error {
	if account == nil || ctx == nil || trustedNow == nil || deliver == nil {
		return ErrUnknown
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if account.unknown || ctx.Err() != nil || !trustedNow().Before(until) {
		return ErrUnknown
	}
	_, external, err := account.load()
	if err != nil || external["held"] != false {
		return ErrUnknown
	}
	metadata, err := account.readMetadata()
	if err != nil {
		return ErrUnknown
	}
	raw, err := account.records.Read("owner-lab-custody.json")
	defer clear(raw)
	if err != nil {
		return ErrUnknown
	}
	custody, err := labcontract.Read("swarma-broker-lab-custody/1", raw)
	if err != nil || custody["state"] != "enrolled" || custody["store_object_id"] != metadata["custody_object_id"] || !labcontract.Equal(custody["context"], account.context) {
		return ErrUnknown
	}
	material := []byte(custody["material"].(string))
	delete(custody, "material")
	defer clear(material)
	if ctx.Err() != nil || !trustedNow().Before(until) {
		return ErrUnknown
	}
	return deliver(material)
}

func sortedStrings(values []string) []any {
	sort.Strings(values)
	result := make([]any, len(values))
	for position, value := range values {
		result[position] = value
	}
	return result
}
