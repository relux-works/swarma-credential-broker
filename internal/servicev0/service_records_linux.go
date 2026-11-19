package servicev0

import (
	"github.com/relux-works/swarma-credential-broker/internal/statev0"
	"github.com/relux-works/swarma-credential-broker/internal/store"
)

const serviceRecordName = "owner-claude-service.json"

type Records struct {
	account *store.Account
}

func NewRecords(account *store.Account) (*Records, error) {
	if account == nil || account.Healthy() != nil {
		return nil, statev0.ErrUnavailable
	}
	return &Records{account: account}, nil
}

func (records *Records) ReadService() ([]byte, error) {
	if records == nil || records.account == nil {
		return nil, statev0.ErrUnavailable
	}
	return records.account.Read(serviceRecordName)
}

func (records *Records) CreateService(state statev0.ServiceStateV2) error {
	if records == nil || records.account == nil {
		return statev0.ErrUnavailable
	}
	present, err := records.account.HasRecords()
	if err != nil || state.Revision != 1 {
		return statev0.ErrUnavailable
	}
	if present {
		return statev0.ErrConflict
	}
	return records.account.Put(serviceRecordName, 0, state)
}

func (records *Records) CommitService(prior uint64, state statev0.ServiceStateV2) error {
	if records == nil || records.account == nil || prior == 0 {
		return statev0.ErrUnavailable
	}
	return records.account.Put(serviceRecordName, prior, state)
}

var _ statev0.ServiceRecords = (*Records)(nil)
