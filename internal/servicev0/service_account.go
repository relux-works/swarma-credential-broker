package servicev0

import (
	"context"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/statev0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type MaterialAccount interface {
	ExpiresAt() (*time.Time, error)
	ServiceAccount() (wire.ServiceAccount, error)
	Publish(context.Context, time.Time, func() time.Time, func([]byte) error) error
}

type JournalAccount struct {
	gate    statev0.Gate
	journal statev0.ServiceJournal
	account string
	custody MaterialAccount
	tx      *statev0.Tx
	receipt *statev0.OperationReceipt
	leaseID string
}

func NewJournalAccount(gate statev0.Gate, journal statev0.ServiceJournal, account string, custody MaterialAccount) (*JournalAccount, error) {
	if gate == nil || journal == nil || !wire.ASCII(account, 128) || custody == nil {
		return nil, statev0.ErrUnavailable
	}
	return &JournalAccount{gate: gate, journal: journal, account: account, custody: custody}, nil
}

func (account *JournalAccount) Locked(tx *statev0.Tx, receipt *statev0.OperationReceipt) (*JournalAccount, error) {
	if account == nil || statev0.Check(tx, account.gate) != nil {
		return nil, statev0.ErrTransaction
	}
	bound := *account
	bound.tx, bound.receipt, bound.leaseID = tx, nil, ""
	if receipt != nil {
		data, err := wire.Encode(receipt)
		var copied statev0.OperationReceipt
		if err != nil || wire.Decode(data, &copied) != nil {
			return nil, statev0.ErrUnavailable
		}
		bound.receipt = &copied
	}
	return &bound, nil
}

func (account *JournalAccount) ForLeaseLocked(tx *statev0.Tx, leaseID string) (*JournalAccount, error) {
	bound, err := account.Locked(tx, nil)
	if err != nil || !wire.ASCII(leaseID, 128) {
		return nil, statev0.ErrTransaction
	}
	bound.leaseID = leaseID
	return bound, nil
}

func (account *JournalAccount) check() error {
	if account == nil {
		return statev0.ErrUnavailable
	}
	return statev0.Check(account.tx, account.gate)
}

func (account *JournalAccount) ExpiresAt() (*time.Time, error) {
	if err := account.check(); err != nil {
		return nil, err
	}
	return account.custody.ExpiresAt()
}

func (account *JournalAccount) ServiceAccount() (wire.ServiceAccount, error) {
	if err := account.check(); err != nil {
		return wire.ServiceAccount{}, err
	}
	return account.custody.ServiceAccount()
}

func project(state statev0.ServiceStateV2) wire.ServiceState {
	legacy := wire.ServiceState{Kind: state.Kind, Installation: state.InstallationID, Revision: state.Revision, Watermark: state.Watermark, Bindings: state.Bindings, Leases: state.Leases, Holds: state.Holds, Operations: []wire.ServiceOperation{}}
	for _, operation := range state.Operations {
		at := time.Time{}
		if operation.At != nil {
			at = *operation.At
		}
		legacy.Operations = append(legacy.Operations, wire.ServiceOperation{Principal: operation.Principal, Method: operation.Method, ID: string(operation.OperationID), Arguments: operation.Arguments, Result: operation.Result, At: at})
	}
	return legacy
}

func (account *JournalAccount) LoadServiceState() (wire.ServiceState, error) {
	if err := account.check(); err != nil {
		return wire.ServiceState{}, err
	}
	state, err := account.journal.LoadLocked(account.tx, account.account)
	if err != nil {
		return wire.ServiceState{}, err
	}
	return project(state), nil
}

func (account *JournalAccount) StoreServiceState(state wire.ServiceState) error {
	if err := account.check(); err != nil {
		return err
	}
	prior, err := account.journal.LoadLocked(account.tx, account.account)
	if err != nil {
		return err
	}
	if state.Kind != statev0.ServiceJournalKind || state.Installation != prior.InstallationID || len(state.Operations) < len(prior.Operations) {
		return statev0.ErrConflict
	}
	next := statev0.ServiceStateV2{Kind: state.Kind, InstallationID: state.Installation, Revision: state.Revision, Watermark: state.Watermark, Bindings: state.Bindings, Leases: state.Leases, Holds: state.Holds, Operations: []statev0.ServiceOperationV2{}}
	projected := project(prior)
	for index, operation := range state.Operations {
		if index < len(prior.Operations) {
			oldBytes, oldErr := wire.Encode(projected.Operations[index])
			newBytes, newErr := wire.Encode(operation)
			if oldErr != nil || newErr != nil || string(oldBytes) != string(newBytes) {
				return statev0.ErrConflict
			}
			next.Operations = append(next.Operations, prior.Operations[index])
			continue
		}
		var at *time.Time
		if !operation.At.IsZero() {
			at = &operation.At
		}
		converted := statev0.ServiceOperationV2{Principal: operation.Principal, Method: operation.Method, Arguments: operation.Arguments, Result: operation.Result, At: at, Receipt: account.receipt}
		converted.OperationID = assemblyv0.OperationID(operation.ID)
		next.Operations = append(next.Operations, converted)
	}
	return account.journal.CommitLocked(account.tx, account.account, prior.Revision, next)
}

func (account *JournalAccount) Publish(ctx context.Context, until time.Time, now func() time.Time, deliver func([]byte) error) error {
	if err := account.check(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil || now == nil || deliver == nil || account.leaseID == "" {
		return statev0.ErrUnavailable
	}
	validate := func() error {
		state, err := account.journal.LoadLocked(account.tx, account.account)
		if err != nil {
			return err
		}
		for _, hold := range state.Holds {
			if hold.State == "active" {
				return statev0.ErrUnavailable
			}
		}
		for _, lease := range state.Leases {
			if lease.ID == account.leaseID && lease.State == "active" && !until.After(lease.Until) && now().Before(until) {
				for _, binding := range state.Bindings {
					if binding.ID == lease.BindingID && binding.State == "active" {
						return nil
					}
				}
			}
		}
		return statev0.ErrUnavailable
	}
	if err := validate(); err != nil {
		return err
	}
	return account.custody.Publish(ctx, until, now, func(material []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := validate(); err != nil {
			return err
		}
		return statev0.Use(account.tx, account.gate, func() error {
			if ctx.Err() != nil || !now().Before(until) {
				return statev0.ErrUnavailable
			}
			return deliver(material)
		})
	})
}

var _ service.Account = (*JournalAccount)(nil)
