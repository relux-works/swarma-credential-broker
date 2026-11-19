package statev0

import (
	"context"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
)

type Gate interface {
	With(context.Context, func(*Tx) error) error
}

// Tx's zero value is not authority. U05 must issue and check live callback tokens.
type Tx struct {
	scope *transactionScope
}

type NonceStore interface {
	ConsumeLocked(*Tx, assemblyv0.TerminalReceipt) error
}

type ServiceJournal interface {
	LoadLocked(*Tx, string) (ServiceStateV2, error)
	CommitLocked(*Tx, string, uint64, ServiceStateV2) error
	ReserveLocked(*Tx, string, ServiceStateV2) error
}

type RevocationStore interface {
	ReadLocked(*Tx) (RevocationState, error)
	PutLocked(*Tx, RevocationState) error
}
