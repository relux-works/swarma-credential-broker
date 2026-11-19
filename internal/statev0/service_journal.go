package statev0

import (
	"bytes"
	"errors"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const ServiceJournalKind = "claude-service-journal/2"
const MaxServiceJournalBytes = 1 << 20

var (
	ErrUnavailable = errors.New("service journal unavailable")
	ErrConflict    = errors.New("service journal conflict")
	ErrCapacity    = errors.New("service narrowing reserve exhausted")
)

type ServiceRecords interface {
	ReadService() ([]byte, error)
	CreateService(ServiceStateV2) error
	CommitService(uint64, ServiceStateV2) error
}

type Journal struct {
	gate         Gate
	installation string
	accounts     map[string]ServiceRecords
	callers      []assemblyv0.PrincipalPin
	uncertain    map[string]bool
	settled      map[string]bool
}

func NewServiceJournal(gate Gate, installation string, accounts map[string]ServiceRecords, callers []assemblyv0.PrincipalPin) (*Journal, error) {
	if gate == nil || !wire.ASCII(installation, 128) || len(accounts) == 0 || len(callers) == 0 {
		return nil, ErrUnavailable
	}
	journal := &Journal{gate: gate, installation: installation, accounts: map[string]ServiceRecords{}, callers: append([]assemblyv0.PrincipalPin(nil), callers...), uncertain: map[string]bool{}, settled: map[string]bool{}}
	for account, records := range accounts {
		if !wire.ASCII(account, 128) || records == nil {
			return nil, ErrUnavailable
		}
		journal.accounts[account] = records
	}
	for _, caller := range callers {
		if caller.Name == "" || !absoluteHome(caller.Home) {
			return nil, ErrUnavailable
		}
	}
	return journal, nil
}

func (journal *Journal) LoadLocked(tx *Tx, account string) (ServiceStateV2, error) {
	var state ServiceStateV2
	if journal == nil {
		return state, ErrUnavailable
	}
	err := Use(tx, journal.gate, func() error {
		var err error
		state, err = journal.load(account)
		return err
	})
	if err != nil {
		return ServiceStateV2{}, err
	}
	return state, err
}

func (journal *Journal) load(account string) (ServiceStateV2, error) {
	var state ServiceStateV2
	records := journal.accounts[account]
	if records == nil || journal.uncertain[account] {
		return state, ErrUnavailable
	}
	if !journal.settled[account] {
		return state, ErrUnavailable
	}
	return journal.read(account)
}

func (journal *Journal) read(account string) (ServiceStateV2, error) {
	var state ServiceStateV2
	records := journal.accounts[account]
	if records == nil {
		return state, ErrUnavailable
	}
	data, err := records.ReadService()
	if err != nil || len(data) > MaxServiceJournalBytes || wire.Decode(data, &state) != nil {
		return ServiceStateV2{}, ErrUnavailable
	}
	canonical, err := wire.Encode(state)
	if err != nil || !bytes.Equal(data, canonical) || journal.valid(account, state) != nil {
		return ServiceStateV2{}, ErrUnavailable
	}
	return state, nil
}

func (journal *Journal) ReconcileLocked(tx *Tx, account string) error {
	if journal == nil {
		return ErrUnavailable
	}
	return Use(tx, journal.gate, func() error {
		state, err := journal.read(account)
		if err != nil || state.Revision == assemblyv0.MaxSafeInteger {
			return ErrUnavailable
		}
		prior := state.Revision
		state.Revision++
		if err := journal.reserve(state); err != nil {
			return err
		}
		if err := journal.accounts[account].CommitService(prior, state); err != nil {
			journal.uncertain[account] = true
			return ErrUnavailable
		}
		journal.uncertain[account], journal.settled[account] = false, true
		return nil
	})
}

func (journal *Journal) InitializeLocked(tx *Tx, account string, state ServiceStateV2) error {
	if journal == nil {
		return ErrUnavailable
	}
	return Use(tx, journal.gate, func() error {
		if journal.accounts[account] == nil || journal.uncertain[account] || state.Revision != 1 || len(state.Bindings)+len(state.Leases)+len(state.Holds)+len(state.Operations) != 0 || journal.valid(account, state) != nil {
			return ErrUnavailable
		}
		if err := journal.reserve(state); err != nil {
			return err
		}
		if err := journal.accounts[account].CreateService(state); err != nil {
			if errors.Is(err, ErrConflict) {
				return err
			}
			journal.uncertain[account] = true
			return ErrUnavailable
		}
		journal.settled[account] = true
		return nil
	})
}

func (journal *Journal) ReserveLocked(tx *Tx, account string, state ServiceStateV2) error {
	if journal == nil {
		return ErrUnavailable
	}
	return Use(tx, journal.gate, func() error {
		prior, err := journal.load(account)
		if err != nil {
			return err
		}
		if state.Revision != prior.Revision+1 || journal.valid(account, state) != nil {
			return ErrConflict
		}
		if _, err := retained(prior, state); err != nil {
			return err
		}
		return journal.reserve(state)
	})
}

func (journal *Journal) CommitLocked(tx *Tx, account string, expectedRevision uint64, state ServiceStateV2) error {
	if journal == nil {
		return ErrUnavailable
	}
	return Use(tx, journal.gate, func() error {
		prior, err := journal.load(account)
		if err != nil {
			return err
		}
		if prior.Revision != expectedRevision || state.Revision != expectedRevision+1 || journal.valid(account, state) != nil {
			return ErrConflict
		}
		_, err = retained(prior, state)
		if err != nil {
			return err
		}
		for _, operation := range state.Operations[len(prior.Operations):] {
			if operation.Receipt == nil {
				continue
			}
			configured := false
			for _, pin := range journal.callers {
				configured = configured || operation.Receipt.TerminalCaller == pin
			}
			if !configured {
				return ErrConflict
			}
		}
		encoded, err := wire.Encode(state)
		if err != nil || len(encoded) > MaxServiceJournalBytes {
			return ErrCapacity
		}
		if err := journal.reserve(state); err != nil {
			return err
		}
		if err := journal.accounts[account].CommitService(expectedRevision, state); err != nil {
			journal.uncertain[account] = true
			return ErrUnavailable
		}
		return nil
	})
}

func (journal *Journal) ReplayLocked(tx *Tx, account, principal, method string, id assemblyv0.OperationID, arguments []byte) (*ServiceOperationV2, error) {
	state, err := journal.LoadLocked(tx, account)
	if err != nil {
		return nil, err
	}
	object, err := wire.Parse(arguments)
	if err != nil {
		return nil, ErrConflict
	}
	canonical, err := wire.Encode(object)
	if err != nil || !bytes.Equal(arguments, canonical) {
		return nil, ErrConflict
	}
	for _, operation := range state.Operations {
		if operation.Principal == principal && operation.Method == method && operation.OperationID == id {
			if !bytes.Equal(operation.Arguments, arguments) {
				return nil, ErrConflict
			}
			return &operation, nil
		}
	}
	return nil, nil
}

var _ ServiceJournal = (*Journal)(nil)
