//go:build linux

package claude

import (
	"context"
	"errors"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// ExpiresAt checks account admission metadata without opening material.
func (a *Account) ExpiresAt() (*time.Time, error) {
	if a == nil {
		return nil, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	held, holdErr := a.serviceHeld()
	if held || holdErr != nil || err != nil || m.Status.State != "enrolled" {
		return nil, ErrUnavailable
	}
	return cloneTime(m.Status.TokenExpiresAt), nil
}

// Publish is the only gateway-material path. It keeps account hold exclusion
// through delivery and clears owned buffers. No material reaches a returned
// error, metadata, environment, argv or log. Its trusted caller must hold the
// current service/caller authority gate, and bound the transport's write.
func (a *Account) Publish(ctx context.Context, until time.Time, now func() time.Time, deliver func([]byte) error) error {
	if a == nil || now == nil || deliver == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	held, holdErr := a.serviceHeld()
	if held || holdErr != nil || err != nil || m.Status.State != "enrolled" || ctx.Err() != nil || !now().Before(until) || m.Status.TokenExpiresAt != nil && (!now().Before(*m.Status.TokenExpiresAt) || until.After(*m.Status.TokenExpiresAt)) {
		return ErrUnavailable
	}
	b, err := a.store.Read(materialName)
	defer clear(b)
	if err != nil {
		return ErrUnavailable
	}
	var token material
	if wire.Decode(b, &token) != nil {
		clear(token.Token)
		return ErrUnavailable
	}
	defer clear(token.Token)
	if token.Kind != "claude-material-record/1" || token.Installation != a.installation || token.Revision != 1 || len(token.Token) == 0 || len(token.Token) > 4096 {
		return ErrUnavailable
	}
	for _, c := range token.Token {
		if c < 0x21 || c > 0x7e {
			return ErrUnavailable
		}
	}
	if ctx.Err() != nil || !now().Before(until) {
		return ErrUnavailable
	}
	if deliver(token.Token) != nil {
		return ErrUnavailable
	}
	return nil
}

// Service state is a protected, atomic transaction containing the closed v0
// records and replay journal. It never contains material or a placeholder.
const serviceStateName = "owner-claude-service.json"

func (a *Account) loadServiceState() (wire.ServiceState, error) {
	var s wire.ServiceState
	b, err := a.store.Read(serviceStateName)
	defer clear(b)
	if errors.Is(err, store.ErrNotFound) {
		return s, nil
	}
	if err != nil || wire.Decode(b, &s) != nil || s.Kind != "claude-service-journal/1" || s.Installation != a.installation || s.Revision == 0 {
		return wire.ServiceState{}, ErrUnavailable
	}
	return s, nil
}
func (a *Account) LoadServiceState() (wire.ServiceState, error) {
	if a == nil {
		return wire.ServiceState{}, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return wire.ServiceState{}, ErrUnavailable
	}
	return a.loadServiceState()
}
func (a *Account) StoreServiceState(s wire.ServiceState) error {
	if a == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || s.Revision == 0 || s.Revision > 9007199254740990 {
		return ErrUnavailable
	}
	s.Kind, s.Installation = "claude-service-journal/1", a.installation
	if a.store.Put(serviceStateName, s.Revision-1, s) != nil {
		// Only the service journal is uncertain. The controller fences material
		// until a protected read and a new durable CAS reconcile this transaction.
		return ErrUnavailable
	}
	return nil
}
func (a *Account) serviceHeld() (bool, error) {
	s, err := a.loadServiceState()
	if err != nil {
		return false, err
	}
	for _, h := range s.Holds {
		if h.State == "active" {
			return true, nil
		}
	}
	return false, nil
}

// ServiceAccount reads account facts independently of material and hold state.
// The service controller owns the typed account-state refusal and hold ordering.
func (a *Account) ServiceAccount() (wire.ServiceAccount, error) {
	if a == nil {
		return wire.ServiceAccount{}, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	if err != nil {
		return wire.ServiceAccount{}, err
	}
	state := "active"
	if m.Status.State != "enrolled" {
		state = "owner_unavailable"
	}
	return wire.ServiceAccount{Account: m.Status.Account, Harness: m.Status.Harness, Kind: m.Status.Kind, State: state, ExpiresAt: cloneTime(m.Status.TokenExpiresAt)}, nil
}
