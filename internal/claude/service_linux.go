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
	if err != nil || m.Status.State != "enrolled" {
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
	if err != nil || m.Status.State != "enrolled" || ctx.Err() != nil || !now().Before(until) || m.Status.TokenExpiresAt != nil && (!now().Before(*m.Status.TokenExpiresAt) || until.After(*m.Status.TokenExpiresAt)) {
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

// LiftHold is a broker-internal primitive: only the service controller's
// authenticated account-owner entry may call it. SPEC-PENDING owner act format,
// content confirmation and recovery rules. It never revives an old lease.
func (a *Account) LiftHold() error {
	if a == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	if err != nil || m.Revision >= 9007199254740990 {
		return ErrUnavailable
	}
	prior := m.Revision
	m.Revision++
	m.Status.State = "enrolled"
	if a.store.Put(metadataName, prior, m) != nil {
		a.failed = true
		return ErrUnavailable
	}
	return nil
}

const bindingName = "owner-claude-service.json"

// SPEC-PENDING: local binding/tombstone record schema. The store's protected
// CAS and directory durability rules apply; a missing initial binding is closed.
func (a *Account) LoadServiceBinding() (wire.ServiceBindingState, error) {
	var s wire.ServiceBindingState
	if a == nil {
		return s, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return s, ErrUnavailable
	}
	b, err := a.store.Read(bindingName)
	defer clear(b)
	if errors.Is(err, store.ErrNotFound) {
		return s, nil
	}
	if err != nil || wire.Decode(b, &s) != nil || s.Kind != "claude-service-binding/1" || s.Installation != a.installation || s.Binding.Account != a.label || s.Revision == 0 {
		return wire.ServiceBindingState{}, ErrUnavailable
	}
	return s, nil
}

func (a *Account) StoreServiceBinding(s wire.ServiceBindingState) error {
	if a == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || s.Binding.Account != a.label || s.Revision == 0 || s.Revision > 9007199254740990 {
		return ErrUnavailable
	}
	s.Kind, s.Installation = "claude-service-binding/1", a.installation
	if a.store.Put(bindingName, s.Revision-1, s) != nil {
		a.failed = true
		return ErrUnavailable
	}
	return nil
}
