//go:build linux

// Package claude provides broker-side custody primitives for the inactive
// secret-free service controller. It supplies no live enrollment command.
package claude

import (
	"errors"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const Kind = "claude-oauth-token"
const Mode = "secret-free"
const metadataName = "owner-claude-account.json"
const materialName = "owner-claude-material.json"

var ErrInvalid = errors.New("claude enrollment invalid")
var ErrExists = errors.New("claude account already recorded")
var ErrUnavailable = errors.New("claude account unavailable")

// Status contains metadata only. An enrollment record is not lease admission,
// gateway readiness, release qualification or evidence of vendor validity.
type Status struct {
	Account        string     `json:"account"`
	Harness        string     `json:"harness"`
	Kind           string     `json:"credential_kind"`
	Mode           string     `json:"mode"`
	State          string     `json:"state"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	Refreshable    bool       `json:"refreshable"`
}

type metadata struct {
	Kind         string `json:"kind"`
	Installation string `json:"installation_id"`
	Revision     uint64 `json:"revision"`
	Status       Status `json:"status"`
}

type material struct {
	Kind         string `json:"kind"`
	Installation string `json:"installation_id"`
	Revision     uint64 `json:"revision"`
	Token        []byte `json:"token"`
}

// Account is confined to a dedicated broker-owned store account. Construction
// is not authority: a future operator entry must authenticate enrollment, and a
// future narrowly authenticated detector entry must bind Hold to this account.
type Account struct {
	mu           sync.Mutex
	store        *store.Account
	installation string
	label        string
	failed       bool
}

func NewAccount(s *store.Account, installation, label string) (*Account, error) {
	if s == nil || !identifier(installation, false) || !identifier(label, true) || s.Healthy() != nil {
		return nil, ErrInvalid
	}
	return &Account{store: s, installation: installation, label: label}, nil
}

func identifier(s string, slash bool) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || slash && c == '/') {
			return false
		}
	}
	return true
}

// Enroll records a fresh, person-supplied setup-token in broker custody only.
// There is no refresh, native-login import, home path or environment channel.
// Expiry is optional vendor evidence, never enrollment time plus a guessed TTL.
// Caller retains its input; this method clears its owned material copy.
func (a *Account) Enroll(token []byte, expiresAt *time.Time) error {
	if a == nil {
		return ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return ErrUnavailable
	}
	if len(token) == 0 || len(token) > 4096 || !validExpiry(expiresAt) {
		return ErrInvalid
	}
	for _, c := range token {
		if c < 0x21 || c > 0x7e {
			return ErrInvalid
		}
	}
	// Refuse existing/unknown metadata before any material write. An orphaned
	// immutable material record cannot be adopted or overwritten by a retry.
	b, err := a.store.Read(metadataName)
	clear(b)
	if err == nil {
		return ErrExists
	}
	if !errors.Is(err, store.ErrNotFound) {
		return ErrUnavailable
	}
	m := material{"claude-material-record/1", a.installation, 1, append([]byte(nil), token...)}
	defer clear(m.Token)
	if err = a.store.Append(materialName, m); err != nil {
		a.failed = true
		return ErrUnavailable
	}
	s := Status{Account: a.label, Harness: "claude_code", Kind: Kind, Mode: Mode, State: "enrolled", TokenExpiresAt: cloneTime(expiresAt), Refreshable: false}
	if err = a.store.Put(metadataName, 0, metadata{"claude-account-record/1", a.installation, 1, s}); err != nil {
		a.failed = true
		return ErrUnavailable
	}
	return nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func validExpiry(t *time.Time) bool {
	return t == nil || !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Location() == time.UTC && t.Nanosecond() == 0
}

func (a *Account) readMetadata() (metadata, error) {
	var m metadata
	if a.failed {
		return m, ErrUnavailable
	}
	b, err := a.store.Read(metadataName)
	defer clear(b)
	if err != nil || wire.Decode(b, &m) != nil || m.Kind != "claude-account-record/1" || m.Installation != a.installation || m.Revision == 0 || m.Revision >= 9007199254740991 || m.Status.Account != a.label || m.Status.Harness != "claude_code" || m.Status.Kind != Kind || m.Status.Mode != Mode || m.Status.Refreshable || !validExpiry(m.Status.TokenExpiresAt) || (m.Status.State != "enrolled" && m.Status.State != "held") {
		return metadata{}, ErrUnavailable
	}
	return m, nil
}

// Status reads only the metadata record, never the token record or its digest.
func (a *Account) Status() (Status, error) {
	if a == nil {
		return Status{}, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := a.readMetadata()
	if err != nil {
		return Status{}, err
	}
	return m.Status, nil
}
