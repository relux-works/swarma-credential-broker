//go:build linux && broker_lab

package service

import (
	"time"
)

const LabKind = "anthropic-api-key-lab/1"

func NewLabWithLifetime(authority Authority, accounts map[string]Account, trustedNow func() time.Time, lifetime time.Duration) (*Broker, error) {
	if trustedNow == nil {
		return nil, refuse("lease_owner_unavailable")
	}
	broker, err := newWithKind(authority, accounts, trustedNow, lifetime, LabKind, true)
	if err == nil {
		broker.strictReplay = true
	}
	return broker, err
}
