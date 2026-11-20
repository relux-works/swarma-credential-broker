//go:build linux && broker_lab

package store

import (
	"errors"
	"os"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const labIdentity = "swarma-broker-lab-store/1"
const labAccountIdentity = "swarma-broker-lab-account-store/1"

func OpenLab(path, installation string, uid uint32, initialize bool, hook Durability) (*Store, error) {
	return openFamily(path, installation, uid, initialize, hook, labIdentity, labAccountIdentity)
}

func (a *Account) LabInstallation() (string, error) {
	if a == nil || a.parent == nil || a.parent.identityKind != labIdentity || a.parent.accountKind != labAccountIdentity || a.Healthy() != nil {
		return "", ErrUnavailable
	}
	return a.installation, nil
}

func (a *Account) AppendLabRecord(raw []byte) error {
	if _, err := a.LabInstallation(); err != nil {
		return ErrUnavailable
	}
	object, err := wire.Parse(raw)
	if err != nil {
		return ErrUnavailable
	}
	format, _ := object["format"].(string)
	name := ""
	switch format {
	case "swarma-broker-lab-account/1":
		name = "owner-lab-account.json"
	case "swarma-broker-lab-custody/1":
		name = "owner-lab-custody.json"
	default:
		return ErrUnavailable
	}
	if _, err := labcontract.Read(format, raw); err != nil {
		return ErrUnavailable
	}
	context := object["context"].(map[string]any)
	if context["installation_id"] != a.installation {
		return ErrConflict
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Healthy() != nil {
		return ErrUnavailable
	}
	previous, err := read(a.root, name, a.uid)
	clear(previous)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	return replaceEncoded(a.root, name, raw, a.hook)
}
