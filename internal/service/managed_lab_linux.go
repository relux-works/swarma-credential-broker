//go:build linux && broker_lab

package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type LabManagedPins struct {
	Gateway         wire.ServiceBinding
	Worker          wire.ServiceCaller
	ManagerSequence int64
	ManagerHash     string
}

type LabManagedAuthority struct {
	managed *ManagedAuthority
	pins    LabManagedPins
}

func NewLabManagedAuthority(root string, facts Authority, pins LabManagedPins) (*LabManagedAuthority, error) {
	if facts == nil || !validBindingForKind(pins.Gateway, LabKind) || !validCaller(pins.Worker) || pins.Gateway.Account != pins.Worker.Account || pins.Gateway.UID == 0 || pins.Worker.UID == 0 || pins.Gateway.UID == pins.Worker.UID || pins.ManagerSequence < 1 || !managedHex(pins.ManagerHash, 64) {
		return nil, managedRefusal()
	}
	managed, err := NewManagedAuthority(root, facts)
	if err != nil {
		return nil, err
	}
	return &LabManagedAuthority{managed: managed, pins: pins}, nil
}

func (authority *LabManagedAuthority) WithIdentity(ctx context.Context, callback func(View) error) error {
	return authority.withManaged(ctx, false, callback)
}

func (authority *LabManagedAuthority) WithCurrent(ctx context.Context, callback func(View) error) error {
	return authority.withManaged(ctx, true, callback)
}

func (authority *LabManagedAuthority) withManaged(ctx context.Context, current bool, callback func(View) error) error {
	if authority == nil || callback == nil {
		return managedRefusal()
	}
	return authority.managed.withManaged(ctx, current, func(base View) error {
		view, ok := base.(*managedView)
		if !ok || view.journal.Tail.Seq != authority.pins.ManagerSequence || view.journal.Tail.Hash != authority.pins.ManagerHash {
			return managedRefusal()
		}
		return callback(&labManagedView{managedView: view, pins: authority.pins})
	})
}

type labManagedView struct {
	*managedView
	pins LabManagedPins
}

func (view *labManagedView) Principal(uid uint32) (Principal, error) {
	if !view.live() {
		return Principal{}, managedRefusal()
	}
	if uid == 0 {
		return Principal{UID: 0, Generation: "lab-root", Role: "operator"}, nil
	}
	if uid != view.pins.Gateway.UID {
		return Principal{}, refuse("role_not_permitted")
	}
	principal, err := view.managedView.Principal(uid)
	if err != nil || principal.Generation != view.pins.Gateway.Generation || principal.Service != view.pins.Gateway.Service {
		return Principal{}, managedRefusal()
	}
	return principal, nil
}

func (view *labManagedView) Service(binding wire.ServiceBinding) error {
	if !view.live() || binding != view.pins.Gateway {
		return refuse("service_binding_mismatch")
	}
	if _, err := view.Principal(binding.UID); err != nil {
		return err
	}
	return view.managedView.Service(binding)
}

func (view *labManagedView) Caller(binding wire.ServiceBinding, caller wire.ServiceCaller) (time.Time, string, error) {
	account, exists := view.accounts[caller.UID]
	if !view.live() || !exists || caller != view.pins.Worker || binding != view.pins.Gateway || account.Kind != "agent" || account.Class != "trusted" || account.Placement != "local" || account.State != "active" || account.Generation != caller.Generation || view.journal.Active(int64(caller.UID), caller.Generation) != nil {
		return time.Time{}, "", managedRefusal()
	}
	return view.managedView.Caller(binding, caller)
}

func (view *labManagedView) OperatorAct(principal Principal, method string, arguments json.RawMessage) bool {
	return view.live() && principal == (Principal{UID: 0, Generation: "lab-root", Role: "operator"}) && view.managedView.OperatorAct(principal, method, arguments)
}
