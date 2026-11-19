package statev0

import (
	"context"
	"errors"
	"sync"
)

var ErrTransaction = errors.New("inactive or foreign state transaction")

type SerialGate struct {
	ready chan struct{}
}

type transactionScope struct {
	mu     sync.Mutex
	gate   *SerialGate
	token  *Tx
	ctx    context.Context
	active bool
}

func NewGate() *SerialGate {
	gate := &SerialGate{ready: make(chan struct{}, 1)}
	gate.ready <- struct{}{}
	return gate
}

func (gate *SerialGate) With(ctx context.Context, callback func(*Tx) error) error {
	if gate == nil || gate.ready == nil || ctx == nil || callback == nil {
		return ErrTransaction
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate.ready:
	}
	scope := &transactionScope{gate: gate, ctx: ctx, active: true}
	token := &Tx{scope: scope}
	scope.token = token
	defer func() {
		scope.mu.Lock()
		scope.active = false
		scope.mu.Unlock()
		gate.ready <- struct{}{}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := callback(token)
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func Use(tx *Tx, gate Gate, callback func() error) error {
	if tx == nil || tx.scope == nil || callback == nil {
		return ErrTransaction
	}
	scope := tx.scope
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.active || scope.token != tx || gate != scope.gate {
		return ErrTransaction
	}
	if err := scope.ctx.Err(); err != nil {
		return err
	}
	err := callback()
	if err == nil {
		err = scope.ctx.Err()
	}
	return err
}

func Check(tx *Tx, gate Gate) error {
	return Use(tx, gate, func() error { return nil })
}
