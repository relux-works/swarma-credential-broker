package server

import (
	"context"
	"sync"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// A distinct identity prevents an exiting handler from retiring a successor
// that has already reused its request ID.
type connectionCall struct{ id string }

type connectionCalls struct {
	mu      sync.Mutex
	pending map[string]*connectionCall
	writer  chan struct{}
}

func newConnectionCalls() *connectionCalls {
	c := &connectionCalls{pending: make(map[string]*connectionCall), writer: make(chan struct{}, 1)}
	c.writer <- struct{}{}
	return c
}

func (c *connectionCalls) acquireWriter(ctx context.Context) error {
	// An immediately available writer can still emit a typed deadline refusal.
	select {
	case <-c.writer:
		return nil
	default:
	}
	select {
	case <-c.writer:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *connectionCalls) reserve(ctx context.Context, id string) (*connectionCall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending[id] != nil || len(c.pending) >= 128 {
		return nil, wire.ErrMalformed
	}
	call := &connectionCall{id: id}
	c.pending[id] = call
	return call, nil
}

func (c *connectionCalls) retire(call *connectionCall) {
	c.mu.Lock()
	c.retireLocked(call)
	c.mu.Unlock()
}

func (c *connectionCalls) retireLocked(call *connectionCall) {
	if call != nil && c.pending[call.id] == call {
		delete(c.pending, call.id)
	}
}

func (c *connectionCalls) respond(ctx context.Context, write func() error) error {
	if err := c.acquireWriter(ctx); err != nil {
		return err
	}
	defer func() { c.writer <- struct{}{} }()
	return write()
}
