package lease

import (
	"context"
	"sync"
)

// stateMutex permits request admission to abandon lock contention at its original
// deadline. Background state transitions use Lock and never hold it over sockets.
type stateMutex struct {
	once sync.Once
	gate chan struct{}
}

func (m *stateMutex) init() {
	m.once.Do(func() { m.gate = make(chan struct{}, 1); m.gate <- struct{}{} })
}
func (m *stateMutex) Lock()   { m.init(); <-m.gate }
func (m *stateMutex) Unlock() { m.gate <- struct{}{} }
func (m *stateMutex) LockContext(ctx context.Context) error {
	m.init()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.gate:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	}
}
