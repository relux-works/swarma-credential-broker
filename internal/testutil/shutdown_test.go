package testutil

import (
	"sync"
	"testing"
	"testing/synctest"
)

// Claim: handler Wait cannot enter while Serve can still make its last Add;
// once Serve completes, shutdown joins that handler exactly once.
func TestStopServerJoinsBeforeHandlerWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stopping, release := make(chan struct{}), make(chan struct{})
		serveDone, shutdownDone := make(chan struct{}), make(chan struct{})
		entered := make(chan struct{}, 2)
		var handlers sync.WaitGroup
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		go func() {
			defer close(serveDone)
			<-stopping
			<-release // Serve still owns the last possible Add.
			handlers.Add(1)
			handlers.Done()
		}()
		go func() {
			defer close(shutdownDone)
			StopServer(func() { close(stopping) }, serveDone, func() {
				entered <- struct{}{}
				handlers.Wait()
			})
		}()
		defer func() { unblock(); <-shutdownDone }()
		synctest.Wait()
		select {
		case <-entered:
			t.Fatal("handler Wait entered before Serve completed")
		default:
		}
		unblock()
		<-shutdownDone
		if len(entered) != 1 {
			t.Fatal("completed Serve did not enter handler Wait exactly once")
		}
	})
}
