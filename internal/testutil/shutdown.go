package testutil

// StopServer joins the accept loop before waiting for its handlers. Serve must
// close serveDone after its last possible handler Add, including on failure.
func StopServer(stop func(), serveDone <-chan struct{}, waitHandlers func()) {
	stop()
	<-serveDone
	waitHandlers()
}
