//go:build linux

package qualify

import (
	"context"
	"net"
	"os"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/server"
)

type rowOrigin struct {
	origin *egress.CaseOrigin
	bind   func() error
}

func originCheck(origins []*rowOrigin) []func(int) bool {
	if len(origins) == 1 {
		return []func(int) bool{origins[0].origin.Live}
	}
	return nil
}

// The pathname may be selected early, but no listening socket object exists
// until the verified exec callback. Close also handles a case that never execs.
func prepareRowListener(ctx context.Context, srv *server.Server, path string, mode os.FileMode, origins ...*rowOrigin) (func() error, error) {
	serveCtx, cancel := context.WithCancel(ctx)
	var l *net.UnixListener
	var done chan error
	bind := func() error {
		var e error
		l, e = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			return e
		}
		l.SetUnlinkOnClose(false)
		if e = os.Chmod(path, mode); e != nil {
			l.Close()
			os.Remove(path)
			l = nil
			return e
		}
		done = make(chan error, 1)
		go func() { done <- srv.Serve(serveCtx, l) }()
		return nil
	}
	closeListener := func() error {
		cancel()
		var e error
		if l != nil {
			l.Close()
			e = <-done
		}
		srv.Close()
		srv.Wait()
		return e
	}
	if len(origins) == 1 {
		origins[0].bind = bind
	} else if e := bind(); e != nil {
		closeListener()
		return nil, e
	}
	return closeListener, nil
}
