//go:build linux

package server

import (
	"encoding/binary"
	"net"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// requestFrameWriter commits frame completion and ID retirement together. A
// normal UnixConn.Write may return after the peer has consumed the whole frame.
// RawConn.Write lets the registry lock cover the nonblocking syscall and retire
// the ID before another admission can inspect it, without covering readiness
// polling. The surrounding writer gate still protects publication/interrupt
// cleanup and prevents a second response from sharing this frame.
type requestFrameWriter struct {
	*net.UnixConn
	raw       syscall.RawConn
	calls     *connectionCalls
	call      *connectionCall
	started   bool
	remaining int
}

func newRequestFrameWriter(conn *net.UnixConn, calls *connectionCalls, call *connectionCall) (*requestFrameWriter, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &requestFrameWriter{UnixConn: conn, raw: raw, calls: calls, call: call}, nil
}

func (w *requestFrameWriter) Write(p []byte) (int, error) {
	if !w.started {
		// wire.Write emits the four-byte header before the encoded payload.
		if len(p) != 4 {
			return 0, wire.ErrMalformed
		}
		w.started = true
		w.remaining = 4 + int(binary.BigEndian.Uint32(p))
	}
	var n int
	var writeErr error
	err := w.raw.Write(func(fd uintptr) bool {
		for {
			w.calls.mu.Lock()
			n, writeErr = syscall.Write(int(fd), p)
			if n > 0 {
				w.remaining -= n
				if w.remaining == 0 && writeErr == nil {
					w.calls.retireLocked(w.call)
				}
			}
			w.calls.mu.Unlock()
			if writeErr == syscall.EINTR {
				continue
			}
			return writeErr != syscall.EAGAIN && writeErr != syscall.EWOULDBLOCK
		}
	})
	if n < 0 {
		n = 0
	}
	if err != nil {
		return n, err
	}
	return n, writeErr
}
