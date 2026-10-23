//go:build linux

package server

import (
	"net"
	"syscall"
)

// PeerUID obtains identity from the accepted socket, never request data.
func PeerUID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var observed error
	e = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			observed = err
			return
		}
		uid = cred.Uid
	})
	if e != nil {
		return 0, e
	}
	return uid, observed
}
