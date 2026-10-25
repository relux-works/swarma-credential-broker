//go:build linux

package server

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// NewQualification serves transport fixtures only. Kernel PID and UID bind
// admission to the supervised transport worker; another process with the same UID cannot use
// its private socket. The caller supplies an isolated, issuance-closed manager.
// The optional probe fault is explicitly model evidence, never foreign-UID proof.
func NewQualification(m *lease.Manager, digest string, uid uint32, pid *atomic.Int64, probeFault bool) (*Server, func() bool, error) {
	return newQualificationPeer(m, digest, uid, pid, probeFault)
}

// NewQualificationAdmission is a separate synthetic-fixture authority. It
// retains the transport identity/DAC checks and allows one request in total.
// There is no command-line or environment selector for this constructor.
func NewQualificationAdmission(m *lease.Manager, digest string, uid uint32, pid *atomic.Int64) (*Server, error) {
	if m == nil || m.Policy().MaxLeaseSeconds > 5 || len(m.Policy().Accounts) != 2 {
		return nil, wire.Refuse("lease_owner_unavailable")
	}
	s, _, err := newQualificationPeer(m, digest, uid, pid, false)
	if err != nil {
		return nil, err
	}
	var requests, calls atomic.Int64
	s.qualificationCall = func(method string) bool {
		if calls.Add(1) > 8 {
			return false
		}
		switch method {
		case "lease.request":
			return requests.Add(1) == 1
		case "lease.renew", "lease.release":
			return true
		}
		return false
	}
	return s, nil
}

func newQualificationPeer(m *lease.Manager, digest string, uid uint32, pid *atomic.Int64, probeFault bool) (*Server, func() bool, error) {
	if pid == nil || m == nil || m.Policy().ExecutableSHA256 != digest || uid != uint32(os.Geteuid()) || !m.Policy().Peer(uid) {
		return nil, nil, wire.Refuse("lease_owner_unavailable")
	}
	s := New(m)
	s.qualification = true
	var fired atomic.Bool
	s.peer = func(c *net.UnixConn) (uint32, error) {
		raw, e := c.SyscallConn()
		if e != nil {
			return 0, e
		}
		var cred *syscall.Ucred
		var probeError error
		e = raw.Control(func(fd uintptr) {
			cred, probeError = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if e != nil || probeError != nil || cred == nil || int64(cred.Pid) != pid.Load() || cred.Uid != uid {
			return 0, errors.New("qualification peer unavailable")
		}
		if probeFault {
			fired.Store(true)
			return 0, errors.New("qualification probe fault")
		}
		return cred.Uid, nil
	}
	return s, fired.Load, nil
}

func qualificationSocket(path string) bool {
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(path), os.ModeDir | 0700}, {path, os.ModeSocket | 0600}} {
		s, e := os.Lstat(item.path)
		if e != nil || s.Mode() != item.mode {
			return false
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			return false
		}
	}
	return true
}

// NewQualificationPeerAdmission keeps synthetic issuance PID-bound while letting
// the configured foreign process reach the production policy denial before I/O.
// Only this separate listener permits the exact group DAC; transport stays 0700/0600.
func NewQualificationPeerAdmission(m *lease.Manager, digest string, uid, foreign, allowedGID, foreignGID, group uint32, pid *atomic.Int64) (*Server, error) {
	if foreign == uid || foreign == uint32(os.Geteuid()) || m == nil || m.Policy().Peer(foreign) {
		return nil, wire.Refuse("lease_owner_unavailable")
	}
	s, e := NewQualificationAdmission(m, digest, uid, pid)
	if e != nil {
		return nil, e
	}
	s.qualificationDAC = func(path string) bool { return QualificationPeerSocket(path, group) }
	s.peer = func(c *net.UnixConn) (uint32, error) {
		raw, e := c.SyscallConn()
		if e != nil {
			return 0, e
		}
		var cred *syscall.Ucred
		var probe error
		e = raw.Control(func(fd uintptr) {
			cred, probe = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if e != nil || probe != nil || cred == nil || int64(cred.Pid) != pid.Load() || !(cred.Uid == uid && cred.Gid == allowedGID || cred.Uid == foreign && cred.Gid == foreignGID) {
			return 0, errors.New("qualification peer unavailable")
		}
		return cred.Uid, nil
	}
	return s, nil
}

// QualificationPeerSocket checks both entries, including ownership and exact
// group. A world permission or a missing/replaced entry never gains credit.
func QualificationPeerSocket(path string, group uint32) bool {
	for _, v := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(path), os.ModeDir | 0750}, {path, os.ModeSocket | 0660}} {
		st, e := os.Lstat(v.path)
		if e != nil || st.Mode() != v.mode {
			return false
		}
		meta, ok := st.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != uint32(os.Geteuid()) || meta.Gid != group {
			return false
		}
	}
	return true
}
