//go:build linux

package server

import (
	"net"
	"sync/atomic"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// RunnerAdmissionCounts counts accepted peers and parsed post-hello methods.
type RunnerAdmissionCounts struct{ connections, requests, releases, other atomic.Int64 }

func (c *RunnerAdmissionCounts) Counts() (int64, int64, int64, int64) {
	return c.connections.Load(), c.requests.Load(), c.releases.Load(), c.other.Load()
}

// NewQualificationRunnerAdmission keeps the existing single-lease budget and
// requires a live exec-verified origin. Only isolated synthetic runners use it.
func NewQualificationRunnerAdmission(m *lease.Manager, digest string, uid uint32, pid *atomic.Int64, live func(int) bool) (*Server, *RunnerAdmissionCounts, error) {
	if live == nil {
		return nil, nil, wire.Refuse("lease_owner_unavailable")
	}
	s, e := NewQualificationAdmission(m, digest, uid, pid, live)
	if e != nil {
		return nil, nil, e
	}
	c := &RunnerAdmissionCounts{}
	peer, call := s.peer, s.qualificationCall
	s.peer = func(conn *net.UnixConn) (uint32, error) { c.connections.Add(1); return peer(conn) }
	s.qualificationCall = func(method string) bool {
		switch method {
		case "lease.request":
			c.requests.Add(1)
		case "lease.release":
			c.releases.Add(1)
		default:
			c.other.Add(1)
		}
		return call(method)
	}
	return s, c, nil
}
