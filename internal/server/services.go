package server

import (
	"context"
	"net"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// serveServices uses the existing listener and broker framing. The fixed role
// comes from the kernel UID's current managed record. No caller role field,
// second socket, placeholder, or service UID constant is accepted.
func (s *Server) serveServices(ctx context.Context, c *net.UnixConn, uid uint32, first wire.Request, hello wire.Hello, firstDeadline time.Time) {
	// Calls use the baseline method-class deadlines (dialect section 2.1).
	// Administrative writes remain bounded to two seconds.
	send := func(ctx context.Context, id string, result any, err error, until time.Time) error {
		r := map[string]any{"request_id": id}
		if err != nil {
			r["error"] = wire.Refuse(lease.ErrorCode(err))
		} else {
			r["result"] = result
		}
		return writeFrame(ctx, c, r, until)
	}
	if len(hello.Versions) != 1 || hello.Versions[0] != 1 {
		_ = send(ctx, first.ID, nil, wire.Refuse("version_unsupported"), firstDeadline)
		return
	}
	open, cancel := context.WithDeadline(ctx, firstDeadline)
	principal, err := s.Services.Open(open, uid)
	cancel()
	if err != nil {
		_ = send(ctx, first.ID, nil, err, firstDeadline)
		return
	}
	cleanup, err := s.Services.RegisterConnection(ctx, principal, func() { _ = c.Close() })
	if err != nil {
		return
	}
	defer cleanup()
	result := map[string]any{"version": 1, "principal": principal}
	// Existing internal profile clients retain their selector response. The
	// standard broker/1 exchange adds no profile member to its baseline hello.
	if hello.Profile != "" {
		result["profile"] = wire.ServiceProfile
	}
	if send(ctx, first.ID, result, nil, firstDeadline) != nil {
		return
	}
	for {
		raw, arrival, err := read(c, true, time.Now().Add(30*time.Second))
		if err != nil {
			return
		}
		var r wire.Request
		if wire.Decode(raw, &r) != nil || !wire.ASCII(r.ID, 64) {
			return
		}
		budget := 2 * time.Second
		switch r.Method {
		case "service.lease.request":
			budget = 30 * time.Second
		case "service.lease.renew":
			budget = 8 * time.Second
		}
		until := arrival.Add(budget)
		call, cancel := context.WithDeadline(ctx, until)
		wrote := false
		err = s.Services.Call(call, principal, r.Method, r.Params, func(result any) error {
			wrote = true
			writeUntil := until
			if material, ok := result.(wire.ServiceLease); ok {
				bound, err := time.Parse(time.RFC3339Nano, material.AuthorizedUntil)
				if err != nil || !time.Now().Before(bound) {
					return wire.Refuse("lease_not_active")
				}
				if bound.Before(writeUntil) {
					writeUntil = bound
				}
			}
			return send(call, r.ID, result, nil, writeUntil)
		})
		cancel()
		if err != nil {
			// Never append an error after an uncertain material frame.
			if wrote {
				return
			}
			if send(ctx, r.ID, nil, err, time.Now().Add(2*time.Second)) != nil {
				return
			}
			if lease.ErrorCode(err) == "role_not_permitted" {
				return
			}
		}
	}
}
