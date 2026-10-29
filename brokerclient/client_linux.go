//go:build linux

// Package brokerclient exposes the finite peer-authenticated v0 client contract.
// Observer metadata is not a lease, launch permit or mutable revocation verdict.
package brokerclient

import (
	"context"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const ProtocolProfile = runner.ProtocolProfile
const ObserverDeadline = 2 * time.Second

type Binding = runner.Binding
type HelloRequest = runner.HelloRequest
type HelloResult = runner.HelloResult
type LeaseRequest = runner.LeaseRequest
type Executor = runner.Executor
type RenewRequest = runner.RenewRequest
type Lease = runner.Lease
type Refusal = runner.Refusal
type Worker = runner.BrokerClient
type AllowlistRequest = wire.AllowlistRequest
type AllowlistResult = wire.AllowlistResult

// DialWorker preserves the existing explicit VerifyServer -> Hello -> lease flow.
// It does not send protocol bytes or authorize an unverified connection.
func DialWorker(ctx context.Context, path string) (Worker, error) {
	ctx, cancel := context.WithTimeout(ctx, ObserverDeadline)
	defer cancel()
	return runner.DialBroker(ctx, path)
}

// Observer deliberately has no acquisition, renewal, release or raw-call method.
type Observer struct{ client *runner.SocketClient }

// DialObserver verifies SO_PEERCRED before any protocol bytes and negotiates v1.
// Dial, identity verification and hello share one two-second overall deadline.
func DialObserver(parent context.Context, path string, expectedBrokerUID uint32) (*Observer, error) {
	ctx, cancel := context.WithTimeout(parent, ObserverDeadline)
	defer cancel()
	c, err := runner.DialBroker(ctx, path)
	if err != nil {
		return nil, err
	}
	if err = c.VerifyServer(ctx, expectedBrokerUID); err == nil {
		_, err = c.Hello(ctx, HelloRequest{Versions: []int{1}, Profile: ProtocolProfile})
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return &Observer{client: c}, nil
}

func (o *Observer) Check(ctx context.Context, r AllowlistRequest) (AllowlistResult, error) {
	if o == nil || o.client == nil {
		return AllowlistResult{}, &Refusal{Code: "allowlist_unavailable", Status: 69}
	}
	return o.client.CheckAllowlist(ctx, r)
}
func (o *Observer) Close() error {
	if o == nil || o.client == nil {
		return nil
	}
	return o.client.Close()
}
