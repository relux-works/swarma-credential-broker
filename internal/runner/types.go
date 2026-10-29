// Package runner implements the external-token, one-turn Codex executor.
// Linux integration uses protected static policy and the broker/1 wire codec.
package runner

import (
	"context"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"time"
)

const Version = "0.1.0"
const ProtocolProfile = "codex-refresher-v0"

// BrokerClient owns a fresh connection. VerifyServer must authenticate the
// kernel peer before any protocol bytes. Every method must honor cancellation;
// Close must unblock outstanding calls. No descriptor may be inherited by exec.
// Release is idempotent, including retry after an uncertain acknowledgement.
type BrokerClient interface {
	VerifyServer(context.Context, uint32) error
	Hello(context.Context, HelloRequest) (HelloResult, error)
	Request(context.Context, LeaseRequest) (Lease, error)
	Renew(context.Context, RenewRequest) (Lease, error)
	Release(context.Context, string) error
	Close() error
}

type HelloRequest struct {
	Versions []int
	Profile  string
}
type HelloResult struct {
	Version          int
	Profile          string
	UID              uint32
	PolicyGeneration uint64
}
type Binding = wire.Binding
type LeaseRequest struct {
	Harness, Profile, Account, Channel, LaunchID string
	CredentialBinding                            Binding
	Network                                      any
	Executor                                     Executor
}
type Executor struct {
	Capabilities []string
	Version      string
}
type RenewRequest struct{ LeaseID, RejectedSHA256 string }

// Token ownership transfers to the caller; its bytes are cleared on all paths.
// The wire adapter must not retain copies or expose material in errors.
type Lease struct {
	ID, Account, Harness, Channel, ChatGPTAccountID, PlanType string
	Token                                                     []byte
	TokenExpiresAt, AuthorizedUntil                           time.Time
	Renewable                                                 bool
}

func (l *Lease) erase() { clear(l.Token); l.Token = nil; l.PlanType = ""; l.ChatGPTAccountID = "" }

// Erase clears the caller-owned token bytes and drops material-bearing metadata.
// It cannot erase strings/copies made by the embedding program or the Go runtime.
func (l *Lease) Erase() { l.erase() }

// Policy is supplied only by a protected authority, never CLI or environment.
// Qualified means the full exact-release qualification/1 record was verified,
// including platform, schema, runner, containment and configuration identities.
// No shipped production release is marked qualified by this package.
type Policy struct {
	Account, Profile, Endpoint, Executable, ExecutableSHA256, Release, SchemaSHA256, ChatGPTAccountID string
	ConfigSHA256, BindingDigest                                                                       string
	UID, BrokerUID                                                                                    uint32
	PolicyGeneration                                                                                  uint64
	Qualified                                                                                         bool
	Catalog                                                                                           map[string][]string
}

// Authority must re-read protected policy and qualification evidence on each
// Resolve. The Linux integration reads protected published evidence and keeps
// production qualification closed while required current observers are unavailable.
type Authority interface {
	Resolve(context.Context, Options) (Policy, error)
}
type Dependencies struct {
	Authority   Authority
	Connect     func(context.Context) (BrokerClient, error)
	Environment []string
	// Supervisor is the embedding executable, which must dispatch SupervisorMain
	// before parsing ordinary commands. It never receives token material in argv.
	Supervisor string
}
type IO struct {
	In       io.Reader
	Out, Err io.Writer
}
type Refusal struct {
	Code   string
	Status int
}

func (e *Refusal) Error() string           { return e.Code }
func refuse(code string, status int) error { return &Refusal{code, status} }
func report(w io.Writer, code string)      { fmt.Fprintf(w, "runner: %s\n", code) }
