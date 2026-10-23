// Package authowner implements contained managed-auth refresh and durable recovery.
// Protected enrolment and qualification supply the initial checkpoint; this
// package never adopts an existing login or publishes a qualification itself.
package authowner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/store"
)

var ErrUnavailable = errors.New("lease_owner_unavailable")
var ErrRenewFailed = owner.ErrRenewFailed

type Identity struct {
	Boot  string `json:"boot_id"`
	UID   uint32 `json:"manager_uid"`
	Epoch string `json:"manager_epoch"`
}
type UnitSpec struct {
	Name, Daemon, Executable, Home string
	ExecutableSHA256               string
	Args, Environment              []string
	Runtime                        time.Duration
	Input, Output                  *os.File
}

// Observation is complete only when every manager/property/cgroup read succeeds.
// PID fields are diagnostic, never an absence certificate.
type Observation struct {
	Identity      Identity  `json:"manager"`
	Unit          string    `json:"unit_name"`
	Invocation    string    `json:"invocation_id"`
	Cgroup        string    `json:"cgroup_path"`
	CgroupID      string    `json:"cgroup_identity"`
	MainPID       uint32    `json:"main_pid"`
	ProcessStart  uint64    `json:"process_start"`
	Properties    string    `json:"verified_property_digest"`
	Active        string    `json:"active_state"`
	Substate      string    `json:"substate"`
	Result        string    `json:"result"`
	ExitStatus    int32     `json:"exit_status"`
	Complete      bool      `json:"complete_read"`
	RestartNo     bool      `json:"restart_no"`
	Empty         bool      `json:"subtree_empty"`
	PopulatedZero bool      `json:"populated_zero"`
	CgroupRemoved bool      `json:"cgroup_removed_after_stop"`
	StopCompleted bool      `json:"stop_completed"`
	Observed      time.Time `json:"observed_at"`
}

type Manager interface {
	Ready(context.Context) error
	Owned(context.Context) error
	Identity(context.Context) (Identity, error)
	Start(context.Context, UnitSpec) error
	Observe(context.Context, string) (Observation, error)
	Stop(context.Context, string, Observation) (Observation, error)
	Unload(context.Context, string) error
}

// Confidence is independent, operator-controlled time and restore evidence.
// The implementation must not derive Fresh from these same local checkpoints.
// Validate supplies evidence to the shared time rule at every admission and
// again before post-vendor or recovered resolution publication.
type Confidence interface {
	Validate(context.Context, string, string, uint64, time.Time) (TimeEvidence, error)
}
type TimeEvidence struct {
	Now, AuthorityUntil time.Time
	Trusted, Fresh      bool
}
type Config struct {
	Installation, DaemonInstance, DaemonUnit, WriterPrefix string
	PolicyGeneration                                       uint64
	Executable, ExecutableSHA256, QualificationID          string
	Runtime, ProactiveWindow                               time.Duration
	MaxAttempts                                            int
	Accounts                                               []AccountConfig
}
type AccountConfig struct {
	Label, VendorID, Home, HomeID string
	Disk                          *store.Account
}
type Disposition string

const (
	Unknown   Disposition = "unknown"
	Committed Disposition = "committed"
	Safe      Disposition = "safe_no_rotation"
	Rejected  Disposition = "reauth_required"
)

// Classifier is supplied by exact-release qualification, never by an RPC peer.
// The default classifier treats every vendor error as ambiguous.
type Classifier interface{ Classify(RPCError) Disposition }

// RPCError excludes the vendor's untrusted message and data from classification.
type RPCError struct{ Code int }

func id() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
