//go:build linux

package qualify

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func rowImplemented(id string) bool {
	switch id {
	case "frame-oversized", "frame-zero-length", "frame-truncated-header", "frame-malformed-first", "profile-unsupported", "peer-identity-unavailable":
		return true
	}
	return admissionRow(id) || id == "peer-denied"
}

type rowInput struct {
	ApprovedDigest string        `json:"approved_digest,omitempty"`
	Policy         policy.Policy `json:"policy"`
	Peer           uint32        `json:"peer"`
	ID             string        `json:"id"`
	Side           string        `json:"side"`
	EndedBy        string        `json:"ended_by"`
	RunnerDigest   string        `json:"runner_digest,omitempty"`
	RunnerConfig   string        `json:"runner_config,omitempty"`
	Socket         string        `json:"socket"`
}
type rowObservation struct {
	Runner     *runnerRowEffects `json:"runner,omitempty"`
	Peer       *peerRowEffects   `json:"peer,omitempty"`
	Admission  *admissionEffects `json:"admission,omitempty"`
	ID         string            `json:"id"`
	Side       string            `json:"side"`
	Candidate  string            `json:"candidate"`
	Refusal    string            `json:"refusal"`
	NoEffects  bool              `json:"no_effects"`
	ProbeFault bool              `json:"probe_fault"`
	Envelopes  []rowEnvelope     `json:"envelopes"`
}

func descriptorDigest(f *os.File) (string, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (512<<20)+1))
	if e != nil || n > 512<<20 {
		return "", qualification.ErrUnavailable
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CaseMain accepts only the retained broker descriptor and a bounded pipe
// context. The approved Codex descriptor is measured at FD6, never executed by
// these transport rows. No path, shell or inherited account context is accepted.
func CaseMain(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "qualification-case" {
		return false, 0
	}
	if os.Args[0] != "/proc/self/fd/4" || len(args) != 3 || !rowImplemented(args[1]) || args[2] != "positive" && args[2] != "negative" {
		return true, 125
	}
	if signalCaseStart() != nil {
		return true, 125
	}
	f := os.NewFile(5, "row-context")
	if f == nil {
		return true, 125
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || s.Mode()&os.ModeNamedPipe == 0 {
		return true, 125
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	var input rowInput
	if e != nil || len(b) > 4096 || wire.Decode(b, &input) != nil || input.ID != args[1] || input.Side != args[2] || input.Peer != uint32(os.Geteuid()) || input.Policy.Validate(uint32(os.Geteuid())) != nil || (len(input.Policy.Accounts) != 1 && !admissionRow(input.ID) || admissionRow(input.ID) && !validAdmissionInput(input)) || !input.Policy.Peer(input.Peer) {
		return true, 125
	}
	candidate := os.NewFile(6, "approved-candidate")
	if candidate == nil {
		return true, 125
	}
	defer candidate.Close()
	digest, e := descriptorDigest(candidate)
	expectedDigest := input.Policy.ExecutableSHA256
	if runnerRow(input.ID) {
		expectedDigest = input.ApprovedDigest
	}
	if e != nil || digest != expectedDigest {
		return true, 125
	}
	observation := rowObservation{Envelopes: []rowEnvelope{}, ID: input.ID, Side: input.Side, Candidate: expectedDigest, NoEffects: true}
	entries, e := os.ReadDir(os.Getenv("HOME"))
	if e != nil || !runnerRow(input.ID) && len(entries) != 0 || os.Getenv("HOME") != os.Getenv("CODEX_HOME") {
		return true, 125
	}
	if runnerRow(input.ID) {
		observation.Refusal, observation.Runner, e = runnerExchange(input)
	} else if admissionRow(input.ID) {
		observation.Refusal, observation.Envelopes, e = admissionExchange(input)
	} else {
		observation.Refusal, observation.Envelopes, e = transportExchangeFacts(input.Socket, input.ID, input.Side, input.Policy.Generation)
	}
	if e != nil {
		return true, 1
	}
	b, e = wire.Encode(observation)
	if e != nil {
		return true, 1
	}
	if _, e = os.Stdout.Write(b); e != nil {
		return true, 1
	}
	return true, 0
}

type rowStoppedOwner struct{ calls atomic.Int64 }

func (o *rowStoppedOwner) Snapshot(context.Context, string) (owner.Snapshot, error) {
	o.calls.Add(1)
	return owner.Snapshot{State: owner.Unavailable}, nil
}
func (o *rowStoppedOwner) Refresh(context.Context, string, uint64) (owner.Snapshot, error) {
	o.calls.Add(1)
	return owner.Snapshot{State: owner.Unavailable}, nil
}

func startTransportRow(ctx context.Context, root string, input rowInput, pid *atomic.Int64) (string, func() bool, error) {
	dir := filepath.Join(root, "q")
	if os.Mkdir(dir, 0700) != nil {
		return "", nil, qualification.ErrUnavailable
	}
	disk, e := store.Open(filepath.Join(root, "store"), input.Policy.Installation, uint32(os.Geteuid()), true, nil)
	if e != nil {
		return "", nil, e
	}
	stopped := &rowStoppedOwner{}
	m, e := lease.New(input.Policy, disk, stopped, lease.Options{Qualification: func(context.Context, policy.Policy) error { return qualification.ErrUnavailable }}, true)
	if e != nil {
		disk.Close()
		return "", nil, e
	}
	probeFault := input.ID == "peer-identity-unavailable" && input.Side == "negative"
	srv, fired, e := server.NewQualification(m, input.Policy.ExecutableSHA256, input.Peer, pid, probeFault)
	if e != nil {
		m.Close()
		disk.Close()
		return "", nil, e
	}
	path := filepath.Join(dir, "s")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		m.Close()
		disk.Close()
		return "", nil, e
	}
	listener.SetUnlinkOnClose(false)
	if os.Chmod(path, 0600) != nil {
		listener.Close()
		m.Close()
		disk.Close()
		return "", nil, qualification.ErrUnavailable
	}
	// Serve may still be starting when a launch fails. Joining it before Wait
	// avoids racing a late accepted connection's WaitGroup.Add.
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(serveCtx, listener) }()
	closeRow := func() bool {
		cancel()
		listener.Close()
		serveError := <-done
		srv.Close()
		srv.Wait()
		records, e := disk.Account(input.Policy.Accounts[0].Label, false)
		good := false
		if e == nil {
			stored, e := records.Records()
			good = e == nil && len(stored) == 0
		}
		m.Close()
		disk.Close()
		_, socketError := os.Lstat(path)
		return good && stopped.calls.Load() == 0 && fired() == probeFault && serveError == nil && os.IsNotExist(socketError)
	}
	return path, closeRow, nil
}

// transportExchange retains the small exchange entry point used by protocol
// regressions; the descriptor worker also returns every validated envelope fact.
func transportExchange(path, id, side string, generation uint64) (string, error) {
	code, _, e := transportExchangeFacts(path, id, side, generation)
	return code, e
}

func transportExchangeFacts(path, id, side string, generation uint64) (string, []rowEnvelope, error) {
	var envelopes []rowEnvelope
	variants := 1
	if (id == "profile-unsupported" || id == "frame-malformed-first") && side == "negative" {
		variants = 2
	}
	for variant := 0; variant < variants; variant++ {
		code, envelope, e := func() (string, rowEnvelope, error) {
			c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				return "", rowEnvelope{}, e
			}
			defer c.Close()
			if c.SetDeadline(time.Now().Add(3*time.Second)) != nil {
				return "", rowEnvelope{}, qualification.ErrUnavailable
			}
			hello := wire.Hello{Versions: []int{1}, Profile: wire.Profile}
			if side == "negative" {
				switch id {
				case "frame-oversized", "frame-zero-length", "frame-truncated-header":
					var header [4]byte
					if id == "frame-oversized" {
						binary.BigEndian.PutUint32(header[:], 65537)
					}
					b := header[:]
					if id == "frame-truncated-header" {
						b = b[:2]
					}
					if _, e = c.Write(b); e != nil {
						return "", rowEnvelope{}, e
					}
					if e = c.CloseWrite(); e != nil {
						return "", rowEnvelope{}, e
					}
				case "frame-malformed-first":
					if variant == 0 {
						body := []byte(`{"request_id":"apparent","method":`)
						var header [4]byte
						binary.BigEndian.PutUint32(header[:], uint32(len(body)))
						if _, e = c.Write(append(header[:], body...)); e != nil {
							return "", rowEnvelope{}, e
						}
						break
					}
					if e = wire.Write(c, map[string]any{"request_id": "apparent", "method": "not-hello", "params": map[string]any{}}); e != nil {
						return "", rowEnvelope{}, e
					}
				case "profile-unsupported":
					if variant == 0 {
						hello.Profile = "unsupported"
					} else {
						hello.Versions = []int{2}
					}
				}
			}
			if side == "positive" || id == "profile-unsupported" {
				params, e := wire.Encode(hello)
				if e != nil {
					return "", rowEnvelope{}, e
				}
				if e = wire.Write(c, wire.Request{Method: "hello", ID: "fixture-hello", Params: params}); e != nil {
					return "", rowEnvelope{}, e
				}
			}
			b, e := wire.Read(c)
			if side == "negative" && (id == "frame-zero-length" || id == "frame-truncated-header" || id == "frame-malformed-first") {
				if !errors.Is(e, io.EOF) || len(b) != 0 {
					return "", rowEnvelope{}, qualification.ErrUnavailable
				}
				return "closed", rowEnvelope{Kind: "closed"}, nil
			}
			if e != nil {
				return "", rowEnvelope{}, qualification.ErrUnavailable
			}
			envelope, e := decodeRowEnvelope(b, id, side, generation)
			if e != nil {
				return "", rowEnvelope{}, e
			}
			if side == "positive" {
				return "hello", envelope, nil
			}
			want := rowRefusal(id)
			var one [1]byte
			n, e := c.Read(one[:])
			if n != 0 || !errors.Is(e, io.EOF) {
				return "", rowEnvelope{}, qualification.ErrUnavailable
			}
			return want, envelope, nil
		}()
		if e != nil {
			return "", nil, e
		}
		envelopes = append(envelopes, envelope)
		if variant == variants-1 {
			return code, envelopes, nil
		}
	}
	return "", nil, qualification.ErrUnavailable
}

func rowRefusal(id string) string {
	switch id {
	case "frame-oversized":
		return "frame_too_large"
	case "profile-unsupported":
		return "version_unsupported"
	case "peer-identity-unavailable":
		return "peer_identity_unavailable"
	case "peer-denied":
		return "role_not_permitted"
	case "home-auth-present", "source-conflict":
		return "credential_source_conflict"
	case "account-denied":
		return "lease_not_authorised"
	case "account-unknown":
		return "lease_account_unknown"
	case "release-unqualified":
		return "lease_harness_unqualified"
	case "lease-ended":
		return "lease_not_active"
	}
	return "closed"
}
