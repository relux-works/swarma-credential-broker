//go:build linux

package qualify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/egress"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type peerRowEffects struct {
	StartedAt         string `json:"started_at"`
	IdentityVerified  bool   `json:"identity_verified"`
	SocketVerified    bool   `json:"socket_verified"`
	DeniedBeforeInput bool   `json:"denied_before_input"`
	NegativeUnchanged bool   `json:"negative_unchanged"`
	Joined            bool   `json:"joined"`
	Records           int    `json:"records"`
	Snapshots         int    `json:"snapshots"`
	Refreshes         int    `json:"refreshes"`
}

func validPeerEffects(o rowObservation) bool {
	f := o.Peer
	if f == nil || o.Runner != nil || o.Admission != nil || !f.IdentityVerified || !f.SocketVerified || !f.NegativeUnchanged || !f.Joined || f.Refreshes != 0 {
		return false
	}
	if o.Side == "negative" {
		return f.DeniedBeforeInput && f.Records == 0 && f.Snapshots == 0
	}
	return o.Side == "positive" && !f.DeniedBeforeInput && f.Records == 1 && f.Snapshots == 2
}
func validPeerEnvelopes(o rowObservation, generation uint64) bool {
	if !validPeerEffects(o) {
		return false
	}
	if o.Side == "negative" {
		return len(o.Envelopes) == 1 && validRowEnvelope(o.Envelopes[0], o.ID, "negative", generation)
	}
	if len(o.Envelopes) != 2 || !validRowEnvelope(o.Envelopes[0], o.ID, "positive", generation) || !validAdmissionGrant(o.Envelopes[1], "fixture-request") {
		return false
	}
	start, e := time.Parse(time.RFC3339Nano, o.Peer.StartedAt)
	return e == nil && o.Envelopes[1].Lease.Until == start.Add(5*time.Second).Truncate(time.Second).Format(time.RFC3339) && o.Envelopes[1].Lease.Expires == start.Add(time.Minute).Truncate(time.Second).Format(time.RFC3339)
}

type peerFixture struct {
	foreign, foreignGID, group uint32
	negativeUnchanged          func() bool
	deniedVerified             bool
}
type peerIdentity struct {
	UID, GID uint32
	PID      int
}
type peerReply struct {
	Execution   rowExecution
	Observation rowObservation
	Network     map[string]egress.Counts
	Incomplete  bool
}

// PeerHelperMain is used only by the separately built fixture program, not by
// the release CLI. After sudo has selected the real identity, its own tracer
// supervises the fixed client. No setuid transition occurs inside the boundary.
func PeerHelperMain() int {
	if len(os.Args) > 1 {
		if os.Args[0] != "/proc/self/fd/4" || len(os.Args) != 4 || os.Args[1] != "qualification-case" || os.Args[2] != "peer-denied" {
			return 125
		}
		if signalCaseStart() != nil {
			return 125
		}
		var in rowInput
		f := os.NewFile(5, "peer-context")
		if f == nil {
			return 125
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		if e != nil || len(b) > 4096 || wire.Decode(b, &in) != nil || in.Side != os.Args[3] {
			return 125
		}
		o := rowObservation{ID: in.ID, Side: in.Side, Candidate: in.Policy.ExecutableSHA256, NoEffects: true}
		if in.Side == "positive" {
			o.Refusal, o.Envelopes, e = admissionExchangeWithPhase(in, nil, nil)
		} else {
			var c *net.UnixConn
			c, e = net.DialUnix("unix", nil, &net.UnixAddr{Name: in.Socket, Net: "unix"})
			if e != nil {
				return 1
			}
			defer c.Close()
			uid, probe := server.PeerUID(c)
			if probe != nil || uid != in.Policy.BrokerUID {
				return 1
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			b, e = wire.Read(c)
			var fact rowEnvelope
			if e == nil {
				fact, e = decodeRowEnvelope(b, in.ID, "negative", in.Policy.Generation)
			}
			if e == nil {
				var one [1]byte
				n, closed := c.Read(one[:])
				if n != 0 || closed != io.EOF {
					return 1
				}
				o.Refusal = "role_not_permitted"
				o.Envelopes = []rowEnvelope{fact}
			}
		}
		if e != nil {
			return 1
		}
		if json.NewEncoder(os.Stdout).Encode(o) != nil {
			return 1
		}
		return 0
	}
	var in rowInput
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 8192))
	if decoder.Decode(&in) != nil || in.ID != "peer-denied" {
		return 125
	}
	self, e := os.Open("/proc/self/exe")
	if e != nil {
		return 125
	}
	defer self.Close()
	inputR, inputW, e := os.Pipe()
	if e != nil {
		return 125
	}
	defer inputR.Close()
	b, e := wire.Encode(in)
	if e != nil {
		return 125
	}
	if _, e = inputW.Write(b); e != nil {
		return 125
	}
	inputW.Close()
	outR, outW, e := os.Pipe()
	if e != nil {
		return 125
	}
	defer outR.Close()
	defer outW.Close()
	startR, startW, e := os.Pipe()
	if e != nil {
		return 125
	}
	defer startR.Close()
	defer startW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	stopped := context.AfterFunc(ctx, func() { outR.Close(); startR.Close(); os.Stdin.Close() })
	defer stopped()
	type output struct {
		b []byte
		e error
	}
	result := make(chan output, 1)
	go func() { b, e := io.ReadAll(io.LimitReader(outR, 8193)); result <- output{b, e} }()
	command := qualification.CaseCommand("peer-denied", in.Side)
	execution := newRowExecution()
	report, _ := egress.Run(ctx, egress.Config{Launcher: "/proc/self/fd/4", LauncherArgs: []string{"--internal-qualification-candidate"}, Executable: command[0], Args: command[1:], Env: []string{"PATH=/usr/bin:/bin"}, Policy: egress.Policy{UnixPaths: []string{in.Socket}, MaxEvents: 4096}, Stdout: outW, Stderr: os.Stderr, ExtraFiles: withCaseStart([]*os.File{self, inputR}, inputR, startW), Waited: execution.waited, Started: func(pid int) {
		execution.Launched = true
		if json.NewEncoder(os.Stdout).Encode(peerIdentity{uint32(os.Geteuid()), uint32(os.Getegid()), pid}) != nil {
			cancel()
			return
		}
		var ack string
		if decoder.Decode(&ack) != nil || ack != "ready" {
			cancel()
		}
	}})
	outW.Close()
	execution.Started = readCaseStart(startR, startW)
	execution.WorkerExit = execution.HelperExit
	execution.Completed = execution.Started && execution.WorkerExit >= 0
	if execution.Completed {
		execution.CaseExit = execution.WorkerExit
	}
	captured := <-result
	var o rowObservation
	if !execution.Started {
		execution.Diagnostic = "case_not_started"
	} else if !execution.Completed {
		execution.Diagnostic = "case_status_unavailable"
	} else if captured.e != nil || len(captured.b) > 8192 || wire.Decode(captured.b, &o) != nil {
		execution.Diagnostic = "observation_invalid"
	}
	if json.NewEncoder(os.Stdout).Encode(peerReply{execution, o, report.Summary, report.Incomplete}) != nil {
		return 1
	}
	return 0
}

func resolvePeerFixture(f fixtureConfiguration) (*peerFixture, error) {
	foreign, e := user.Lookup(f.Foreign)
	if e != nil {
		return nil, e
	}
	uid, e := strconv.ParseUint(foreign.Uid, 10, 32)
	if e != nil {
		return nil, e
	}
	gid, e := strconv.ParseUint(foreign.Gid, 10, 32)
	if e != nil {
		return nil, e
	}
	group, e := user.LookupGroup(f.Group)
	if e != nil {
		return nil, e
	}
	shared, e := strconv.ParseUint(group.Gid, 10, 32)
	if e != nil {
		return nil, e
	}
	groups, e := foreign.GroupIds()
	member := false
	for _, g := range groups {
		member = member || g == group.Gid
	}
	if e != nil || !member || uint32(uid) == uint32(os.Geteuid()) || uint32(shared) != uint32(os.Getegid()) {
		return nil, qualification.ErrUnavailable
	}
	return &peerFixture{foreign: uint32(uid), foreignGID: uint32(gid), group: uint32(shared)}, nil
}
func runPeerClient(ctx context.Context, f fixtureConfiguration, peers *peerFixture, in rowInput, pid *atomic.Int64) (peerReply, error) {
	result := peerReply{Execution: newRowExecution()}
	args := []string{"-n", "-u", f.Foreign, "--", f.PeerHelper}
	uid, gid := peers.foreign, peers.foreignGID
	if in.Side == "positive" {
		args = []string{"-n", "-u", f.Allowed, "-g", f.Group, "--", f.PeerHelper}
		uid, gid = in.Peer, peers.group
	}
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	stdin, e := cmd.StdinPipe()
	if e != nil {
		result.Execution.Diagnostic = "helper_pipe_unavailable"
		return result, e
	}
	defer stdin.Close()
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		result.Execution.Diagnostic = "helper_pipe_unavailable"
		return result, e
	}
	if e = cmd.Start(); e != nil {
		result.Execution.Diagnostic = launchDiagnostic(e)
		return result, e
	}
	result.Execution.Launched = true
	decoder := json.NewDecoder(io.LimitReader(stdout, 16384))
	encoder := json.NewEncoder(stdin)
	e = encoder.Encode(in)
	var identity peerIdentity
	if e == nil {
		e = decoder.Decode(&identity)
	}
	result.Execution.Diagnostic = "peer_handshake_unavailable"
	if e == nil && (identity.UID != uid || identity.GID != gid || identity.PID <= 0) {
		e = qualification.ErrUnavailable
		result.Execution.Diagnostic = "peer_identity_mismatch"
	}
	if e == nil {
		pid.Store(int64(identity.PID))
		e = encoder.Encode("ready")
		result.Execution.Handshake = e == nil
	}
	stdin.Close()
	if e == nil {
		var reply peerReply
		e = decoder.Decode(&reply)
		if e == nil && !workerDiagnostic(reply.Execution.Diagnostic) {
			e = qualification.ErrUnavailable
			result.Execution.Diagnostic = "case_evidence_invalid"
		} else if e == nil {
			result.Observation, result.Network, result.Incomplete = reply.Observation, reply.Network, reply.Incomplete
			result.Execution.Diagnostic = reply.Execution.Diagnostic
		} else {
			result.Execution.Diagnostic = "case_evidence_unavailable"
		}
	}
	wait := cmd.Wait()
	result.Execution.waited(cmd.ProcessState)
	result.Execution.unavailableOrigin()
	if e == nil {
		e = wait
	}
	if e == nil && (!result.Execution.credit(true) || result.Execution.Diagnostic != "") {
		e = qualification.ErrUnavailable
	}
	return result, e
}

// Both controls share this one real listener. Missing identities/group/helper
// leave the registry pending, without inventing a UID or execution evidence.
func (d driver) runPeerRows(parent context.Context, f fixtureConfiguration, p policy.Policy, root string, c *qualification.Case) {
	executions := map[string]rowExecution{}
	for _, side := range []string{"negative", "positive"} {
		e := newRowExecution()
		e.Diagnostic = "peer_fixture_unavailable"
		executions[side] = e
	}
	defer func() {
		for _, side := range []string{"negative", "positive"} {
			d.recordExecution(c.ID, side, executions[side])
		}
	}()
	peers, e := resolvePeerFixture(f)
	if e != nil {
		return
	}
	helper, e := qualification.OpenExecutable(f.PeerHelper)
	if e != nil {
		return
	}
	defer helper.Close()
	candidate, e := qualification.OpenExecutable(p.Executable)
	if e != nil {
		return
	}
	digest, e := descriptorDigest(candidate)
	candidate.Close()
	if e != nil || digest != p.ExecutableSHA256 {
		return
	}
	scratch, e := os.MkdirTemp("/tmp", "qualification-peer-")
	if e != nil {
		return
	}
	pending := *c
	defer func() {
		if os.RemoveAll(scratch) != nil {
			*c = pending
		}
	}()
	if os.Mkdir(filepath.Join(scratch, "home"), 0700) != nil {
		return
	}
	// All ancestors up to /tmp must be traversable for the configured group.
	// This separate owned root is group-only, never a shared directory chmod.
	if os.Chmod(scratch, 0750) != nil {
		return
	}
	copy, e := os.OpenFile(filepath.Join(scratch, "helper"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0750)
	if e != nil {
		return
	}
	_, e = io.Copy(copy, helper)
	ce := copy.Close()
	if e != nil || ce != nil {
		return
	}
	f.PeerHelper = filepath.Join(scratch, "helper")
	in := admissionInput(rowInput{Policy: p, Peer: uint32(os.Geteuid()), ID: "account-unknown", Side: "positive"})
	var pid atomic.Int64
	var effects admissionEffects
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	socket, closeRow, _, e := startAdmissionFixture(ctx, scratch, in, &pid, &effects, peers)
	if e != nil {
		return
	}
	replies := map[string]peerReply{}
	controls := map[string]qualification.Control{}
	for _, side := range []string{"negative", "positive"} {
		request := in
		request.ID, request.Side, request.Socket = "peer-denied", side, socket
		started := time.Now()
		reply, err := runPeerClient(ctx, f, peers, request, &pid)
		executions[side] = reply.Execution
		controls[side] = executionControl(c.ID, side, reply.Execution, time.Since(started))
		if !controls[side].Executed {
			if side == "negative" {
				next := executions["positive"]
				next.Diagnostic = "peer_pair_unavailable"
				executions["positive"] = next
			}
			break
		}
		unchanged := peers.negativeUnchanged()
		if side == "negative" {
			peers.deniedVerified = err == nil && unchanged
		}
		reply.Observation.Peer = &peerRowEffects{StartedAt: effects.StartedAt, IdentityVerified: err == nil, SocketVerified: server.QualificationPeerSocket(socket, peers.group), DeniedBeforeInput: side == "negative" && err == nil, NegativeUnchanged: peers.deniedVerified, Joined: true}
		if side == "positive" {
			reply.Observation.Peer.Records = 1
			reply.Observation.Peer.Snapshots = 2
		}
		control := controls[side]
		if err == nil && control.ExitCode == 0 && validPeerEnvelopes(reply.Observation, p.Generation) && rowIsolated(rowArtifact{Network: reply.Network, Incomplete: reply.Incomplete}) {
			control.Verdict = "passed"
		}
		controls[side] = control
		replies[side] = reply
	}
	verified := closeRow()
	if !controls["negative"].Executed || !controls["positive"].Executed {
		c.Positive, c.Negative = pendingRowControl(), pendingRowControl()
		return
	}
	for _, side := range []string{"negative", "positive"} {
		reply := replies[side]
		control := controls[side]
		if !verified {
			control.Verdict = "failed"
		}
		if side == "positive" {
			reply.Observation.Peer.Records = effects.Records
			reply.Observation.Peer.Snapshots = effects.Snapshots
			reply.Observation.Peer.Refreshes = effects.Refreshes
		}
		execution := executions[side]
		artifact := rowArtifact{"qualification-row-control/1", p.ExecutableSHA256, c.ID, side, control, reply.Observation, reply.Network, false, reply.Incomplete, &execution}
		b, e := wire.Encode(artifact)
		if e != nil || os.WriteFile(rowFile(root, c.ID, side), b, 0600) != nil {
			continue
		}
		control.Artifacts = []string{qualification.Hash(b)}
		if side == "positive" {
			c.Positive = control
		} else {
			c.Negative = control
		}
	}
}
