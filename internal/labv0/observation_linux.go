//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

const observationEndpoint = "/opt/swarma/run/lab-manager/observation.sock"
const observationRequestFormat = "swarma-broker-lab-observation-request/1"
const observationResponseFormat = "swarma-broker-lab-observation-response/1"
const observationWindow = 250 * time.Millisecond

type observationPins struct {
	daemonUID       uint32
	manager         map[string]any
	managerHead     map[string]any
	storeGeneration string
	start           map[string]any
}

type observationSocketPolicy struct {
	path, address, anchor string
	owner, group          uint32
}

type observationClient struct {
	pins   observationPins
	policy observationSocketPolicy
}

type observationSample struct {
	record                  map[string]any
	before, after, deadline int64
}

type observationPair struct {
	initial, final observationSample
}

func newObservationClient(pins observationPins) (*observationClient, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != pins.manager["boot_id"] || pins.daemonUID == 0 || pins.daemonUID > 4294967294 || pins.daemonUID != uint32(os.Geteuid()) {
		return nil, ErrUnknown
	}
	manager, err := object(pins.manager)
	if err != nil {
		return nil, ErrUnknown
	}
	start, err := object(pins.start)
	if err != nil {
		return nil, ErrUnknown
	}
	head, err := object(pins.managerHead)
	if err != nil {
		return nil, ErrUnknown
	}
	pins.manager, pins.start, pins.managerHead = manager, start, head
	return &observationClient{pins: pins, policy: observationSocketPolicy{path: observationEndpoint, address: observationEndpoint, anchor: "/", owner: 0, group: uint32(os.Getegid())}}, nil
}

func bootNanos() (int64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, ErrUnknown
	}
	return now.Nano(), nil
}

func (policy observationSocketPolicy) inspect() ([]os.FileInfo, error) {
	if !filepath.IsAbs(policy.path) || filepath.Clean(policy.path) != policy.path || !filepath.IsAbs(policy.anchor) || filepath.Clean(policy.anchor) != policy.anchor {
		return nil, ErrUnknown
	}
	var records []os.FileInfo
	path := policy.path
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, ErrUnknown
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, ErrUnknown
		}
		if stat.Uid != policy.owner || stat.Mode&07000 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnknown
		}
		if len(records) == 0 {
			if info.Mode()&os.ModeSocket == 0 || stat.Mode&0777 != 0660 || stat.Gid != policy.group || stat.Nlink != 1 {
				return nil, ErrUnknown
			}
		} else if !info.IsDir() || stat.Mode&0022 != 0 {
			return nil, ErrUnknown
		}
		if len(records) == 1 && (stat.Mode&0777 != 0710 || stat.Gid != policy.group) {
			return nil, ErrUnknown
		}
		records = append(records, info)
		if path == policy.anchor {
			return records, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil, ErrUnknown
		}
		path = parent
	}
}

func observationPeer(connection *net.UnixConn, expected uint32) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *unix.Ucred
	var peerErr error
	if raw.Control(func(descriptor uintptr) {
		credentials, peerErr = unix.GetsockoptUcred(int(descriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil {
		return false
	}
	return peerErr == nil && credentials != nil && credentials.Uid == expected
}

func readObservationFrame(connection *net.UnixConn) ([]byte, error) {
	var frame bytes.Buffer
	buffer, control := make([]byte, 4096), make([]byte, unix.CmsgSpace(64))
	for {
		count, ancillary, flags, _, err := connection.ReadMsgUnix(buffer, control)
		if count < 0 || ancillary < 0 || ancillary > len(control) {
			return nil, ErrUnknown
		}
		if ancillary > 0 {
			messages, _ := unix.ParseSocketControlMessage(control[:ancillary])
			for _, message := range messages {
				descriptors, _ := unix.ParseUnixRights(&message)
				for _, descriptor := range descriptors {
					unix.Close(descriptor)
				}
			}
			return nil, fmt.Errorf("%w: ancillary control", ErrUnknown)
		}
		if flags&unix.MSG_CTRUNC != 0 || frame.Len()+count > 65540 {
			return nil, fmt.Errorf("%w: frame size or flags", ErrUnknown)
		}
		frame.Write(buffer[:count])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: frame receive", ErrUnknown)
		}
	}
	raw := frame.Bytes()
	if len(raw) < 5 || binary.BigEndian.Uint32(raw[:4]) == 0 || binary.BigEndian.Uint32(raw[:4]) > 65536 || int(binary.BigEndian.Uint32(raw[:4])) != len(raw)-4 {
		return nil, fmt.Errorf("%w: frame length", ErrUnknown)
	}
	return bytes.Clone(raw[4:]), nil
}

func (client *observationClient) collect(ctx context.Context, floor int64) (observationSample, error) {
	var sample observationSample
	if client == nil || ctx == nil || ctx.Err() != nil || client.pins.daemonUID == 0 || client.pins.daemonUID != uint32(os.Geteuid()) || floor < 0 || floor >= 9007199254740991 {
		return sample, ErrUnknown
	}
	before, err := bootNanos()
	if err != nil {
		return sample, ErrUnknown
	}
	sample.before, sample.deadline = before, before+int64(observationWindow)
	ctx, cancel := context.WithTimeout(ctx, observationWindow)
	defer cancel()
	oldPath, err := client.policy.inspect()
	if err != nil {
		return sample, ErrUnknown
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", client.policy.address)
	if err != nil {
		return sample, ErrUnknown
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() { connection.Close() })
	defer stopCancellation()
	channel, ok := connection.(*net.UnixConn)
	if !ok || !observationPeer(channel, client.policy.owner) {
		return sample, ErrUnknown
	}
	deadline, _ := ctx.Deadline()
	if channel.SetDeadline(deadline) != nil {
		return sample, ErrUnknown
	}
	request := map[string]any{"format": observationRequestFormat, "operation_id": client.pins.start["operation_id"], "start_id": client.pins.start["start_id"]}
	encoded, err := wire.Encode(request)
	if err != nil {
		return sample, ErrUnknown
	}
	if _, err = labcontract.Read(observationRequestFormat, encoded); err != nil || len(encoded) > 4096 {
		return sample, ErrUnknown
	}
	if wire.Write(channel, request) != nil || channel.CloseWrite() != nil {
		return sample, ErrUnknown
	}
	response, err := readObservationFrame(channel)
	if err != nil {
		return sample, err
	}
	sample.record, err = labcontract.Read(observationResponseFormat, response)
	if err != nil {
		return sample, fmt.Errorf("%w: response shape", ErrUnknown)
	}
	newPath, err := client.policy.inspect()
	if err != nil || len(oldPath) != len(newPath) {
		return sample, ErrUnknown
	}
	for index, info := range oldPath {
		if !os.SameFile(info, newPath[index]) {
			return sample, ErrUnknown
		}
	}
	sample.after, err = bootNanos()
	if err != nil || ctx.Err() != nil || sample.after < sample.before || sample.after >= sample.deadline || !client.valid(sample, floor) {
		return observationSample{}, fmt.Errorf("%w: interval or semantic join", ErrUnknown)
	}
	return sample, nil
}

func (client *observationClient) valid(sample observationSample, floor int64) bool {
	record := sample.record
	manager := record["manager"].(map[string]any)
	store := record["store"].(map[string]any)
	start := record["start"].(map[string]any)
	if !labcontract.Equal(manager, client.pins.manager) || manager["uid"] != int64(0) || store["generation"] != client.pins.storeGeneration || record["sequence_generation"] != client.pins.storeGeneration || !labcontract.Equal(store["manager_head"], client.pins.managerHead) || store["generation_current"] != true || record["complete"] != true || record["sequence"].(int64) <= floor {
		return false
	}
	if record["operation_id"] != client.pins.start["operation_id"] || record["start_id"] != client.pins.start["start_id"] || start["phase"] != "admitted" {
		return false
	}
	copy, err := object(start)
	if err != nil {
		return false
	}
	delete(copy, "phase")
	if !labcontract.Equal(copy, client.pins.start) {
		return false
	}
	observed := record["observed_monotonic_ms"].(int64)
	if observed < sample.before/int64(time.Millisecond) || observed > sample.after/int64(time.Millisecond) {
		return false
	}
	receipts, debits := record["receipts"].([]any), record["debits"].([]any)
	if len(receipts) != 1 || len(debits) != 1 || len(record["invalidations"].([]any)) != 0 || len(record["stops"].([]any)) != 0 {
		return false
	}
	receipt, debit := receipts[0].(map[string]any), debits[0].(map[string]any)
	for _, name := range []string{"execution_id", "epoch", "pid", "start_time", "boot_id"} {
		if receipt[name] != debit[name] {
			return false
		}
	}
	if receipt["execution_id"] != start["start_id"] || receipt["epoch"] != start["epoch"] || receipt["boot_id"] != manager["boot_id"] || debit["generation"] != start["generation"] || debit["committed_ms"].(int64) > observed {
		return false
	}
	if start["uid"].(int64) < 1 || start["uid"].(int64) > 4294967294 || receipt["pid"].(int64) < 1 || receipt["pid"].(int64) > 4194304 || receipt["session_id"].(int64) < 1 || receipt["session_id"].(int64) > 4194304 || store["debits_head"].(map[string]any)["sequence"].(int64) < 1 {
		return false
	}
	return true
}

func waitObservationCooldown(ctx context.Context, until int64) error {
	for {
		now, err := bootNanos()
		if err != nil || ctx.Err() != nil {
			return ErrUnknown
		}
		if now >= until {
			return nil
		}
		wait := time.Duration(until - now)
		if wait > 25*time.Millisecond {
			wait = 25 * time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrUnknown
		case <-timer.C:
		}
	}
}

func (client *observationClient) pair(ctx context.Context, floor int64) (observationPair, error) {
	var pair observationPair
	var err error
	pair.initial, err = client.collect(ctx, floor)
	if err != nil {
		return pair, err
	}
	if waitObservationCooldown(ctx, pair.initial.after+int64(observationWindow)) != nil {
		return pair, ErrUnknown
	}
	pair.final, err = client.collect(ctx, floor)
	if err != nil || pair.final.before < pair.initial.after+int64(observationWindow) || pair.final.record["sequence"].(int64) <= pair.initial.record["sequence"].(int64) {
		return pair, ErrUnknown
	}
	old, _ := object(pair.initial.record)
	newer, _ := object(pair.final.record)
	for _, record := range []map[string]any{old, newer} {
		delete(record, "sequence")
		delete(record, "observed_monotonic_ms")
	}
	if !labcontract.Equal(old, newer) {
		return pair, ErrUnknown
	}
	return pair, nil
}
