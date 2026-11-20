//go:build linux && broker_lab

package labv0

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	labcontract "github.com/relux-works/swarma-credential-broker/contracts/lab-v0"
	"github.com/relux-works/swarma-credential-broker/internal/service"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

type observationFixtureServer struct {
	listener       *net.UnixListener
	client         *observationClient
	response, stop map[string]any
	invalidation   map[string]any
	mode           string
	modeMu         sync.Mutex
	requests       atomic.Int64
	workers        sync.WaitGroup
	released       int64
	beforeWrite    func(int64)
}

func newObservationFixtureServer(test *testing.T, mode string) *observationFixtureServer {
	test.Helper()
	raw, err := os.ReadFile("../../contracts/lab-v0/observation-fixtures.json")
	if err != nil {
		test.Fatal(err)
	}
	var decoded struct {
		Response     map[string]any `json:"response"`
		Expected     map[string]any `json:"expected"`
		Stop         map[string]any `json:"stop"`
		Invalidation map[string]any `json:"invalidation"`
	}
	if json.Unmarshal(raw, &decoded) != nil {
		test.Fatal("fixture decode")
	}
	response, _ := object(decoded.Response)
	expected, _ := object(decoded.Expected)
	stop, _ := object(decoded.Stop)
	invalidation, _ := object(decoded.Invalidation)
	parent := filepath.Join(test.TempDir(), "p")
	if os.Mkdir(parent, 0710) != nil || os.Chmod(parent, 0710) != nil {
		test.Fatal("fixture parent")
	}
	directory, err := os.Open(parent)
	if err != nil {
		test.Fatal(err)
	}
	address := fmt.Sprintf("/proc/self/fd/%d/o", directory.Fd())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		directory.Close()
		test.Fatal(err)
	}
	path := filepath.Join(parent, "o")
	if os.Chmod(path, 0660) != nil {
		test.Fatal("fixture socket mode")
	}
	server := &observationFixtureServer{listener: listener, mode: mode, response: response, stop: stop, invalidation: invalidation}
	server.client = &observationClient{pins: observationPins{daemonUID: uint32(os.Geteuid()), manager: expected["manager"].(map[string]any), managerHead: expected["manager_head"].(map[string]any), storeGeneration: expected["store_generation"].(string), start: expected["start"].(map[string]any)}, policy: observationSocketPolicy{path: path, address: address, anchor: parent, owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}}
	server.workers.Add(1)
	go func() {
		defer server.workers.Done()
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			server.serve(connection)
		}
	}()
	test.Cleanup(func() { listener.Close(); server.workers.Wait(); directory.Close() })
	return server
}

func (server *observationFixtureServer) setMode(mode string, enabled bool) {
	server.modeMu.Lock()
	defer server.modeMu.Unlock()
	if enabled {
		server.mode = mode
	} else {
		server.mode = "valid"
	}
}

func (server *observationFixtureServer) serve(connection *net.UnixConn) {
	server.modeMu.Lock()
	mode := server.mode
	beforeWrite := server.beforeWrite
	server.modeMu.Unlock()
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(time.Second))
	if !observationPeer(connection, uint32(os.Geteuid())) || mode == "deny-client" {
		return
	}
	request, err := io.ReadAll(io.LimitReader(connection, 4101))
	if err != nil || len(request) < 5 || int(binary.BigEndian.Uint32(request[:4])) != len(request)-4 {
		return
	}
	frame, err := labcontract.Read(observationRequestFormat, request[4:])
	if err != nil || frame["operation_id"] != server.client.pins.start["operation_id"] || frame["start_id"] != server.client.pins.start["start_id"] {
		return
	}
	now, err := bootNanos()
	if err != nil || server.released != 0 && now-server.released < int64(observationWindow) {
		return
	}
	ordinal := server.requests.Add(1)
	if mode == "timeout" {
		time.Sleep(300 * time.Millisecond)
		return
	}
	response, _ := object(server.response)
	response["sequence"] = 7 + ordinal
	response["observed_monotonic_ms"] = now / int64(time.Millisecond)
	response["debits"].([]any)[0].(map[string]any)["committed_ms"] = int64(1)
	start := response["start"].(map[string]any)
	store := response["store"].(map[string]any)
	switch mode {
	case "terminal-stop", "terminal-wrong-stop", "terminal-pending-stop", "terminal-invalidation", "terminal-wrong-invalidation", "terminal-missing", "terminal-final-mismatch":
		start["phase"] = "terminal"
		if mode == "terminal-invalidation" || mode == "terminal-wrong-invalidation" {
			invalidation, _ := object(server.invalidation)
			invalidation["invalidated_ms"] = int64(1)
			if mode == "terminal-wrong-invalidation" {
				invalidation["generation"] = "dddddddddddddddddddddddddddddddd"
			}
			response["invalidations"] = []any{invalidation}
		} else if mode != "terminal-missing" {
			stop, _ := object(server.stop)
			stop["phase"] = "terminal"
			if mode == "terminal-wrong-stop" {
				stop["operation_id"] = "another-stop"
			}
			if mode == "terminal-pending-stop" {
				stop["phase"] = "admitted"
			}
			response["stops"] = []any{stop}
			if mode == "terminal-final-mismatch" && ordinal%2 == 0 {
				store["effects_sha256"] = digest("moved-native-proof")
			}
		}
	case "slow-valid":
		time.Sleep(190 * time.Millisecond)
	case "moved-proof":
		store["effects_sha256"] = digest("moved-native-proof")
	case "revalidation-mismatch":
		if ordinal%2 == 0 {
			store["effects_sha256"] = digest("moved-native-proof")
		}
	case "stale-generation":
		start["generation"] = "dddddddddddddddddddddddddddddddd"
	case "wrong-start-uid":
		start["uid"] = int64(4103)
	case "not-current":
		store["generation_current"] = false
	case "partial":
		delete(response, "complete")
	case "incomplete":
		response["complete"] = false
	case "pending-stop":
		response["stops"] = []any{server.stop}
	case "stopped":
		start["phase"] = "terminal"
	case "wrong-manager":
		response["manager"].(map[string]any)["instance_id"] = "dddddddddddddddddddddddddddddddd"
	case "store-generation":
		store["generation"] = "dddddddddddddddddddddddddddddddd"
	case "counter-generation":
		response["sequence_generation"] = "dddddddddddddddddddddddddddddddd"
	case "old-observation":
		response["observed_monotonic_ms"] = now/int64(time.Millisecond) - 500
	case "future-observation":
		response["observed_monotonic_ms"] = now/int64(time.Millisecond) + 500
	case "response-operation-id":
		response["operation_id"] = "dddddddddddddddddddddddddddddddd"
	case "response-start-id":
		response["start_id"] = "dddddddddddddddddddddddddddddddd"
	case "debit-mismatch":
		response["debits"].([]any)[0].(map[string]any)["pid"] = int64(4322)
	case "missing-debit":
		response["debits"] = []any{}
	case "invalidation":
		response["invalidations"] = []any{server.invalidation}
	case "duplicate-receipt":
		response["receipts"] = append(response["receipts"].([]any), response["receipts"].([]any)[0])
	case "replayed-sequence":
		response["sequence"] = int64(7)
	case "final-sequence":
		if ordinal == 2 {
			response["sequence"] = int64(8)
		}
	case "final-stop":
		if ordinal == 2 {
			response["stops"] = []any{server.stop}
		}
	case "final-mismatch":
		if ordinal == 2 {
			store["effects_revision"] = int64(5)
			store["effects_sha256"] = digest("fixture-changed-effects")
		}
	}
	if beforeWrite != nil {
		beforeWrite(ordinal)
	}
	server.released, _ = bootNanos()
	var encoded bytes.Buffer
	if wire.Write(&encoded, response) != nil {
		return
	}
	switch mode {
	case "truncated":
		connection.Write(encoded.Bytes()[:encoded.Len()/2])
		return
	case "two-frames":
		connection.Write(encoded.Bytes())
		connection.Write(encoded.Bytes())
		return
	case "ancillary":
		file, err := os.CreateTemp(filepath.Dir(server.client.policy.path), "descriptor-")
		if err != nil {
			return
		}
		defer file.Close()
		connection.WriteMsgUnix(encoded.Bytes(), unix.UnixRights(int(file.Fd())), nil)
		return
	}
	connection.Write(encoded.Bytes())
	if mode == "delayed-eof" {
		time.Sleep(300 * time.Millisecond)
	}
}

func observationPairControl(test *testing.T) {
	test.Helper()
	server := newObservationFixtureServer(test, "valid")
	if _, err := server.client.policy.inspect(); err != nil {
		test.Fatal("fixture socket-policy control refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pair, err := server.client.pair(ctx, 7)
	if err != nil || pair.initial.record["sequence"] != int64(8) || pair.final.record["sequence"] != int64(9) || server.requests.Load() != 2 {
		test.Fatalf("two fresh observation control refused: %v; requests=%d", err, server.requests.Load())
	}
	if pair.final.before-pair.initial.after < int64(observationWindow) {
		test.Fatal("cooldown skipped")
	}
}

// Claim: the real Unix client accepts its contract-exact fixture pair and returns UNKNOWN for each independently malformed, stale, stopped or changed join; the private fixture peer policy is not root-native qualification.
func TestLabObservationClientPairs(test *testing.T) {
	for _, mode := range []string{"stale-generation", "wrong-start-uid", "not-current", "partial", "incomplete", "pending-stop", "stopped", "wrong-manager", "store-generation", "counter-generation", "old-observation", "debit-mismatch", "missing-debit", "invalidation", "duplicate-receipt", "replayed-sequence", "final-sequence", "final-stop", "final-mismatch", "truncated", "two-frames", "ancillary", "timeout", "delayed-eof", "deny-client"} {
		test.Run(mode, func(test *testing.T) {
			observationPairControl(test)
			server := newObservationFixtureServer(test, mode)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := server.client.pair(ctx, 7); !errors.Is(err, ErrUnknown) {
				test.Fatalf("%s: intended UNKNOWN, got %v", mode, err)
			}
		})
	}
}

// Claim: the authenticated first observation must exceed the supplied durable replay floor, independently of the later final-sequence comparison.
func TestLabObservationSequenceFloor(test *testing.T) {
	for _, mode := range []string{"valid", "replayed-sequence"} {
		server := newObservationFixtureServer(test, mode)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		sample, err := server.client.collect(ctx, 7)
		if mode == "valid" {
			if err != nil || sample.record["sequence"] != int64(8) {
				test.Fatalf("first observation control: %v", err)
			}
		} else if !errors.Is(err, ErrUnknown) {
			test.Fatal("replayed initial sequence admitted")
		}
	}
}

// Claim: a single well-framed fixture answer with prompt EOF succeeds, whereas the same valid answer with EOF delayed beyond the nonextendable 250 ms window yields UNKNOWN.
func TestLabObservationTransportWindow(test *testing.T) {
	for _, mode := range []string{"valid", "delayed-eof"} {
		server := newObservationFixtureServer(test, mode)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := server.client.collect(ctx, 7)
		if mode == "valid" {
			if err != nil {
				test.Fatalf("prompt EOF control: %v", err)
			}
		} else if !errors.Is(err, ErrUnknown) {
			test.Fatal("late EOF admitted")
		}
	}
}

// Claim: protected socket mode, parent mode and symlink checks refuse the fixture after a valid pair; this is not privileged installation qualification.
func TestLabObservationPathChanges(test *testing.T) {
	for _, mode := range []string{"socket-mode", "parent-mode", "symlink"} {
		test.Run(mode, func(test *testing.T) {
			observationPairControl(test)
			server := newObservationFixtureServer(test, "valid")
			path := server.client.policy.path
			switch mode {
			case "socket-mode":
				if err := os.Chmod(path, 0666); err != nil {
					test.Fatal(err)
				}
			case "parent-mode":
				if err := os.Chmod(filepath.Dir(path), 0712); err != nil {
					test.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+"-original"); err != nil {
					test.Fatal(err)
				}
				if err := os.Symlink(path+"-original", path); err != nil {
					test.Fatal(err)
				}
			}
			if _, err := server.client.collect(context.Background(), 7); !errors.Is(err, ErrUnknown) || server.requests.Load() != 0 {
				test.Fatal("changed path reached observation")
			}
		})
	}
}

// Claim (historical pre-C0d diagnostic, not current acceptance): two fresh observations per successful use and the global cooldown leave no recurring success margin below the 500 ms watchdog; a 750 ms diagnostic control succeeds, whereas a 500 ms window from the previous receipt yields UNKNOWN.
func TestLabObservationRecurringWatchdogBudget(test *testing.T) {
	for _, budget := range []time.Duration{750 * time.Millisecond, 500 * time.Millisecond} {
		test.Run(budget.String(), func(test *testing.T) {
			server := newObservationFixtureServer(test, "valid")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			first, err := server.client.pair(ctx, 7)
			cancel()
			if err != nil {
				test.Fatal("first pair refused")
			}
			now, clockErr := bootNanos()
			if clockErr != nil {
				test.Fatal(clockErr)
			}
			ctx, cancel = context.WithTimeout(context.Background(), budget-time.Duration(now-first.final.after))
			defer cancel()
			if err := waitObservationCooldown(ctx, first.final.after+int64(observationWindow)); err != nil {
				test.Fatal("first cooldown refused")
			}
			second, err := server.client.pair(ctx, first.final.record["sequence"].(int64))
			if budget == 750*time.Millisecond {
				if err != nil || second.final.after-first.final.after < int64(500*time.Millisecond) || server.requests.Load() != 4 {
					test.Fatalf("recurring diagnostic control: %v", err)
				}
			} else if !errors.Is(err, ErrUnknown) || server.requests.Load() != 3 {
				test.Fatalf("watchdog window: error=%v requests=%d", err, server.requests.Load())
			}
		})
	}
}

// Claim: SO_PEERCRED matches the actual fixture peer and refuses a different expected UID; dedicated-client binding and production root path policy separately refuse the same nonroot fixture when retargeted.
func TestLabObservationKernelPeerAndPath(test *testing.T) {
	observationPairControl(test)
	server := newObservationFixtureServer(test, "valid")
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: server.client.policy.address, Net: "unix"})
	if err != nil {
		test.Fatal(err)
	}
	defer connection.Close()
	if !observationPeer(connection, uint32(os.Geteuid())) || observationPeer(connection, uint32(os.Geteuid()+1)) {
		test.Fatal("kernel peer binding")
	}
	connection.Close()
	server.client.pins.daemonUID++
	if _, err := server.client.collect(context.Background(), 7); !errors.Is(err, ErrUnknown) || server.requests.Load() != 0 {
		test.Fatal("wrong daemon UID binding admitted")
	}
	server.client.pins.daemonUID--
	server.client.policy.owner = 0
	if _, err := server.client.collect(context.Background(), 7); !errors.Is(err, ErrUnknown) {
		test.Fatal("production root-socket policy admitted nonroot fixture")
	}
}

// Claim (historical pre-C0d diagnostic, not current acceptance): a complete initial/final pair works with a one-second caller budget, but the unchanged 200 ms current-RPC budget necessarily expires in the mandatory cooldown before a second request; no usable result is returned.
func TestLabObservationCurrentRPCBudget(test *testing.T) {
	observationPairControl(test)
	server := newObservationFixtureServer(test, "valid")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started, _ := bootNanos()
	_, err := server.client.pair(ctx, 7)
	ended, _ := bootNanos()
	if !errors.Is(err, ErrUnknown) || server.requests.Load() != 1 || ended-started < int64(190*time.Millisecond) {
		test.Fatalf("current budget witness: error=%v requests=%d", err, server.requests.Load())
	}
}

type observationBudgetAuthority struct {
	base   *fixtureAuthority
	client *observationClient
}

func (authority observationBudgetAuthority) WithIdentity(ctx context.Context, callback func(service.View) error) error {
	return authority.base.WithIdentity(ctx, callback)
}

func (authority observationBudgetAuthority) WithCurrent(ctx context.Context, callback func(service.View) error) error {
	if _, err := authority.client.pair(ctx, 7); err != nil {
		return err
	}
	return authority.base.WithCurrent(ctx, callback)
}

// Claim (historical pre-C0d diagnostic, not current acceptance): the existing-engine revocation-check path can publish not_revoked after a fake pair with one second, but never under the historical 200 ms diagnostic budget; the negative makes no journal change or publication.
func TestLabObservationComposedCurrentBudget(test *testing.T) {
	for _, budget := range []time.Duration{time.Second, 200 * time.Millisecond} {
		test.Run(budget.String(), func(test *testing.T) {
			server := newObservationFixtureServer(test, "valid")
			fixture := newLabFixture(test, true)
			fixture.facts.caller["generation"] = server.client.pins.start["generation"]
			fixture.facts.caller["execution_id"] = server.client.pins.start["start_id"]
			server.client.pins.start["uid"] = int64(4102)
			server.response["start"].(map[string]any)["uid"] = int64(4102)
			fixture.start(test)
			fixture.bind(test)
			issued, err := fixture.call(test, 4101, "service.lease.request", fixture.request("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
			if err != nil {
				test.Fatal(err)
			}
			broker, err := service.NewLabWithLifetime(observationBudgetAuthority{base: fixture.authority, client: server.client}, map[string]service.Account{accountLabel: fixture.a}, func() time.Time { return fixture.now }, fixture.facts.lifetime)
			if err != nil {
				test.Fatal(err)
			}
			principal, err := broker.Open(context.Background(), 4101)
			if err != nil {
				test.Fatal(err)
			}
			before, err := fixture.a.Snapshot()
			if err != nil {
				test.Fatal(err)
			}
			raw, err := wire.Encode(wire.ServiceLeaseID{LeaseID: issued.(wire.ServiceLease).LeaseID})
			if err != nil {
				test.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			var result any
			err = broker.Call(ctx, principal, "service.revocation.check", raw, func(value any) error { result = value; return nil })
			after, readErr := fixture.a.Snapshot()
			if readErr != nil || !bytes.Equal(before, after) {
				test.Fatal("read-only check changed journal")
			}
			if budget == time.Second {
				if err != nil || result == nil || result.(map[string]any)["verdict"] != "not_revoked" || server.requests.Load() != 2 {
					test.Fatalf("composed valid control: %v", err)
				}
			} else if err == nil || err.Error() != "request_deadline_exceeded" || result != nil || server.requests.Load() != 1 {
				test.Fatalf("composed current budget: error=%v requests=%d published=%v", err, server.requests.Load(), result != nil)
			}
		})
	}
}
