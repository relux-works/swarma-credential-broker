package servicev0

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/statev0"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

const fixtureAccount = "fixture/claude/subscription"
const fixtureInstallation = "fixture-installation-v0"

type diskFixture struct {
	gate    *statev0.SerialGate
	journal *statev0.Journal
	records *Records
	account *store.Account
	path    string
	pin     assemblyv0.PrincipalPin
}

func readVector(test *testing.T, name string) statev0.ServiceStateV2 {
	test.Helper()
	data, err := os.ReadFile(filepath.Join("..", "statev0", "testdata", "construction-v0", "service-"+name+".json"))
	var state statev0.ServiceStateV2
	if err != nil || wire.Decode(data, &state) != nil {
		test.Fatal("landed vector could not decode", err)
	}
	return state
}

func diskState(test *testing.T) statev0.ServiceStateV2 {
	test.Helper()
	state := readVector(test, "utc")
	at := *state.Operations[0].At
	binding := wire.ServiceBindingRecord{ID: strings.Repeat("1", 32), Service: "credential-gateway", UID: 4005, Generation: strings.Repeat("2", 32), Account: fixtureAccount, Kind: "claude-oauth-token", PolicyDigest: "sha256:" + strings.Repeat("a", 64), CreatedBy: state.Operations[0].Principal, OperationID: strings.Repeat("3", 32), CreatedAt: at, State: "active"}
	state.Bindings = append(state.Bindings, binding)
	lease := wire.ServiceLeaseRecord{ID: strings.Repeat("4", 32), BindingID: binding.ID, Service: binding.Service, UID: binding.UID, Generation: binding.Generation, Account: fixtureAccount, Harness: "claude_code", Kind: binding.Kind, AgentUID: 4010, AgentGeneration: strings.Repeat("5", 32), AgentBindingID: strings.Repeat("6", 32), LaunchID: strings.Repeat("7", 32), OperationID: strings.Repeat("8", 32), Until: at.Add(300 * time.Second), State: "active"}
	state.Leases = append(state.Leases, lease)
	state.Operations[0].OperationID = assemblyv0.OperationID(binding.OperationID)
	state.Operations[0].Arguments, _ = wire.Encode(wire.ServiceBind{OperationID: binding.OperationID, ServiceBinding: binding.Binding()})
	state.Operations[0].Result, _ = wire.Encode(map[string]any{"service_binding_id": binding.ID, "service_name": binding.Service, "uid": binding.UID, "service_generation": binding.Generation, "account": binding.Account, "kind": binding.Kind, "installation_policy_digest": binding.PolicyDigest, "state": "active"})
	arguments, _ := wire.Encode(wire.ServiceRequest{OperationID: lease.OperationID, ServiceCaller: lease.Caller()})
	result, _ := wire.Encode(map[string]any{"service_lease_id": lease.ID, "authorized_until": lease.Until})
	state.Operations = append(state.Operations, statev0.ServiceOperationV2{Principal: "4005:" + lease.Generation + ":service:credential-gateway", Method: "service.lease.request", OperationID: assemblyv0.OperationID(lease.OperationID), Arguments: arguments, Result: result, At: &at})
	return state
}

func newDiskFixture(test *testing.T, state statev0.ServiceStateV2, hook store.Durability) diskFixture {
	test.Helper()
	root := filepath.Join(test.TempDir(), "protected-store")
	storage, err := store.Open(root, fixtureInstallation, uint32(os.Getuid()), true, hook)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() {
		if err := storage.Close(); err != nil {
			test.Error(err)
		}
	})
	account, err := storage.Account(fixtureAccount, true)
	if err != nil {
		test.Fatal(err)
	}
	records, err := NewRecords(account)
	if err != nil {
		test.Fatal(err)
	}
	gate := statev0.NewGate()
	pin := readVector(test, "utc").Operations[0].Receipt.TerminalCaller
	journal, err := statev0.NewServiceJournal(gate, fixtureInstallation, map[string]statev0.ServiceRecords{fixtureAccount: records}, []assemblyv0.PrincipalPin{pin})
	if err != nil {
		test.Fatal(err)
	}
	if state.Kind != "" {
		if err := account.Put(serviceRecordName, 0, state); err != nil {
			test.Fatal(err)
		}
		if err := gate.With(context.Background(), func(tx *statev0.Tx) error { return journal.ReconcileLocked(tx, fixtureAccount) }); err != nil {
			test.Fatal("existing-state durability control failed", err)
		}
	}
	sum := sha256.Sum256([]byte(fixtureAccount))
	return diskFixture{gate, journal, records, account, filepath.Join(root, fmt.Sprintf("account-%x", sum), serviceRecordName), pin}
}

func narrow(test *testing.T, state *statev0.ServiceStateV2) {
	test.Helper()
	operation := readVector(test, "boottime").Operations[0]
	operation.Arguments, _ = wire.Encode(wire.ServiceUnbind{OperationID: string(operation.OperationID), BindingID: state.Bindings[0].ID})
	operation.Result, _ = wire.Encode(map[string]any{"service_binding_id": state.Bindings[0].ID, "state": "removed"})
	id := string(operation.OperationID)
	state.Bindings[0].State, state.Bindings[0].RemovedAt, state.Bindings[0].RemovedOperationID = "removed", &state.Watermark, &id
	state.Operations = append(state.Operations, operation)
	state.Revision++
}

// Claim: the real protected-store adapter never initializes a missing committed account, adopts /1, or accepts mode/symlink drift; an explicitly fresh empty store admits /2 once with real durability.
func TestJournalVersionedStoreBoundary(test *testing.T) {
	fixture := newDiskFixture(test, statev0.ServiceStateV2{}, nil)
	empty := readVector(test, "utc")
	empty.Operations = []statev0.ServiceOperationV2{}
	if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
		if _, err := fixture.journal.LoadLocked(tx, fixtureAccount); !errors.Is(err, statev0.ErrUnavailable) {
			test.Fatal("missing journal admitted service state", err)
		}
		return fixture.journal.InitializeLocked(tx, fixtureAccount, empty)
	}); err != nil {
		test.Fatal("fresh /2 initialization failed", err)
	}
	before, err := os.ReadFile(fixture.path)
	if err != nil || !bytes.Contains(before, []byte(statev0.ServiceJournalKind)) {
		test.Fatal("fresh /2 record missing", err)
	}
	if err := os.Chmod(fixture.path, 0644); err != nil {
		test.Fatal(err)
	}
	err = fixture.gate.With(context.Background(), func(tx *statev0.Tx) error { _, err := fixture.journal.LoadLocked(tx, fixtureAccount); return err })
	if !errors.Is(err, statev0.ErrUnavailable) {
		test.Fatal("mode drift accepted", err)
	}
	if err := os.Chmod(fixture.path, 0600); err != nil {
		test.Fatal(err)
	}
	if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error { _, err := fixture.journal.LoadLocked(tx, fixtureAccount); return err }); err != nil {
		test.Fatal("restored mode positive control failed", err)
	}
	saved := fixture.path + ".saved"
	if err := os.Rename(fixture.path, saved); err != nil {
		test.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(saved), fixture.path); err != nil {
		test.Fatal(err)
	}
	err = fixture.gate.With(context.Background(), func(tx *statev0.Tx) error { _, err := fixture.journal.LoadLocked(tx, fixtureAccount); return err })
	if !errors.Is(err, statev0.ErrUnavailable) {
		test.Fatal("symlink journal admitted", err)
	}
	if err := os.Remove(fixture.path); err != nil {
		test.Fatal(err)
	}
	if err := os.Rename(saved, fixture.path); err != nil {
		test.Fatal(err)
	}
	for _, name := range []string{"legacy", "committed-missing"} {
		test.Run(name, func(test *testing.T) {
			fixture := newDiskFixture(test, statev0.ServiceStateV2{}, nil)
			if name == "legacy" {
				legacy := project(readVector(test, "utc"))
				legacy.Kind = "claude-service-journal/1"
				if err := fixture.account.Put(serviceRecordName, 0, legacy); err != nil {
					test.Fatal(err)
				}
			} else {
				metadata := map[string]any{"kind": "fixture-committed-enrollment", "installation_id": fixtureInstallation, "revision": 1}
				if err := fixture.account.Put("owner-metadata.json", 0, metadata); err != nil {
					test.Fatal(err)
				}
			}
			before, err := fixture.account.Records()
			if err != nil {
				test.Fatal(err)
			}
			err = fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
				if _, err := fixture.journal.LoadLocked(tx, fixtureAccount); !errors.Is(err, statev0.ErrUnavailable) {
					test.Fatal("legacy or committed-missing state adopted", err)
				}
				if err := fixture.journal.ReconcileLocked(tx, fixtureAccount); !errors.Is(err, statev0.ErrUnavailable) {
					test.Fatal("legacy or missing committed state reconciled", err)
				}
				return fixture.journal.InitializeLocked(tx, fixtureAccount, empty)
			})
			after, readErr := fixture.account.Records()
			beforeBytes, _ := wire.Encode(before)
			afterBytes, _ := wire.Encode(after)
			if !errors.Is(err, statev0.ErrConflict) || readErr != nil || !bytes.Equal(beforeBytes, afterBytes) {
				test.Fatal("existing account was silently initialized", err, readErr)
			}
		})
	}
}

// Claim: write/file-sync/rename/directory-sync faults never acknowledge a narrowing or publish it as settled; explicit healthy CAS reconciliation confirms only the exact observed durable outcome, never an invented result. This is injected I/O uncertainty, not power-loss qualification.
func TestServiceJournalDurabilityAndReconciliation(test *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		test.Run(stage, func(test *testing.T) {
			fail := false
			var observed []string
			hook := func(current string) error {
				if fail {
					observed = append(observed, current)
					if current == stage {
						return errors.New("synthetic storage fault")
					}
				}
				return nil
			}
			fixture := newDiskFixture(test, diskState(test), hook)
			if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
				prior, err := fixture.journal.LoadLocked(tx, fixtureAccount)
				if err != nil {
					return err
				}
				narrow(test, &prior)
				fail = true
				if err := fixture.journal.CommitLocked(tx, fixtureAccount, prior.Revision-1, prior); !errors.Is(err, statev0.ErrUnavailable) {
					test.Fatal("publication fault acknowledged narrowing", err)
				}
				if len(observed) == 0 || observed[len(observed)-1] != stage {
					test.Fatal("fault plant did not reach its intended durability stage", observed)
				}
				if _, err := fixture.journal.LoadLocked(tx, fixtureAccount); !errors.Is(err, statev0.ErrUnavailable) {
					test.Fatal("uncertain account was not fenced", err)
				}
				fail = false
				if err := fixture.journal.ReconcileLocked(tx, fixtureAccount); err != nil {
					return err
				}
				loaded, err := fixture.journal.LoadLocked(tx, fixtureAccount)
				if err != nil {
					return err
				}
				operation := prior.Operations[len(prior.Operations)-1]
				replayed, err := fixture.journal.ReplayLocked(tx, fixtureAccount, operation.Principal, operation.Method, operation.OperationID, operation.Arguments)
				present := stage == "rename" || stage == "directory-sync"
				if err != nil || (replayed != nil) != present || (loaded.Bindings[0].State == "removed") != present {
					test.Fatal("reconciliation fabricated or lost the observed outcome", stage, err)
				}
				return nil
			}); err != nil {
				test.Fatal(err)
			}
		})
	}
}

type inertCustody struct {
	publications int
	before       func()
}

func (*inertCustody) ExpiresAt() (*time.Time, error) { return nil, nil }
func (*inertCustody) ServiceAccount() (wire.ServiceAccount, error) {
	return wire.ServiceAccount{Account: fixtureAccount, Harness: "claude_code", Kind: "claude-oauth-token", State: "active"}, nil
}
func (custody *inertCustody) Publish(_ context.Context, _ time.Time, _ func() time.Time, deliver func([]byte) error) error {
	custody.publications++
	if custody.before != nil {
		custody.before()
	}
	return deliver([]byte("inert-fixture-material"))
}

// Claim: the explicit /2-to-service.Account bridge preserves operator receipt and at:null across projections, refuses /1 and unreceipted operator additions, and cannot be used outside the issuing callback.
func TestJournalAccountVersionProjection(test *testing.T) {
	fixture := newDiskFixture(test, diskState(test), nil)
	account, err := NewJournalAccount(fixture.gate, fixture.journal, fixtureAccount, &inertCustody{})
	if err != nil {
		test.Fatal(err)
	}
	var escaped *JournalAccount
	if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
		bound, err := account.Locked(tx, nil)
		if err != nil {
			return err
		}
		escaped = bound
		state, err := bound.LoadServiceState()
		if err != nil || state.Kind != statev0.ServiceJournalKind {
			test.Fatal("bridge pretended to be /1", err)
		}
		state.Revision++
		if err := bound.StoreServiceState(state); err != nil {
			return err
		}
		state.Revision++
		state.Kind = "claude-service-journal/1"
		if err := bound.StoreServiceState(state); !errors.Is(err, statev0.ErrConflict) {
			test.Fatal("bridge accepted legacy journal adoption", err)
		}
		current, err := fixture.journal.LoadLocked(tx, fixtureAccount)
		if err != nil {
			return err
		}
		narrow(test, &current)
		projection := project(current)
		if err := bound.StoreServiceState(projection); !errors.Is(err, statev0.ErrConflict) {
			test.Fatal("unreceipted new operator operation passed", err)
		}
		bound, err = account.Locked(tx, current.Operations[len(current.Operations)-1].Receipt)
		if err != nil {
			return err
		}
		if err := bound.StoreServiceState(projection); err != nil {
			return err
		}
		reprojected, err := bound.LoadServiceState()
		if err != nil || !reprojected.Operations[len(reprojected.Operations)-1].At.IsZero() {
			test.Fatal("nullable time was fabricated", err)
		}
		reprojected.Revision++
		if err := bound.StoreServiceState(reprojected); err != nil {
			return err
		}
		loaded, err := fixture.journal.LoadLocked(tx, fixtureAccount)
		if err != nil || loaded.Operations[len(loaded.Operations)-1].At != nil || loaded.Operations[len(loaded.Operations)-1].Receipt == nil || loaded.Operations[0].Receipt == nil {
			test.Fatal("projection lost retained receipt or null", err)
		}
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	for _, invalid := range []*JournalAccount{account, escaped, nil} {
		if _, err := invalid.LoadServiceState(); err == nil {
			test.Fatal("unbound or escaped bridge remained usable")
		}
	}
}

// Claim: final service material delivery and removal share the injected state gate: removal cannot acknowledge during delivery, and the next release observes the durable removal. The fixture has inert bytes and makes no live custody claim.
func TestSharedServicePublicationBoundary(test *testing.T) {
	fixture := newDiskFixture(test, diskState(test), nil)
	custody := &inertCustody{}
	account, err := NewJournalAccount(fixture.gate, fixture.journal, fixtureAccount, custody)
	if err != nil {
		test.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC) }
	until := clock().Add(time.Minute)
	entered, release, attempt := make(chan struct{}), make(chan struct{}), make(chan struct{})
	publication, removal := make(chan error, 1), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		publication <- fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
			bound, err := account.ForLeaseLocked(tx, strings.Repeat("4", 32))
			if err != nil {
				return err
			}
			return bound.Publish(context.Background(), until, clock, func(material []byte) error {
				if string(material) != "inert-fixture-material" {
					return errors.New("inert material control mismatch")
				}
				close(entered)
				<-release
				return nil
			})
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		test.Fatal("positive material control did not enter")
	}
	go func() {
		close(attempt)
		removal <- fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
			state, err := fixture.journal.LoadLocked(tx, fixtureAccount)
			if err != nil {
				return err
			}
			narrow(test, &state)
			return fixture.journal.CommitLocked(tx, fixtureAccount, state.Revision-1, state)
		})
	}()
	<-attempt
	select {
	case err := <-removal:
		test.Fatal("removal escaped the shared publication boundary", err)
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	for _, done := range []chan error{publication, removal} {
		select {
		case err := <-done:
			if err != nil {
				test.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			test.Fatal("shared gate did not release")
		}
	}
	if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
		bound, err := account.ForLeaseLocked(tx, strings.Repeat("4", 32))
		if err != nil {
			return err
		}
		return bound.Publish(context.Background(), until, clock, func([]byte) error { test.Error("removed binding released material"); return nil })
	}); !errors.Is(err, statev0.ErrUnavailable) || custody.publications != 1 {
		test.Fatal("successor release did not observe narrowing", err, custody.publications)
	}
}

// Claim: cancellation immediately before the final callback prevents delivery despite a healthy preceding release control, without journal mutation.
func TestServicePublicationCancellation(test *testing.T) {
	fixture := newDiskFixture(test, diskState(test), nil)
	custody := &inertCustody{}
	account, err := NewJournalAccount(fixture.gate, fixture.journal, fixtureAccount, custody)
	if err != nil {
		test.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC) }
	for _, cancelled := range []bool{false, true} {
		deliveries := 0
		ctx, cancel := context.WithCancel(context.Background())
		custody.before = nil
		if cancelled {
			custody.before = cancel
		}
		err := fixture.gate.With(ctx, func(tx *statev0.Tx) error {
			bound, err := account.ForLeaseLocked(tx, strings.Repeat("4", 32))
			if err != nil {
				return err
			}
			return bound.Publish(ctx, clock().Add(time.Minute), clock, func([]byte) error { deliveries++; return nil })
		})
		cancel()
		if !cancelled && (err != nil || deliveries != 1) || cancelled && (!errors.Is(err, context.Canceled) || deliveries != 0) {
			test.Fatal("final delivery cancellation boundary failed", cancelled, err, deliveries)
		}
	}
}

// Claim: inert delivery succeeds, but a delivery that re-enters the live account refuses with ErrTransaction instead of deadlocking; both refusal and cancellation release the shared gate for a successor.
func TestServicePublicationReentryRefuses(test *testing.T) {
	for _, name := range []string{"inert", "reentrant", "cancelled-reentrant"} {
		test.Run(name, func(test *testing.T) {
			fixture := newDiskFixture(test, diskState(test), nil)
			account, err := NewJournalAccount(fixture.gate, fixture.journal, fixtureAccount, &inertCustody{})
			if err != nil {
				test.Fatal(err)
			}
			clock := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC) }
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			deliveries := 0
			go func() {
				done <- fixture.gate.With(ctx, func(tx *statev0.Tx) error {
					bound, err := account.ForLeaseLocked(tx, strings.Repeat("4", 32))
					if err != nil {
						return err
					}
					return bound.Publish(ctx, clock().Add(time.Minute), clock, func([]byte) error {
						deliveries++
						if name == "inert" {
							return nil
						}
						if name == "cancelled-reentrant" {
							cancel()
						}
						_, err := bound.ServiceAccount()
						return err
					})
				})
			}()
			select {
			case err := <-done:
				if deliveries != 1 || name == "inert" && err != nil || name != "inert" && !errors.Is(err, statev0.ErrTransaction) {
					test.Fatal("live-account delivery reentry did not refuse", err)
				}
			case <-time.After(2 * time.Second):
				test.Fatal("live-account delivery reentry deadlocked past its deadline")
			}
			successor, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := fixture.gate.With(successor, func(tx *statev0.Tx) error { return statev0.Check(tx, fixture.gate) }); err != nil {
				test.Fatal("delivery reentry or cancellation stranded the gate", err)
			}
		})
	}
}

// Claim: a valid active hold blocks final inert material release without a write, both before custody and when placed at the final recheck; the same unheld account delivers once.
func TestServicePublicationRefusesActiveHold(test *testing.T) {
	for _, name := range []string{"unheld", "held", "held-before-delivery"} {
		test.Run(name, func(test *testing.T) {
			fixture := newDiskFixture(test, diskState(test), nil)
			custody := &inertCustody{}
			account, err := NewJournalAccount(fixture.gate, fixture.journal, fixtureAccount, custody)
			if err != nil {
				test.Fatal(err)
			}
			clock := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC) }
			deliveries := 0
			if err := fixture.gate.With(context.Background(), func(tx *statev0.Tx) error {
				var expected []byte
				place := func() {
					state, err := fixture.journal.LoadLocked(tx, fixtureAccount)
					if err != nil {
						test.Fatal(err)
					}
					lease := state.Leases[0]
					identifier := strings.Repeat("e", 32)
					hold := wire.AccountHoldRecord{ID: strings.Repeat("f", 32), Account: fixtureAccount, Reason: "leak_match", Service: lease.Service, UID: lease.UID, Generation: lease.Generation, BindingID: lease.BindingID, LeaseID: lease.ID, OperationID: identifier, PlacedAt: state.Watermark, State: "active"}
					arguments, _ := wire.Encode(wire.ServiceHold{OperationID: identifier, LeaseID: lease.ID, Account: fixtureAccount, Reason: "leak_match"})
					result, _ := wire.Encode(hold.Metadata())
					state.Holds = append(state.Holds, hold)
					state.Operations = append(state.Operations, statev0.ServiceOperationV2{Principal: "4005:" + lease.Generation + ":service:credential-gateway", Method: "account.hold", OperationID: assemblyv0.OperationID(identifier), Arguments: arguments, Result: result, At: &state.Watermark})
					state.Revision++
					if err := fixture.journal.CommitLocked(tx, fixtureAccount, state.Revision-1, state); err != nil {
						test.Fatal("valid hold control failed", err)
					}
					expected, err = os.ReadFile(fixture.path)
					if err != nil {
						test.Fatal(err)
					}
				}
				if name == "held" {
					place()
				} else if name == "held-before-delivery" {
					custody.before = place
				}
				bound, err := account.ForLeaseLocked(tx, strings.Repeat("4", 32))
				if err != nil {
					return err
				}
				expected, err = os.ReadFile(fixture.path)
				if err != nil {
					return err
				}
				err = bound.Publish(context.Background(), clock().Add(time.Minute), clock, func([]byte) error { deliveries++; return nil })
				if name == "unheld" {
					if err != nil || deliveries != 1 || custody.publications != 1 {
						test.Fatal("unheld delivery control failed", err, deliveries)
					}
				} else if !errors.Is(err, statev0.ErrUnavailable) || deliveries != 0 {
					test.Fatal("held account released material through the bridge", err, deliveries)
				}
				after, readErr := os.ReadFile(fixture.path)
				if readErr != nil || !bytes.Equal(expected, after) {
					test.Fatal("publication refusal changed durable state", readErr)
				}
				if name == "held-before-delivery" {
					state, err := fixture.journal.LoadLocked(tx, fixtureAccount)
					if err != nil || len(state.Holds) != 1 || state.Holds[0].State != "active" || len(state.Operations) != 3 {
						test.Fatal("final refusal lost held-state evidence", err)
					}
				}
				return nil
			}); err != nil {
				test.Fatal(err)
			}
		})
	}
}
