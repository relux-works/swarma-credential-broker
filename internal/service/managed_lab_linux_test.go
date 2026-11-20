//go:build linux && broker_lab

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func labManagedFixture(test *testing.T) (*LabManagedAuthority, *managedFixture, *authorityFixture) {
	test.Helper()
	fixture := newManagedFixture(test)
	raw := managedBytes(test, "journal.jsonl")
	view, err := genjournal.Verify(bytes.NewReader(raw), genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil {
		test.Fatal(err)
	}
	workerGeneration := strings.Repeat("2", 32)
	for _, state := range []string{"creating", "active"} {
		record, err := genjournal.Encode(genjournal.Record{Seq: view.Tail.Seq + 1, Prev: view.Tail.Hash, UID: 30002, Generation: workerGeneration, State: state, Writer: "operator-manual", Time: "2026-11-20T00:00:00Z"})
		if err != nil {
			test.Fatal(err)
		}
		raw = append(raw, record...)
		view, err = genjournal.Verify(bytes.NewReader(raw), genjournal.Floor{Hash: genjournal.ZeroHash})
		if err != nil {
			test.Fatal(err)
		}
	}
	managedWrite(test, filepath.Join(fixture.journal, "journal"), raw)
	accounts := []managedAccount{
		{UID: managedFixtureUID, Kind: "service", Name: Gateway, Class: "trusted", Placement: "local", Generation: managedFixtureGeneration, State: "active"},
		{UID: 30002, Kind: "agent", Name: "synthetic-worker", Class: "trusted", Placement: "local", Generation: workerGeneration, State: "active"},
	}
	projection, _ := wire.Encode(managedDocument{Format: "swarma-managed-identities/1", JournalHead: view.Tail.Hash, Accounts: accounts})
	managedWrite(test, filepath.Join(fixture.parent, "identities.json"), projection)
	binding := wire.ServiceBinding{UID: managedFixtureUID, Service: Gateway, Generation: managedFixtureGeneration, Account: "lab/anthropic", Kind: LabKind, PolicyDigest: strings.Repeat("a", 64)}
	caller := wire.ServiceCaller{Account: binding.Account, UID: 30002, Generation: workerGeneration, LaunchID: "synthetic-start"}
	facts := &authorityFixture{binding: binding, caller: caller, serviceOK: true, callerOK: true, local: true, available: true, mode: "secret-free", callerUntil: time.Now().Add(time.Hour), bindingID: "synthetic-binding", confirmed: true, principals: map[uint32]Principal{binding.UID: {UID: binding.UID, Generation: binding.Generation, Role: "service", Service: Gateway}, caller.UID: {UID: caller.UID, Generation: caller.Generation, Role: "worker"}}}
	result, err := NewLabManagedAuthority(filepath.Dir(filepath.Dir(fixture.parent)), facts, LabManagedPins{Gateway: binding, Worker: caller, ManagerSequence: view.Tail.Seq, ManagerHash: view.Tail.Hash})
	if err != nil {
		test.Fatal(err)
	}
	result.managed.policy = fixture.authority.policy
	return result, fixture, facts
}

// Claim: the tagged adapter reuses the protected native projection/journal for service identity and active native agent-as-worker facts; stale UID generation, class, placement, kind, prefix, and JSON-root spoofing refuse beside the valid composed view.
func TestLabManagedAuthorityPairs(test *testing.T) {
	for _, mode := range []string{"valid", "worker-principal", "root-json-spoof", "worker-kind", "cold-worker-kind", "worker-class", "worker-placement", "worker-generation", "worker-state", "gateway-class", "gateway-generation", "manager-head", "pending-writer"} {
		test.Run(mode, func(test *testing.T) {
			authority, fixture, facts := labManagedFixture(test)
			control := func(view View) error {
				if _, err := view.Principal(facts.binding.UID); err != nil {
					return err
				}
				if err := view.Service(facts.binding); err != nil {
					return err
				}
				_, _, err := view.Caller(facts.binding, facts.caller)
				return err
			}
			if err := authority.WithCurrent(context.Background(), control); err != nil {
				test.Fatal("valid composed managed facts", err)
			}
			if mode == "valid" {
				return
			}
			path := filepath.Join(fixture.parent, "identities.json")
			var projection managedDocument
			raw, _ := os.ReadFile(path)
			if json.Unmarshal(raw, &projection) != nil {
				test.Fatal("projection fixture")
			}
			switch mode {
			case "worker-principal":
				err := authority.WithIdentity(context.Background(), func(view View) error { _, err := view.Principal(facts.caller.UID); return err })
				if err == nil {
					test.Fatal("worker admitted as gateway")
				}
				return
			case "root-json-spoof":
				err := authority.WithIdentity(context.Background(), func(view View) error {
					if view.OperatorAct(Principal{UID: facts.binding.UID, Generation: "lab-root", Role: "operator"}, "service.bind", nil) {
						test.Fatal("JSON root spoof admitted")
					}
					return nil
				})
				if err != nil {
					test.Fatal(err)
				}
				return
			case "worker-kind", "cold-worker-kind":
				projection.Accounts[1].Kind = "workplace"
			case "worker-class":
				projection.Accounts[1].Class = "untrusted"
			case "worker-placement":
				projection.Accounts[1].Placement = "remote"
			case "worker-generation":
				projection.Accounts[1].Generation = strings.Repeat("3", 32)
			case "worker-state":
				projection.Accounts[1].State = "retired"
			case "gateway-class":
				projection.Accounts[0].Class = "untrusted"
			case "gateway-generation":
				projection.Accounts[0].Generation = strings.Repeat("3", 32)
			case "manager-head":
				authority.pins.ManagerHash = strings.Repeat("a", 64)
			case "pending-writer":
				managedWrite(test, filepath.Join(fixture.journal, "writer.pending"), []byte("pending"))
			}
			raw, _ = wire.Encode(projection)
			managedWrite(test, path, raw)
			if mode == "cold-worker-kind" {
				cold, err := NewLabManagedAuthority(authority.managed.root, facts, authority.pins)
				if err != nil {
					test.Fatal(err)
				}
				cold.managed.policy = authority.managed.policy
				authority = cold
			}
			if err := authority.WithCurrent(context.Background(), control); err == nil {
				test.Fatal("invalid managed facts admitted")
			}
		})
	}
}
