package statev0

import (
	"bytes"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

var errContract = errors.New("invalid construction port contract")

func checkPortContract(source []byte) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), "ports.go", source, 0)
	if err != nil {
		return errContract
	}
	expected := map[string]string{
		"Gate.With":                    "func(context.Context, func(*Tx) error) error",
		"NonceStore.ConsumeLocked":     "func(*Tx, assemblyv0.TerminalReceipt) error",
		"ServiceJournal.LoadLocked":    "func(*Tx, string) (ServiceStateV2, error)",
		"ServiceJournal.CommitLocked":  "func(*Tx, string, uint64, ServiceStateV2) error",
		"ServiceJournal.ReserveLocked": "func(*Tx, string, ServiceStateV2) error",
		"RevocationStore.ReadLocked":   "func(*Tx) (RevocationState, error)",
		"RevocationStore.PutLocked":    "func(*Tx, RevocationState) error",
	}
	found := map[string]string{}
	for _, declaration := range parsed.Decls {
		if _, implemented := declaration.(*ast.FuncDecl); implemented {
			return errContract
		}
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, specification := range general.Specs {
			declared, ok := specification.(*ast.TypeSpec)
			if !ok {
				continue
			}
			port, ok := declared.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}
			for _, method := range port.Methods.List {
				if len(method.Names) != 1 {
					return errContract
				}
				var formatted bytes.Buffer
				if format.Node(&formatted, token.NewFileSet(), method.Type) != nil {
					return errContract
				}
				found[declared.Name.Name+"."+method.Names[0].Name] = formatted.String()
			}
		}
	}
	if !reflect.DeepEqual(expected, found) {
		return errContract
	}
	return nil
}

// Claim: the shared serialization API is frozen and declaration-only; Tx exposes no forgeable authority fields. Runtime token checks belong to U05.
func TestSharedGateContract(test *testing.T) {
	source, err := os.ReadFile("ports.go")
	if err != nil || checkPortContract(source) != nil {
		test.Fatal("shared gate/locked method contract changed")
	}
	transaction := reflect.TypeFor[Tx]()
	if transaction.NumField() == 0 {
		test.Fatal("transaction lacks its opaque scope")
	}
	for position := 0; position < transaction.NumField(); position++ {
		if transaction.Field(position).IsExported() {
			test.Fatal("transaction exposes authority state")
		}
	}
	if !reflect.ValueOf(Tx{}).IsZero() {
		test.Fatal("zero transaction is not inert")
	}
}

// Claim: removing the callback token or a Locked token is detected by this structural instrument, not by a fabricated runtime gate.
func TestSharedGatePlantControls(test *testing.T) {
	source, err := os.ReadFile("ports.go")
	if err != nil || checkPortContract(source) != nil {
		test.Fatal("valid port control refused")
	}
	for _, original := range []string{"func(*Tx) error", "ReadLocked(*Tx)"} {
		planted := bytes.Replace(source, []byte(original), []byte(strings.Replace(original, "*Tx", "any", 1)), 1)
		if bytes.Equal(planted, source) || !errors.Is(checkPortContract(planted), errContract) {
			test.Fatal("token-removing plant was not detected")
		}
	}
}

func journalControls() []any {
	return []any{
		NonceState{"swarma-broker-operator-nonces/1", "fixture-installation-v0", 1, []ConsumedNonce{}},
		RevocationState{"swarma-broker-revocations/1", "fixture-installation-v0", 1, BaselineRevocationState{0, []assemblyv0.RevocationEnvelope{}}},
		ServiceStateV2{
			Kind: "claude-service-journal/2", InstallationID: "fixture-installation-v0", Revision: 1,
			Watermark: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Bindings: []wire.ServiceBindingRecord{},
			Leases: []wire.ServiceLeaseRecord{}, Holds: []wire.AccountHoldRecord{}, Operations: []ServiceOperationV2{},
		},
	}
}

// Claim: complete declared journal schemas preserve explicit empty arrays and the sole zero revocation sequence, rejecting missing/null/extra members beside valid controls.
func TestJournalSchemaControls(test *testing.T) {
	for _, control := range journalControls() {
		encoded, err := wire.Encode(control)
		if err != nil {
			test.Fatal("cannot encode valid journal control")
		}
		newTarget := func() any { return reflect.New(reflect.TypeOf(control)).Interface() }
		decoded := newTarget()
		if wire.Decode(encoded, decoded) != nil {
			test.Fatal("valid journal schema refused")
		}
		roundTrip, err := wire.Encode(decoded)
		if err != nil || !bytes.Equal(encoded, roundTrip) {
			test.Fatal("journal bytes changed on round trip")
		}
		members, err := wire.Parse(encoded)
		if err != nil {
			test.Fatal("invalid canonical journal control")
		}
		for member := range members {
			modified, _ := wire.Parse(encoded)
			delete(modified, member)
			data, err := wire.Encode(modified)
			if err != nil || !errors.Is(wire.Decode(data, newTarget()), wire.ErrMalformed) {
				test.Fatal("missing required journal member accepted")
			}
			modified, _ = wire.Parse(encoded)
			modified[member] = nil
			data, err = wire.Encode(modified)
			if err != nil || !errors.Is(wire.Decode(data, newTarget()), wire.ErrMalformed) {
				test.Fatal("null journal member accepted")
			}
		}
		members["unpublished_member"] = true
		data, err := wire.Encode(members)
		if err != nil || !errors.Is(wire.Decode(data, newTarget()), wire.ErrMalformed) {
			test.Fatal("extra journal member accepted")
		}
	}
}

// Claim: /2's required nullable receipt cannot be dropped into the legacy /1 operation schema, and forbidden token-verifier fields stay absent.
func TestServiceJournalVersionContract(test *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	operation := ServiceOperationV2{
		Principal: "fixture-service", Method: "service.unbind", OperationID: "00112233445566778899aabbccddeeff",
		Arguments: []byte(`{"operation_id":"00112233445566778899aabbccddeeff","service_binding_id":"11223344556677889900aabbccddeeff"}`),
		Result:    []byte(`{"service_binding_id":"11223344556677889900aabbccddeeff"}`), At: &at, Receipt: nil,
	}
	encoded, err := wire.Encode(operation)
	if err != nil {
		test.Fatal("invalid versioned operation control")
	}
	var current ServiceOperationV2
	if wire.Decode(encoded, &current) != nil || !bytes.Contains(encoded, []byte(`"receipt":null`)) {
		test.Fatal("required nullable receipt lost")
	}
	var legacy wire.ServiceOperation
	if !errors.Is(wire.Decode(encoded, &legacy), wire.ErrMalformed) {
		test.Fatal("legacy operation accepted versioned receipt")
	}
	withoutReceipt, _ := wire.Parse(encoded)
	delete(withoutReceipt, "receipt")
	legacyBytes, err := wire.Encode(withoutReceipt)
	if err != nil || wire.Decode(legacyBytes, &legacy) != nil || !errors.Is(wire.Decode(legacyBytes, &current), wire.ErrMalformed) {
		test.Fatal("version boundary failed adjacent control")
	}
	for _, forbidden := range []string{"act_id", "act_ids", "argument_commitment", "token_sha256_prefix", "token"} {
		modified, _ := wire.Parse(encoded)
		modified[forbidden] = "synthetic-forbidden-field"
		data, err := wire.Encode(modified)
		if err != nil || !errors.Is(wire.Decode(data, &current), wire.ErrMalformed) {
			test.Fatal("service journal accepted a forbidden verifier member")
		}
	}
}
