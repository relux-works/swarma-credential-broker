package statev0

import (
	"bytes"
	"errors"
	"flag"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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

func journalControls(test *testing.T) map[string]any {
	test.Helper()
	controls := map[string]any{
		"nonces-empty":      NonceState{"swarma-broker-operator-nonces/1", "fixture-installation-v0", 1, []ConsumedNonce{}},
		"revocations-empty": RevocationState{"swarma-broker-revocations/1", "fixture-installation-v0", 1, BaselineRevocationState{0, []assemblyv0.RevocationEnvelope{}}},
		"service-empty": ServiceStateV2{
			Kind: "claude-service-journal/2", InstallationID: "fixture-installation-v0", Revision: 1,
			Watermark: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Bindings: []wire.ServiceBindingRecord{},
			Leases: []wire.ServiceLeaseRecord{}, Holds: []wire.AccountHoldRecord{}, Operations: []ServiceOperationV2{},
		},
	}
	controls["nonces-nonempty"] = NonceState{"swarma-broker-operator-nonces/1", "fixture-installation-v0", 1, []ConsumedNonce{{"00112233445566778899aabbccddeeff", "11111111-2222-4333-8444-555555555555", 101, 1235}}}
	for _, kind := range []string{"utc", "boottime"} {
		name := "act-bind.receipt.json"
		method := "service.bind"
		arguments := []byte(`{"account":"fixture/claude/subscription","installation_policy_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","kind":"claude-oauth-token","operation_id":"00112233445566778899aabbccddeeff","service_generation":"00112233445566778899aabbccddeeff","service_name":"credential-gateway","uid":4005}`)
		result := []byte(`{"account":"fixture/claude/subscription","installation_policy_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","kind":"claude-oauth-token","service_binding_id":"11223344556677889900aabbccddeeff","service_generation":"00112233445566778899aabbccddeeff","service_name":"credential-gateway","state":"active","uid":4005}`)
		at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		var timestamp *time.Time = &at
		if kind == "boottime" {
			name = "act-unbind.receipt.json"
			method = "service.unbind"
			arguments = []byte(`{"operation_id":"00112233445566778899aabbccddeeff","service_binding_id":"11223344556677889900aabbccddeeff"}`)
			result = []byte(`{"service_binding_id":"11223344556677889900aabbccddeeff","state":"removed"}`)
			timestamp = nil
		}
		data, err := os.ReadFile(filepath.Join("..", "assemblyv0", "testdata", "construction-v0", name))
		parsed, parseErr := wire.Parse(append(append([]byte(`{"receipt":`), data...), byte(125)))
		var receipt OperationReceipt
		if err != nil || parseErr != nil {
			test.Fatal("cannot decode non-empty receipt source control")
		}
		source := parsed["receipt"].(map[string]any)
		if kind == "utc" {
			arguments = bytes.ReplaceAll(arguments, []byte("sha256:"+strings.Repeat("0", 64)), []byte(source["authority_digest"].(string)))
			result = bytes.ReplaceAll(result, []byte("sha256:"+strings.Repeat("0", 64)), []byte(source["authority_digest"].(string)))
		}
		projected := map[string]any{}
		for _, member := range []string{"nonce", "terminal_caller", "boot_id", "peer_pid", "peer_start_ticks", "freshness"} {
			projected[member] = source[member]
		}
		receiptBytes, err := wire.Encode(projected)
		if err != nil || wire.Decode(receiptBytes, &receipt) != nil {
			test.Fatal("declared non-empty receipt cannot decode")
		}
		operation := ServiceOperationV2{
			Principal: "4002::operator:", Method: method, OperationID: "00112233445566778899aabbccddeeff", Arguments: arguments, Result: result, At: timestamp,
			Receipt: &receipt,
		}
		journal := controls["service-empty"].(ServiceStateV2)
		journal.Operations = []ServiceOperationV2{operation}
		controls["service-"+kind] = journal
	}
	records := []assemblyv0.RevocationEnvelope{}
	for _, kind := range []string{"grant", "key"} {
		name := "revocation-" + kind + ".json"
		if kind == "key" {
			name = "revocation-key-reason.json"
		}
		data, err := os.ReadFile(filepath.Join("..", "assemblyv0", "testdata", "construction-v0", name))
		var state BaselineRevocationState
		wrapped := append(append([]byte(`{"records":[`), data...), []byte(`],"seq":1}`)...)
		if err != nil || wire.Decode(wrapped, &state) != nil || len(state.Records) != 1 {
			test.Fatal("cannot decode non-empty revocation source control")
		}
		records = append(records, state.Records[0])
	}
	controls["revocations-nonempty"] = RevocationState{"swarma-broker-revocations/1", "fixture-installation-v0", 1, BaselineRevocationState{2, records}}
	return controls
}

// Claim: these empty and non-empty journal fixtures round-trip through the declared record codecs; top-level missing/null/extra members refuse. This is not a production loader.
func TestJournalSchemaControls(test *testing.T) {
	for name, control := range journalControls(test) {
		test.Run(name, func(test *testing.T) {
			encoded, err := wire.Encode(control)
			if err != nil {
				test.Fatal("cannot encode valid journal control")
			}
			newTarget := func() any { return reflect.New(reflect.TypeOf(control)).Interface() }
			decoded := newTarget()
			if wire.Decode(encoded, decoded) != nil || !reflect.DeepEqual(control, reflect.ValueOf(decoded).Elem().Interface()) {
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
		})
	}
}

var updateStateVectors = flag.Bool("update-state-vectors", false, "rewrite synthetic non-empty journal vectors after source review")

// Claim: /2 UTC and narrowing BOOTTIME receipts and both signed revocation targets have exact non-empty byte controls (S:774-776,892-895).
func TestJournalNonEmptyVectors(test *testing.T) {
	controls := journalControls(test)
	for _, name := range []string{"service-utc", "service-boottime", "revocations-nonempty"} {
		test.Run(name, func(test *testing.T) {
			encoded, err := wire.Encode(controls[name])
			if err != nil {
				test.Fatal(err)
			}
			filename := filepath.Join("testdata", "construction-v0", name+".json")
			if *updateStateVectors {
				if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
					test.Fatal(err)
				}
				if err := os.WriteFile(filename, encoded, 0644); err != nil {
					test.Fatal(err)
				}
			}
			stored, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(stored, encoded) {
				test.Fatal("non-empty journal vector differs")
			}
		})
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
