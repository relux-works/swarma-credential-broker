package assemblyv0

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Claim: these literal spec member sets freeze every declared JSON struct tag, including the only two optional members; golden regeneration cannot add a field.
func TestConstructionSpecMemberSets(test *testing.T) {
	cases := []struct {
		value  any
		tags   string
		source string
	}{
		{PrincipalPin{}, "uid name home", "S:417,792,795"},
		{BrokerPin{}, "uid gid name home", "S:791"},
		{UTCFreshness{}, "kind not_before expires_at", "S:424-427"},
		{BoottimeFreshness{}, "kind boot_id not_before_ms expires_at_ms", "S:428-433"},
		{Continuity{}, "kind", "S:1425-1427"},
		{EntryPin{}, "path digest", "S:793"},
		{LoginPath{}, "kind implementation executable_digest config_digest", "S:796"},
		{TerminalAuth{}, "sudo_digest sudoers_digest pam_service pam_digest witness_digest confinement_digest launcher_digest trusted_path_digest login_paths", "S:796"},
		{DispatcherPin{}, "uid generation key", "S:800"},
		{AccountPolicy{}, "account owner_uid harness kind mode test_subscription", "S:801"},
		{AuthorityDocument{}, "format installation_id revision broker operator observer operator_entry operator_key terminal_callers terminal_auth continuity event_schema root_keys dispatchers accounts", "S:790-801"},
		{ActivationDocument{}, "format enabled test_profile installation_id platform_root service_name kind authority_digest continuity service_lease_max_lifetime_seconds,omitempty", "S:1414-1423,1506-1515"},
		{LoginSession{}, "kind id loginuid login_pid login_start_ticks login_executable_digest", "S:830-834"},
		{TTYDevice{}, "major minor", "S:838-839"},
		{SessionAccountPolicy{}, "account test_subscription", "S:360-362"},
		{TerminalSession{}, "format installation_id authority_revision authority_digest nonce operator terminal_caller broker_uid socket_path freshness tty_device account_policy continuity", "S:355-362"},
		{TerminalReceipt{}, "format installation_id authority_revision authority_digest act_id nonce operator_uid terminal_caller login_session boot_id peer_pid peer_start_ticks executable_digest tty_device freshness authentication confirmation", "S:827-834"},
		{BindArguments{}, "operation_id service_name uid service_generation account kind installation_policy_digest", "S:454-457"},
		{EnrolArguments{}, "operation_id account harness kind token_expires_at token_sha256_prefix", "S:458-474"},
		{EnrolCandidateArguments{}, "operation_id account harness kind token_expires_at", "S:108-113,458-468"},
		{UnbindArguments{}, "operation_id service_binding_id", "S:477-483"},
		{LiftArguments{}, "operation_id hold_id account", "S:485-488"},
		{OperatorCandidate{}, "method arguments", "S:95-96"},
		{OperatorBody{}, "format installation_id authority_revision authority_digest operator operation_id nonce freshness method arguments", "S:411-422"},
		{OperatorEnvelope{}, "body id sig", "S:435-446"},
		{OperatorRequest{}, "act receipt_nonce token", "S:518-529"},
		{LeaseEvent{}, "kind", "S:1055-1061"},
		{CredentialErrorEvent{}, "kind class", "S:1055-1061"},
		{GrantBody{}, "type issuer subject actions accounts harnesses profiles not_before expires_at depth parent", "broker.md:367-389"},
		{GrantEnvelope{}, "body id sig", "broker.md:367-389"},
		{GrantTarget{}, "grant", "broker.md:417-429"},
		{KeyTarget{}, "key", "broker.md:417-429"},
		{RevocationBody{}, "type revokes by at reason,omitempty", "broker.md:417-429"},
		{RevocationEnvelope{}, "body id sig", "broker.md:417-429"},
	}
	for _, entry := range cases {
		declared := reflect.TypeOf(entry.value)
		test.Run(declared.Name(), func(test *testing.T) {
			var tags []string
			for position := 0; position < declared.NumField(); position++ {
				tags = append(tags, declared.Field(position).Tag.Get("json"))
			}
			if strings.Join(tags, " ") != entry.tags {
				test.Fatalf("member/tag set differs from %s: %v", entry.source, tags)
			}
		})
	}
}

// Claim: S:96,113,1409 accept exactly 16 KiB and refuse 16 KiB+1 for otherwise valid candidate and activation fixtures; this is not a reader/deadline check.
func TestConstructionSizeBounds(test *testing.T) {
	for _, name := range []string{"activation-default.json", "candidate-enrol.json"} {
		test.Run(name, func(test *testing.T) {
			vector := constructionVectors()[name]
			control := fixtureTree(vector.bytes)
			object := control
			member := "installation_id"
			if name == "candidate-enrol.json" {
				object = control["arguments"].(map[string]any)
				member = "account"
			}
			original := object[member].(string)
			object[member] = original + strings.Repeat("x", 16*1024-len(vector.bytes))
			valid := canonicalBytes(control)
			if len(valid) != 16*1024 || decodeFixture(valid, reflect.New(reflect.TypeOf(vector.value)).Interface()) != nil {
				test.Fatal("exact size boundary valid control refused")
			}
			object[member] = object[member].(string) + "x"
			invalid := canonicalBytes(control)
			if len(invalid) != 16*1024+1 || !errors.Is(decodeFixture(invalid, reflect.New(reflect.TypeOf(vector.value)).Interface()), errFixture) {
				test.Fatal("oversized neighbor accepted")
			}
			if !bytes.Equal(invalid, canonicalBytes(control)) {
				test.Fatal("size refusal changed input")
			}
		})
	}
}

// Claim: S:499-503 hashing uses literal CCJ-1 UTF-8, not an escaped display; actual reversible display and terminal safety remain U13/U15 obligations.
func TestUnicodeActBytes(test *testing.T) {
	vectors := constructionVectors()
	body := vectors["act-lift-unicode.body.json"].bytes
	preimage := vectors["act-lift-unicode.preimage"].bytes
	if !bytes.Contains(body, []byte("λ")) || !bytes.Contains(body, []byte("😀")) || !bytes.Equal(preimage, append([]byte("swarma-credential-broker operator-act/1\n"), body...)) {
		test.Fatal("act lost literal UTF-8 bytes")
	}
	display := bytes.ReplaceAll(preimage, []byte("λ"), []byte(`\u03bb`))
	display = bytes.ReplaceAll(display, []byte("😀"), []byte(`\ud83d\ude00`))
	if bytes.Equal(display, preimage) || digestBytes(display) == digestBytes(preimage) {
		test.Fatal("escaped display was treated as signed bytes")
	}
}
