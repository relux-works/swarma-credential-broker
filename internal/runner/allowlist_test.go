//go:build linux

package runner

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

func allowlistTuple() wire.AllowlistRequest {
	return wire.AllowlistRequest{TargetUID: 42, Account: "example", Profile: "example", Harness: "codex_cli", Channel: "external-token", Binding: wire.Binding{Digest: "binding", Harness: "codex_cli", Profile: "example", Account: "example", Channel: "external-token", Endpoint: "https://example.invalid", ExecutableSHA256: "executable", PolicyGeneration: 1}, ExpectedGeneration: 1}
}

// Claim: every result tuple field, generation, decision, ID and closed-schema
// member is validated. Bad responses yield a zero result and sanitized refusal.
func TestAllowlistClientClosedResults(t *testing.T) {
	fields := []string{"valid", "Generation", "Decision", "Tuple.TargetUID", "Tuple.Account", "Tuple.Profile", "Tuple.Harness", "Tuple.Channel", "Tuple.ExpectedGeneration", "Binding.Digest", "Binding.Harness", "Binding.Profile", "Binding.Account", "Binding.Channel", "Binding.Endpoint", "Binding.ExecutableSHA256", "Binding.PolicyGeneration", "unknown-result", "unknown-binding", "wrong-id", "raw-error", "unknown-error", "eof"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			c := clientPeer(t, func(peer *net.UnixConn) {
				h := peerRequest(peer)
				wire.Write(peer, map[string]any{"request_id": h.ID, "result": helloPayload()})
				r := peerRequest(peer)
				if field == "eof" {
					return
				}
				result := wire.AllowlistResult{Tuple: allowlistTuple(), Generation: 1, Decision: "allow"}
				v := reflect.ValueOf(&result).Elem()
				name := field
				if len(field) > 6 && field[:6] == "Tuple." {
					v = v.FieldByName("Tuple")
					name = field[6:]
				}
				if len(field) > 8 && field[:8] == "Binding." {
					v = v.FieldByName("Tuple").FieldByName("Binding")
					name = field[8:]
				}
				if f := v.FieldByName(name); f.IsValid() {
					if f.Kind() == reflect.String {
						f.SetString(f.String() + "x")
					} else {
						f.SetUint(f.Uint() + 1)
					}
				}
				raw, _ := wire.Encode(result)
				m, _ := wire.Parse(raw)
				if field == "unknown-result" {
					m["access_token"] = "synthetic-secret-sentinel"
				}
				if field == "unknown-binding" {
					m["tuple"].(map[string]any)["credential_binding"].(map[string]any)["extra"] = "sentinel"
				}
				id := r.ID
				if field == "wrong-id" {
					id = "another"
				}
				response := map[string]any{"request_id": id, "result": m}
				if field == "raw-error" || field == "unknown-error" {
					code := "allowlist_tuple_mismatch"
					msg := "synthetic-secret-sentinel"
					if field == "unknown-error" {
						code = "unknown"
						msg = "request refused"
					}
					response = map[string]any{"request_id": id, "error": map[string]any{"code": code, "message": msg, "details": map[string]any{}}}
				}
				wire.Write(peer, response)
			})
			clientHello(t, c)
			got, err := c.CheckAllowlist(context.Background(), allowlistTuple())
			if field == "valid" {
				if err != nil || got.Decision != "allow" {
					t.Fatal("positive result failed")
				}
				return
			}
			if got != (wire.AllowlistResult{}) {
				t.Fatal("partial/untrusted result exposed")
			}
			refusalCode(t, err, "allowlist_unavailable", 69)
		})
	}
}

// Claim: canceled, timed-out and closed streams never return an observation;
// the caller deadline also covers waiting for the serialized connection gate.
func TestAllowlistClientDeadline(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "closed", "gate"} {
		t.Run(mode, func(t *testing.T) {
			c := clientPeer(t, func(peer *net.UnixConn) {
				h := peerRequest(peer)
				wire.Write(peer, map[string]any{"request_id": h.ID, "result": helloPayload()})
				peerRequest(peer)
				var b [1]byte
				peer.Read(b[:])
			})
			clientHello(t, c)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			if mode == "closed" {
				c.Close()
			}
			if mode == "gate" {
				c.gate <- struct{}{}
				defer func() { <-c.gate }()
			}
			start := time.Now()
			got, err := c.CheckAllowlist(ctx, allowlistTuple())
			if err == nil || got != (wire.AllowlistResult{}) || time.Since(start) > time.Second {
				t.Fatal("deadline/cancel/closed was not bounded refusal")
			}
		})
	}
}

// Claim: even without a caller deadline, the new check itself expires within
// its two-second transport budget (one second scheduling slack in this test).
func TestAllowlistDefaultDeadline(t *testing.T) {
	c := clientPeer(t, func(peer *net.UnixConn) {
		h := peerRequest(peer)
		wire.Write(peer, map[string]any{"request_id": h.ID, "result": helloPayload()})
		peerRequest(peer)
		var b [1]byte
		peer.Read(b[:])
	})
	clientHello(t, c)
	done := make(chan error, 1)
	go func() { _, err := c.CheckAllowlist(context.Background(), allowlistTuple()); done <- err }()
	select {
	case err := <-done:
		refusalCode(t, err, "allowlist_unavailable", 69)
	case <-time.After(3 * time.Second):
		c.Close()
		<-done
		t.Fatal("allowlist transport exceeded its intrinsic deadline")
	}
}
