// rowprobe is an account-free adversarial observation fixture, not a candidate.
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

func main() {
	if handled, code := qualification.CandidateLauncherMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) != 4 {
		os.Exit(125)
	}
	var input struct {
		Policy struct {
			Digest     string `json:"executable_sha256"`
			Generation uint64 `json:"policy_generation"`
		}
		ID, Side string
	}
	f := os.NewFile(5, "context")
	b, _ := io.ReadAll(f)
	json.Unmarshal(b, &input)
	// Invalid FD guarantees no traffic even if a boundary mutant grants the call.
	unix.Connect(-1, &unix.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}, Port: 443})
	hello := map[string]any{"version": 1, "profile": wire.Profile, "principal": map[string]any{"uid": os.Geteuid()}, "policy_generation": input.Policy.Generation}
	payload, _ := wire.Encode(map[string]any{"request_id": "fixture-hello", "result": hello})
	facts := []any{map[string]any{"kind": "hello", "request_id": "fixture-hello", "payload_bytes": len(payload), "hello": hello, "refusal": nil}}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"id": input.ID, "side": input.Side, "candidate": input.Policy.Digest, "refusal": "hello", "no_effects": true, "probe_fault": false, "envelopes": facts})
}
