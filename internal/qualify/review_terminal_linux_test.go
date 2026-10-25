//go:build linux && amd64

package qualify

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the exact terminal envelope, fixed message and empty details are required;
// adjacent valid frames must succeed. The local fixture sends only synthetic data.
func TestReviewTerminalEnvelope(t *testing.T) {
	for _, name := range []string{"valid", "extra-result", "nonempty-details", "oversized-terminal"} {
		t.Run(name, func(t *testing.T) {
			root, err := os.MkdirTemp("", "qe-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			path := filepath.Join(root, "s")
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			terminal := map[string]any{"request_id": nil, "error": wire.Refuse("peer_identity_unavailable")}
			if name == "extra-result" {
				terminal["result"] = map[string]any{"unexpected": true}
			}
			if name == "nonempty-details" {
				terminal["error"] = map[string]any{"code": "peer_identity_unavailable", "message": wire.Refuse("peer_identity_unavailable").Message, "details": map[string]any{"unexpected": true}}
			}
			if name == "oversized-terminal" {
				terminal["error"] = map[string]any{"code": "peer_identity_unavailable", "message": strings.Repeat("x", 600), "details": map[string]any{}}
			}
			done := make(chan error, 1)
			go func() {
				conn, e := l.AcceptUnix()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				done <- wire.Write(conn, terminal)
			}()
			_, err = transportExchange(path, "peer-identity-unavailable", "negative", 1)
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if name == "valid" {
				if err != nil {
					t.Fatal("valid terminal control refused", err)
				}
			} else if err == nil {
				t.Fatal("malformed terminal envelope credited")
			}
		})
	}
	var _ json.RawMessage
}
