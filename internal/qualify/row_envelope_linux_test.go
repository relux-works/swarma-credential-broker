//go:build linux && amd64

package qualify

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: a valid adjacent hello passes; extra/null error members, malformed
// result metadata and incorrect correlation cannot earn positive row credit.
// These fixtures use a local socket and synthetic hello metadata only.
func TestRowHelloEnvelope(t *testing.T) {
	for _, name := range []string{"valid", "error-null", "error-object", "extra", "missing-id", "null-id", "wrong-id", "null-result", "result-extra", "principal-extra", "generation"} {
		t.Run(name, func(t *testing.T) {
			result := map[string]any{"version": 1, "profile": wire.Profile, "principal": map[string]any{"uid": os.Geteuid()}, "policy_generation": 1}
			reply := map[string]any{"request_id": "fixture-hello", "result": result}
			switch name {
			case "error-null":
				reply["error"] = nil
			case "error-object":
				reply["error"] = wire.Refuse("version_unsupported")
			case "extra":
				reply["unexpected"] = true
			case "missing-id":
				delete(reply, "request_id")
			case "null-id":
				reply["request_id"] = nil
			case "wrong-id":
				reply["request_id"] = "other"
			case "null-result":
				reply["result"] = nil
			case "result-extra":
				result["unexpected"] = true
			case "principal-extra":
				result["principal"].(map[string]any)["unexpected"] = true
			case "generation":
				result["policy_generation"] = 2
			}
			path := filepath.Join(t.TempDir(), "s")
			l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, e := l.AcceptUnix()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				if e = c.SetDeadline(time.Now().Add(time.Second)); e == nil {
					_, e = wire.Read(c)
				}
				if e == nil {
					e = wire.Write(c, reply)
				}
				done <- e
			}()
			_, e = transportExchange(path, "frame-oversized", "positive", 1)
			if serverError := <-done; serverError != nil {
				t.Fatal(serverError)
			}
			if name == "valid" {
				if e != nil {
					t.Fatal("valid hello refused", e)
				}
			} else if e != qualification.ErrUnavailable {
				t.Fatal("invalid hello did not get the expected refusal", e)
			}
		})
	}
}

// Claim: closed terminal members, sanitized text, required empty details and the
// null/validated ID rule are checked independently of the expected refusal code.
// The unsupported-profile fixture covers its validated-ID error envelope here;
// TestRowsHarness also requires both real negotiation variants and terminal EOF.
func TestRowErrorEnvelope(t *testing.T) {
	for _, id := range []string{"frame-oversized", "profile-unsupported", "peer-identity-unavailable"} {
		t.Run(id, func(t *testing.T) {
			for _, name := range []string{"valid", "result-null", "extra", "error-extra", "missing-details", "null-details", "null-error", "missing-id", "wrong-id", "wrong-code", "message"} {
				t.Run(name, func(t *testing.T) {
					refusal := wire.Refuse(rowRefusal(id))
					detail := map[string]any{"code": refusal.Code, "message": refusal.Message, "details": map[string]any{}}
					reply := map[string]any{"request_id": nil, "error": detail}
					if id == "profile-unsupported" {
						reply["request_id"] = "fixture-hello"
					}
					switch name {
					case "result-null":
						reply["result"] = nil
					case "extra":
						reply["unexpected"] = true
					case "error-extra":
						detail["unexpected"] = true
					case "missing-details":
						delete(detail, "details")
					case "null-details":
						detail["details"] = nil
					case "null-error":
						reply["error"] = nil
					case "missing-id":
						delete(reply, "request_id")
					case "wrong-id":
						if id == "profile-unsupported" {
							reply["request_id"] = nil
						} else {
							reply["request_id"] = "fixture-hello"
						}
					case "wrong-code":
						detail["code"] = "lease_not_owner"
					case "message":
						detail["message"] = "unexpected"
					}
					b, e := wire.Encode(reply)
					if e != nil {
						t.Fatal(e)
					}
					f, e := decodeRowEnvelope(b, id, "negative", 1)
					if name == "valid" {
						if e != nil || !validRowEnvelope(f, id, "negative", 1) || f.PayloadBytes != len(b) || f.Refusal.Code != refusal.Code {
							t.Fatal("valid terminal refused", e)
						}
					} else if e != qualification.ErrUnavailable {
						t.Fatal("invalid terminal did not get the expected refusal", e)
					}
				})
			}
		})
	}
}

// Claim: both negative exchange variants remain mandatory and independently
// validated; a single valid exchange cannot stand in for the pair.
func TestRowEnvelopeVariants(t *testing.T) {
	for _, id := range []string{"profile-unsupported", "frame-malformed-first"} {
		t.Run(id, func(t *testing.T) {
			f := rowEnvelope{Kind: "closed"}
			if id == "profile-unsupported" {
				b, e := wire.Encode(map[string]any{"request_id": "fixture-hello", "error": wire.Refuse("version_unsupported")})
				if e != nil {
					t.Fatal(e)
				}
				f, e = decodeRowEnvelope(b, id, "negative", 1)
				if e != nil {
					t.Fatal(e)
				}
			}
			o := rowObservation{ID: id, Side: "negative", Envelopes: []rowEnvelope{f, f}}
			if !validRowEnvelopes(o, 1) {
				t.Fatal("valid exchange pair refused")
			}
			o.Envelopes = o.Envelopes[:1]
			if validRowEnvelopes(o, 1) {
				t.Fatal("missing second exchange credited")
			}
			for n := range 2 {
				o.Envelopes = []rowEnvelope{f, f}
				o.Envelopes[n].PayloadBytes++
				if validRowEnvelopes(o, 1) {
					t.Fatal("invalid exchange credited", n)
				}
			}
		})
	}
}
