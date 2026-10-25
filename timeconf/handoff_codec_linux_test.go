//go:build linux

package timeconf

import (
	"errors"
	"strings"
	"testing"
)

// Claim: bounded closed decoding rejects malformed, unknown, null, duplicate,
// trailing and oversized packets without returning partial data. Positive real
// receipt/envelope round trips run in TestHandoffCodec under the fixture tag.
func TestHandoffMalformed(t *testing.T) {
	for _, raw := range []string{"", `{}`, `null`, `{"version":"unknown"}`, `{"version":"qualified-time/handoff/1","version":"qualified-time/handoff/1"}`, strings.Repeat("[", 17), strings.Repeat("x", handoffLimit+1)} {
		h, err := DecodeHandoff([]byte(raw))
		var r *HandoffRefusal
		if !errors.As(err, &r) || h.Version != "" {
			t.Fatal("malformed handoff accepted", err)
		}
	}
}
