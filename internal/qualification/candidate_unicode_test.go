//go:build linux && amd64

package qualification

import (
	"errors"
	"testing"
)

// Claim: keys and values reject unpaired UTF-16 escapes before decoding loses
// them. Valid pairs, literal replacement characters and escaped text retain
// their independently specified canonical bytes.
func TestCandidateUnicodeEscapes(t *testing.T) {
	for _, r := range []struct {
		name, raw, want string
	}{
		{"pair", `{"x":"\ud83d\ude00"}`, `{"x":"😀"}`},
		{"pair-edges", `{"x":"\uD800\uDC00\uDBFF\uDFFF"}`, "{\"x\":\"\U00010000\U0010ffff\"}"},
		{"key-pair", `{"\ud83d\ude00":1}`, `{"😀":1}`},
		{"replacement", `{"x":"\ufffd"}`, `{"x":"�"}`},
		{"escaped-backslash", `{"x":"\\ud800"}`, `{"x":"\\ud800"}`},
		{"escaped-quote", `{"x":"\"\\ud800"}`, `{"x":"\"\\ud800"}`},
		{"high", `{"x":"\ud800"}`, ""},
		{"low", `{"x":"\udc00"}`, ""},
		{"key-high", `{"\udbff":1}`, ""},
		{"key-low", `{"\udfff":1}`, ""},
		{"nested-high", `{"x":[{"y":"\ud800"}]}`, ""},
		{"high-high", `{"x":"\ud800\ud800"}`, ""},
		{"low-high", `{"x":"\udc00\ud800"}`, ""},
		{"nonadjacent-pair", `{"x":"\ud800x\udc00"}`, ""},
		{"escaped-low", `{"x":"\ud800\\udc00"}`, ""},
		{"truncated", `{"x":"\ud8`, ""},
		{"bad-hex", `{"x":"\ud80g"}`, ""},
	} {
		t.Run(r.name, func(t *testing.T) {
			got, e := canonicalJSON([]byte(r.raw))
			if r.want == "" {
				if !errors.Is(e, ErrUnavailable) || len(got) != 0 {
					t.Fatal("invalid Unicode produced canonical bytes", e)
				}
			} else if e != nil || string(got) != r.want {
				t.Fatalf("canonical bytes = %q, error = %v; want %q", got, e, r.want)
			}
		})
	}
}
