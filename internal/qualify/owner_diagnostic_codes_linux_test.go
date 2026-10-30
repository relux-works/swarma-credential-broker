//go:build linux && amd64

package qualify

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// Independent frozen sorted message-to-token contract; these are text classes,
// not assertions about the origin of the error or the cause of a lifecycle failure.
var ownerDiagnosticLiteralCases = []struct{ message, label string }{
	{"Safe early demand started writer", "lifecycle-message-01"},
	{"Safe early second demand started", "lifecycle-message-02"},
	{"Safe pre-due restart started", "lifecycle-message-03"},
	{"Safe retry does not start at resolution", "lifecycle-message-04"},
	{"Safe retry lost at restart", "lifecycle-message-05"},
	{"ambiguous owner acquired resolution", "lifecycle-message-06"},
	{"ambiguous/partial owner resolved or retried", "lifecycle-message-07"},
	{"candidate identity mismatch", "lifecycle-message-08"},
	{"exact synchronous crash gate missing", "lifecycle-message-09"},
	{"lifecycle actual lease startup missing", "lifecycle-message-10"},
	{"lifecycle clock budget", "lifecycle-message-11"},
	{"lifecycle clock reversed", "lifecycle-message-12"},
	{"lifecycle execution unavailable", "lifecycle-message-13"},
	{"lifecycle observation invalid", "lifecycle-message-14"},
	{"lifecycle publication/generation mismatch", "lifecycle-message-15"},
	{"lifecycle requires row deadline", "lifecycle-message-16"},
	{"partial constructor recorded absence", "lifecycle-message-17"},
	{"second Safe backoff/history mismatch", "lifecycle-message-18"},
}

// Claim: all 18 exact frozen standard messages label through the existing graph
// formatter without input mutation or an origin/authority claim.
func TestOwnerDiagnosticLiteralCatalog(t *testing.T) {
	for _, c := range ownerDiagnosticLiteralCases {
		t.Run(c.label, func(t *testing.T) {
			e := errors.New(c.message)
			before := e.Error()
			got, held := ownerDiagnosticInspect(e)
			if got != "*errors.errorString("+c.label+")" || held || e.Error() != before {
				t.Fatalf("catalog label lost: %q held=%t", got, held)
			}
		})
	}
}

// Claim: actual sentinel identities retain priority; same-text new standard
// errors, unknown/long/normalized-looking text and controls remain redacted.
func TestOwnerDiagnosticLiteralRedaction(t *testing.T) {
	for _, e := range []error{context.Canceled, context.DeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe, os.ErrDeadlineExceeded} {
		got, held := ownerDiagnosticInspect(e)
		if held || strings.Contains(got, "text-redacted") || strings.Contains(got, "lifecycle-message") {
			t.Fatal("sentinel label changed", got)
		}
		lookalike := errors.New(e.Error())
		if got, held = ownerDiagnosticInspect(lookalike); !strings.Contains(got, "text-redacted") || held {
			t.Fatal("sentinel lookalike labeled", got)
		}
	}
	base := ownerDiagnosticLiteralCases[0].message
	for _, message := range []string{"unknown-synthetic-canary", base + "\r", base + "\n", base + "\x00", " " + base, base + " ", strings.ToLower(base), base + "é", base + "\u00a0", strings.Repeat("x", 44), strings.Repeat("x", 4096)} {
		got, held := ownerDiagnosticInspect(errors.New(message))
		if !strings.Contains(got, "text-redacted") || strings.Contains(got, "lifecycle-message") || strings.Contains(got, "unknown-synthetic-canary") || held {
			t.Fatalf("unknown raw text admitted: %q", got)
		}
	}
}

type ownerDiagnosticLiteralCustom struct {
	calls      *atomic.Int32
	message    string
	panicError bool
}

func (e *ownerDiagnosticLiteralCustom) Error() string {
	e.calls.Add(1)
	if e.panicError {
		panic("custom Error invoked")
	}
	return e.message
}
func (e *ownerDiagnosticLiteralCustom) Is(error) bool { e.calls.Add(1); panic("custom Is invoked") }
func (e *ownerDiagnosticLiteralCustom) As(any) bool   { e.calls.Add(1); panic("custom As invoked") }

// Claim: custom same-text and panicking Error/Is/As are never called, including
// under a standard wrapper. Exact standard typed nil and nil input are safe.
func TestOwnerDiagnosticLiteralTypeSafety(t *testing.T) {
	var calls atomic.Int32
	for _, panicError := range []bool{false, true} {
		e := &ownerDiagnosticLiteralCustom{&calls, ownerDiagnosticLiteralCases[0].message, panicError}
		for _, input := range []error{e, &ownerDiagnosticLiteralWrapper{e}} {
			got, held := ownerDiagnosticInspect(input)
			if held || !strings.Contains(got, "text-redacted") || strings.Contains(got, "lifecycle-message") {
				t.Fatal("custom message labeled", got)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("custom methods called", calls.Load())
	}
	typedNil := reflect.Zero(reflect.TypeOf(errors.New(""))).Interface().(error)
	if got, held := ownerDiagnosticInspect(typedNil); held || got != "*errors.errorString(text-redacted)" {
		t.Fatal("typed nil labeled", got)
	}
	if got, held := ownerDiagnosticInspect(nil); got != "" || held {
		t.Fatal("nil contract changed", got)
	}
}

type ownerDiagnosticLiteralWrapper struct{ next error }

func (*ownerDiagnosticLiteralWrapper) Error() string   { panic("wrapper Error invoked") }
func (e *ownerDiagnosticLiteralWrapper) Unwrap() error { return e.next }

// Claim: labels do not alter the existing eight-step traversal, Held result,
// truncation or nil-child accounting for wrapped/deep/wide/cyclic graphs.
func TestOwnerDiagnosticLiteralGraphs(t *testing.T) {
	leaf := errors.New(ownerDiagnosticLiteralCases[12].message)
	for _, wrappers := range []int{7, 8} {
		var steps atomic.Int32
		var e error = leaf
		for i := 0; i < wrappers; i++ {
			e = &ownerDiagnosticCounted{next: e, steps: &steps}
		}
		got, held := ownerDiagnosticInspect(e)
		if held || steps.Load() > 7 || strings.Contains(got, "truncated") != (wrappers == 8) || strings.Contains(got, "lifecycle-message-13") != (wrappers == 7) {
			t.Fatal("deep graph changed", got, steps.Load())
		}
	}
	var steps atomic.Int32
	got, held := ownerDiagnosticInspect(&ownerDiagnosticJoined{children: []error{nil, leaf, errOwnerHeld}, steps: &steps})
	if !held || !strings.Contains(got, "lifecycle-message-13") || strings.Contains(got, "truncated") || steps.Load() != 1 {
		t.Fatal("nil-child/held graph changed", got)
	}
	children := make([]error, 16)
	children[15] = errOwnerHeld
	got, held = ownerDiagnosticInspect(&ownerDiagnosticJoined{children: children, steps: &steps})
	if held || !strings.Contains(got, "truncated") {
		t.Fatal("wide graph changed", got)
	}
	got, held = ownerDiagnosticInspect(&ownerDiagnosticCycle{})
	if held || !strings.Contains(got, "truncated") || strings.Count(got, "text-redacted") != 8 {
		t.Fatal("cycle graph changed", got)
	}
}
