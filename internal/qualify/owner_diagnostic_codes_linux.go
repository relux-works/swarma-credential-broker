//go:build linux

package qualify

import (
	"errors"
	"reflect"
)

// Message classes only: identical standard errors from other origins get the
// same label. These tokens prove no origin, cause, trust or authority.
// Frozen source SHA-256: owner_lifecycle_scripts_linux.go
// 028eeba8a63a4029b4f8fa4761e845e1cd951b3acf83c9fe82a96da7f080b4f0
// and owner_lifecycle_collect_linux.go
// 7f8c7bac517eeb112eb418721a9b2e48e10a8ce5d033bd1904a9fc96e2791048.
var ownerDiagnosticStandardErrorType = reflect.TypeOf(errors.New(""))

func ownerDiagnosticLiteralLabel(err error) string {
	value := reflect.ValueOf(err)
	if !value.IsValid() || value.Type() != ownerDiagnosticStandardErrorType || value.IsNil() {
		return "text-redacted"
	}
	// Only the exact non-nil standard concrete type can reach this accessor.
	message := err.Error()
	if len(message) > 43 {
		return "text-redacted"
	}
	for i := range message {
		if message[i] > 127 {
			return "text-redacted"
		}
	}
	switch message {
	case "Safe early demand started writer":
		return "lifecycle-message-01"
	case "Safe early second demand started":
		return "lifecycle-message-02"
	case "Safe pre-due restart started":
		return "lifecycle-message-03"
	case "Safe retry does not start at resolution":
		return "lifecycle-message-04"
	case "Safe retry lost at restart":
		return "lifecycle-message-05"
	case "ambiguous owner acquired resolution":
		return "lifecycle-message-06"
	case "ambiguous/partial owner resolved or retried":
		return "lifecycle-message-07"
	case "candidate identity mismatch":
		return "lifecycle-message-08"
	case "exact synchronous crash gate missing":
		return "lifecycle-message-09"
	case "lifecycle actual lease startup missing":
		return "lifecycle-message-10"
	case "lifecycle clock budget":
		return "lifecycle-message-11"
	case "lifecycle clock reversed":
		return "lifecycle-message-12"
	case "lifecycle execution unavailable":
		return "lifecycle-message-13"
	case "lifecycle observation invalid":
		return "lifecycle-message-14"
	case "lifecycle publication/generation mismatch":
		return "lifecycle-message-15"
	case "lifecycle requires row deadline":
		return "lifecycle-message-16"
	case "partial constructor recorded absence":
		return "lifecycle-message-17"
	case "second Safe backoff/history mismatch":
		return "lifecycle-message-18"
	default:
		return "text-redacted"
	}
}
