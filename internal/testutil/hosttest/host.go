// Package hosttest centralizes skips for explicitly provisioned test fixtures.
// It has no dependencies on the broker or its configuration.
package hosttest

import (
	"os"
	"testing"
)

// Unprivileged reports the exact opt-in mode used by hosted CI. Review leaves
// this unset so the provisioned qualification fixtures retain their assertions.
func Unprivileged() bool { return os.Getenv("SWARMA_TEST_UNPRIVILEGED") == "1" }

// Require skips a fixture unavailable to the unprivileged CI environment.
// Call it before opening configuration, starting helpers or reading host state.
// Runnable kernel-backed tests must not call it unless a capability probe fails.
func Require(t testing.TB, reason string) {
	t.Helper()
	if reason == "" {
		t.Fatal("host fixture requires an explicit reason")
	}
	if Unprivileged() {
		t.Skip("host fixture unavailable in unprivileged CI: " + reason)
	}
}
