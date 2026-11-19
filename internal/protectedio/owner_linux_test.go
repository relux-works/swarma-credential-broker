package protectedio

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Claim: an unchanged real directory admits the test owner as an ancestor but refuses that same ancestor as a third UID; no privileged chown fixture is needed.
func TestDirectoryAncestorOwnerBoundary(test *testing.T) {
	path, policy := fixture(test, "inert", 0640)
	directory := filepath.Dir(path)
	policy.Mode = 0700
	reader := Reader{}
	if err := reader.CheckDirectory(context.Background(), directory, policy, uint32(os.Getuid())); err != nil {
		test.Fatalf("valid ancestor-owner control refused: %v", err)
	}
	if err := reader.CheckDirectory(context.Background(), directory, policy, uint32(os.Getuid())+1); !errors.Is(err, ErrProtection) {
		test.Fatalf("ancestor owned by a third UID admitted: %v", err)
	}
}
