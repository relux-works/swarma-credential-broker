//go:build linux && amd64

package qualify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Claim: the real close timeout samples a quiescent entered supervisor, then
// cancellation releases supervision and joins the child before diagnostics.
// The barrier exists only in the overlay; production keeps its nonblocking reads.
func TestOwnerCloseTimeoutSnapshot(t *testing.T) {
	output, err := runOwnerCloseTimeoutFixture(t, false)
	if err != nil || !strings.Contains(output, "--- PASS: TestOwnerCloseTimeoutSnapshotOverlay") {
		t.Fatalf("timeout snapshot overlay: %v\n%s", err, output)
	}
	t.Logf("timeout snapshot overlay\n%s", output)
}

// Claim: capturing after cancellation and join must fail the timeout assertion,
// while the same real clean-exit and ordinary-cancellation controls still pass.
func TestOwnerCloseTimeoutSnapshotLateCapture(t *testing.T) {
	output, err := runOwnerCloseTimeoutFixture(t, true)
	if err == nil ||
		!strings.Contains(output, "--- FAIL: TestOwnerCloseTimeoutSnapshotOverlay/timeout") ||
		!strings.Contains(output, "pre-cancel snapshot missing or changed") ||
		!strings.Contains(output, "--- PASS: TestOwnerCloseTimeoutSnapshotOverlay/clean") ||
		!strings.Contains(output, "--- PASS: TestOwnerCloseTimeoutSnapshotOverlay/cancelled") {
		t.Fatalf("late-capture mutant missed its intended regression or broke controls: %v\n%s", err, output)
	}
	t.Logf("late-capture mutant exit=%v\n%s", err, output)
}

func runOwnerCloseTimeoutFixture(t *testing.T, knownBad bool) (string, error) {
	t.Helper()
	dir := t.TempDir()
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Clean(filepath.Join(packageDir, "../egress/origin_linux_amd64.go"))
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	anchor := "\t\tif tid == 0 {\n\t\t\to.observeOperation(OperationPause)\n"
	if strings.Count(string(source), anchor) != 1 {
		t.Fatal("supervisor pause instrumentation anchor changed")
	}
	instrumented := strings.Replace(string(source), anchor, anchor+"\t\t\tif OwnerCloseFixturePause != nil { OwnerCloseFixturePause(ctx) }\n", 1)
	instrumented += "\nvar OwnerCloseFixturePause func(context.Context)\n"
	sourceOverlay := filepath.Join(dir, "origin_linux_amd64.go")
	if err := os.WriteFile(sourceOverlay, []byte(instrumented), 0o600); err != nil {
		t.Fatal(err)
	}
	replacements := map[string]string{
		sourcePath: sourceOverlay,
		filepath.Join(packageDir, "owner_close_timeout_overlay_test.go"): filepath.Join(packageDir, "testdata/owner-close-timeout-overlay_test.go"),
	}
	if knownBad {
		ownerPath := filepath.Join(packageDir, "owner_rows_linux.go")
		ownerSource, err := os.ReadFile(ownerPath)
		if err != nil {
			t.Fatal(err)
		}
		capture := "\t\tsnapshot = s.closeSnapshot(cancelIssued)\n"
		joined := "\t\ts.ch.w.Close()\n\t\t<-s.done\n"
		if strings.Count(string(ownerSource), capture) != 1 || strings.Count(string(ownerSource), joined) != 1 {
			t.Fatal("late-capture mutation anchor changed")
		}
		mutant := strings.Replace(string(ownerSource), capture, "", 1)
		mutant = strings.Replace(mutant, joined, joined+capture, 1)
		ownerOverlay := filepath.Join(dir, "owner_rows_linux.go")
		if err := os.WriteFile(ownerOverlay, []byte(mutant), 0o600); err != nil {
			t.Fatal(err)
		}
		replacements[ownerPath] = ownerOverlay
	}
	manifest, err := json.Marshal(map[string]map[string]string{"Replace": replacements})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"test"}
	if ownerCloseRaceEnabled {
		args = append(args, "-race")
	}
	args = append(args, "-mod=readonly", "-overlay="+overlayPath, "-p=1", "-count=1", "-timeout=45s", "-run=^TestOwnerCloseTimeoutSnapshotOverlay$", "-v", ".")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	cmd.Dir = packageDir
	cmd.Env = ownerCloseOfflineEnv()
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("timeout snapshot overlay deadline: %w", ctx.Err())
	}
	return string(output), err
}
