//go:build linux

package timeconf

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Claim: the actual compiled VerifyWindow graph, including generated equality
// helpers and inlined foreign calls, contains only package-local scalar checks
// and listed runtime language intrinsics. Unknown or indirect calls fail closed.
// Runtime allocation/equality/stack/panic intrinsics are terminal language
// operations, not a claim that the Go scheduler itself performs no system calls.
// A real time.Now plant is applied during review validation. This structural
// check does not qualify native timing, storage or custom machine instructions.
func TestVerifyWindowCompiledPurity(t *testing.T) {
	_, _ = VerifyWindow(PreparedHandoff{}, WindowExpected{}, LockedWindowState{}, FinalCapture{})
	for _, tag := range []string{"", "swarma_timeconf_fixture"} {
		t.Run("compiled-"+tag, func(t *testing.T) { checkWindowCompiledPurity(t, tag) })
	}
}
func checkWindowCompiledPurity(t *testing.T, tag string) {
	binary := filepath.Join(t.TempDir(), "inspect.test")
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, goTool, "test", "-c", "-tags="+tag, "-ldflags=-s=false", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("inspection build failed: %v: %s", err, out)
	}
	const pkg = "github.com/relux-works/swarma-credential-broker/timeconf"
	cmd := exec.CommandContext(ctx, goTool, "tool", "objdump", "-s", `(?:type:\.eq\.)?`+regexp.QuoteMeta(pkg)+`[.(]`, binary)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compiled graph unavailable: %v: %s", err, out)
	}
	text := regexp.MustCompile(`^TEXT (\S+)\(SB\)`)
	call := regexp.MustCompile(`\b(?:CALL|BL|JMP|B)\s+(\S+)\(SB\)`)
	indirect := regexp.MustCompile(`\b(?:CALL|BL)\s+(?:[A-Z][A-Z0-9]*|0x[0-9a-f]+)\s*$`)
	graph := map[string][]string{}
	bad := map[string]bool{}
	current := ""
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if m := text.FindStringSubmatch(line); m != nil {
			current = m[1]
			graph[current] = nil
			continue
		}
		if current == "" {
			continue
		}
		if m := call.FindStringSubmatch(line); m != nil {
			target := strings.Split(m[1], "+")[0]
			graph[current] = append(graph[current], target)
		} else if indirect.MatchString(line) {
			bad[current] = true
		}
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	queue := []string{pkg + ".VerifyWindow"}
	seen := map[string]bool{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		edges, ok := graph[name]
		if !ok || bad[name] {
			t.Fatalf("unresolved compiled dependency: %s", name)
		}
		for _, target := range edges {
			if strings.HasPrefix(target, pkg+".") || strings.HasPrefix(target, "type:.eq."+pkg+".") {
				queue = append(queue, target)
				continue
			}
			if pureRuntimeIntrinsic(target) {
				continue
			}
			t.Fatalf("forbidden compiled dependency: %s -> %s", name, target)
		}
	}
	t.Logf("checked %d reachable compiled functions", len(seen))
}
func pureRuntimeIntrinsic(name string) bool {
	switch name {
	case "runtime.newobject", "runtime.memequal", "runtime.memequal0", "runtime.memequal8", "runtime.memequal16", "runtime.memequal32", "runtime.memequal64", "runtime.memequal128", "runtime.morestack_noctxt.abi0", "runtime.morestack.abi0", "runtime.panicIndex", "runtime.panicSliceB", "runtime.panicSliceAlen", "runtime.panicSliceAcap", "runtime.duffcopy", "runtime.duffzero":
		return true
	}
	return false
}
