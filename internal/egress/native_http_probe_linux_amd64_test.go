//go:build linux && amd64 && realcandidate

package egress

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/internal/testutil/hosttest"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Claim: the explicitly selected native binary can initialize and send an
// account-free HTTP request to an allowed loopback provider with generated proxy
// settings. The fake never forwards and returns 503: arrival is the claim, not
// successful qualification. Boundary records and independent connect tracing
// must show zero external grants and only loopback connect attempts.
func TestLocalCandidateHTTPProbe(t *testing.T) {
	hosttest.Require(t, "explicit protected real candidate and private evidence directory")
	root := os.Getenv("EGRESS_SMOKE_EVIDENCE")
	candidate := os.Getenv("EGRESS_SMOKE_CANDIDATE")
	if !filepath.IsAbs(root) || !filepath.IsAbs(candidate) {
		t.Fatal("explicit absolute candidate and private evidence directory required")
	}
	if os.Getenv("EGRESS_TRACE_CHILD") != "1" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/strace", "-f", "-e", "trace=connect", "-o", filepath.Join(root, "connect.trace"), self, "-test.run=^TestLocalCandidateHTTPProbe$", "-test.v")
		cmd.Env = []string{"GO=" + os.Getenv("GO"), "GOTOOLCHAIN=local", "GOMAXPROCS=2", "PATH=/usr/bin:/bin", "TMPDIR=" + os.Getenv("TMPDIR"), "EGRESS_TRACE_CHILD=1", "EGRESS_TEST_LAUNCHER=" + launcher, "EGRESS_SMOKE_CANDIDATE=" + candidate, "EGRESS_SMOKE_EVIDENCE=" + root}
		b, err := cmd.CombinedOutput()
		t.Log(string(b))
		if err != nil {
			t.Fatal("traced local HTTP probe:", err)
		}
		trace, err := os.ReadFile(filepath.Join(root, "connect.trace"))
		if err != nil {
			t.Fatal(err)
		}
		attempts, err := loopbackConnectTrace(string(trace))
		if err != nil {
			t.Fatal(err)
		}
		writeProbeJSON(t, filepath.Join(root, "connect-summary.json"), map[string]int{"loopback_attempts": attempts, "external_attempts": 0})
		t.Logf("strace loopback connect attempts=%d external=0", attempts)
		return
	}
	home := t.TempDir()
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("home is not fresh and empty")
	}
	l, port := tcp(t)
	var requests atomic.Int32
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"local fixture response","type":"fixture"}}`))
	})}
	go s.Serve(l)
	defer s.Close()
	env, err := ProxyEnvironment([]string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, closedProxy(t), []uint16{port})
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(filepath.Join(root, "candidate-output.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	args := []string{"-a", "never", "exec", "--skip-git-repo-check", "--sandbox", "read-only", "--model", "fixture", "-c", `model_provider="fixture"`, "-c", `model_providers.fixture.name="Local fixture"`, "-c", `model_providers.fixture.base_url="http://127.0.0.1:` + strconv.Itoa(int(port)) + `/v1"`, "-c", `model_providers.fixture.wire_api="responses"`, "-c", `model_providers.fixture.requires_openai_auth=false`, "-c", `model_providers.fixture.request_max_retries=0`, "-c", `model_providers.fixture.stream_max_retries=0`, "Return a short fixture response."}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, runErr := Run(ctx, Config{Launcher: launcher, Executable: candidate, Args: args, Env: env, Policy: Policy{Ports: []uint16{port}, MaxEvents: 4096}, Stdout: out, Stderr: out})
	writeProbeJSON(t, filepath.Join(root, "boundary.json"), r)
	external := 0
	for _, e := range r.Events {
		if e.Class == "external" && e.Verdict == "allow" {
			external++
		}
	}
	writeProbeJSON(t, filepath.Join(root, "summary.json"), map[string]any{"requests": requests.Load(), "external_grants": external, "run_error": runErr != nil, "incomplete": r.Incomplete})
	if external != 0 || requests.Load() == 0 {
		t.Fatalf("HTTP requests=%d external grants=%d", requests.Load(), external)
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || !r.Incomplete || ctx.Err() != nil {
		t.Fatalf("expected candidate service-error exit after fake 503: %v incomplete=%t", runErr, r.Incomplete)
	}
	event(t, r, "ioctl", "descriptor", "allow")
	event(t, r, "connect", "loopback", "allow")
	t.Logf("local HTTP requests=%d external grants=%d; expected candidate error and incomplete report after fake 503", requests.Load(), external)
}

func loopbackConnectTrace(trace string) (int, error) {
	v4 := regexp.MustCompile(`sa_family=AF_INET,.*sin_addr=inet_addr\("([^"]+)"\)`)
	v6 := regexp.MustCompile(`sa_family=AF_INET6,.*inet_pton\(AF_INET6, "([^"]+)",`)
	attempts := 0
	for _, line := range strings.Split(trace, "\n") {
		if !strings.Contains(line, "connect(") {
			continue
		}
		attempts++
		match := v4.FindStringSubmatch(line)
		if match == nil {
			match = v6.FindStringSubmatch(line)
		}
		if len(match) != 2 || !net.ParseIP(match[1]).IsLoopback() {
			return attempts, errors.New("external or undecodable connect in native HTTP probe")
		}
	}
	if attempts == 0 {
		return 0, errors.New("independent trace missed the local request")
	}
	return attempts, nil
}

// Claim: the independent trace gate detects planted external or undecodable
// connects and missing evidence, alongside valid IPv4/IPv6 loopback controls.
func TestNativeConnectTrace(t *testing.T) {
	for _, row := range []struct {
		name, trace string
		allowed     bool
	}{
		{"loopback-v4", `1 connect(4, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`, true},
		{"loopback-v6", `1 connect(4, {sa_family=AF_INET6, sin6_port=htons(1234), inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = 0`, true},
		{"external-v4", `1 connect(4, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("192.0.2.1")}, 16) = 0`, false},
		{"external-v6", `1 connect(4, {sa_family=AF_INET6, sin6_port=htons(1234), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = 0`, false},
		{"undecodable", `1 connect(4, 0x1234, 16) = -1 EFAULT`, false},
		{"missing", "1 +++ exited with 0 +++", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := loopbackConnectTrace(row.trace)
			if (err == nil) != row.allowed {
				t.Fatalf("trace verdict: %v", err)
			}
		})
	}
}

func writeProbeJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
