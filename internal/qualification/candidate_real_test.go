//go:build linux && amd64 && realcandidate

package qualification

import (
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/internal/testutil/hosttest"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Claim: the selected real candidate's version, two independent schema
// observations and required catalog are measured in fresh account-free homes
// under egress. strace independently rejects external/undecodable connects.
// This supplies identity evidence only; pending rows still prevent publication.
func TestRealCandidateObservers(t *testing.T) {
	hosttest.Require(t, "explicit protected real candidate and private evidence directory")
	root := os.Getenv("CANDIDATE_EVIDENCE_DIR")
	candidate := os.Getenv("CANDIDATE_EXECUTABLE")
	if !filepath.IsAbs(root) || !filepath.IsAbs(candidate) {
		t.Fatal("explicit private evidence and candidate paths required")
	}
	if os.Getenv("CANDIDATE_TRACE_CHILD") != "1" {
		if os.MkdirAll(root, 0700) != nil {
			t.Fatal("evidence directory")
		}
		self, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/strace", "-f", "-e", "trace=connect", "-o", filepath.Join(root, "connect.trace"), self, "-test.run=^TestRealCandidateObservers$", "-test.v")
		cmd.Env = []string{"GO=" + os.Getenv("GO"), "GOTOOLCHAIN=local", "GOMAXPROCS=2", "PATH=/usr/bin:/bin", "TMPDIR=" + os.Getenv("TMPDIR"), "CANDIDATE_TRACE_CHILD=1", "CANDIDATE_TEST_LAUNCHER=" + candidateLauncher, "CANDIDATE_EXECUTABLE=" + candidate, "CANDIDATE_EVIDENCE_DIR=" + root}
		out, e := cmd.CombinedOutput()
		t.Log(string(out))
		if e != nil {
			t.Fatal("traced observers", e)
		}
		trace, e := os.ReadFile(filepath.Join(root, "connect.trace"))
		if e != nil {
			t.Fatal(e)
		}
		attempts, e := candidateTrace(string(trace))
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("independent connect attempts=%d; external=0", attempts)
		b, _ := json.Marshal(map[string]int{"loopback_attempts": attempts, "external_attempts": 0})
		if os.WriteFile(filepath.Join(root, "connect-summary.json"), b, 0600) != nil {
			t.Fatal("trace summary")
		}
		return
	}
	f, e := OpenExecutable(candidate)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := hashFile(context.Background(), f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	homes := filepath.Join(root, "homes")
	if os.Mkdir(homes, 0700) != nil {
		t.Fatal("fresh homes parent")
	}
	evidence := &CandidateEvidence{}
	o := NativeObserver{ExecutablePath: candidate, ExecutableSHA256: digest, LauncherPath: candidateLauncher, ScratchRoot: homes, Evidence: evidence}
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	version, ve := o.Version(ctx)
	// Persist only the candidate's own help, collected through the same boundary.
	for n, args := range [][]string{{"app-server", "--help"}, {"app-server", "generate-json-schema", "--help"}} {
		r, e := o.candidate(ctx, "schema-help/1", args, 65536, nil)
		if e != nil {
			t.Fatal("help unavailable", e)
		}
		b, _ := json.Marshal(map[string]any{"argv": args, "help": string(r.stdout)})
		if os.WriteFile(filepath.Join(root, []string{"app-server-help.json", "schema-help.json"}[n]), b, 0600) != nil {
			t.Fatal("help evidence")
		}
	}
	a, ae := o.Schema(ctx)
	b, be := o.Schema(ctx)
	catalog, models, ce := o.Catalog(ctx)
	result := map[string]any{"executable_sha256": digest, "version": version, "version_measurement": evidence.Version, "schema_first": a, "schema_second": b, "catalog": catalog, "catalog_models": len(models.Models), "evidence": evidence, "version_error": ve != nil, "schema_first_error": ae != nil, "schema_second_error": be != nil, "catalog_error": ce != nil}
	raw, _ := json.MarshalIndent(result, "", "  ")
	if os.WriteFile(filepath.Join(root, "measurements.json"), raw, 0600) != nil {
		t.Fatal("measurement evidence")
	}
	if ve != nil || version != "0.163.0" || ae != nil || be != nil || a != b || ce != nil {
		t.Fatalf("measurements unavailable: version=%v schema1=%v schema2=%v catalog=%v", ve, ae, be, ce)
	}
	for _, r := range evidence.Runs {
		if r.IsolationFailed || r.Incomplete || r.Summary["external"].Allowed != 0 {
			t.Fatal("failed observer isolation")
		}
	}
	entries, e := os.ReadDir(homes)
	if e != nil || len(entries) != 0 {
		t.Fatal("fresh homes retained")
	}
	t.Logf("version=%s schema=%s catalog=%s models=%d; external grants=0", version, a.SHA256, catalog.SHA256, len(models.Models))
}

func candidateTrace(trace string) (int, error) {
	v4 := regexp.MustCompile(`sa_family=AF_INET,.*sin_addr=inet_addr\("([^"]+)"\)`)
	v6 := regexp.MustCompile(`sa_family=AF_INET6,.*inet_pton\(AF_INET6, "([^"]+)",`)
	n := 0
	for _, line := range strings.Split(trace, "\n") {
		if !strings.Contains(line, "connect(") {
			continue
		}
		n++
		m := v4.FindStringSubmatch(line)
		if m == nil {
			m = v6.FindStringSubmatch(line)
		}
		if len(m) != 2 || !net.ParseIP(m[1]).IsLoopback() {
			return n, ErrUnavailable
		}
	}
	return n, nil
}

// Claim: the independent observer trace gate accepts absence/loopback and
// rejects planted external and undecodable connect records.
func TestCandidateTraceControls(t *testing.T) {
	for _, r := range []struct {
		trace   string
		allowed bool
	}{{"", true}, {`1 connect(4, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16) = 0`, true}, {`1 connect(4, {sa_family=AF_INET, sin_addr=inet_addr("192.0.2.1")}, 16) = 0`, false}, {`1 connect(4, 0x1234, 16) = -1 EFAULT`, false}} {
		_, e := candidateTrace(r.trace)
		if (e == nil) != r.allowed {
			t.Fatal("trace control verdict", e)
		}
	}
}
