//go:build linux && amd64

package qualify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type boundedReportBuffer struct{ bytes.Buffer }

func (b *boundedReportBuffer) Write(p []byte) (int, error) {
	if len(p) > 128<<10-b.Len() {
		return 0, errors.New("pending report exceeds bound")
	}
	return b.Buffer.Write(p)
}

// Claim: the public pending path with a non-executable synthetic candidate
// refuses unsupported launchers without recursive test entry, emits at most
// 128 KiB and allocates less than 16 MiB in this process. Child/runtime memory
// is separately bounded by the test command's scope, not by this heap assertion.
func TestPendingReportBounded(t *testing.T) {
	path, c, evidence := setup(t)
	var control boundedReportBuffer
	if _, e := control.Write(make([]byte, 128<<10+1)); e == nil || control.Len() != 0 {
		t.Fatal("output limit missed planted overflow")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var out boundedReportBuffer
	code := Command(ctx, []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}, path, nil, &out)
	runtime.ReadMemStats(&after)
	if code != 69 || ctx.Err() != nil || after.TotalAlloc-before.TotalAlloc >= 16<<20 {
		t.Fatal("pending path exceeded execution/allocation bound", code, after.TotalAlloc-before.TotalAlloc)
	}
	var r report
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil || r.Disposition != "pending" || len(r.Observers.Runs) > 6 {
		t.Fatal("pending report exceeded output/launch bound")
	}
	for _, run := range r.Observers.Runs {
		if run.Observer != "version/1" {
			t.Fatal("unsupported candidate advanced beyond version gate")
		}
	}
	entries, e := os.ReadDir(evidence)
	if e != nil || len(entries) != 1 || entries[0].Name() != "run.json" {
		t.Fatal("pending path retained launch state")
	}
	t.Logf("pending report bytes=%d; parent allocation=%d; launches=%d", out.Len(), after.TotalAlloc-before.TotalAlloc, len(r.Observers.Runs))
}

// Claim: the real observer implementation feeds protected pending run.json with
// real version/schema/catalog digests and boundary summaries, while publishing
// nothing. Unsupported version and schema drift retain empty corresponding
// measurements and explicit unavailable/nondeterministic evidence.
// An executable refused before launch still yields a decodable empty run list.
func TestObservedReport(t *testing.T) {
	goTool := os.Getenv("GO")
	if !filepath.IsAbs(goTool) {
		t.Fatal("absolute GO required")
	}
	tools := t.TempDir()
	launcher := filepath.Join(tools, "broker")
	fixture := filepath.Join(tools, "fixture")
	for _, b := range []struct{ out, pkg string }{{launcher, "../../cmd/swarma-credential-broker"}, {fixture, "../qualification/testdata/candidate"}} {
		cmd := exec.Command(goTool, "build", "-p=2", "-o", b.out, b.pkg)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(e, string(out))
		}
		if os.Chmod(b.out, 0700) != nil {
			t.Fatal("tool protection")
		}
	}
	for _, mode := range []string{"correct", "wrong", "schema-drift", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			path, c, evidence := setup(t)
			b, e := os.ReadFile(fixture)
			if e != nil {
				t.Fatal(e)
			}
			if os.WriteFile(c.Policy.Executable, b, 0700) != nil {
				t.Fatal("fixture copy")
			}
			c.Policy.ExecutableSHA256 = qualification.Hash(b)
			raw, _ := wire.Encode(c)
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("config")
			}
			settings, _ := json.Marshal(map[string]string{"Mode": mode, "Counter": filepath.Join(filepath.Dir(path), "counter")})
			if os.WriteFile(c.Policy.Executable+".json", settings, 0600) != nil {
				t.Fatal("settings")
			}
			if mode == "unavailable" && os.Chmod(c.Policy.Executable, 0600) != nil {
				t.Fatal("unavailable executable fixture")
			}
			d := driver{path: path, observer: func(c policy.Config) qualification.IdentityObserver {
				raw, _ := wire.Encode(c)
				return qualification.NativeObserver{ExecutablePath: c.Policy.Executable, ExecutableSHA256: c.Policy.ExecutableSHA256, StaticPolicy: raw, LauncherPath: launcher, ScratchRoot: evidence, Evidence: &qualification.CandidateEvidence{}}
			}}
			var out bytes.Buffer
			if code := d.run(context.Background(), []string{"--executable", c.Policy.Executable, "--evidence-dir", evidence, "--fixtures"}, &out); code != 69 {
				t.Fatal("pending exit", code)
			}
			var r report
			if wire.Decode(bytes.TrimSpace(out.Bytes()), &r) != nil {
				t.Fatal("missing protected report")
			}
			if mode == "correct" {
				if r.Identity.Version != "0.163.0" || r.Identity.Schema.SHA256 == "" || r.Identity.Catalog.SHA256 == "" || r.Observers.Version.SHA256 != qualification.Hash([]byte("0.163.0")) || len(r.Observers.Runs) == 0 {
					t.Fatal("missing measurements")
				}
			} else if mode == "wrong" {
				if r.Identity.Version != "" || r.Observers.Version.SHA256 != "" {
					t.Fatal("unsupported version measured")
				}
			} else if mode == "unavailable" {
				if r.Identity.Version != "" || r.Observers.Runs == nil || len(r.Observers.Runs) != 0 {
					t.Fatal("unavailable executable gained evidence")
				}
			} else if r.Identity.Schema.SHA256 != "" || r.Observers.SchemaComparison != "different" {
				t.Fatal("schema drift not reported")
			}
			for _, run := range r.Observers.Runs {
				if run.IsolationFailed || run.Incomplete || run.Summary["external"].Allowed != 0 {
					t.Fatal("observer isolation")
				}
			}
			for _, row := range r.Cases {
				if row.Positive.Executed || row.Negative.Executed {
					t.Fatal("pending row executed")
				}
			}
			if len(r.Unavailable) == 0 || r.Disposition != "pending" {
				t.Fatal("publication gate open")
			}
			if _, e := os.Lstat(filepath.Join(qualification.Directory(path), "qualified.json")); !os.IsNotExist(e) {
				t.Fatal("published qualification", e)
			}
			entries, e := os.ReadDir(evidence)
			if e != nil || len(entries) != 1 || entries[0].Name() != "run.json" {
				t.Fatal("home/socket retained")
			}
		})
	}
}
