//go:build linux && amd64

package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

var candidateFixture, candidateLauncher string

func TestMain(m *testing.M) {
	if os.Getenv("CANDIDATE_TRACE_CHILD") == "1" {
		candidateLauncher = os.Getenv("CANDIDATE_TEST_LAUNCHER")
		os.Exit(m.Run())
	}
	goTool := os.Getenv("GO")
	if !filepath.IsAbs(goTool) {
		fmt.Fprintln(os.Stderr, "absolute GO required")
		os.Exit(2)
	}
	root, e := os.MkdirTemp("", "candidate-tools-")
	if e != nil {
		panic(e)
	}
	candidateFixture = filepath.Join(root, "fixture")
	candidateLauncher = filepath.Join(root, "broker")
	for _, b := range []struct{ out, pkg string }{{candidateFixture, "./testdata/candidate"}, {candidateLauncher, "../../cmd/swarma-credential-broker"}} {
		cmd := exec.Command(goTool, "build", "-p=2", "-o", b.out, b.pkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if cmd.Run() != nil {
			os.RemoveAll(root)
			os.Exit(2)
		}
		if os.Chmod(b.out, 0700) != nil {
			os.RemoveAll(root)
			os.Exit(2)
		}
	}
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}
func candidateObserver(t *testing.T, mode string) (NativeObserver, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "candidate")
	b, e := os.ReadFile(candidateFixture)
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(path, b, 0700) != nil {
		t.Fatal("fixture copy")
	}
	config := map[string]string{"Mode": mode, "Marker": filepath.Join(root, "homes"), "Counter": filepath.Join(root, "counter"), "PID": filepath.Join(root, "child-pid")}
	raw, _ := json.Marshal(config)
	if os.WriteFile(path+".json", raw, 0600) != nil {
		t.Fatal("settings")
	}
	return NativeObserver{ExecutablePath: path, ExecutableSHA256: Hash(b), LauncherPath: candidateLauncher, ScratchRoot: root, Evidence: &CandidateEvidence{}}, root
}
func noHomes(t *testing.T, root string) {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(root, "homes"))
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, home := range strings.Fields(string(raw)) {
		if seen[home] {
			t.Fatal("home reused")
		}
		seen[home] = true
		if _, e := os.Lstat(home); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("home retained", e)
		}
	}
}

// Claim: only the exact expected version is measured, with bounded stdout and
// stderr. Each neighboring refusal leaves no version string/digest or home.
func TestCandidateVersion(t *testing.T) {
	for _, mode := range []string{"wrong", "malformed", "oversized", "stderr-oversized", "correct"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			v, e := o.Version(context.Background())
			if mode == "correct" {
				if e != nil || v != "0.163.0" || o.Evidence.Version.SHA256 != Hash([]byte(v)) {
					t.Fatal("version measurement", v, e)
				}
			} else if !errors.Is(e, ErrUnavailable) || v != "" || o.Evidence.Version.SHA256 != "" {
				t.Fatal("invalid version measured", v, e)
			}
			noHomes(t, root)
		})
	}
}

// Claim: actual-socket and harmless bad-FD external-address attempts both
// and denied Unix-address attempts invalidate an otherwise correct version.
// The bad-FD case safely kills the bypass
// mutant without any possibility of a packet leaving the host.
func TestCandidateIsolation(t *testing.T) {
	for _, mode := range []string{"external", "external-bad-fd", "unix"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			v, e := o.Version(context.Background())
			if !errors.Is(e, ErrUnavailable) || v != "" {
				t.Fatal("external attempt measured", v, e)
			}
			class := "external"
			if mode == "unix" {
				class = "unix"
			}
			if len(o.Evidence.Runs) != 1 || !o.Evidence.Runs[0].IsolationFailed || o.Evidence.Runs[0].Summary[class].Refused == 0 {
				t.Fatal("missing isolation refusal")
			}
			noHomes(t, root)
		})
	}
}

// Claim: semantically unchanged schema bytes with reordered keys/whitespace
// yield the independently specified digest; changing content, duplicate keys,
// symlinks or excessive output never yields a schema measurement.
func TestCandidateSchema(t *testing.T) {
	for _, mode := range []string{"schema-drift", "schema-duplicate", "schema-link", "schema-oversized", "correct"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			m, e := o.Schema(context.Background())
			if mode == "correct" {
				want := Hash([]byte(`{"schema.json":{"a":1,"b":2}}`))
				if e != nil || m.Observer != "schema/1" || m.SHA256 != want {
					t.Fatal("canonical schema", m, e)
				}
			} else if !errors.Is(e, ErrUnavailable) || m.SHA256 != "" {
				t.Fatal("invalid schema measured", m, e)
			}
			if mode == "schema-drift" && o.Evidence.SchemaComparison != "different" {
				t.Fatal("nondeterminism was not reported")
			}
			noHomes(t, root)
		})
	}
}

// Claim: stdio initialize/model-list measures advertised model/effort pairs
// in canonical order; an empty catalog remains unavailable, with no network.
func TestCandidateCatalog(t *testing.T) {
	for _, mode := range []string{"catalog-invalid", "correct"} {
		t.Run(mode, func(t *testing.T) {
			o, root := candidateObserver(t, mode)
			m, c, e := o.Catalog(context.Background())
			if mode == "correct" {
				raw, _ := wire.Encode(Catalog{Models: []Model{{Name: "fixture-model", Efforts: []string{"low", "medium"}}}})
				if e != nil || m.SHA256 != Hash(raw) || len(c.Models) != 1 {
					t.Fatal("catalog", m, e)
				}
			} else if !errors.Is(e, ErrUnavailable) || m.SHA256 != "" {
				t.Fatal("invalid catalog measured", e)
			}
			noHomes(t, root)
		})
	}
}

// Claim: digest drift, writable files, links and an unavailable trusted launcher
// cannot execute a candidate or produce a version measurement.
func TestCandidateExecutableBinding(t *testing.T) {
	for _, kind := range []string{"digest", "writable", "symlink", "hardlink", "launcher"} {
		t.Run(kind, func(t *testing.T) {
			o, _ := candidateObserver(t, "correct")
			switch kind {
			case "digest":
				o.ExecutableSHA256 = Hash([]byte("wrong"))
			case "writable":
				os.Chmod(o.ExecutablePath, 0777)
			case "symlink":
				os.Symlink(o.ExecutablePath, o.ExecutablePath+"-link")
				o.ExecutablePath += "-link"
			case "hardlink":
				os.Link(o.ExecutablePath, o.ExecutablePath+"-link")
			case "launcher":
				o.LauncherPath = "/missing-candidate-launcher"
			}
			v, e := o.Version(context.Background())
			if !errors.Is(e, ErrUnavailable) || v != "" || len(o.Evidence.Runs) > 0 {
				t.Fatal("unsafe executable measured", v, e)
			}
		})
	}
}

// Claim: cancellation removes the fresh home, and a version process leaving an
// ordinary descendant behind loses that descendant to the owned group cleanup.
// The test adopts/reaps only its named fixture child to avoid an orphan zombie.
func TestCandidateCleanup(t *testing.T) {
	o, root := candidateObserver(t, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := o.Version(ctx); result <- e }()
	for {
		if _, e := os.Stat(filepath.Join(root, "homes")); e == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("candidate did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if e := <-result; e == nil {
		t.Fatal("cancellation ignored")
	}
	noHomes(t, root)
	var old int32
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&old)), 0, 0, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		t.Fatal("subreaper")
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(old), 0, 0, 0)
	o, root = candidateObserver(t, "leftover")
	if _, e := o.Version(context.Background()); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(root, "child-pid"))
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(string(raw))
	if e != nil || pid <= 1 {
		t.Fatal("child pid")
	}
	deadline := time.Now().Add(2 * time.Second)
	var status syscall.WaitStatus
	for {
		got, e := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if got == pid {
			if !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("child not killed", status)
			}
			break
		}
		if e != nil || time.Now().After(deadline) {
			t.Fatal("leftover child not reaped", e)
		}
		time.Sleep(time.Millisecond)
	}
	if _, e := os.Stat(fmt.Sprintf("/proc/%d", pid)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("child remains")
	}
	noHomes(t, root)
}

// Claim: schema directory enumeration has a real entry/depth budget and obeys
// cancellation, while a nearby valid tree still yields its canonical bundle.
func TestCandidateSchemaTreeBounds(t *testing.T) {
	for _, kind := range []string{"correct", "depth", "entries", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if e := os.WriteFile(filepath.Join(root, "schema.json"), []byte(`{"a":1}`), 0600); e != nil {
				t.Fatal(e)
			}
			if kind == "depth" {
				path := root
				for i := 0; i < 33; i++ {
					path = filepath.Join(path, "d")
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
				}
			}
			if kind == "entries" {
				for i := 0; i < 8192; i++ {
					if e := os.Mkdir(filepath.Join(root, fmt.Sprintf("d%d", i)), 0700); e != nil {
						t.Fatal(e)
					}
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			b, e := schemaDirectory(ctx, root)
			if kind == "correct" {
				if e != nil || string(b) != `{"schema.json":{"a":1}}` {
					t.Fatal("valid tree refused", e)
				}
			} else if !errors.Is(e, ErrUnavailable) || b != nil {
				t.Fatal("tree limit accepted", e)
			}
		})
	}
}
