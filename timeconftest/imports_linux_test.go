//go:build linux

package timeconftest_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Claim: the real default compiled dependency graph excludes test-only imports
// but exposes a planted application import. The accepted external module also
// runs tagged positive receipt and handoff checks through the public helpers.
func TestFixtureConsumerDependencyBoundary(t *testing.T) {
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	const module = "github.com/relux-works/swarma-credential-broker"
	for _, plant := range []bool{false, true} {
		name := "test-only"
		if plant {
			name = "application-plant"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"go.mod":      "module consumer.example/fixturecheck\n\ngo 1.25\nrequire " + module + " v0.0.0\nreplace " + module + " => " + filepath.ToSlash(repo) + "\n",
				"consumer.go": "package consumer\n",
				"consumer_test.go": `package consumer
import (
 "context"
 "os"
 "testing"
 "time"
 tc "` + module + `/timeconf"
 fixture "` + module + `/timeconftest"
)
func TestPositiveReceipt(t *testing.T) {
 root:=t.TempDir();if err:=os.Chmod(root,0700);err!=nil {t.Fatal(err)}
 f,err:=fixture.New(root);if err!=nil {t.Fatal(err)}
 d,_:=tc.NativeOperationDigest("operation",[]byte("public identity"))
 raw,err:=f.ConsumeBeforePin(context.Background(),tc.ConsumptionRequest{Deadline:time.Now().Add(400*time.Millisecond),Expected:f.Enrollment(),OperationDigest:d,Challenge:"11111111111111111111111111111111",JournalFloor:140000000000})
 if err!=nil {t.Fatal(err)}
 if _,err=tc.DecodeReceipt(raw);err!=nil {t.Fatal(err)}
 hr:=t.TempDir();if err=os.Chmod(hr,0700);err!=nil {t.Fatal(err)}
 hp,err:=fixture.NewHandoffProvider(hr);if err!=nil {t.Fatal(err)}
 packet,err:=hp.CollectHandoff(context.Background(),tc.ConsumptionRequest{Deadline:time.Now().Add(400*time.Millisecond),Expected:hp.Enrollment(),OperationDigest:d,Challenge:"22222222222222222222222222222222",JournalFloor:140000000000},tc.WindowIdentity{Profile:"fixture-window",Sequence:"1"},"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
 if err!=nil {t.Fatal(err)}
 candidate,err:=tc.VerifyWindow(packet.Prepared,packet.Expected,packet.Local,packet.Capture);if err!=nil {t.Fatal(err)}
 _ = candidate; e:=packet.Expected;key:=tc.UseKey{Consumer:e.Enrollment.Scope.Consumer,Store:e.Enrollment.Store,Operation:e.Operation,Window:e.Window};_ = fixture.NewUseStore(e.Epoch,key)
}
`,
			}
			if plant {
				files["consumer.go"] = "package consumer\nimport fixture \"" + module + "/timeconftest\"\nvar _ = fixture.New\nvar _ = fixture.NewHandoffProvider\nvar _ = fixture.PrepareHandoff\nvar _ = fixture.NewUseStore\n"
			}
			for file, source := range files {
				if err := os.WriteFile(filepath.Join(root, file), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			run := func(args ...string) []byte {
				cmd := exec.CommandContext(ctx, goTool, args...)
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GOWORK=off")
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("external module command failed: %v\n%s", err, out)
				}
				return out
			}
			for _, tag := range []string{"", "swarma_timeconf_fixture"} {
				out := run("list", "-mod=mod", "-tags="+tag, "-deps", "-compiled", "-f={{.ImportPath}}", "./...")
				violation := strings.Contains("\n"+string(out), "\n"+module+"/timeconftest\n")
				if violation != plant {
					t.Fatalf("test-only dependency guard: tag=%q planted=%v detected=%v", tag, plant, violation)
				}
			}
			if !plant {
				run("test", "-mod=mod", "-tags=swarma_timeconf_fixture", "-count=1", ".")
			}
		})
	}
}
