//go:build linux && amd64

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

type authority struct{ p runner.Policy }

func (a authority) Resolve(context.Context, runner.Options) (runner.Policy, error) { return a.p, nil }

type broker struct{ releases int }

func (b *broker) VerifyServer(context.Context, uint32) error { return nil }
func (b *broker) Hello(context.Context, runner.HelloRequest) (runner.HelloResult, error) {
	return runner.HelloResult{Version: 1, Profile: runner.ProtocolProfile, UID: uint32(os.Getuid()), PolicyGeneration: 1}, nil
}
func (b *broker) Request(context.Context, runner.LeaseRequest) (runner.Lease, error) {
	return runner.Lease{ID: "synthetic-lease", Account: "synthetic", Harness: "codex_cli", Channel: "external-token", ChatGPTAccountID: "vendor-account", Token: []byte("synthetic-material"), TokenExpiresAt: time.Now().Add(time.Hour), AuthorizedUntil: time.Now().Add(time.Minute), Renewable: true}, nil
}
func (*broker) Renew(context.Context, runner.RenewRequest) (runner.Lease, error) {
	panic("unexpected renewal")
}
func (b *broker) Release(context.Context, string) error { b.releases++; return nil }
func (*broker) Close() error                            { return nil }
func main() {
	if handled, code := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	switch os.Args[1] {
	case "threads":
		var ready, done sync.WaitGroup
		gate := make(chan struct{})
		ready.Add(4)
		done.Add(4)
		for range 4 {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				defer done.Done()
				ready.Done()
				<-gate
			}()
		}
		ready.Wait()
		close(gate)
		done.Wait()
	case "exit17":
		os.Exit(17)
	case "exec":
		_ = unix.Exec("/bin/true", []string{"/bin/true"}, []string{})
	case "compose":
		os.Exit(compose(os.Args[2], os.Args[3]))
	default:
		os.Exit(125)
	}
}
func compose(root, fake string) int {
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	args := []string{"--account", "synthetic", "--profile", "fixture", "--launch-home", home, "--prompt-stdin", "--model", "synthetic-model", "--reasoning-effort", "medium", "--output-last-message", filepath.Join(root, "answer"), "--cwd", project, "--timeout", "10"}
	opts, err := runner.Parse(args)
	if err != nil {
		return 125
	}
	env := []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	config, err := runner.ConfigurationDigest(opts, env)
	if err != nil {
		return 125
	}
	data, err := os.ReadFile(fake)
	if err != nil {
		return 125
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	p := runner.Policy{Account: "synthetic", Profile: "fixture", Endpoint: "https://synthetic.invalid", Executable: fake, ExecutableSHA256: digest, Release: "codex-cli 0.163.0", SchemaSHA256: strings.Repeat("a", 64), ChatGPTAccountID: "vendor-account", ConfigSHA256: config, BindingDigest: strings.Repeat("b", 64), UID: uint32(os.Getuid()), BrokerUID: uint32(os.Getuid()), PolicyGeneration: 1, Qualified: true, Catalog: map[string][]string{"synthetic-model": {"medium"}}}
	b := &broker{}
	d := runner.Dependencies{Authority: authority{p}, Environment: env, Supervisor: "/proc/self/exe", Connect: func(context.Context) (runner.BrokerClient, error) { return b, nil }}
	code := runner.Command(context.Background(), args, runner.IO{In: strings.NewReader("synthetic prompt"), Out: os.Stdout, Err: os.Stderr}, d)
	if code == 0 && b.releases != 1 {
		return 125
	}
	return code
}
