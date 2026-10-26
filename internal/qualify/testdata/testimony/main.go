//go:build linux && amd64

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualify"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"golang.org/x/sys/unix"
)

type authority struct{ p runner.Policy }

func (a authority) Resolve(context.Context, runner.Options) (runner.Policy, error) { return a.p, nil }

type broker struct{ root, mode string }

func (*broker) VerifyServer(context.Context, uint32) error { return nil }
func (*broker) Hello(context.Context, runner.HelloRequest) (runner.HelloResult, error) {
	return runner.HelloResult{Version: 1, Profile: runner.ProtocolProfile, UID: uint32(os.Getuid()), PolicyGeneration: 1}, nil
}
func (b *broker) Request(context.Context, runner.LeaseRequest) (runner.Lease, error) {
	if b.mode == "panic" {
		panic("fixture")
	}
	if b.mode == "defer" {
		return runner.Lease{}, &runner.Refusal{Code: "lease_owner_unavailable", Status: 69}
	}
	return runner.Lease{ID: "synthetic-lease", Account: "synthetic", Harness: "codex_cli", Channel: "external-token", ChatGPTAccountID: "vendor-account", Token: []byte("synthetic-material"), TokenExpiresAt: time.Now().Add(time.Hour), AuthorizedUntil: time.Now().Add(time.Minute), Renewable: true}, nil
}
func (*broker) Renew(context.Context, runner.RenewRequest) (runner.Lease, error) {
	panic("unexpected renewal")
}
func (*broker) Release(context.Context, string) error { return nil }
func (b *broker) Close() error {
	if b.mode == "defer" || b.mode == "panic" {
		os.WriteFile(filepath.Join(b.root, "cleanup"), nil, 0600)
		for {
			if _, e := os.Stat(filepath.Join(b.root, "continue")); e == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	return nil
}
func main() {
	if handled, code := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	mode := os.Args[1]
	if mode == "command" || mode == "conflict" || mode == "defer" || mode == "panic" {
		os.Exit(command(mode, os.Args[2], os.Args[3]))
	}
	if mode == "helper-answer" || mode == "helper-ready" {
		b, _ := hex.DecodeString(os.Args[2])
		unix.Write(4, b)
		if mode == "helper-answer" {
			unix.Read(4, make([]byte, 1))
		}
		return
	}
	f := os.NewFile(4, "context")
	path, _ := io.ReadAll(io.LimitReader(f, 108))
	f.Close()
	fd, _ := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	defer unix.Close(fd)
	if unix.Connect(fd, &unix.SockaddrUnix{Name: string(path)}) != nil {
		return
	}
	if mode == "early" {
		unix.Write(fd, append(append([]byte{'A'}, make([]byte, 32)...), 0, byte(runner.OutcomeSuccess)))
		unix.Read(fd, make([]byte, 1))
		return
	}
	if mode == "receipt" {
		unix.Write(fd, make([]byte, 32))
		unix.Read(fd, make([]byte, 1))
		return
	}
	if mode == "wrong-pid" {
		sender(fd, "helper-ready", []byte{'R'})
	} else {
		unix.Write(fd, []byte{'R'})
	}
	if mode == "exit" {
		return
	}
	var buf [64]byte
	n, _ := unix.Read(fd, buf[:])
	if n != 33 {
		return
	}
	answer := append(append([]byte{'A'}, buf[1:n]...), 0, byte(runner.OutcomeSuccess))
	switch mode {
	case "replay":
		old, _ := hex.DecodeString(os.Args[2])
		copy(answer[1:33], old)
	case "late":
		time.Sleep(150 * time.Millisecond)
	case "twice":
		answer = []byte{'R'}
	case "truncated":
		answer = answer[:34]
	case "oversized":
		answer = make([]byte, 65)
	case "wrong-answer":
		sender(fd, "helper-answer", answer)
		return
	}
	unix.Write(fd, answer)
	if mode == "extra" {
		unix.Write(fd, answer)
	}
	unix.Read(fd, buf[:])
}
func sender(fd int, mode string, b []byte) {
	pad, _ := os.Open(os.DevNull)
	defer pad.Close()
	cmd := exec.Command("/proc/self/exe", mode, hex.EncodeToString(b))
	cmd.Env = []string{"GOMAXPROCS=2"}
	cmd.ExtraFiles = []*os.File{pad, os.NewFile(uintptr(fd), "case-channel")}
	cmd.Run()
}
func command(mode, root, fake string) int {
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	args := []string{"--account", "synthetic", "--profile", "fixture", "--launch-home", home, "--prompt-stdin", "--model", "synthetic-model", "--reasoning-effort", "medium", "--output-last-message", filepath.Join(root, "answer"), "--cwd", project, "--timeout", "10"}
	opts, _ := runner.Parse(args)
	env := []string{"HOME=" + home, "CODEX_HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	config, _ := runner.ConfigurationDigest(opts, env)
	if mode == "conflict" {
		env = append(env, "OPENAI_API_KEY=")
	}
	data, e := os.ReadFile(fake)
	if e != nil {
		return 125
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	p := runner.Policy{Account: "synthetic", Profile: "fixture", Endpoint: "https://synthetic.invalid", Executable: fake, ExecutableSHA256: digest, Release: "codex-cli 0.163.0", SchemaSHA256: strings.Repeat("a", 64), ChatGPTAccountID: "vendor-account", ConfigSHA256: config, BindingDigest: strings.Repeat("b", 64), UID: uint32(os.Getuid()), BrokerUID: uint32(os.Getuid()), PolicyGeneration: 1, Qualified: true, Catalog: map[string][]string{"synthetic-model": {"medium"}}}
	d := runner.Dependencies{Authority: authority{p}, Environment: env, Supervisor: "/proc/self/exe", Connect: func(context.Context) (runner.BrokerClient, error) { return &broker{root, mode}, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, e := qualify.RunnerTestimonyCommand(ctx, args, runner.IO{In: strings.NewReader("synthetic prompt"), Out: io.Discard, Err: io.Discard}, d)
	if e != nil || mode == "command" && out.Status != 0 || mode == "conflict" && out.Kind != runner.OutcomeSourceConflict {
		return 125
	}
	return 0
}
