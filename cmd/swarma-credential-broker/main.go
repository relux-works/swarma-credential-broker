package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/internal/qualify"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
)

func main() {
	if handled, code := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) > 1 && (os.Args[1] == "daemon" || os.Args[1] == "status") {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) > 1 && os.Args[1] == "qualify-codex" {
		os.Exit(qualify.Command(ctx, os.Args[2:], runner.DefaultPolicyPath, os.Environ(), os.Stdout))
	}
	if len(os.Args) < 2 || os.Args[1] != "run-codex" {
		os.Stderr.WriteString("runner: invalid_command\n")
		os.Exit(64)
	}
	os.Exit(runner.Command(ctx, os.Args[2:], runner.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}, runner.ProtectedDependencies(runner.DefaultPolicyPath, os.Environ())))
}
