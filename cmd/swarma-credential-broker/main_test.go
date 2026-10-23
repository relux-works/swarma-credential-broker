//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: CLI argument/config errors reveal no supplied material; status uses the authenticated socket and emits scoped metadata.
func TestCommands(t *testing.T) {
	secret := testutil.Token()
	var out, diagnostic bytes.Buffer
	for _, args := range [][]string{nil, {"unknown", "--config", secret}, {"status", "--unknown=" + secret}, {"daemon", "--config", secret}, {"status", "--config", secret, "--init-store"}} {
		out.Reset()
		diagnostic.Reset()
		code := run(args, &out, &diagnostic)
		if code == 0 || bytes.Contains(out.Bytes(), []byte(secret)) || bytes.Contains(diagnostic.Bytes(), []byte(secret)) {
			t.Fatal("invalid command accepted or reflected input")
		}
	}
	e := testutil.New(t, lease.Options{})
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "c-")
	if err != nil {
		t.Fatal("fixture directory failed")
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	listener, err := server.Listen(path)
	if err != nil {
		t.Fatal("listener failed")
	}
	srv := server.New(e.Manager)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Serve(ctx, listener) }()
	defer func() { cancel(); srv.Close(); <-stopped; srv.Wait() }()
	cfg := policy.Config{SocketPath: path, StoreRoot: e.Root, Policy: e.Policy}
	b, _ := wire.Encode(cfg)
	config := filepath.Join(dir, "config.json")
	if os.WriteFile(config, b, 0600) != nil {
		t.Fatal("fixture config failed")
	}
	out.Reset()
	diagnostic.Reset()
	if run([]string{"status", "--config", config}, &out, &diagnostic) != 0 || diagnostic.Len() != 0 {
		t.Fatal("status command failed")
	}
	var status wire.Status
	if wire.Decode(bytes.TrimSpace(out.Bytes()), &status) != nil || len(status.Accounts) != 1 {
		t.Fatal("status output invalid")
	}
}
