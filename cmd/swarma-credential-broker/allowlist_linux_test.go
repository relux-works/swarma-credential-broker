//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: the actual daemon source checker admits the same protected static
// snapshot only; missing/unprotected/changed/canceled evidence returns one typed
// sentinel, never a raw filesystem error or a disk reload/current grant claim.
func TestAllowlistProtectedSource(t *testing.T) {
	e := testutil.New(t, lease.Options{})
	c := policy.Config{SocketPath: filepath.Join(t.TempDir(), "s"), StoreRoot: e.Root, Policy: e.Policy}
	path := filepath.Join(t.TempDir(), "policy.json")
	for _, mode := range []string{"valid", "missing", "mode", "generation", "endpoint", "socket", "root", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			next := c
			next.Policy = c.Policy.Clone()
			if mode == "generation" {
				next.Policy.Generation++
			}
			if mode == "endpoint" {
				next.Policy.Accounts[0].Endpoint = "https://other.invalid"
			}
			if mode == "socket" {
				next.SocketPath += "x"
			}
			if mode == "root" {
				next.StoreRoot += "x"
			}
			b, _ := wire.Encode(next)
			if os.WriteFile(path, b, 0600) != nil || os.Chmod(path, 0600) != nil {
				t.Fatal("write fixture")
			}
			if mode == "missing" {
				os.Remove(path)
			}
			if mode == "mode" {
				os.Chmod(path, 0644)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			err := observeConfiguredPolicy(ctx, path, c, c.Policy)
			if mode == "valid" {
				if err != nil {
					t.Fatal("valid protected source refused")
				}
			} else if err != qualification.ErrUnavailable {
				t.Fatal("source refusal was not closed")
			}
		})
	}
}
