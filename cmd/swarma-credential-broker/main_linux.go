//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/server"
	"github.com/relux-works/swarma-credential-broker/internal/store"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func run(args []string, out, diagnostic io.Writer) int {
	if len(args) == 0 {
		return 64
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "protected configuration file")
	initialize := fs.Bool("init-store", false, "initialize new metadata directories")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *config == "" || (args[0] != "daemon" && args[0] != "status") || args[0] == "status" && *initialize {
		return 64
	}
	c, e := policy.Load(*config, uint32(os.Geteuid()))
	if e != nil {
		fmt.Fprintln(diagnostic, "configuration_unavailable")
		return 69
	}
	if args[0] == "status" {
		status, e := server.Status(context.Background(), c.SocketPath, c.Policy.BrokerUID)
		if e != nil {
			fmt.Fprintln(diagnostic, lease.ErrorCode(e))
			return 69
		}
		b, e := wire.Encode(status)
		if e != nil {
			return 69
		}
		_, e = out.Write(append(b, '\n'))
		if e != nil {
			return 75
		}
		return 0
	}
	s, e := store.Open(c.StoreRoot, c.Policy.Installation, c.Policy.BrokerUID, *initialize, nil)
	if e != nil {
		fmt.Fprintln(diagnostic, "lease_owner_unavailable")
		return 69
	}
	defer s.Close()
	m, e := lease.New(c.Policy, s, owner.Stopped{}, lease.Options{}, *initialize)
	if e != nil {
		fmt.Fprintln(diagnostic, "lease_owner_unavailable")
		return 69
	}
	defer m.Close()
	listener, e := server.Listen(c.SocketPath)
	if e != nil {
		fmt.Fprintln(diagnostic, "lease_owner_unavailable")
		return 69
	}
	srv := server.New(m)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	var reloadWG sync.WaitGroup
	reloadWG.Add(1)
	defer func() { cancel(); reloadWG.Wait() }()
	go func() {
		defer reloadWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				next, e := policy.Load(*config, c.Policy.BrokerUID)
				if e != nil || next.SocketPath != c.SocketPath || next.StoreRoot != c.StoreRoot || m.Replace(next.Policy) != nil {
					fmt.Fprintln(diagnostic, "configuration_reload_refused")
					continue
				}
				srv.CloseConnections()
			}
		}
	}()
	e = srv.Serve(ctx, listener)
	srv.Close()
	srv.Wait()
	if e != nil {
		fmt.Fprintln(diagnostic, "lease_owner_unavailable")
		return 75
	}
	return 0
}
