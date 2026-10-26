// This synthetic fault fixture changes one observed effect before the real
// dispatcher runs. It has no production flag or environment selector.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/qualify"
	"github.com/relux-works/swarma-credential-broker/internal/runner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"golang.org/x/sys/unix"
)

var fault string

func main() {
	if len(os.Args) == 2 && os.Args[1] == "child" {
		return
	}
	if handled, code := runner.SupervisorMain(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) == 4 && os.Args[3] == "negative" {
		fd, e := unix.Dup(5)
		if e != nil {
			os.Exit(120)
		}
		f := os.NewFile(uintptr(fd), "context-copy")
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		if e != nil {
			os.Exit(120)
		}
		var in struct {
			Socket         string `json:"socket"`
			ID             string `json:"id"`
			Side           string `json:"side"`
			ApprovedDigest string `json:"approved_digest"`
		}
		// Only decode the socket; the unchanged full context goes to CaseMain.
		// json.Unmarshal intentionally allows the other fixture fields here.
		if json.Unmarshal(b, &in) != nil {
			os.Exit(120)
		}
		r, w, e := os.Pipe()
		if e != nil {
			os.Exit(120)
		}
		w.Write(b)
		w.Close()
		e = unix.Dup3(int(r.Fd()), 5, 0)
		r.Close()
		if e != nil {
			os.Exit(120)
		}
		root := filepath.Dir(os.Getenv("HOME"))
		switch fault {
		case "unexpected":
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Real Command parses the unsupported option and returns 64 before work.
			out, e := qualify.RunnerTestimonyCommand(ctx, []string{"--unknown-fixture-option"}, runner.IO{Err: io.Discard}, runner.Dependencies{})
			if e != nil {
				os.Exit(120)
			}
			effects := map[string]any{"status": out.Status}
			for _, key := range []string{"resolves", "connects", "requests", "releases", "login"} {
				effects[key] = 0
			}
			for _, key := range []string{"local_conflict", "version", "state_verified"} {
				effects[key] = false
			}
			if json.NewEncoder(os.Stdout).Encode(map[string]any{"id": in.ID, "side": in.Side, "candidate": in.ApprovedDigest, "refusal": "runner_failure", "no_effects": true, "probe_fault": false, "envelopes": []any{}, "runner": effects}) != nil {
				os.Exit(120)
			}
			return
		case "connection", "request", "method":
			c, e := net.Dial("unix", in.Socket)
			if e != nil {
				os.Exit(120)
			}
			c.SetDeadline(time.Now().Add(time.Second))
			if fault != "connection" {
				params, _ := wire.Encode(wire.Hello{Versions: []int{1}, Profile: wire.Profile})
				wire.Write(c, wire.Request{Method: "hello", ID: "hello", Params: params})
				wire.Read(c)
				method := "lease.request"
				if fault == "method" {
					method = "status"
				}
				wire.Write(c, wire.Request{Method: method, ID: "fault", Params: []byte(`{}`)})
				wire.Read(c)
			}
			c.Close()
		case "filesystem":
			path := filepath.Join(root, "project", "unexpected")
			if os.WriteFile(path, nil, 0600) != nil || os.Remove(path) != nil {
				os.Exit(120)
			}
		case "child":
			if exec.Command("/proc/self/exe", "child").Run() != nil {
				os.Exit(120)
			}
		case "missing":
			// The direct case joins normally but never sends post-Command testimony.
			return
		}
	}
	handled, code := qualify.CaseMain(os.Args[1:])
	if !handled {
		os.Exit(121)
	}
	if fault == "case-status" && code == 0 {
		code = 17
	}
	os.Exit(code)
}
