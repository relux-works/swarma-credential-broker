//go:build linux

// This program is a synthetic vendor used only by isolated owner tests.
// Keeping it separate avoids hashing the entire test suite at every replacement;
// the owner still validates the actual executable bytes on every construction.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "entry-echo":
		group, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			os.Exit(12)
		}
		fmt.Fprintln(os.Stdout, strings.TrimSpace(string(group)))
		if _, err = io.Copy(os.Stdout, os.Stdin); err != nil {
			os.Exit(13)
		}
	case "app-server":
		fakeVendor()
	case "grandchild":
		signalIgnore()
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(2)
	}
}
func signalIgnore() { signal.Ignore(syscall.SIGTERM) }

func fixtureAuth(home, token string) error {
	b, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh", "account_id": "fixture-account"}})
	f, e := os.OpenFile(filepath.Join(home, "fixture-pending"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(home, "fixture-pending"), filepath.Join(home, "auth.json")); e != nil {
		return e
	}
	d, e := os.Open(home)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func fakeVendor() {
	home := os.Getenv("CODEX_HOME")
	mode, e := os.ReadFile(filepath.Join(home, "scenario"))
	if e != nil {
		os.Exit(3)
	}
	scanner := bufio.NewScanner(os.Stdin)
	send := func(v any) { b, _ := json.Marshal(v); fmt.Fprintln(os.Stdout, string(b)) }
	state := 0
	for scanner.Scan() {
		var v struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &v) != nil {
			os.Exit(4)
		}
		switch state {
		case 0:
			if v.Method != "initialize" {
				os.Exit(5)
			}
			send(map[string]any{"id": v.ID, "result": map[string]any{"userAgent": "fixture"}})
			state++
		case 1:
			if v.Method != "initialized" {
				os.Exit(6)
			}
			state++
		case 2:
			var p struct {
				Refresh bool `json:"refreshToken"`
			}
			if v.Method != "account/read" || json.Unmarshal(v.Params, &p) != nil || !p.Refresh {
				os.Exit(7)
			}
			switch string(mode) {
			case "safe", "rejected":
				code := 1001
				if string(mode) == "rejected" {
					code = 1002
				}
				send(map[string]any{"id": v.ID, "error": map[string]any{"code": code, "message": "synthetic error"}})
			case "rotate-crash":
				os.WriteFile(filepath.Join(home, "exchange-observed"), []byte("1"), 0600)
				os.Exit(9)
			case "hang":
				for {
					time.Sleep(time.Hour)
				}
			case "grandchild":
				signalIgnore()
				exe, _ := os.Executable()
				cmd := exec.Command(exe, "grandchild")
				cmd.Env = []string{"HOME=" + home, "CODEX_HOME=" + home}
				if cmd.Start() != nil {
					os.Exit(10)
				}
				os.WriteFile(filepath.Join(home, "grandchild-pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
				for {
					time.Sleep(time.Hour)
				}
			case "exit-zero":
				return
			default:
				if string(mode) != "unchanged" {
					token, e := os.ReadFile(filepath.Join(home, "next-token"))
					if e != nil || fixtureAuth(home, string(token)) != nil {
						os.Exit(8)
					}
				}
				if string(mode) == "metadata-only" {
					token, e := os.ReadFile(filepath.Join(home, "next-token"))
					if e != nil || probeMetadata(home, string(token)) != nil {
						os.Exit(8)
					}
				}
				plan := "plus"
				if string(mode) == "bad-plan" {
					token, _ := os.ReadFile(filepath.Join(home, "next-token"))
					plan = string(token)
				}
				send(map[string]any{"id": v.ID, "result": map[string]any{"requiresOpenaiAuth": true, "account": map[string]string{"type": "chatgpt", "planType": plan}}})
			}
			state++
		default:
			os.Exit(11)
		}
	}
	// A detached writer can outlive both its daemon and private pipes. Preserve
	// this explicit witness instead of mistaking retained fake metadata for life.
	if string(mode) == "survive-pipe-loss" {
		signalIgnore()
		if os.WriteFile(filepath.Join(home, "pipes-closed-writer-live"), []byte("1"), 0600) != nil {
			os.Exit(14)
		}
		for {
			time.Sleep(time.Hour)
		}
	}

}

func probeMetadata(home, token string) error {
	b, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": token, "refresh_token": "synthetic-refresh", "account_id": "fixture-account"}, "last_refresh": "2026-01-01T00:00:00Z"})
	if err != nil {
		return err
	}
	pending := filepath.Join(home, "probe-pending")
	file, err := os.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(b); err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return err
	}
	if err = os.Rename(pending, filepath.Join(home, "auth.json")); err != nil {
		return err
	}
	dir, err := os.Open(home)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
