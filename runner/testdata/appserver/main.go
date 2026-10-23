// This fake speaks the generated 0.163.0 stdio subset. It performs no network
// requests and accepts synthetic tokens only through JSON-RPC, never env/argv.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type scenario struct {
	InitFail, LoginFail, Hang, Spawn, Echo, PreviousMismatch, Duplicate, WrongTurn, Escape, RetryAfterError bool
	RefreshCount                                                                                            int
	Status                                                                                                  string
	Approvals                                                                                               []string
	Version                                                                                                 string
}
type msg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

var home string

func send(v any) {
	if json.NewEncoder(os.Stdout).Encode(v) != nil {
		os.Exit(1)
	}
}
func response(id json.RawMessage, v any) { send(map[string]any{"id": id, "result": v}) }
func record(v any) {
	f, e := os.OpenFile(filepath.Join(home, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		os.Exit(1)
	}
	json.NewEncoder(f).Encode(v)
	f.Close()
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--child" {
		signal.Ignore(syscall.SIGTERM)
		if len(os.Args) > 2 && os.Args[2] == "spawn" {
			p := exec.Command(os.Args[0], "--child")
			p.Stdout = os.Stdout
			p.Stderr = os.Stderr
			if p.Start() != nil {
				os.Exit(1)
			}
			os.WriteFile(filepath.Join(os.Getenv("CODEX_HOME"), "grandchild-pid"), []byte(strconv.Itoa(p.Process.Pid)), 0600)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	home = os.Getenv("CODEX_HOME")
	var s scenario
	data, _ := os.ReadFile(filepath.Join(home, "scenario.json"))
	if json.Unmarshal(data, &s) != nil {
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		v := s.Version
		if v == "" {
			v = "codex-cli 0.163.0"
		}
		fmt.Println(v)
		return
	}
	if len(os.Args) < 4 || os.Args[1] != "app-server" || os.Args[2] != "--listen" || os.Args[3] != "stdio://" {
		os.Exit(2)
	}
	if !strings.Contains(strings.Join(os.Args, " "), `cli_auth_credentials_store="ephemeral"`) {
		os.Exit(2)
	}
	os.WriteFile(filepath.Join(home, "server-pid"), []byte(strconv.Itoa(os.Getpid())), 0600)
	if s.Spawn {
		p := exec.Command(os.Args[0], "--child", "spawn")
		if s.Escape {
			p.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		}
		p.Stdout = os.Stdout
		p.Stderr = os.Stderr
		if p.Start() != nil {
			os.Exit(1)
		}
		os.WriteFile(filepath.Join(home, "child-pid"), []byte(strconv.Itoa(p.Process.Pid)), 0600)
	}
	var token string
	var initialized, notified bool
	remaining := s.RefreshCount
	approval := 0
	refreshIndex := 0
	finish := func() {
		if s.Hang {
			return
		}
		status := s.Status
		if status == "" {
			status = "completed"
		}
		text := "answer"
		if s.Echo {
			text = "safe " + token + " tail"
			fmt.Fprintln(os.Stderr, token)
		}
		thread := "thread"
		if s.WrongTurn {
			thread = "other"
		}
		// Deliberately split secret-bearing output across RPC boundaries.
		for _, part := range []string{text[:len(text)/2], text[len(text)/2:]} {
			send(map[string]any{"method": "item/agentMessage/delta", "params": map[string]any{"threadId": thread, "turnId": "turn", "itemId": "message", "delta": part}})
		}
		item := map[string]any{"id": "message", "type": "agentMessage", "phase": "final_answer", "text": text}
		send(map[string]any{"method": "item/completed", "params": map[string]any{"threadId": thread, "turnId": "turn", "completedAtMs": 0, "item": item}})
		send(map[string]any{"method": "turn/completed", "params": map[string]any{"threadId": thread, "turn": map[string]any{"id": "turn", "status": status, "items": []any{item}}}})
	}
	var next func()
	next = func() {
		if remaining > 0 {
			remaining--
			refreshIndex++
			id := "refresh-" + strconv.Itoa(refreshIndex)
			if s.Duplicate {
				id = "refresh-1"
			}
			previous := "vendor-account"
			if s.PreviousMismatch {
				previous = "wrong-account"
			}
			send(map[string]any{"id": id, "method": "account/chatgptAuthTokens/refresh", "params": map[string]any{"reason": "unauthorized", "previousAccountId": previous}})
			return
		}
		if approval < len(s.Approvals) {
			method := s.Approvals[approval]
			approval++
			send(map[string]any{"id": "approval-" + strconv.Itoa(approval), "method": method, "params": map[string]any{}})
			return
		}
		finish()
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var m msg
		if json.Unmarshal(scanner.Bytes(), &m) != nil {
			os.Exit(1)
		}
		if m.Method == "" {
			record(map[string]any{"reply": string(m.ID), "error": len(m.Error) > 0, "result": safeResult(m.Result)})
			var payload struct {
				AccessToken string `json:"accessToken"`
				Account     string `json:"chatgptAccountId"`
			}
			json.Unmarshal(m.Result, &payload)
			if payload.AccessToken != "" {
				if payload.Account != "vendor-account" {
					os.Exit(1)
				}
				token = payload.AccessToken
			}
			if len(m.Error) == 0 || strings.Contains(string(m.ID), "approval-") || s.RetryAfterError {
				next()
			}
			continue
		}
		record(map[string]any{"method": m.Method})
		fail := false
		switch m.Method {
		case "initialize":
			var p struct {
				Capabilities struct {
					Experimental bool `json:"experimentalApi"`
				} `json:"capabilities"`
			}
			json.Unmarshal(m.Params, &p)
			fail = s.InitFail || !p.Capabilities.Experimental
			initialized = !fail
		case "initialized":
			if !initialized {
				os.Exit(1)
			}
			notified = true
			continue
		case "account/login/start":
			var p struct {
				Type    string `json:"type"`
				Token   string `json:"accessToken"`
				Account string `json:"chatgptAccountId"`
			}
			json.Unmarshal(m.Params, &p)
			fail = s.LoginFail || !notified || p.Type != "chatgptAuthTokens" || p.Account != "vendor-account"
			if !fail {
				token = p.Token
				response(m.ID, map[string]any{"type": "chatgptAuthTokens"})
				continue
			}
		case "thread/start":
			var p struct {
				Model string `json:"model"`
			}
			json.Unmarshal(m.Params, &p)
			response(m.ID, map[string]any{"thread": map[string]any{"id": "thread"}, "model": p.Model})
			continue
		case "turn/start":
			response(m.ID, map[string]any{"turn": map[string]any{"id": "turn", "status": "inProgress", "items": []any{}}})
			next()
			continue
		case "turn/interrupt":
			response(m.ID, map[string]any{})
			continue
		default:
			fail = true
		}
		if fail {
			send(map[string]any{"id": m.ID, "error": map[string]any{"code": -32600, "message": "synthetic refusal"}})
		} else {
			response(m.ID, map[string]any{})
		}
	}
}
func safeResult(raw json.RawMessage) any {
	var p map[string]any
	json.Unmarshal(raw, &p)
	delete(p, "accessToken")
	delete(p, "chatgptAccountId")
	delete(p, "chatgptPlanType")
	return p
}
