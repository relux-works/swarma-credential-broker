package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

// Only anonymous pipes and synthetic RPC messages are used. No app-server,
// provider, managed account, root service or producer event log is executed/read.
func TestLeaseDeadlineCoversInitialization(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "live-positive-control"
		if delayed {
			name = "initialize-crosses-lease-expiry"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			until := time.Now().Add(3 * time.Second).UTC().Truncate(time.Second)
			if delayed {
				until = time.Now().Add(time.Second).UTC().Truncate(time.Second)
			}
			r := &rpc{in: writer, messages: make(chan incoming, 32), closed: make(chan struct{})}
			policy := Policy{Account: "synthetic-account-label", ChatGPTAccountID: "synthetic-account"}
			acquired := Lease{ID: "synthetic-lease", Account: policy.Account, Harness: "codex_cli", Channel: "external-token", Token: []byte("synthetic-review-canary"), ChatGPTAccountID: policy.ChatGPTAccountID, AuthorizedUntil: until, TokenExpiresAt: until.Add(time.Hour), Renewable: true}
			if !validLease(acquired, policy, nil) {
				t.Fatal("test did not start with a valid acquired lease")
			}
			s := &session{ctx: ctx, rpc: r, policy: policy, lease: &acquired, answered: map[string]bool{}, stream: &textStream{}, state: &statusRecord{}}
			var mu sync.Mutex
			var after []string
			done := make(chan struct{})
			go func() {
				defer close(done)
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					var m message
					if json.Unmarshal(scanner.Bytes(), &m) != nil {
						return
					}
					if !time.Now().Before(until) && (m.Method == "account/login/start" || m.Method == "thread/start" || m.Method == "turn/start") {
						mu.Lock()
						after = append(after, m.Method)
						mu.Unlock()
					}
					if m.Method == "initialize" && delayed {
						timer := time.NewTimer(time.Until(until.Add(50 * time.Millisecond)))
						select {
						case <-timer.C:
						case <-ctx.Done():
							timer.Stop()
							return
						}
					}
					raw := json.RawMessage(`{}`)
					switch m.Method {
					case "initialized":
						continue
					case "account/login/start":
						raw = json.RawMessage(`{"type":"chatgptAuthTokens"}`)
					case "thread/start":
						raw = json.RawMessage(`{"thread":{"id":"synthetic-thread"},"model":"synthetic-model"}`)
					case "turn/start":
						raw = json.RawMessage(`{"turn":{"id":"synthetic-turn"}}`)
					}
					select {
					case r.messages <- incoming{msg: message{ID: m.ID, Result: raw}}:
					case <-ctx.Done():
						return
					}
					if m.Method == "turn/start" {
						r.messages <- incoming{msg: message{Method: "turn/completed", Params: json.RawMessage(`{"threadId":"synthetic-thread","turn":{"id":"synthetic-turn","status":"completed","items":[]}}`)}}
						return
					}
				}
			}()
			_, driveErr := s.drive([]byte("fixed synthetic prompt"), Options{Model: "synthetic-model", ReasoningEffort: "medium", Cwd: "/synthetic"})
			writer.Close()
			<-done
			mu.Lock()
			observed := append([]string{}, after...)
			mu.Unlock()
			t.Logf("delayed=%t expired_actions=%v drive_error=%v", delayed, observed, driveErr)
			if !delayed && driveErr != nil {
				t.Fatalf("live control refused: %v", driveErr)
			}
			if len(observed) > 0 {
				t.Fatalf("authorization expired before credential/turn actions: %v", observed)
			}
			if delayed && driveErr == nil {
				t.Fatal("expired initialization was accepted")
			}
		})
	}
}
