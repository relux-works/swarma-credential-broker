//go:build linux

package authowner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestManagedHumanAccountReferenceEveryRefresh(t *testing.T) {
	for _, tc := range []struct {
		name      string
		email     any
		reference string
		committed bool
	}{
		{"match", "human@example.invalid", "human@example.invalid", true},
		{"mismatch", "other@example.invalid", "human@example.invalid", false},
		{"missing", nil, "human@example.invalid", false},
		{"empty-admission", "human@example.invalid", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responses, serverWrite, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer responses.Close()
			defer serverWrite.Close()
			serverRead, requests, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer serverRead.Close()
			defer requests.Close()
			stop := make(chan struct{})
			defer close(stop)
			done := make(chan struct{})
			go func() {
				defer close(done)
				scan := bufio.NewScanner(serverRead)
				for scan.Scan() {
					var q struct {
						ID     int    `json:"id"`
						Method string `json:"method"`
						Params struct {
							Refresh bool `json:"refreshToken"`
						} `json:"params"`
					}
					if json.Unmarshal(scan.Bytes(), &q) != nil {
						return
					}
					switch q.Method {
					case "initialize":
						b, _ := json.Marshal(map[string]any{"id": q.ID, "result": map[string]any{}})
						serverWrite.Write(append(b, '\n'))
					case "initialized":
					case "account/read":
						if !q.Params.Refresh {
							return
						}
						b, _ := json.Marshal(map[string]any{"id": q.ID, "result": map[string]any{"requiresOpenaiAuth": true, "account": map[string]any{"type": "chatgpt", "planType": "pro", "email": tc.email}}})
						serverWrite.Write(append(b, '\n'))
						return
					default:
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := managed(ctx, responses, requests, nil, tc.reference)
			if (result.Outcome == Committed) != tc.committed {
				t.Fatal("human account reference comparison failed")
			}
			requests.Close()
			serverRead.Close()
			<-done
		})
	}
}
