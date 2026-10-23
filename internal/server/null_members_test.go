package server

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type nullPath []any

func memberPaths(v any, prefix nullPath) []nullPath {
	var out []nullPath
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := append(append(nullPath{}, prefix...), k)
			out = append(out, p)
			out = append(out, memberPaths(x[k], p)...)
		}
	case []any:
		for i, item := range x {
			p := append(append(nullPath{}, prefix...), i)
			out = append(out, p)
			out = append(out, memberPaths(item, p)...)
		}
	}
	return out
}
func replaceNull(v any, path nullPath) {
	for i, part := range path {
		switch x := v.(type) {
		case map[string]any:
			k := part.(string)
			if i == len(path)-1 {
				x[k] = nil
				return
			}
			v = x[k]
		case []any:
			k := part.(int)
			if i == len(path)-1 {
				x[k] = nil
				return
			}
			v = x[k]
		}
	}
}
func pathName(path nullPath) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, "/")
}
func nullRequest(t *testing.T, e *testutil.Env, method string) map[string]any {
	t.Helper()
	var params any
	switch method {
	case "hello":
		params = wire.Hello{Versions: []int{1}, Profile: wire.Profile}
	case "status":
		params = struct{}{}
	case "lease.request":
		params = e.Request
	case "lease.renew":
		r := e.Issue(t)
		params = wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)}
	case "lease.release":
		r := e.Issue(t)
		params = wire.Release{LeaseID: r.LeaseID}
	}
	b, err := json.Marshal(map[string]any{"method": method, "params": params, "request_id": "probe"})
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	var result map[string]any
	if json.Unmarshal(b, &result) != nil {
		t.Fatal("fixture decode failed")
	}
	return result
}

// Claim: null at every required envelope/parameter/object/array member of all five methods closes silently without record changes or refresh; typed requests, including network:null, succeed.
func TestNullRequestMemberSweep(t *testing.T) {
	for _, method := range []string{"hello", "status", "lease.request", "lease.renew", "lease.release"} {
		t.Run(method, func(t *testing.T) {
			fixture := testutil.New(t, lease.Options{})
			paths := memberPaths(nullRequest(t, fixture, method), nil)
			paths = append(paths, nil) // typed positive control
			for _, path := range paths {
				if pathName(path) == "params/network" {
					continue
				} // explicitly nullable raw member
				name := pathName(path)
				if path == nil {
					name = "typed-control"
				}
				t.Run(name, func(t *testing.T) {
					e := testutil.New(t, lease.Options{})
					frame := nullRequest(t, e, method)
					disk, _ := e.Store.Account(e.Account, false)
					before, err := disk.Records()
					if err != nil {
						t.Fatal("fixture read failed")
					}
					if path != nil {
						replaceNull(frame, path)
					}
					c := dial(t, start(t, e, nil))
					if method != "hello" {
						hello(t, c)
					}
					if wire.Write(c, frame) != nil {
						t.Fatal("fixture write failed")
					}
					if path == nil {
						if reply(t, c).Error != nil {
							t.Fatal("typed positive control refused")
						}
						return
					}
					closed(t, c)
					after, err := disk.Records()
					if err != nil {
						t.Fatal("post-refusal read failed")
					}
					b, _ := wire.Encode(before)
					a, _ := wire.Encode(after)
					// []byte maps are encoded identically; a rejection must leave byte-exact metadata.
					if string(a) != string(b) {
						t.Fatal("malformed null changed lease metadata")
					}
					if n, _ := e.Owner.Counts(); n != 0 {
						t.Fatal("malformed null started owner work")
					}
				})
			}
		})
	}
}
