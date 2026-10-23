//go:build linux

package runner

import (
	"context"
	static "github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/qualification"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Claim: a corrupt listed tuple closes both public admission paths even when
// the requested tuple's own record is valid; a one-entry positive control admits.
func TestReviewWholeListAdmission(t *testing.T) {
	for _, surface := range []string{"daemon", "runner"} {
		for _, mode := range []string{"valid", "missing-before", "missing-after", "bad-before", "bad-after", "native-unavailable"} {
			t.Run(surface+"/"+mode, func(t *testing.T) {
				f := newFixture(t, nil)
				path := filepath.Join(f.root, "policy.json")
				observer := &publicationObserver{NativeObserver: qualification.NativeObserver{ExecutablePath: f.a.p.Executable}, path: path, platform: "fixture-platform", catalog: qualification.Catalog{Models: []qualification.Model{{Name: f.o.Model, Efforts: []string{f.o.ReasoningEffort}}}}}
				gate := func(ctx context.Context, p static.Policy) error {
					c, e := static.Load(path, p.BrokerUID)
					if e != nil || !reflect.DeepEqual(c.Policy, p) {
						return qualification.ErrUnavailable
					}
					if mode == "native-unavailable" {
						_, _, e = c.Qualified(ctx, path, nil)
					} else {
						_, _, e = c.Qualified(ctx, path, observer)
					}
					return e
				}
				integratedFixture(t, f, false, false, gate)
				rec := publishFixtureRecord(t, path, observer)
				f.d = newPublishedAuthority(path, observer)
				if mode == "native-unavailable" {
					f.d = ProtectedDependencies(path, nil)
				}
				c, e := static.Load(path, uint32(os.Geteuid()))
				must(t, e)
				if strings.HasPrefix(mode, "missing-") || strings.HasPrefix(mode, "bad-") {
					lp := filepath.Join(qualification.Directory(path), "qualified.json")
					raw, e := os.ReadFile(lp)
					must(t, e)
					var list qualification.List
					must(t, wire.Decode(raw, &list))
					other := rec.Identity
					other.Executable.SHA256 = qualification.Hash([]byte("other binary"))
					ref := qualification.Hash([]byte("absent"))
					if strings.HasPrefix(mode, "bad-") {
						body := []byte("{}")
						ref = qualification.Hash(body)
						must(t, os.WriteFile(filepath.Join(qualification.Directory(path), "record-"+ref+".json"), body, 0600))
					}
					entry := qualification.Entry{Identity: other, Evidence: ref}
					if strings.HasSuffix(mode, "before") {
						list.Entries = append([]qualification.Entry{entry}, list.Entries...)
					} else {
						list.Entries = append(list.Entries, entry)
					}
					raw, e = wire.Encode(list)
					must(t, e)
					must(t, os.WriteFile(lp, raw, 0600))
					activation, _ := wire.Encode(map[string]any{"kind": "qualification-activation/1", "list_sha256": qualification.Hash(raw)})
					must(t, os.WriteFile(filepath.Join(qualification.Directory(path), "activation.json"), activation, 0600))
				}
				if surface == "runner" {
					got := f.run()
					want := 0
					if mode != "valid" {
						want = 69
					}
					if got != want {
						t.Fatalf("runner admitted invalid whole list: status=%d want=%d", got, want)
					}
					return
				}
				client, e := DialBroker(context.Background(), c.SocketPath)
				must(t, e)
				defer client.Close()
				clientHello(t, client)
				p := f.a.p
				b := c.Policy.Binding(p.UID, c.Policy.Accounts[0], f.o.Profile)
				l, e := client.Request(context.Background(), LeaseRequest{Harness: "codex_cli", Profile: f.o.Profile, Account: f.o.Account, Channel: "external-token", LaunchID: "fixture-launch", CredentialBinding: Binding{Digest: b.Digest, Harness: b.Harness, Profile: b.Profile, Account: b.Account, Channel: b.Channel, Endpoint: b.Endpoint, ExecutableSHA256: b.ExecutableSHA256, PolicyGeneration: b.PolicyGeneration}, Executor: Executor{Capabilities: []string{"credential-injection/1"}, Version: Version}})
				defer l.erase()
				if mode == "valid" {
					must(t, e)
					must(t, client.Release(context.Background(), l.ID))
				} else {
					if e == nil {
						client.Release(context.Background(), l.ID)
						t.Fatal("daemon admitted tuple despite missing unrelated evidence")
					}
					refusalCode(t, e, "lease_harness_unqualified", 69)
				}
			})
		}
	}
}
