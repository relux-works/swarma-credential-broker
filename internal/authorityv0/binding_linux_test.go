package authorityv0

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
)

type protectedCall struct {
	kind, path  string
	policy      protectedio.FilePolicy
	ancestorUID uint32
}

type recordingReader struct {
	calls  []protectedCall
	refuse string
}

func (recorder *recordingReader) mapped(policy protectedio.FilePolicy) protectedio.FilePolicy {
	policy.UID, policy.GID = uint32(os.Getuid()), uint32(os.Getgid())
	return policy
}

func (recorder *recordingReader) Read(ctx context.Context, path string, policy protectedio.FilePolicy) (protectedio.Identity, []byte, error) {
	recorder.calls = append(recorder.calls, protectedCall{kind: "read", path: path, policy: policy})
	if path == recorder.refuse {
		return protectedio.Identity{}, nil, protectedio.ErrProtection
	}
	return (protectedio.Reader{}).Read(ctx, path, recorder.mapped(policy))
}

func (recorder *recordingReader) CheckDirectory(ctx context.Context, path string, policy protectedio.FilePolicy, ancestorUID uint32) error {
	recorder.calls = append(recorder.calls, protectedCall{kind: "directory", path: path, policy: policy, ancestorUID: ancestorUID})
	if path == recorder.refuse {
		return protectedio.ErrProtection
	}
	return (protectedio.Reader{}).CheckDirectory(ctx, path, recorder.mapped(policy), uint32(os.Getuid()))
}

func (recorder *recordingReader) newGate(ctx context.Context, path string, policy protectedio.FilePolicy) (protectedio.ConfigGate, error) {
	recorder.calls = append(recorder.calls, protectedCall{kind: "lock", path: path, policy: policy})
	if path == recorder.refuse {
		return nil, protectedio.ErrProtection
	}
	return protectedio.NewConfigGate(ctx, path, recorder.mapped(policy))
}

func replaceBrokerFacts(test *testing.T, fixture *authorityFixture, uid, gid uint32) {
	test.Helper()
	old := ":x:" + strconv.FormatUint(uint64(fixture.document.Broker.UID), 10) + ":" + strconv.FormatUint(uint64(fixture.document.Broker.GID), 10) + ":"
	updated := ":x:" + strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10) + ":"
	fixture.passwd = strings.Replace(fixture.passwd, old, updated, 1)
	fixture.group = strings.Replace(fixture.group, ":x:"+strconv.FormatUint(uint64(fixture.document.Broker.GID), 10)+":", ":x:"+strconv.FormatUint(uint64(gid), 10)+":", 1)
	fixture.document.Broker.UID, fixture.document.Broker.GID = uid, gid
	fixture.reader.config.Policy.BrokerUID = uid
	write(test, fixture.reader.paths.passwd, []byte(fixture.passwd), 0644)
	write(test, fixture.reader.paths.group, []byte(fixture.group), 0644)
	fixture.publish(test)
}

// Claim: all three composed windows pass every exact path/policy/ancestor binding, including lock creation and final rechecks, with distinct synthetic root/broker IDs; only delegated real filesystem IDs are mapped.
// Each source's explicit refusal then returns no startup result and invokes no use/identity callback; this does not provision distinct privileged owners.
func TestSourcePolicyCallSites(test *testing.T) {
	fixture := newFixture(test)
	validWindow(test, fixture)
	reader := fixture.reader
	reader.rootUID, reader.rootGID, reader.brokerUID, reader.brokerGID = 100, 200, 300, 400
	replaceBrokerFacts(test, fixture, 300, 400)
	recorder := &recordingReader{}
	reader.files, reader.newGate, reader.gate = recorder, recorder.newGate, nil
	path := reader.paths
	lock := protectedCall{kind: "lock", path: path.lock, policy: protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0640, Links: 1}}
	current := []protectedCall{
		{kind: "directory", path: path.directory, policy: protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0750}, ancestorUID: 100},
		{kind: "directory", path: path.data, policy: protectedio.FilePolicy{UID: 300, GID: 400, Mode: 0700}, ancestorUID: 100},
		{kind: "directory", path: path.store, policy: protectedio.FilePolicy{UID: 300, GID: 400, Mode: 0700}, ancestorUID: 300},
		{kind: "read", path: path.authority, policy: protectedio.FilePolicy{UID: 100, GID: 400, Mode: 0640, Links: 1, MaxBytes: 1 << 20}},
		{kind: "read", path: path.passwd, policy: protectedio.FilePolicy{UID: 100, GID: 200, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
		{kind: "read", path: path.group, policy: protectedio.FilePolicy{UID: 100, GID: 200, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
	}
	var pins StartupPins
	for _, method := range []string{"Load", "WithPinned", "WithIdentity"} {
		test.Run(method, func(test *testing.T) {
			invoke := func() (bool, error) {
				called := false
				switch method {
				case "Load":
					document, loaded, err := reader.Load(context.Background())
					if err != nil && (document.Format != "" || loaded.owner != nil) {
						test.Fatal("refused composed startup leaked a result")
					}
					if err == nil {
						pins, called = loaded, true
					}
					return called, err
				case "WithPinned":
					err := reader.WithPinned(context.Background(), pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
					return called, err
				default:
					err := reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
					return called, err
				}
			}
			recorder.calls, reader.gate = nil, nil
			if called, err := invoke(); err != nil || !called {
				test.Fatalf("valid composed policy control refused: %v result=%v", err, called)
			}
			expected := append([]protectedCall{lock}, current...)
			expected = append(expected, current...)
			if !reflect.DeepEqual(recorder.calls, expected) {
				test.Fatalf("composed source policy binding differs: got %+v want %+v", recorder.calls, expected)
			}
			for _, refused := range append([]protectedCall{lock}, current...) {
				recorder.refuse, reader.gate = refused.path, nil
				if called, err := invoke(); !errors.Is(err, ErrIdentityChanged) || called {
					test.Fatalf("source refusal escaped composed window: %s %v result=%v", refused.path, err, called)
				}
			}
			recorder.refuse = ""
		})
	}
}

// Claim: document/config/passwd/group agreement cannot replace the captured process UID or GID; mismatches refuse the identity callback beside the unchanged valid window.
func TestBrokerProcessBinding(test *testing.T) {
	for _, name := range []string{"uid", "gid"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			uid, gid := fixture.document.Broker.UID, fixture.document.Broker.GID
			if name == "uid" {
				uid += 7000
			} else {
				gid += 7000
			}
			replaceBrokerFacts(test, fixture, uid, gid)
			called := false
			err := fixture.reader.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
			if !errors.Is(err, ErrIdentityChanged) || called {
				test.Fatalf("document broker %s differing from the process admitted: %v callback=%v", name, err, called)
			}
		})
	}
}
