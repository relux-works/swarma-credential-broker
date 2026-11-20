package authorityv0

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/protectedio"
)

// Claim: New binds the exact concrete protected reader and lock factory, not adapters that could rewrite the policies witnessed at their call sites.
func TestNewBindsProductionSeam(test *testing.T) {
	reader := New(policy.Config{})
	if _, ok := reader.files.(protectedio.Reader); !ok {
		test.Fatalf("production protected reader rebound: %T", reader.files)
	}
	if reader.newGate == nil || reflect.ValueOf(reader.newGate).Pointer() != reflect.ValueOf(protectedio.NewConfigGate).Pointer() {
		test.Fatal("production lock gate rebound")
	}
}

// Claim: nil, zero-value and incompletely initialized readers refuse all public windows without panic, callback or startup output, beside a valid real-filesystem control.
func TestUninitializedReaderRefuses(test *testing.T) {
	for _, name := range []string{"nil", "zero", "missing-reader", "missing-gate"} {
		test.Run(name, func(test *testing.T) {
			fixture := newFixture(test)
			pins := validWindow(test, fixture)
			reader := fixture.reader
			switch name {
			case "nil":
				reader = nil
			case "zero":
				reader = &Reader{}
			case "missing-reader":
				reader.files = nil
			case "missing-gate":
				reader.newGate = nil
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					test.Fatalf("uninitialized reader panicked: %v", recovered)
				}
			}()
			document, refusedPins, err := reader.Load(context.Background())
			if !errors.Is(err, ErrIdentityChanged) || !reflect.DeepEqual(document, assemblyv0.AuthorityDocument{}) || !reflect.DeepEqual(refusedPins, StartupPins{}) {
				test.Fatalf("uninitialized reader returned startup output or wrong refusal: %v", err)
			}
			for _, method := range []string{"WithPinned", "WithIdentity"} {
				called := false
				callback := func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil }
				if method == "WithPinned" {
					err = reader.WithPinned(context.Background(), pins, callback)
				} else {
					err = reader.WithIdentity(context.Background(), callback)
				}
				if !errors.Is(err, ErrIdentityChanged) || called {
					test.Fatalf("uninitialized reader admitted %s or wrong refusal: %v callback=%v", method, err, called)
				}
			}
		})
	}
}

type protectedCall struct {
	kind, path  string
	policy      protectedio.FilePolicy
	ancestorUID uint32
}

type recordingReader struct {
	calls    []protectedCall
	refuse   *protectedCall
	refuseAt int
	paths    map[string]string
}

func (recorder *recordingReader) record(call protectedCall) bool {
	recorder.calls = append(recorder.calls, call)
	if recorder.refuse == nil || call != *recorder.refuse {
		return false
	}
	matches := 0
	for _, recorded := range recorder.calls {
		if recorded == *recorder.refuse {
			matches++
		}
	}
	return matches >= recorder.refuseAt
}

func (recorder *recordingReader) mappedPath(path string) (string, bool) {
	if recorder.paths == nil {
		return path, true
	}
	mapped, ok := recorder.paths[path]
	return mapped, ok
}

func (recorder *recordingReader) mapped(policy protectedio.FilePolicy) protectedio.FilePolicy {
	policy.UID, policy.GID = uint32(os.Getuid()), uint32(os.Getgid())
	return policy
}

func (recorder *recordingReader) Read(ctx context.Context, path string, policy protectedio.FilePolicy) (protectedio.Identity, []byte, error) {
	refused := recorder.record(protectedCall{kind: "read", path: path, policy: policy})
	mapped, ok := recorder.mappedPath(path)
	if !ok || refused {
		return protectedio.Identity{}, nil, protectedio.ErrProtection
	}
	return (protectedio.Reader{}).Read(ctx, mapped, recorder.mapped(policy))
}

func (recorder *recordingReader) CheckDirectory(ctx context.Context, path string, policy protectedio.FilePolicy, ancestorUID uint32) error {
	refused := recorder.record(protectedCall{kind: "directory", path: path, policy: policy, ancestorUID: ancestorUID})
	mapped, ok := recorder.mappedPath(path)
	if !ok || refused {
		return protectedio.ErrProtection
	}
	return (protectedio.Reader{}).CheckDirectory(ctx, mapped, recorder.mapped(policy), uint32(os.Getuid()))
}

func (recorder *recordingReader) newGate(ctx context.Context, path string, policy protectedio.FilePolicy) (protectedio.ConfigGate, error) {
	refused := recorder.record(protectedCall{kind: "lock", path: path, policy: policy})
	mapped, ok := recorder.mappedPath(path)
	if !ok || refused {
		return nil, protectedio.ErrProtection
	}
	return protectedio.NewConfigGate(ctx, mapped, recorder.mapped(policy))
}

// Claim: the refusal instrument matches the complete call and can target either recheck; changing any field still records but does not refuse that different call.
func TestRecordingRefusalPolicyMatch(test *testing.T) {
	call := protectedCall{kind: "directory", path: "/synthetic", policy: protectedio.FilePolicy{UID: 0, GID: 3, Mode: 0750, Links: 1, MaxBytes: 7}, ancestorUID: 0}
	for _, field := range []string{"kind", "path", "uid", "gid", "mode", "links", "size", "ancestor"} {
		test.Run(field, func(test *testing.T) {
			changed := call
			switch field {
			case "kind":
				changed.kind = "read"
			case "path":
				changed.path += "/other"
			case "uid":
				changed.policy.UID++
			case "gid":
				changed.policy.GID++
			case "mode":
				changed.policy.Mode = 0700
			case "links":
				changed.policy.Links++
			case "size":
				changed.policy.MaxBytes++
			case "ancestor":
				changed.ancestorUID++
			}
			recorder := &recordingReader{refuse: &call}
			if recorder.record(changed) || !recorder.record(call) || !reflect.DeepEqual(recorder.calls, []protectedCall{changed, call}) {
				test.Fatal("refusal instrument ignored an exact call field")
			}
		})
	}
	recorder := &recordingReader{refuse: &call, refuseAt: 2}
	if recorder.record(call) || !recorder.record(call) || !recorder.record(call) {
		test.Fatal("refusal instrument targeted the wrong recheck")
	}
	if (&recordingReader{}).record(call) {
		test.Fatal("unarmed refusal instrument refused a valid call")
	}
}

// Claim: through New and all public windows, every call matches literal production ownership/modes and implementation bounds before fixture remapping; every exact-policy refusal stops at its complete trace prefix in either pass.
// A final-pass refusal may follow a callback, but Load returns no partial startup output. Lock-factory refusal is reachable only before a gate exists, not through already-owned WithPinned pins. No privileged owner provisioning is claimed.
func TestNewComposedProductionCalls(test *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		test.Fatal("production composition requires non-root process IDs")
	}
	lock := protectedCall{kind: "lock", path: "/etc/swarma/credential-broker/authority.lock", policy: protectedio.FilePolicy{UID: 0, GID: gid, Mode: 0640, Links: 1}}
	current := []protectedCall{
		{kind: "directory", path: "/etc/swarma/credential-broker", policy: protectedio.FilePolicy{UID: 0, GID: gid, Mode: 0750}, ancestorUID: 0},
		{kind: "directory", path: "/opt/swarma/services/swarma-credential-broker", policy: protectedio.FilePolicy{UID: uid, GID: gid, Mode: 0700}, ancestorUID: 0},
		{kind: "directory", path: "/opt/swarma/services/swarma-credential-broker/store", policy: protectedio.FilePolicy{UID: uid, GID: gid, Mode: 0700}, ancestorUID: uid},
		{kind: "read", path: "/etc/swarma/credential-broker/authority-v0.json", policy: protectedio.FilePolicy{UID: 0, GID: gid, Mode: 0640, Links: 1, MaxBytes: 1 << 20}},
		{kind: "read", path: "/etc/passwd", policy: protectedio.FilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
		{kind: "read", path: "/etc/group", policy: protectedio.FilePolicy{UID: 0, GID: 0, Mode: 0644, Links: 1, MaxBytes: 1 << 20}},
	}
	for _, method := range []string{"Load", "WithPinned", "WithIdentity"} {
		test.Run(method, func(test *testing.T) {
			fixture := newFixture(test)
			validWindow(test, fixture)
			fresh := func() (*Reader, *recordingReader) {
				production := New(fixture.reader.config)
				recorder := &recordingReader{paths: map[string]string{
					"/etc/swarma/credential-broker/authority.lock":        fixture.reader.paths.lock,
					"/etc/swarma/credential-broker":                       fixture.reader.paths.directory,
					"/opt/swarma/services/swarma-credential-broker":       fixture.reader.paths.data,
					"/opt/swarma/services/swarma-credential-broker/store": fixture.reader.paths.store,
					"/etc/swarma/credential-broker/authority-v0.json":     fixture.reader.paths.authority,
					"/etc/passwd": fixture.reader.paths.passwd,
					"/etc/group":  fixture.reader.paths.group,
				}}
				production.files, production.newGate = recorder, recorder.newGate
				return production, recorder
			}
			load := func(test *testing.T, production *Reader, recorder *recordingReader) StartupPins {
				test.Helper()
				_, pins, err := production.Load(context.Background())
				expected := append([]protectedCall{lock}, current...)
				expected = append(expected, current...)
				if !reflect.DeepEqual(recorder.calls, expected) {
					test.Fatalf("composed production call binding differs: got %+v want %+v", recorder.calls, expected)
				}
				if err != nil || pins.owner != production {
					test.Fatalf("production startup control refused: %v", err)
				}
				recorder.calls = nil
				return pins
			}
			invoke := func(test *testing.T, production *Reader, pins *StartupPins) (bool, error) {
				test.Helper()
				called := false
				switch method {
				case "Load":
					document, loaded, err := production.Load(context.Background())
					if err != nil && (!reflect.DeepEqual(document, assemblyv0.AuthorityDocument{}) || !reflect.DeepEqual(loaded, StartupPins{})) {
						test.Fatal("refused production startup leaked a result")
					}
					if err == nil {
						*pins, called = loaded, true
					}
					return called, err
				case "WithPinned":
					err := production.WithPinned(context.Background(), *pins, func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
					return called, err
				default:
					err := production.WithIdentity(context.Background(), func(context.Context, assemblyv0.AuthorityDocument) error { called = true; return nil })
					return called, err
				}
			}
			production, recorder := fresh()
			var pins StartupPins
			if method == "WithPinned" {
				pins = load(test, production, recorder)
			}
			called, err := invoke(test, production, &pins)
			var expected []protectedCall
			if method != "WithPinned" {
				expected = append(expected, lock)
			}
			expected = append(expected, current...)
			expected = append(expected, current...)
			if !reflect.DeepEqual(recorder.calls, expected) {
				test.Fatalf("composed production call binding differs: got %+v want %+v", recorder.calls, expected)
			}
			if err != nil || !called {
				test.Fatalf("valid production composition refused: %v result=%v", err, called)
			}
			recorder.calls = nil
			called, err = invoke(test, production, &pins)
			expected = append(append([]protectedCall{}, current...), current...)
			if !reflect.DeepEqual(recorder.calls, expected) {
				test.Fatalf("composed production call binding differs: got %+v want %+v", recorder.calls, expected)
			}
			if err != nil || !called {
				test.Fatalf("cached production composition refused: %v result=%v", err, called)
			}
			if method != "WithPinned" {
				test.Run("lock", func(test *testing.T) {
					production, recorder := fresh()
					recorder.refuse = &lock
					var pins StartupPins
					called, err := invoke(test, production, &pins)
					if !reflect.DeepEqual(recorder.calls, []protectedCall{lock}) {
						test.Fatalf("production refusal call binding differs: got %+v want %+v", recorder.calls, []protectedCall{lock})
					}
					if !errors.Is(err, ErrIdentityChanged) || called {
						test.Fatalf("production lock refusal escaped composed window: %v result=%v", err, called)
					}
				})
			}
			test.Run("gate-refusal", func(test *testing.T) {
				production, recorder := fresh()
				pins := load(test, production, recorder)
				if err := os.Rename(fixture.reader.paths.lock, fixture.reader.paths.lock+"-old"); err != nil {
					test.Fatal(err)
				}
				write(test, fixture.reader.paths.lock, nil, 0640)
				called, err := invoke(test, production, &pins)
				if !errors.Is(err, protectedio.ErrProtection) || called || len(recorder.calls) != 0 {
					test.Fatalf("production gate refusal retried or returned output: %v callback=%v calls=%+v", err, called, recorder.calls)
				}
			})
			for index, refused := range current {
				for pass := 1; pass <= 2; pass++ {
					test.Run(fmt.Sprintf("source-%d/pass-%d", index, pass), func(test *testing.T) {
						production, recorder := fresh()
						pins := load(test, production, recorder)
						recorder.refuse, recorder.refuseAt = &refused, pass
						called, err := invoke(test, production, &pins)
						var expected []protectedCall
						if pass == 2 {
							expected = append(expected, current...)
						}
						expected = append(expected, current[:index+1]...)
						if !reflect.DeepEqual(recorder.calls, expected) {
							test.Fatalf("production refusal call binding differs: got %+v want %+v", recorder.calls, expected)
						}
						wantCallback := pass == 2 && method != "Load"
						if !errors.Is(err, ErrIdentityChanged) || called != wantCallback {
							test.Fatalf("production source refusal escaped composed window: %v result=%v want=%v", err, called, wantCallback)
						}
					})
				}
			}
		})
	}
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
	_, pins, err := reader.Load(context.Background())
	if err != nil {
		test.Fatalf("synthetic startup control refused: %v", err)
	}
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
			for index, refused := range append([]protectedCall{lock}, current...) {
				recorder.calls, recorder.refuse, reader.gate = nil, &refused, nil
				called, err := invoke()
				expected := append([]protectedCall{lock}, current[:index]...)
				if !reflect.DeepEqual(recorder.calls, expected) {
					test.Fatalf("synthetic refusal call binding differs: got %+v want %+v", recorder.calls, expected)
				}
				if !errors.Is(err, ErrIdentityChanged) || called {
					test.Fatalf("source refusal escaped composed window: %s %v result=%v", refused.path, err, called)
				}
			}
			recorder.refuse = nil
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
