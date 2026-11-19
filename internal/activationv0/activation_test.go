package activationv0_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/activationv0"
	"github.com/relux-works/swarma-credential-broker/internal/assemblyv0"
	"github.com/relux-works/swarma-credential-broker/internal/policy"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type protectedReader struct {
	source   []byte
	identity assemblyv0.FileIdentity
	err      error
	calls    int
	path     string
	policy   assemblyv0.ProtectedFilePolicy
	cancel   context.CancelFunc
}

func (reader *protectedReader) Read(_ context.Context, path string, filePolicy assemblyv0.ProtectedFilePolicy) (assemblyv0.FileIdentity, []byte, error) {
	reader.calls++
	reader.path = path
	reader.policy = filePolicy
	if reader.cancel != nil {
		reader.cancel()
	}
	return reader.identity, reader.source, reader.err
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "assemblyv0", "testdata", "construction-v0", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func configuration() policy.Config {
	return policy.Config{Policy: policy.Policy{Installation: "fixture-installation-v0", MaxLeaseSeconds: 17}}
}

func readerFor(source []byte) *protectedReader {
	return &protectedReader{
		source:   source,
		identity: assemblyv0.FileIdentity{Device: 1, Inode: 2, Mode: 0644, Links: 1, Size: int64(len(source))},
	}
}

func encoded(t *testing.T, object map[string]any) []byte {
	t.Helper()
	source, err := wire.Encode(object)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func changed(t *testing.T, source []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	object, err := wire.Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	mutate(object)
	return encoded(t, object)
}

func requireRefused(t *testing.T, selection activationv0.Selection, err error) {
	t.Helper()
	if !errors.Is(err, activationv0.ErrRefused) || selection.State() != activationv0.Refused || selection.ServiceLifetime() != 0 || len(selection.Bytes()) != 0 || selection.Digest() != "" || selection.Identity() != (assemblyv0.FileIdentity{}) || !reflect.DeepEqual(selection.Document(), assemblyv0.ActivationDocument{}) {
		t.Fatalf("wanted empty refused selection, got state=%v lifetime=%v err=%v", selection.State(), selection.ServiceLifetime(), err)
	}
}

func requireReadBoundary(t *testing.T, reader *protectedReader) {
	t.Helper()
	expected := assemblyv0.ProtectedFilePolicy{Mode: 0644, Links: 1, MaxBytes: 16 * 1024}
	if reader.calls != 1 || reader.path != activationv0.Path || reader.policy != expected {
		t.Fatalf("read boundary: calls=%d path=%q policy=%+v", reader.calls, reader.path, reader.policy)
	}
}

// Safe absence stays stopped, while the same reader's present true control is structural only.
func TestACTIVATEAbsentStaysStopped(t *testing.T) {
	reader := &protectedReader{err: fmt.Errorf("missing leaf: %w", fs.ErrNotExist)}
	selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
	if err != nil || selection.State() != activationv0.Absent || selection.ServiceLifetime() != 0 || len(selection.Bytes()) != 0 || selection.Digest() != "" || selection.Identity() != (assemblyv0.FileIdentity{}) || !reflect.DeepEqual(selection.Document(), assemblyv0.ActivationDocument{}) {
		t.Fatalf("absent activation must stay stopped: state=%v lifetime=%v err=%v", selection.State(), selection.ServiceLifetime(), err)
	}
	requireReadBoundary(t, reader)
	reader = readerFor(fixture(t, "activation-enabled-synthetic"))
	selection, err = (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
	if err != nil || selection.State() != activationv0.Enabled || selection.ServiceLifetime() != 900*time.Second {
		t.Fatalf("present true control: state=%v lifetime=%v err=%v", selection.State(), selection.ServiceLifetime(), err)
	}
	requireReadBoundary(t, reader)
}

// Landed exact vectors select only structural states and the sole activation ceiling.
func TestACTIVATEExactVectors(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   activationv0.State
		seconds uint32
		present bool
	}{
		{"activation-default", activationv0.Inactive, 900, false},
		{"activation-900", activationv0.Inactive, 900, true},
		{"activation-1", activationv0.Inactive, 1, true},
		{"activation-enabled-synthetic", activationv0.Enabled, 900, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := fixture(t, test.name)
			reader := readerFor(source)
			selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
			if err != nil || selection.State() != test.state || selection.ServiceLifetime() != time.Duration(test.seconds)*time.Second {
				t.Fatalf("vector: state=%v lifetime=%v err=%v", selection.State(), selection.ServiceLifetime(), err)
			}
			document := selection.Document()
			var expected assemblyv0.ActivationDocument
			if err := wire.Decode(source, &expected); err != nil || !reflect.DeepEqual(document, expected) {
				t.Fatalf("landed activation type mismatch: %v", err)
			}
			if document.Enabled != (test.state == activationv0.Enabled) || (document.ServiceLeaseMaxLifetimeSeconds != nil) != test.present {
				t.Fatal("document state/presence lost")
			}
			if test.present && *document.ServiceLeaseMaxLifetimeSeconds != test.seconds {
				t.Fatal("document lifetime changed")
			}
			digest := sha256.Sum256(source)
			if selection.Digest() != assemblyv0.Digest("sha256:"+hex.EncodeToString(digest[:])) || !bytes.Equal(selection.Bytes(), source) || selection.Identity() != reader.identity {
				t.Fatal("exact protected source identity/bytes/digest not retained")
			}
			requireReadBoundary(t, reader)
		})
	}
}

// Present false does not bypass closed-schema, pin, canonical-byte or selector validation.
func TestConstructionRefusals(t *testing.T) {
	valid := fixture(t, "activation-default")
	mutations := map[string]func(map[string]any){
		"lifetime-null":        func(object map[string]any) { object["service_lease_max_lifetime_seconds"] = nil },
		"unknown":              func(object map[string]any) { object["unexpected"] = true },
		"conflicting-selector": func(object map[string]any) { object["max_lease_seconds"] = int64(1) },
		"nested-selector":      func(object map[string]any) { object["policy"] = map[string]any{"max_lease_seconds": int64(1)} },
		"format":               func(object map[string]any) { object["format"] = "swarma-broker-activation/2" },
		"profile":              func(object map[string]any) { object["test_profile"] = "test-c" },
		"enabled-string":       func(object map[string]any) { object["enabled"] = "false" },
		"installation":         func(object map[string]any) { object["installation_id"] = "different-installation" },
		"empty-installation":   func(object map[string]any) { object["installation_id"] = "" },
		"root":                 func(object map[string]any) { object["platform_root"] = "/other" },
		"relative-root":        func(object map[string]any) { object["platform_root"] = "opt/swarma" },
		"unclean-root":         func(object map[string]any) { object["platform_root"] = "/opt/./swarma" },
		"service":              func(object map[string]any) { object["service_name"] = "other" },
		"kind":                 func(object map[string]any) { object["kind"] = "other" },
		"digest-length":        func(object map[string]any) { object["authority_digest"] = "sha256:ab" },
		"digest-uppercase":     func(object map[string]any) { object["authority_digest"] = "sha256:" + strings.Repeat("A", 64) },
		"digest-prefix":        func(object map[string]any) { object["authority_digest"] = strings.Repeat("a", 64) },
		"continuity":           func(object map[string]any) { object["continuity"] = map[string]any{"kind": "unknown"} },
		"continuity-unknown": func(object map[string]any) {
			object["continuity"] = map[string]any{"kind": "production", "extra": true}
		},
	}
	object, err := wire.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	for member := range object {
		mutations["missing-"+member] = func(object map[string]any) { delete(object, member) }
		mutations["null-"+member] = func(object map[string]any) { object[member] = nil }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			selection, err := (activationv0.Loader{Reader: readerFor(changed(t, valid, mutate))}).Load(context.Background(), configuration())
			requireRefused(t, selection, err)
		})
	}
	for name, source := range map[string][]byte{
		"empty":            {},
		"malformed":        []byte("{"),
		"trailing-newline": append(bytes.Clone(valid), '\n'),
		"leading-space":    append([]byte(" "), valid...),
		"duplicate":        bytes.Replace(valid, []byte(`"enabled":false`), []byte(`"enabled":false,"enabled":false`), 1),
		"invalid-utf8":     bytes.Replace(valid, []byte("fixture"), []byte{0xff}, 1),
		"invalid-unicode":  bytes.Replace(valid, []byte("fixture"), []byte(`\ud800`), 1),
		"top-array":        []byte("[]"),
		"extra-document":   append(bytes.Clone(valid), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			selection, err := (activationv0.Loader{Reader: readerFor(source)}).Load(context.Background(), configuration())
			requireRefused(t, selection, err)
		})
	}
	reader := readerFor(valid)
	selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
	if err != nil || selection.State() != activationv0.Inactive {
		t.Fatalf("valid false control: state=%v err=%v", selection.State(), err)
	}
	requireReadBoundary(t, reader)
}

// Invalid explicit ceilings refuse on both enabled and inactive documents, never clamp or default.
func TestACTIVATELifetimeRefusals(t *testing.T) {
	valid := fixture(t, "activation-900")
	for name, literal := range map[string]string{
		"zero": "0", "negative": "-1", "float": "1.5", "integral-float": "900.0",
		"exponent": "9e2", "string": `"900"`, "null": "null", "above-900": "901",
		"unsafe-integer": "9007199254740992", "overflow": "18446744073709551616",
		"negative-zero": "-0", "boolean": "true", "array": "[]", "object": "{}",
	} {
		t.Run(name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				source := bytes.Replace(valid, []byte(`"service_lease_max_lifetime_seconds":900`), []byte(`"service_lease_max_lifetime_seconds":`+literal), 1)
				if enabled {
					source = bytes.Replace(source, []byte(`"enabled":false`), []byte(`"enabled":true`), 1)
				}
				selection, err := (activationv0.Loader{Reader: readerFor(source)}).Load(context.Background(), configuration())
				requireRefused(t, selection, err)
			}
		})
	}
	for _, seconds := range []int64{1, 450, 899, 900} {
		for _, enabled := range []bool{false, true} {
			source := changed(t, valid, func(object map[string]any) {
				object["enabled"] = enabled
				object["service_lease_max_lifetime_seconds"] = seconds
			})
			selection, err := (activationv0.Loader{Reader: readerFor(source)}).Load(context.Background(), configuration())
			if err != nil || selection.ServiceLifetime() != time.Duration(seconds)*time.Second || selection.Document().Enabled != enabled {
				t.Fatalf("valid ceiling control %d/%t: lifetime=%v err=%v", seconds, enabled, selection.ServiceLifetime(), err)
			}
		}
	}
}

// The reader contract and leaf metadata fail closed; simulated ancestor errors are not native traversal proof.
func TestACTIVATEProtectionSelector(t *testing.T) {
	valid := fixture(t, "activation-default")
	for name, mutate := range map[string]func(*protectedReader){
		"owner":           func(reader *protectedReader) { reader.identity.UID = 1234 },
		"group":           func(reader *protectedReader) { reader.identity.GID = 1234 },
		"writable-mode":   func(reader *protectedReader) { reader.identity.Mode = 0664 },
		"private-mode":    func(reader *protectedReader) { reader.identity.Mode = 0600 },
		"extra-mode-bits": func(reader *protectedReader) { reader.identity.Mode |= fs.ModeSetuid },
		"symlink":         func(reader *protectedReader) { reader.identity.Mode |= fs.ModeSymlink },
		"directory":       func(reader *protectedReader) { reader.identity.Mode |= fs.ModeDir },
		"fifo":            func(reader *protectedReader) { reader.identity.Mode |= fs.ModeNamedPipe },
		"hardlink":        func(reader *protectedReader) { reader.identity.Links = 2 },
		"zero-links":      func(reader *protectedReader) { reader.identity.Links = 0 },
		"size":            func(reader *protectedReader) { reader.identity.Size++ },
		"negative-size":   func(reader *protectedReader) { reader.identity.Size = -1 },
		"unreadable":      func(reader *protectedReader) { reader.err = fs.ErrPermission },
		"unsafe-ancestor": func(reader *protectedReader) { reader.err = errors.New("unsafe ancestor") },
		"read-failure":    func(reader *protectedReader) { reader.err = errors.New("read failure") },
		"partial-missing": func(reader *protectedReader) { reader.err = fs.ErrNotExist },
	} {
		t.Run(name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				source := changed(t, valid, func(object map[string]any) { object["enabled"] = enabled })
				reader := readerFor(source)
				mutate(reader)
				selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
				requireRefused(t, selection, err)
				requireReadBoundary(t, reader)
			}
		})
	}
	for _, size := range []int{16 * 1024, 16*1024 + 1} {
		config := configuration()
		config.Policy.Installation = strings.Repeat("i", len(config.Policy.Installation)+size-len(valid))
		source := changed(t, valid, func(object map[string]any) { object["installation_id"] = config.Policy.Installation })
		if len(source) != size {
			t.Fatal("size control did not reach boundary")
		}
		reader := readerFor(source)
		selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), config)
		if size > 16*1024 {
			requireRefused(t, selection, err)
		} else if err != nil || selection.State() != activationv0.Inactive {
			t.Fatalf("16 KiB valid control: state=%v err=%v", selection.State(), err)
		}
		requireReadBoundary(t, reader)
	}
}

// Unaccepted C always stops at its open point, including an otherwise plausible full C object.
func TestACTIVATETestCStopsO21(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, full := range []bool{false, true} {
			source := changed(t, fixture(t, "activation-default"), func(object map[string]any) {
				object["enabled"] = enabled
				continuity := map[string]any{"kind": "test-c"}
				if full {
					continuity["machine_id"] = "synthetic-machine"
					continuity["qualification_revision"] = strings.Repeat("a", 40)
					continuity["qualification_expires_at"] = "2099-01-01T00:00:00Z"
				}
				object["continuity"] = continuity
			})
			selection, err := (activationv0.Loader{Reader: readerFor(source)}).Load(context.Background(), configuration())
			requireRefused(t, selection, err)
			if !errors.Is(err, activationv0.ErrUnacceptedContinuity) || !strings.Contains(err.Error(), "STOP:O-21") {
				t.Fatalf("C must preserve its open point: %v", err)
			}
		}
	}
}

// Operational legacy lifetime and environment variables cannot supply an activation ceiling or opt in.
func TestACTIVATESoleLifetimeSelector(t *testing.T) {
	t.Setenv("SWARMA_SERVICE_LEASE_MAX_LIFETIME_SECONDS", "1")
	t.Setenv("SWARMA_ACTIVATION", "enabled")
	for _, legacy := range []int64{-1, 0, 1, 17, 900, 3600} {
		config := configuration()
		config.Policy.MaxLeaseSeconds = legacy
		selection, err := (activationv0.Loader{Reader: readerFor(fixture(t, "activation-default"))}).Load(context.Background(), config)
		if err != nil || selection.State() != activationv0.Inactive || selection.ServiceLifetime() != 900*time.Second {
			t.Fatalf("legacy selector leaked into activation: legacy=%d lifetime=%v err=%v", legacy, selection.ServiceLifetime(), err)
		}
	}
	reader := &protectedReader{err: fs.ErrNotExist}
	selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
	if err != nil || selection.State() != activationv0.Absent {
		t.Fatalf("environment enabled absent file: state=%v err=%v", selection.State(), err)
	}
}

// A failed/cancelled read exposes no selection; cancellation before the read has no I/O effect.
func TestACTIVATECancellationAndMissingReader(t *testing.T) {
	selection, err := (activationv0.Loader{}).Load(context.Background(), configuration())
	requireRefused(t, selection, err)
	reader := readerFor(fixture(t, "activation-default"))
	selection, err = (activationv0.Loader{Reader: reader}).Load(nil, configuration())
	requireRefused(t, selection, err)
	if reader.calls != 0 {
		t.Fatal("nil context performed I/O")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	selection, err = (activationv0.Loader{Reader: reader}).Load(ctx, configuration())
	requireRefused(t, selection, err)
	if !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatal("pre-cancelled load performed I/O or lost cancellation")
	}
	for _, absent := range []bool{false, true} {
		ctx, cancel = context.WithCancel(context.Background())
		reader = readerFor(fixture(t, "activation-enabled-synthetic"))
		if absent {
			reader = &protectedReader{err: fs.ErrNotExist}
		}
		reader.cancel = cancel
		selection, err = (activationv0.Loader{Reader: reader}).Load(ctx, configuration())
		requireRefused(t, selection, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("in-read cancellation lost")
		}
		requireReadBoundary(t, reader)
		cancel()
	}
}

// Caller/reader mutations cannot rewrite a retained structural selection or its exact source digest.
func TestACTIVATESelectionSnapshot(t *testing.T) {
	reader := readerFor(fixture(t, "activation-1"))
	selection, err := (activationv0.Loader{Reader: reader}).Load(context.Background(), configuration())
	if err != nil {
		t.Fatal(err)
	}
	digest := selection.Digest()
	snapshot := selection.Bytes()
	reader.source[0] = '!'
	selection.Bytes()[0] = '?'
	document := selection.Document()
	*document.ServiceLeaseMaxLifetimeSeconds = 901
	if selection.Digest() != digest || !bytes.Equal(selection.Bytes(), snapshot) || *selection.Document().ServiceLeaseMaxLifetimeSeconds != 1 || selection.ServiceLifetime() != time.Second {
		t.Fatal("retained source/document was aliased")
	}
}
