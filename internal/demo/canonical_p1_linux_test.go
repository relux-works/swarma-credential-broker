//go:build linux

package demo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func canonicalP1Roster(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "p1", name+"-roster.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func putRosterBytes(t *testing.T, b []byte) {
	t.Helper()
	if err := os.WriteFile(RosterPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(RosterPath, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalP1ProgramFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/p1/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ProgramRevision          string            `json:"program_revision"`
		FrozenCopySourceRevision string            `json:"frozen_copy_source_revision"`
		Outputs                  map[string]string `json:"outputs"`
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ProgramRevision != "bf72a78a2c02ca30d1238e218df2f3318a63b92b" || manifest.FrozenCopySourceRevision != FrozenCopySourceRevision || len(manifest.Outputs) != 4 {
		t.Fatal("out-of-band qualification changed")
	}
	for name, digest := range manifest.Outputs {
		b, err := os.ReadFile(filepath.Join("testdata", "p1", name))
		if err != nil || Hash(b) != digest {
			t.Fatalf("fixture %s changed: %v", name, err)
		}
		var record struct {
			SourceRevision string `json:"source_revision"`
		}
		if err := json.Unmarshal(b, &record); err != nil || record.SourceRevision != FrozenCopySourceRevision {
			t.Fatalf("fixture %s wire revision differs: %v", name, err)
		}
	}
	for _, name := range []string{"witness", "codex"} {
		t.Run(name, func(t *testing.T) {
			original := canonicalP1Roster(t, name)
			r, err := DecodeRoster(original)
			if err != nil || FixedExecutorApproved(r) != (name == "codex") {
				t.Fatal("unmodified P1 output refused or misapproved", err)
			}
			for _, bad := range rejectedP1Rosters(t, original) {
				t.Run(bad.name, func(t *testing.T) {
					// Keep the actual canonical positive beside each single wire mutation.
					if _, err := DecodeRoster(original); err != nil {
						t.Fatal("positive control refused", err)
					}
					if _, err := DecodeRoster(bad.raw); err == nil {
						t.Fatal("invalid wire roster accepted")
					}
				})
			}
		})
	}
}

type rejectedRoster struct {
	name string
	raw  []byte
}

func rejectedP1Rosters(t *testing.T, original []byte) []rejectedRoster {
	t.Helper()
	mutations := []struct {
		name   string
		change func(map[string]any)
	}{
		{"third-executor", func(m map[string]any) {
			m["executor"] = map[string]any{"id": "third", "path": "/usr/local/libexec/swarma/third", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		}},
		{"mixed-witness-id-codex-path", func(m map[string]any) {
			m["executor"].(map[string]any)["id"] = "swarma-demo-executor"
			m["executor"].(map[string]any)["path"] = ExecutorPath
		}},
		{"mixed-codex-id-witness-path", func(m map[string]any) {
			m["executor"].(map[string]any)["id"] = ExecutorID
			m["executor"].(map[string]any)["path"] = "/usr/local/libexec/swarma/swarma-demo-executor"
		}},
		{"wrong-codex-id", func(m map[string]any) { m["executor"].(map[string]any)["id"] = "codex-other" }},
		{"wrong-codex-path", func(m map[string]any) { m["executor"].(map[string]any)["path"] = "/other/codex" }},
		{"executor-list", func(m map[string]any) { m["executor"] = []any{m["executor"], m["executor"]} }},
		{"unknown-executor-field", func(m map[string]any) { m["executor"].(map[string]any)["extra"] = true }},
		{"unknown-field", func(m map[string]any) { m["extra"] = true }},
		{"wrong-format", func(m map[string]any) { m["format"] = "swarma-user-manager demo-roster/0" }},
		{"program-pin-as-wire-revision", func(m map[string]any) { m["source_revision"] = "bf72a78a2c02ca30d1238e218df2f3318a63b92b" }},
		{"other-wire-revision", func(m map[string]any) { m["source_revision"] = "0000000000000000000000000000000000000000" }},
	}
	var result []rejectedRoster
	for _, mutation := range mutations {
		var m map[string]any
		if err := json.Unmarshal(original, &m); err != nil {
			t.Fatal(err)
		}
		mutation.change(m)
		result = append(result, rejectedRoster{mutation.name, raw(t, m)})
	}
	return result
}
