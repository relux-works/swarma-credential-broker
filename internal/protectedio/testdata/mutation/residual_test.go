package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Claim: only the expected named assertion with exit one is a privileged kill; infrastructure, wrong tests and panics never qualify.
func TestPrivilegedKillEvidence(test *testing.T) {
	expected := privilegedWitnesses["M0240"]
	valid := "--- FAIL: " + expected.Test + " (0.01s)\n    " + expected.Assertion + " equal-size read error admitted\n"
	for _, entry := range []struct {
		name, output string
		exit         int
		want         bool
	}{
		{"assertion", valid, 1, true},
		{"success", valid, 0, false},
		{"timeout", valid, 124, false},
		{"wrong-test", strings.ReplaceAll(valid, expected.Test, "TestOther"), 1, false},
		{"no-assertion", strings.ReplaceAll(valid, expected.Assertion, "setup failed"), 1, false},
		{"panic", valid + "panic: witness crashed", 1, false},
		{"build", valid + "[build failed]", 1, false},
		{"unapplied", valid + "privileged fault not applied", 1, false},
		{"setup", valid + "privileged fixture setup: permission denied", 1, false},
		{"infrastructure", valid + "privileged fixture infrastructure failed:", 1, false},
	} {
		test.Run(entry.name, func(test *testing.T) {
			if got := privilegedKill(entry.exit, []byte(entry.output), expected); got != entry.want {
				test.Fatalf("kill=%v want=%v", got, entry.want)
			}
		})
	}
}

// Claim: the privileged inventory preserves the exact 18 audited substitutions across execution identities and rejects stale or expanded residuals.
func TestResidualInventory(test *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	rows, err := readAudit("results.tsv")
	if err != nil {
		test.Fatal(err)
	}
	uid, gid, err := auditBrokerIdentity(rows)
	if err != nil {
		test.Fatal(err)
	}
	generated := inventory(root, uid, gid)
	selected, err := residualInventory(generated, rows)
	if err != nil || len(selected) != 18 {
		test.Fatalf("exact residual control: count=%d error=%v", len(selected), err)
	}
	for _, mutation := range selected {
		expected := uid
		if strings.Contains(strings.ToLower(mutation.Operator), "gid") {
			expected = gid
		}
		if strings.HasSuffix(mutation.Operator, "-broker") && mutation.After != strconv.Itoa(expected) {
			test.Fatalf("historical substitution was rebound for %s", mutation.ID)
		}
	}
	for _, variant := range []string{"missing", "duplicate", "stale", "extra", "substitution", "invalid-broker", "false-equivalence"} {
		test.Run(variant, func(test *testing.T) {
			changed := make([][]string, len(rows))
			for index, row := range rows {
				changed[index] = append([]string(nil), row...)
			}
			switch variant {
			case "missing":
				changed = append(changed[:111], changed[112:]...)
			case "duplicate":
				changed = append(changed, changed[111])
			case "stale":
				changed[111][4] = "not the source expression"
			case "extra":
				changed[1][6] = "SURVIVED"
			case "substitution":
				changed[111][5] = "true"
			case "invalid-broker":
				changed[197][5] = "not a numeric identity"
			case "false-equivalence":
				changed[111][6] = "EQUIVALENT"
			}
			if _, err := residualInventory(generated, changed); err == nil {
				test.Fatal("invalid residual inventory admitted")
			}
		})
	}
}

// Claim: audit export requires all unique named kills, preserves unrelated rows and leaves an existing destination untouched on rejected evidence.
func TestPrivilegedAuditExport(test *testing.T) {
	rows, err := readAudit("results.tsv")
	if err != nil {
		test.Fatal(err)
	}
	var results []result
	for id, expected := range privilegedWitnesses {
		results = append(results, result{mutant: mutant{ID: id}, Status: "KILLED", Tests: expected.Test, Exit: 1, Log: id + ".log"})
	}
	path := filepath.Join(test.TempDir(), "results.tsv")
	if err := writePrivilegedAudit(path, rows, results); err != nil {
		test.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		test.Fatalf("audit must be readable by the unprivileged artifact uploader: %v", err)
	}
	updated, err := readAudit(path)
	if err != nil || len(updated) != len(rows) {
		test.Fatalf("audit control: rows=%d error=%v", len(updated), err)
	}
	for index, row := range updated {
		if expected, changed := privilegedWitnesses[row[0]]; changed {
			if row[6] != "KILLED" || row[7] != expected.Test+"; "+expected.Assertion || row[8] != "1" {
				test.Fatalf("kill evidence missing for %s", row[0])
			}
		} else if strings.Join(row, "\t") != strings.Join(rows[index], "\t") {
			test.Fatalf("unrelated audit row changed: %s", row[0])
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		test.Fatal(err)
	}
	for _, variant := range []string{"partial", "survivor", "wrong-test", "duplicate", "missing-log"} {
		test.Run(variant, func(test *testing.T) {
			invalid := append([]result(nil), results...)
			switch variant {
			case "partial":
				invalid = invalid[:17]
			case "survivor":
				invalid[0].Status = "SURVIVED"
			case "wrong-test":
				invalid[0].Tests = "TestOther"
			case "duplicate":
				invalid[0] = invalid[1]
			case "missing-log":
				invalid[0].Log = ""
			}
			if err := writePrivilegedAudit(path, rows, invalid); err == nil {
				test.Fatal("unproved audit exported")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(before) {
				test.Fatalf("rejected export changed destination: %v", err)
			}
		})
	}
}

// Claim: historical UID and GID binding is consistent and complete before enumeration; malformed or conflicting broker replacements refuse.
func TestAuditBrokerIdentity(test *testing.T) {
	rows, err := readAudit("results.tsv")
	if err != nil {
		test.Fatal(err)
	}
	if _, _, err := auditBrokerIdentity(rows); err != nil {
		test.Fatal(err)
	}
	for _, variant := range []string{"invalid", "conflicting", "missing-gid"} {
		test.Run(variant, func(test *testing.T) {
			changed := [][]string{rows[0]}
			for _, row := range rows[1:] {
				if variant == "missing-gid" && strings.Contains(strings.ToLower(row[3]), "gid") {
					continue
				}
				copied := append([]string(nil), row...)
				if row[0] == "M0197" {
					if variant == "invalid" {
						copied[5] = "not a numeric identity"
					} else if variant == "conflicting" {
						copied[5] = "4294967295"
					}
				}
				changed = append(changed, copied)
			}
			if _, _, err := auditBrokerIdentity(changed); err == nil {
				test.Fatal("invalid historical identity binding admitted")
			}
		})
	}
}
