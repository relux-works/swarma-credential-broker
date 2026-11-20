package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type witness struct {
	Test, Assertion string
}

var privilegedWitnesses = map[string]witness{
	"M0111": {"TestPrivilegedActualRoot/other-write", "ASSERT_PRIVILEGED_ROOT:"},
	"M0113": {"TestPrivilegedActualRoot/owner", "ASSERT_PRIVILEGED_ROOT:"},
	"M0118": {"TestPrivilegedActualRoot/group-write", "ASSERT_PRIVILEGED_ROOT:"},
	"M0120": {"TestPrivilegedActualRoot/group-write", "ASSERT_PRIVILEGED_ROOT:"},
	"M0122": {"TestPrivilegedActualRoot/other-write", "ASSERT_PRIVILEGED_ROOT:"},
	"M0123": {"TestPrivilegedActualRoot/group-write", "ASSERT_PRIVILEGED_ROOT:"},
	"M0124": {"TestPrivilegedActualRoot/sticky", "ASSERT_PRIVILEGED_ROOT:"},
	"M0125": {"TestPrivilegedActualRoot/setgid", "ASSERT_PRIVILEGED_ROOT:"},
	"M0126": {"TestPrivilegedActualRoot/setuid", "ASSERT_PRIVILEGED_ROOT:"},
	"M0197": {"TestPrivilegedPolicyOwner", "ASSERT_PRIVILEGED_POLICY:"},
	"M0204": {"TestPrivilegedNegativeSize", "ASSERT_PRIVILEGED_SIZE:"},
	"M0240": {"TestPrivilegedReadFault", "ASSERT_PRIVILEGED_READ:"},
	"M0275": {"TestPrivilegedGateOwners/gate-parent-owner", "ASSERT_PRIVILEGED_GATE:"},
	"M0277": {"TestPrivilegedGateOwners/gate-parent-group", "ASSERT_PRIVILEGED_GATE:"},
	"M0281": {"TestPrivilegedGateOwners/gate-ancestor-owner", "ASSERT_PRIVILEGED_GATE:"},
	"M0300": {"TestPrivilegedGateOwners/window-parent-owner", "ASSERT_PRIVILEGED_GATE:"},
	"M0302": {"TestPrivilegedGateOwners/window-parent-group", "ASSERT_PRIVILEGED_GATE:"},
	"M0306": {"TestPrivilegedGateOwners/window-ancestor-owner", "ASSERT_PRIVILEGED_GATE:"},
}

const privilegedSelection = "^TestPrivileged(ActualRoot|PolicyOwner|GateOwners|ReadFault|NegativeSize)$"

func readAudit(path string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.Comma, reader.FieldsPerRecord = '\t', 12
	return reader.ReadAll()
}

func auditBrokerIdentity(rows [][]string) (int, int, error) {
	identities := map[string]int{}
	for _, row := range rows[1:] {
		if !strings.HasSuffix(row[3], "-broker") {
			continue
		}
		kind := "uid"
		if strings.Contains(strings.ToLower(row[3]), "gid") {
			kind = "gid"
		}
		value, err := strconv.ParseUint(row[5], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid historical broker identity %s", row[0])
		}
		if previous, exists := identities[kind]; exists && previous != int(value) {
			return 0, 0, fmt.Errorf("inconsistent historical broker %s", kind)
		}
		identities[kind] = int(value)
	}
	if len(identities) != 2 {
		return 0, 0, fmt.Errorf("audit must bind both historical broker identities")
	}
	return identities["uid"], identities["gid"], nil
}

func residualInventory(generated []mutant, rows [][]string) ([]mutant, error) {
	if len(rows) != len(generated)+1 || len(rows[0]) != 12 || rows[0][0] != "mutant" {
		return nil, fmt.Errorf("audit must contain the complete generated inventory and header")
	}
	audit := make(map[string][]string)
	for _, row := range rows[1:] {
		if _, exists := audit[row[0]]; exists {
			return nil, fmt.Errorf("duplicate audit row %s", row[0])
		}
		if row[6] == "SURVIVED" {
			if _, expected := privilegedWitnesses[row[0]]; !expected {
				return nil, fmt.Errorf("unexpected residual %s", row[0])
			}
		}
		audit[row[0]] = row
	}
	var selected []mutant
	for _, mutation := range generated {
		if _, expected := privilegedWitnesses[mutation.ID]; !expected {
			continue
		}
		row, exists := audit[mutation.ID]
		if !exists || (row[6] != "SURVIVED" && row[6] != "KILLED") || row[1] != fmt.Sprintf("%s:%d", mutation.File, mutation.Line) || row[2] != fmt.Sprintf("%d:%d", mutation.Start, mutation.End) || row[3] != mutation.Operator || row[4] != mutation.Before {
			return nil, fmt.Errorf("stale or missing audit identity %s", mutation.ID)
		}
		if row[5] != mutation.After {
			return nil, fmt.Errorf("changed audited substitution %s", mutation.ID)
		}
		selected = append(selected, mutation)
	}
	if len(selected) != 18 {
		return nil, fmt.Errorf("expected exactly 18 residual identities, got %d", len(selected))
	}
	return selected, nil
}

func privilegedKill(exit int, output []byte, expected witness) bool {
	if exit != 1 || !bytes.Contains(output, []byte(expected.Assertion)) {
		return false
	}
	for _, invalid := range []string{"panic:", "[build failed]", "privileged fixture setup:", "privileged fixture infrastructure failed:", "privileged fault not applied", "privileged trace", "privileged fault valid control", "privileged fixtures require actual root"} {
		if bytes.Contains(output, []byte(invalid)) {
			return false
		}
	}
	failures := regexp.MustCompile(`--- FAIL: ([^\s]+)`)
	for _, match := range failures.FindAllSubmatch(output, -1) {
		if string(match[1]) == expected.Test {
			return true
		}
	}
	return false
}

func writePrivilegedAudit(path string, rows [][]string, results []result) error {
	if len(results) != len(privilegedWitnesses) {
		return fmt.Errorf("audit export requires all 18 results")
	}
	byID := make(map[string]result)
	for _, entry := range results {
		expected, exists := privilegedWitnesses[entry.ID]
		if !exists || entry.Status != "KILLED" || entry.Tests != expected.Test || entry.Exit != 1 || entry.Log == "" {
			return fmt.Errorf("audit export refuses unproved result %s", entry.ID)
		}
		if _, duplicate := byID[entry.ID]; duplicate {
			return fmt.Errorf("audit export refuses duplicate result %s", entry.ID)
		}
		byID[entry.ID] = entry
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	writer.Comma = '\t'
	for _, row := range rows {
		updated := append([]string(nil), row...)
		if entry, exists := byID[row[0]]; exists {
			updated[6], updated[7] = "KILLED", entry.Tests+"; "+privilegedWitnesses[entry.ID].Assertion
			updated[8], updated[9], updated[10], updated[11] = strconv.Itoa(entry.Exit), "-1", entry.Log, ""
		}
		if err := writer.Write(updated); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".privileged-audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(output.Bytes()); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
