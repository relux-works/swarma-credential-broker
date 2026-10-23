//go:build linux

package authowner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type chainFault struct {
	name   string
	path   []string
	value  any
	remove bool
}

// Claim: the normative table's seven phases require every encoded field. For
// each field, removing it from an otherwise valid committed chain closes load,
// Snapshot, fresh-home and writer admission. Additional single-value faults
// exercise the table's semantic constraints, not just closed-schema decoding.
// Diagnostic values have presence requirements, not invented semantic bounds.
func TestRetainedChainTable(t *testing.T) {
	// This table owns its stores, clocks and managers independently of other tables.
	t.Parallel()
	doc, err := os.ReadFile("../../docs/auth-owner.md")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(doc), "| Phase |", 2)
	if len(parts) != 2 {
		t.Fatal("normative phase table missing")
	}
	var phases []string
	for _, line := range strings.Split(strings.SplitN(parts[1], "\n\n", 2)[0], "\n")[2:] {
		cells := strings.Split(line, "|")
		if len(cells) > 2 {
			phases = append(phases, strings.TrimSpace(cells[1]))
		}
	}
	if strings.Join(phases, ",") != "intent,submitted,running,stopping,absent,resolved,checkpoint" {
		t.Fatalf("uncovered normative phases: %v", phases)
	}
	f := newFixture(t, "rotate")
	if _, err = f.refresh(); err != nil {
		t.Fatal(err)
	}
	f.e.Close()
	baseline, err := f.disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	label := sha256.Sum256([]byte(f.c.Accounts[0].Label))
	dir := filepath.Join(f.root, "store", "account-"+hex.EncodeToString(label[:]))
	byPhase := map[string]string{}
	var running any
	for name, raw := range baseline {
		var record map[string]any
		if json.Unmarshal(raw, &record) != nil {
			t.Fatal("record fixture")
		}
		if record["kind"] == "account-checkpoint/1" {
			byPhase["checkpoint"] = name
		} else if phase, ok := record["phase"].(string); ok {
			byPhase[phase] = name
			if phase == "running" {
				running = record["observation"]
			}
		}
	}
	// The submitted observation is optional; supply a valid one to exercise its
	// conditional tuple contract as well as the ordinary empty-observation path.
	var submitted map[string]any
	if json.Unmarshal(baseline[byPhase["submitted"]], &submitted) != nil {
		t.Fatal("submitted fixture")
	}
	submitted["observation"] = running
	baseline[byPhase["submitted"]], err = wire.Encode(submitted)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(byPhase["submitted"], baseline[byPhase["submitted"]])
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			name := byPhase[phase]
			var original map[string]any
			if json.Unmarshal(baseline[name], &original) != nil {
				t.Fatal("phase fixture missing")
			}
			faults := []chainFault{{name: "consistent-control"}}
			var fields func(map[string]any, []string)
			fields = func(m map[string]any, prefix []string) {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, key := range keys {
					path := append(append([]string{}, prefix...), key)
					faults = append(faults, chainFault{name: strings.Join(path, ".") + "/missing", path: path, remove: true})
					if nested, ok := m[key].(map[string]any); ok {
						fields(nested, path)
					}
				}
			}
			fields(original, nil)
			faults = append(faults, semanticChainFaults(phase)...)
			if phase == "resolved" {
				var v Evidence
				if json.Unmarshal(baseline[name], &v) != nil {
					t.Fatal("resolution fixture")
				}
				faults = append(faults,
					chainFault{name: "resolved_at/before-intent", path: []string{"resolved_at"}, value: v.Created.Add(-time.Nanosecond)},
					chainFault{name: "resolved_at/after-watermark", path: []string{"resolved_at"}, value: v.ResolvedAt.Add(time.Second)},
					chainFault{name: "token_expires_at/nonzero-conflict", path: []string{"token_expires_at"}, value: v.TokenExpires.Add(time.Second)},
				)
			}
			if phase == "checkpoint" {
				var c Checkpoint
				if json.Unmarshal(baseline[name], &c) != nil {
					t.Fatal("checkpoint fixture")
				}
				for _, fault := range []chainFault{
					{name: "next_proactive/erased", path: []string{"next_proactive"}, value: time.Time{}},
					{name: "next_proactive/shortened-nonzero", path: []string{"next_proactive"}, value: c.NextProactive.Add(-time.Second)},
					{name: "safe_failures/inconsistent-nonzero", path: []string{"safe_failures"}, value: 2},
					{name: "retry_at/unexpected-nonzero", path: []string{"retry_at"}, value: c.Watermark.Add(time.Second)},
				} {
					faults = append(faults, fault)
				}
			}
			for _, fault := range faults {
				t.Run(fault.name, func(t *testing.T) {
					for _, entry := range []string{"load", "snapshot", "fresh-home", "writer"} {
						t.Run(entry, func(t *testing.T) {
							if entry == "writer" && fault.name == "consistent-control" {
								// The valid neighbor actually admits a second writer with
								// new synthetic material; refusal cannot win by rejecting all work.
								third := jwt(f.t.now.Add(6*time.Hour), "synthetic-third")
								if err := os.WriteFile(filepath.Join(f.home, "next-token"), []byte(third), 0600); err != nil {
									t.Fatal(err)
								}
								defer func() {
									if fixtureAuth(f.home, f.next) != nil || os.WriteFile(filepath.Join(f.home, "next-token"), []byte(f.next), 0600) != nil {
										t.Fatal("restore synthetic control material")
									}
								}()
							}
							// Restore only synthetic owner records, including any forbidden
							// partial writes if a regression admits a new writer.
							defer func() {
								current, err := f.disk.Records()
								if err != nil {
									t.Fatal(err)
								}
								for n := range current {
									if _, ok := baseline[n]; !ok && strings.HasPrefix(n, "owner-") {
										if err := os.Remove(filepath.Join(dir, n)); err != nil {
											t.Fatal(err)
										}
									}
								}
								for n, raw := range baseline {
									write(n, raw)
								}
							}()
							var changed map[string]any
							if json.Unmarshal(baseline[name], &changed) != nil {
								t.Fatal("decode fixture")
							}
							if len(fault.path) != 0 {
								m := changed
								for _, k := range fault.path[:len(fault.path)-1] {
									m = m[k].(map[string]any)
								}
								key := fault.path[len(fault.path)-1]
								if fault.remove {
									delete(m, key)
								} else {
									m[key] = fault.value
								}
							}
							raw, err := wire.Encode(changed)
							if err != nil {
								t.Fatal(err)
							}
							if fault.name != "consistent-control" && bytes.Equal(raw, baseline[name]) {
								t.Fatal("fault not applied")
							}
							var r *Engine
							open := func() {
								var err error
								r, err = New(context.Background(), f.c, f.m, f.t, fakeClassifier{})
								if err != nil {
									t.Fatal(err)
								}
							}
							if entry != "load" {
								open()
							}
							write(name, raw)
							if entry == "load" {
								open()
							}
							defer r.Close()
							before, err := f.disk.Records()
							if err != nil {
								t.Fatal(err)
							}
							starts := f.m.count()
							var snapshot owner.Snapshot
							if entry == "fresh-home" {
								err = r.AdmitFreshHome(context.Background(), f.c.Accounts[0].Label)
							} else if entry == "writer" {
								snapshot, err = r.Refresh(context.Background(), f.c.Accounts[0].Label, 2)
							} else {
								snapshot, err = r.Snapshot(context.Background(), f.c.Accounts[0].Label)
							}
							if fault.name == "consistent-control" {
								if err != nil || entry != "fresh-home" && snapshot.State != owner.Active {
									t.Fatal("consistent chain refused", err)
								}
							} else {
								if !errors.Is(err, ErrUnavailable) || snapshot.AccessToken != "" {
									t.Fatal("inconsistent retained chain admitted", err)
								}
								after, err := f.disk.Records()
								if err != nil {
									t.Fatal(err)
								}
								if len(after) != len(before) {
									t.Fatal("refusal wrote another record")
								}
								for n, b := range before {
									if !bytes.Equal(b, after[n]) {
										t.Fatal("refusal changed protected record")
									}
								}
							}
							if entry == "writer" && fault.name == "consistent-control" {
								starts++
							}
							if f.m.count() != starts {
								t.Fatal("retained fault started another writer")
							}
						})
					}
				})
			}
		})
	}
}

func semanticChainFaults(phase string) []chainFault {
	var faults []chainFault
	add := func(path string, value any) {
		faults = append(faults, chainFault{name: path + "/conflicting", path: strings.Split(path, "."), value: value})
	}
	if phase == "checkpoint" {
		for _, field := range []string{"installation_id", "account", "vendor_account_id", "vendor_home_id", "state", "last_resolved_attempt", "vendor_store_digest", "current_token_digest", "plan_type"} {
			add(field, "")
		}
		for _, field := range []string{"revision", "retained_attempts", "store_generation", "token_generation", "policy_generation"} {
			add(field, 0)
		}
		add("pending_attempt", id())
		add("watermark", "0001-01-01T00:00:00Z")
		return faults
	}
	for _, field := range []string{"kind", "phase", "installation_id", "account", "attempt_id", "operation", "daemon_instance_id", "boot_id", "manager_epoch", "unit_name", "executable_sha256", "vendor_home_id"} {
		add(field, "")
	}
	for _, field := range []string{"attempt_sequence", "revision", "policy_generation", "store_generation_before", "token_generation_before"} {
		add(field, 0)
	}
	add("manager_uid", 0)
	add("created_at", "0001-01-01T00:00:00Z")
	add("deadline", "0001-01-01T00:00:00Z")
	if phase == "intent" {
		return faults
	}
	if phase == "resolved" {
		add("resolved_at", "0001-01-01T00:00:00Z")
		add("token_expires_at", "0001-01-01T00:00:00Z")
	} else {
		add("resolved_at", time.Now().UTC())
		add("token_expires_at", time.Now().UTC())
	}
	for _, field := range []string{"invocation_id", "cgroup_path", "cgroup_identity", "verified_property_digest", "unit_name", "manager.boot_id", "manager.manager_epoch"} {
		add("observation."+field, "")
	}
	for _, field := range []string{"complete_read", "restart_no"} {
		add("observation."+field, false)
	}
	add("observation.manager.manager_uid", 0)
	if phase == "absent" || phase == "resolved" {
		add("observation.active_state", "active")
		for _, field := range []string{"stop_completed", "subtree_empty", "populated_zero"} {
			add("observation."+field, false)
		}
	} else {
		add("observation.active_state", "inactive")
		add("observation.substate", "dead")
		add("observation.main_pid", 0)
		add("observation.process_start", 0)
		for _, field := range []string{"stop_completed", "subtree_empty", "populated_zero", "cgroup_removed_after_stop"} {
			add("observation."+field, true)
		}
	}
	add("absence", "contradictory")
	add("store_generation_after", 999)
	if phase == "stopping" || phase == "absent" || phase == "resolved" {
		add("rpc_outcome", string(Unknown))
	} else {
		add("rpc_outcome", string(Committed))
	}
	if phase == "resolved" {
		add("outcome", string(Unknown))
	} else {
		add("outcome", string(Committed))
	}
	add("plan_type", "unsupported")
	return faults
}
