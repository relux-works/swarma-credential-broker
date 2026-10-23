//go:build linux

package authowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/internal/owner"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
)

type retainedField struct {
	path string
	typ  reflect.Type
}
type fieldRule struct{ class, rule string }

func reflectedFields(typ reflect.Type, prefix string) []retainedField {
	var out []retainedField
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if f.Anonymous {
			out = append(out, reflectedFields(f.Type, prefix)...)
			continue
		}
		if f.PkgPath != "" || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		path := prefix + name
		out = append(out, retainedField{path, f.Type})
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeFor[time.Time]() {
			out = append(out, reflectedFields(f.Type, path+".")...)
		}
	}
	return out
}
func classification(t *testing.T, phase string) map[string]fieldRule {
	t.Helper()
	raw, err := os.ReadFile("../../docs/auth-owner.md")
	if err != nil {
		t.Fatal(err)
	}
	part := strings.SplitN(string(raw), "| Record / phases |", 2)
	if len(part) != 2 {
		t.Fatal("field inventory missing")
	}
	rules := map[string]fieldRule{}
	quoted := regexp.MustCompile("`([^`]+)`")
	for _, line := range strings.Split(strings.SplitN(part[1], "\n\n", 2)[0], "\n")[2:] {
		c := strings.Split(line, "|")
		if len(c) != 6 {
			t.Fatal("invalid classification row", line)
		}
		selector := strings.TrimSpace(c[1])
		match := selector == "Intent, all Evidence" && phase != "checkpoint" || selector == "Intent" && phase == "intent" || selector == "All Evidence" && phase != "intent" && phase != "checkpoint" || selector == "Checkpoint" && phase == "checkpoint"
		if strings.HasSuffix(selector, " Evidence") && selector != "All Evidence" {
			for _, p := range strings.Split(strings.TrimSuffix(strings.ToLower(selector), " evidence"), ",") {
				if strings.TrimSpace(p) == phase {
					match = true
				}
			}
		}
		if !match {
			continue
		}
		class := strings.TrimSpace(c[3])
		if class != "identity" && class != "authority" && class != "diagnostic" {
			t.Fatal("unknown field class", class)
		}
		for _, m := range quoted.FindAllStringSubmatch(c[2], -1) {
			if _, ok := rules[m[1]]; ok {
				t.Fatal("duplicate classification", phase, m[1])
			}
			rules[m[1]] = fieldRule{class, strings.TrimSpace(c[4])}
		}
	}
	return rules
}
func verifyClassification(typ reflect.Type, rules map[string]fieldRule) error {
	fields := reflectedFields(typ, "")
	for _, f := range fields {
		r, ok := rules[f.path]
		if !ok || r.rule == "" {
			return fmt.Errorf("unclassified retained field %s", f.path)
		}
	}
	if len(fields) != len(rules) {
		return fmt.Errorf("schema/classification count mismatch: %d fields, %d rules", len(fields), len(rules))
	}

	return nil
}
func retainedSchemas() map[string]reflect.Type {
	return map[string]reflect.Type{"intent": reflect.TypeFor[Intent](), "submitted": reflect.TypeFor[Evidence](), "running": reflect.TypeFor[Evidence](), "stopping": reflect.TypeFor[Evidence](), "absent": reflect.TypeFor[Evidence](), "resolved": reflect.TypeFor[Evidence](), "checkpoint": reflect.TypeFor[Checkpoint]()}
}

// Claim: every serialized field and object has exactly one documented class for
// each phase. A synthetic added authority field proves the inventory rejects
// schema growth rather than silently omitting the new field from generated cases.
func TestRetainedFieldClassification(t *testing.T) {
	for phase, typ := range retainedSchemas() {
		t.Run(phase, func(t *testing.T) {
			rules := classification(t, phase)
			if err := verifyClassification(typ, rules); err != nil {
				t.Fatal(err)
			}
			fields := make([]reflect.StructField, typ.NumField())
			for i := range fields {
				fields[i] = typ.Field(i)
			}
			for _, tag := range []reflect.StructTag{`json:"additional_authority"`, ""} {
				plant := append(append([]reflect.StructField{}, fields...), reflect.StructField{Name: "AdditionalAuthority", Type: reflect.TypeFor[uint64](), Tag: tag})
				if err := verifyClassification(reflect.StructOf(plant), rules); err == nil {
					t.Fatal("unclassified authority control accepted")
				}
			}
		})
	}
}

func substituteField(m map[string]any, f retainedField, phase string, anchor time.Time) {
	keys := strings.Split(f.path, ".")
	leaf := m
	for _, k := range keys[:len(keys)-1] {
		leaf = leaf[k].(map[string]any)
	}
	key := keys[len(keys)-1]
	old := leaf[key]
	if f.typ == reflect.TypeFor[time.Time]() {
		value, _ := time.Parse(time.RFC3339Nano, old.(string))
		switch f.path {
		case "watermark", "resolved_at":
			value = anchor.Add(-time.Nanosecond)
		case "retry_at":
			if value.IsZero() {
				value = anchor.Add(time.Second)
			} else {
				value = value.Add(-time.Nanosecond)
			}
		default:
			if value.IsZero() {
				value = anchor.Add(time.Second)
			} else {
				value = value.Add(time.Second)
			}
		}
		leaf[key] = value
		return
	}
	switch f.typ.Kind() {
	case reflect.Bool:
		leaf[key] = !old.(bool)
	case reflect.Uint64, reflect.Uint32, reflect.Int32:
		if phase == "checkpoint" && f.path == "revision" {
			leaf[key] = 1
		} else {
			leaf[key] = old.(float64) + 1
		}
	case reflect.Struct:
		b, _ := json.Marshal(old)
		var value map[string]any
		json.Unmarshal(b, &value)
		if f.path == "observation" {
			value["active_state"] = "failed"
		} else {
			value["boot_id"] = "alternate-boot"
		}
		leaf[key] = value
	case reflect.String:
		value := old.(string)
		replacement := "alternate-value"
		switch key {
		case "kind":
			replacement = "attempt-intent/1"
			if value == replacement {
				replacement = "attempt-evidence/1"
			}
		case "phase":
			replacement = "intent"
			if value == replacement {
				replacement = "submitted"
			}
		case "plan_type", "plan_before":
			replacement = "pro"
			if value == replacement {
				replacement = "plus"
			}
		case "rpc_outcome", "outcome":
			replacement = string(Safe)
			if value == replacement {
				replacement = string(Committed)
			}
		case "state":
			replacement = owner.Active
			if value == replacement {
				replacement = owner.Transient
			}
		case "absence":
			replacement = "unknown"
			if value == replacement {
				replacement = "confirmed"
			}
		case "active_state":
			replacement = "inactive"
			if value == replacement {
				replacement = "failed"
			}
		case "substate":
			replacement = "dead"
			if value == replacement {
				replacement = "running"
			}
		case "cgroup_path":
			replacement = "/fixture/alternate-group"
		case "unit_name":
			replacement = "fixture-alternate.service"
		case "pending_attempt", "last_resolved_attempt", "attempt_id", "daemon_instance_id":
			replacement = strings.Repeat("a", 32)
			if value == replacement {
				replacement = strings.Repeat("b", 32)
			}
		default:
			if strings.Contains(key, "digest") || strings.Contains(key, "sha256") || len(value) == 64 {
				replacement = strings.Repeat("a", 64)
				if value == replacement {
					replacement = strings.Repeat("b", 64)
				}
			}
		}
		leaf[key] = replacement
	default:
		panic("unsupported retained schema type: " + f.typ.String())
	}
}

// Claim: reflected field substitutions with valid ordinary types/enums but
// contradictory history close Snapshot and fresh-home, live and replacement,
// for committed/safe/rejected/pending prefixes. Documented diagnostics remain
// admissible. This is a finite generated counterexample set, not a claim that
// all different values violate bounded rules such as conservative retry times.
// Each negative case also preserves protected records and admits no new writer.
func TestRetainedFieldSubstitutions(t *testing.T) {
	for _, history := range []string{"committed", "safe", "rejected", "pending-safe", "pending-rejected"} {
		t.Run(history, func(t *testing.T) {
			f := newFixture(t, "rotate")
			label := f.c.Accounts[0].Label
			if _, err := f.refresh(); err != nil {
				t.Fatal(err)
			}
			before := f.e.accounts[label].checkpoint
			if history != "committed" {
				mode := strings.TrimPrefix(history, "pending-")
				if err := os.WriteFile(filepath.Join(f.home, "scenario"), []byte(mode), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := f.e.Refresh(context.Background(), label, 2); err != nil {
					t.Fatal(err)
				}
			}
			settled := f.e.accounts[label].checkpoint
			f.e.Close()
			baseline, err := f.disk.Records()
			if err != nil {
				t.Fatal(err)
			}
			settledRaw := append([]byte(nil), baseline["owner-checkpoint.json"]...)
			pending := strings.HasPrefix(history, "pending-")
			if pending {
				before.Revision = settled.Revision - 1
				before.State = owner.Unavailable
				before.PendingAttempt = settled.LastAttempt
				baseline["owner-checkpoint.json"], err = wire.Encode(before)
				if err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Dir(authorityRecordPath(f, "owner-checkpoint.json"))
			restore := func() {
				t.Helper()
				current, err := f.disk.Records()
				if err != nil {
					t.Fatal(err)
				}
				for name := range current {
					if _, ok := baseline[name]; !ok && strings.HasPrefix(name, "owner-") {
						if err := os.Remove(filepath.Join(dir, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				for name, raw := range baseline {
					if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			names := make([]string, 0, len(baseline))
			for n := range baseline {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, name := range names {
				var original map[string]any
				if json.Unmarshal(baseline[name], &original) != nil {
					t.Fatal("record fixture")
				}
				phase, _ := original["phase"].(string)
				if name == "owner-checkpoint.json" {
					phase = "checkpoint"
				}
				typ := retainedSchemas()[phase]
				if typ == nil {
					t.Fatal("unclassified owner record", name)
				}
				rules := classification(t, phase)
				if err := verifyClassification(typ, rules); err != nil {
					t.Fatal(err)
				}
				anchor := before.Watermark
				recordName := phase
				if sequence, ok := original["attempt_sequence"]; ok {
					recordName += fmt.Sprint("-", sequence)
				}
				t.Run(recordName, func(t *testing.T) {
					for _, field := range reflectedFields(typ, "") {
						t.Run(field.path, func(t *testing.T) {
							for _, mode := range []string{"live", "replacement"} {
								t.Run(mode, func(t *testing.T) {
									restore()
									defer restore()
									open := func() *Engine {
										t.Helper()
										e, err := New(context.Background(), f.c, f.m, f.t, fakeClassifier{})
										if err != nil {
											t.Fatal(err)
										}
										return e
									}
									var e *Engine
									if mode == "live" {
										if pending {
											if err := os.WriteFile(filepath.Join(dir, "owner-checkpoint.json"), settledRaw, 0600); err != nil {
												t.Fatal(err)
											}
										}
										e = open()
										restore()
									}
									var changed map[string]any
									json.Unmarshal(baseline[name], &changed)
									substituteField(changed, field, phase, anchor)
									raw, err := wire.Encode(changed)
									if err != nil || bytes.Equal(raw, baseline[name]) {
										t.Fatal("substitution not applied", err)
									}
									if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
										t.Fatal(err)
									}
									records, err := f.disk.Records()
									if err != nil {
										t.Fatal(err)
									}
									starts := f.m.count()
									if mode == "replacement" {
										e = open()
									}
									defer e.Close()
									diagnostic := rules[field.path].class == "diagnostic"
									if mode == "live" && pending {
										// Exercise the production restore/recovery methods on the already-live
										// engine. Ordinary public admission alone cannot resolve a pending writer.
										a, err := e.enter(context.Background(), label, true)
										if err != nil {
											t.Fatal(err)
										}
										err = e.restore(a)
										if err == nil {
											err = e.recover(context.Background(), a)
										}
										e.leave(a)
										if diagnostic && err != nil {
											t.Fatal("diagnostic pending recovery refused", err)
										}
									}
									s, readErr := e.Snapshot(context.Background(), label)
									freshErr := e.AdmitFreshHome(context.Background(), label)
									if diagnostic {
										if readErr != nil || freshErr != nil || history != "rejected" && history != "pending-rejected" && s.AccessToken == "" {
											t.Fatal("diagnostic substitution refused", readErr, freshErr)
										}
									} else {
										if !errors.Is(readErr, ErrUnavailable) || !errors.Is(freshErr, ErrUnavailable) || s.AccessToken != "" {
											t.Fatalf("%s field admitted: snapshot=%v fresh=%v", rules[field.path].class, readErr, freshErr)
										}
										after, err := f.disk.Records()
										if err != nil || len(after) != len(records) {
											t.Fatal("fault mutated records")
										}
										for n, b := range records {
											if !bytes.Equal(b, after[n]) {
												t.Fatal("fault changed protected record", n)
											}
										}
									}
									if f.m.count() != starts {
										t.Fatal("substitution started writer")
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

// Claim: explicit initial enrollment plans and genuine committed vendor plan
// changes remain legitimate; preserving an older plan must not reject new truth.
func TestRetainedPlanControls(t *testing.T) {
	f := newFixture(t, "rotate")
	label := f.c.Accounts[0].Label
	c := f.e.accounts[label].checkpoint
	c.Plan = "pro"
	if err := f.e.checkpoint(f.e.accounts[label], c); err != nil {
		t.Fatal(err)
	}
	if s, err := f.snapshot(); err != nil || s.PlanType != "pro" {
		t.Fatal("initial enrollment plan refused", err)
	}
	// The real fixture RPC reports plus, so this is an actual plan-changing commit.
	if s, err := f.refresh(); err != nil || s.PlanType != "plus" {
		t.Fatal("genuine plan-changing commit refused", err)
	}
	if s, err := f.replacement(t).Snapshot(context.Background(), label); err != nil || s.PlanType != "plus" {
		t.Fatal("committed plan not retained", err)
	}
}
