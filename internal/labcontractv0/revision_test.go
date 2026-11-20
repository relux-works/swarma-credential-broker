package labcontractv0

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func observationStops(stops []any, generation, execution string) []any {
	selected := []any{}
	for _, raw := range stops {
		stop := raw.(map[string]any)
		if stop["generation"] == generation && stop["start_id"] == execution {
			selected = append(selected, raw)
		}
	}
	return selected
}

// Claim: terminal launch and pending/terminal stop independently close use without a static phase pin; selector changes cannot hide a selected stop or alter publication on refusal.
func TestLabObservationStopPairs(test *testing.T) {
	for _, phase := range []string{"admitted", "terminal"} {
		test.Run("launch-"+phase, func(test *testing.T) {
			fixture := observationControl(test)
			if got := observationAdmission(test, fixture, true); got != "valid" {
				test.Fatal("valid stop control:", got)
			}
			if _, exists := fixture.Expected["start"].(map[string]any)["phase"]; exists {
				test.Fatal("phase must not be a protected pin")
			}
			fixture.Response["start"].(map[string]any)["phase"] = phase
			want := "valid"
			if phase == "terminal" {
				want = "start_phase"
			}
			if got := observationAdmission(test, fixture, true); got != want {
				test.Fatalf("stop verdict: %s want %s", got, want)
			}
		})
		test.Run("stop-"+phase, func(test *testing.T) {
			fixture := observationControl(test)
			if got := observationAdmission(test, fixture, true); got != "valid" {
				test.Fatal("valid stop control:", got)
			}
			fixture.Stop["phase"] = phase
			fixture.Response["stops"] = []any{fixture.Stop}
			if got := observationAdmission(test, fixture, true); got != "stop" {
				test.Fatalf("stop verdict: %s want stop", got)
			}
			first, final := freshObservationPair(test)
			final.Response["stops"] = []any{fixture.Stop}
			state := observationPublication{Floor: 7}
			original := state
			if got := publishObservation(test, &state, first, final, validObservationTransport(), 2353, true, true); got != "unknown_observation" || state != original {
				test.Fatalf("stop publication: %s state=%v", got, state)
			}
		})
	}
	fixture := observationControl(test)
	for _, sides := range [][]string{nil, {"generation"}, {"start_id"}, {"generation", "start_id"}} {
		test.Run("selection-"+strings.Join(sides, "-"), func(test *testing.T) {
			if got := observationStops([]any{fixture.Stop}, fixture.Stop["generation"].(string), fixture.Stop["start_id"].(string)); len(got) != 1 {
				test.Fatal("valid selected stop missing")
			}
			stop := normalizedBounded(test, cloneObject(test, fixture.Stop))
			for _, side := range sides {
				if side == "generation" {
					stop[side] = strings.Repeat("d", 32)
				} else {
					stop[side] = "fixture-other"
				}
			}
			selected := observationStops([]any{stop}, fixture.Stop["generation"].(string), fixture.Stop["start_id"].(string))
			want := 0
			if len(sides) == 0 {
				want = 1
			}
			if len(selected) != want {
				test.Fatalf("stop selector: %d want %d", len(selected), want)
			}
		})
	}
}

type observationCurrentView struct {
	Locked, Found, Latest, AccountTerminal, ActiveOK bool
	RowUID, AccountUID                               int64
	RowGeneration, AccountGeneration, State          string
}

func currentObservationView(fixture observationFixture) observationCurrentView {
	start := fixture.Response["start"].(map[string]any)
	return observationCurrentView{true, true, true, true, true, start["uid"].(int64), start["uid"].(int64), start["generation"].(string), start["generation"].(string), "active"}
}

func observationGenerationCurrent(fixture observationFixture, view observationCurrentView) bool {
	start := fixture.Response["start"].(map[string]any)
	return view.Locked && view.Found && view.Latest && view.AccountTerminal && view.ActiveOK &&
		view.RowUID == start["uid"].(int64) && view.AccountUID == start["uid"].(int64) &&
		view.RowGeneration == start["generation"] && view.AccountGeneration == start["generation"] && view.State == "active"
}

// Claim: every conjunct of the pinned native account-currentness predicate is necessary independently of the installed store-generation pin.
func TestLabObservationCurrentnessPairs(test *testing.T) {
	for _, name := range []string{"locked", "found", "latest", "account-terminal", "active-check", "row-uid", "account-uid", "row-generation", "account-generation", "state-pending", "state-retired"} {
		test.Run(name, func(test *testing.T) {
			fixture := observationControl(test)
			view := currentObservationView(fixture)
			if !observationGenerationCurrent(fixture, view) {
				test.Fatal("valid currentness control refused")
			}
			switch name {
			case "locked":
				view.Locked = false
			case "found":
				view.Found = false
			case "latest":
				view.Latest = false
			case "account-terminal":
				view.AccountTerminal = false
			case "active-check":
				view.ActiveOK = false
			case "row-uid":
				view.RowUID++
			case "account-uid":
				view.AccountUID++
			case "row-generation":
				view.RowGeneration = strings.Repeat("d", 32)
			case "account-generation":
				view.AccountGeneration = strings.Repeat("d", 32)
			case "state-pending":
				view.State = "pending"
			case "state-retired":
				view.State = "retired"
			}
			fixture.Response["store"].(map[string]any)["generation_current"] = observationGenerationCurrent(fixture, view)
			if got := observationAdmission(test, fixture, true); got != "currentness" {
				test.Fatalf("native currentness: %s want currentness", got)
			}
		})
	}
}

func observationLoad(input observationTransport) string {
	if input.InFlight != 1 {
		return "concurrency"
	}
	if input.NativeWaitMS <= 0 || input.LockHoldMS < 0 || input.LockHoldMS >= 25 || input.LockHoldMS >= input.NativeWaitMS {
		return "lock_hold"
	}
	if input.CooldownMS < 250 {
		return "lock_rate"
	}
	return "valid"
}

// Claim: load limits check both sides of every limit beside a valid control; excess work closes before the native lock and does not queue.
func TestLabObservationLoadPairs(test *testing.T) {
	for _, name := range []string{"in-flight", "hold", "native-wait", "cooldown"} {
		values := map[string][]int64{"in-flight": {-1, 0, 1, 2}, "hold": {-1, 0, 1, 23, 24, 25, 26}, "native-wait": {-1, 0, 1, 23, 24, 25, 26}, "cooldown": {-1, 0, 1, 248, 249, 250, 251}}[name]
		for _, value := range values {
			test.Run(fmt.Sprintf("%s-%d", name, value), func(test *testing.T) {
				input := validObservationTransport()
				if name == "hold" {
					input.NativeWaitMS = 100
				}
				if got := observationTransportAdmission(input); got != "valid" {
					test.Fatal("valid load control:", got)
				}
				want := "valid"
				switch name {
				case "in-flight":
					input.InFlight = value
					if value != 1 {
						want = "concurrency"
					}
				case "hold":
					input.LockHoldMS = value
					if value < 0 || value >= 25 {
						want = "lock_hold"
					}
				case "native-wait":
					input.NativeWaitMS = value
					if value <= 24 {
						want = "lock_hold"
					}
				case "cooldown":
					input.CooldownMS = value
					if value < 250 {
						want = "lock_rate"
					}
				}
				if got := observationTransportAdmission(input); got != want {
					test.Fatalf("load verdict: %s want %s", got, want)
				}
			})
		}
	}
}

func reserveSnapshotSequence(test *testing.T, before, after map[string]any, counterGeneration string, current int64, durable, installed bool) (int64, string) {
	test.Helper()
	if counterGeneration != before["generation"] {
		return current, "generation"
	}
	if !reflect.DeepEqual(before, after) {
		return current, "snapshot"
	}
	return reserveObservationSequence(current, durable, installed)
}

// Claim: sequence scope and counter scope independently equal the installation; reservation cannot change any native store-proof member, even when the counter increases durably.
func TestLabObservationSnapshotSequencePairs(test *testing.T) {
	for _, sides := range [][]string{{"response"}, {"store"}, {"response", "store"}} {
		test.Run("scope-"+strings.Join(sides, "-"), func(test *testing.T) {
			fixture := observationControl(test)
			if got := observationAdmission(test, fixture, true); got != "valid" {
				test.Fatal("valid sequence scope:", got)
			}
			for _, side := range sides {
				if side == "response" {
					fixture.Response["sequence_generation"] = strings.Repeat("d", 32)
				} else {
					fixture.Response["store"].(map[string]any)["generation"] = strings.Repeat("d", 32)
				}
			}
			want := "sequence_generation"
			if len(sides) > 1 || sides[0] == "store" {
				want = "store_generation"
			}
			if got := observationAdmission(test, fixture, true); got != want {
				test.Fatalf("sequence scope: %s want %s", got, want)
			}
		})
	}
	fixture := observationControl(test)
	before := fixture.Response["store"].(map[string]any)
	for _, field := range append([]string{"counter-generation"}, sortedObservationFields(before)...) {
		test.Run("reservation-"+field, func(test *testing.T) {
			if next, got := reserveSnapshotSequence(test, before, before, before["generation"].(string), 7, true, true); next != 8 || got != "reserved" {
				test.Fatal("valid unchanged snapshot:", got)
			}
			after := normalizedBounded(test, cloneObject(test, before))
			generation := before["generation"].(string)
			want := "snapshot"
			if field == "counter-generation" {
				generation = strings.Repeat("d", 32)
				want = "generation"
			} else {
				switch value := after[field].(type) {
				case int64:
					after[field] = value + 1
				case bool:
					after[field] = !value
				case string:
					if field == "generation" {
						after[field] = strings.Repeat("d", 32)
					} else {
						after[field] = "sha256:" + strings.Repeat("0", 64)
					}
				case map[string]any:
					value["sequence"] = value["sequence"].(int64) + 1
				}
			}
			next, got := reserveSnapshotSequence(test, before, after, generation, 7, true, true)
			if got != want || next != 7 {
				test.Fatalf("snapshot reservation: %d/%s want 7/%s", next, got, want)
			}
		})
	}
}

func sortedObservationFields(record map[string]any) []string {
	fields := []string{}
	for field := range record {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

type boundedAuthority struct {
	Now, Approved, ReleaseApproved, ApprovalExpiry, ReleaseExpiry, QualificationExpiry int64
	OwnerVerified, ClockVerified, AccessCurrent, Revoked                               bool
}

func validBoundedAuthority() boundedAuthority {
	return boundedAuthority{10, 1, 1, 20, 20, 20, true, true, true, false}
}

func boundedReauthorize(state *boundedLedger, authority boundedAuthority) string {
	if !authority.OwnerVerified || !authority.ClockVerified || !authority.AccessCurrent || authority.Now < authority.Approved || authority.Now < authority.ReleaseApproved {
		state.Unknown, state.Stopped, state.Active = true, true, false
		return "unknown"
	}
	if authority.Revoked || authority.Now >= authority.ApprovalExpiry || authority.Now >= authority.ReleaseExpiry || authority.Now >= authority.QualificationExpiry {
		state.Stopped, state.Active = true, false
		return "stopped_authority"
	}
	return "current"
}

// Claim: every ordinal and active observation independently checks both approval windows, qualification, revocation and current access; stopped/unknown authority retains cost/count and cannot reopen.
func TestLabBoundedAuthorityPairs(test *testing.T) {
	for _, stage := range []string{"next-attempt", "in-flight"} {
		for _, name := range []string{"approval-expiry", "release-expiry", "qualification-expiry", "approved", "release-approved", "revoked", "owner", "clock", "access"} {
			values := []int64{0, 1}
			if strings.Contains(name, "expiry") || strings.Contains(name, "approved") {
				values = []int64{9, 10, 11}
			}
			for _, value := range values {
				test.Run(fmt.Sprintf("%s/%s-%d", stage, name, value), func(test *testing.T) {
					authority := validBoundedAuthority()
					limit := boundedLimits{3, 128000, 100000, 5000, 10000}
					seed := boundedLedger{Attempts: 1, Cost: 2, PlanDigest: "fixture-plan", Operation: "fixture-group"}
					if stage == "in-flight" {
						seed.Active = true
						seed.Reserved = 10
					}
					check := func(state *boundedLedger, input boundedAuthority) string {
						if stage == "in-flight" {
							return boundedObserve(state, input, limit, 0, 2, 0, 0, true)
						}
						return boundedStart(state, input, limit, seed.PlanDigest, seed.Operation, 10, 0, true)
					}
					control := seed
					wantControl := "started"
					if stage == "in-flight" {
						wantControl = "running"
					}
					if got := check(&control, authority); got != wantControl {
						test.Fatal("valid authority control:", got)
					}
					want := wantControl
					switch name {
					case "approval-expiry":
						authority.ApprovalExpiry = value
						if value <= 10 {
							want = "stopped_authority"
						}
					case "release-expiry":
						authority.ReleaseExpiry = value
						if value <= 10 {
							want = "stopped_authority"
						}
					case "qualification-expiry":
						authority.QualificationExpiry = value
						if value <= 10 {
							want = "stopped_authority"
						}
					case "approved":
						authority.Approved = value
						if value > 10 {
							want = "unknown"
						}
					case "release-approved":
						authority.ReleaseApproved = value
						if value > 10 {
							want = "unknown"
						}
					case "revoked":
						authority.Revoked = value == 1
						if value == 1 {
							want = "stopped_authority"
						}
					case "owner":
						authority.OwnerVerified = value == 1
						if value == 0 {
							want = "unknown"
						}
					case "clock":
						authority.ClockVerified = value == 1
						if value == 0 {
							want = "unknown"
						}
					case "access":
						authority.AccessCurrent = value == 1
						if value == 0 {
							want = "unknown"
						}
					}
					state := seed
					got := check(&state, authority)
					if got != want {
						test.Fatalf("authority verdict: %s want %s", got, want)
					}
					if want == "unknown" || want == "stopped_authority" {
						if !state.Stopped || state.Active || state.Attempts != seed.Attempts || state.Cost != seed.Cost || state.Reserved != seed.Reserved {
							test.Fatal("authority refusal changed debit/ordinal or left active")
						}
						if again := boundedStart(&state, validBoundedAuthority(), limit, seed.PlanDigest, seed.Operation, 10, 0, true); again != "exhausted" && again != "unknown" {
							test.Fatal("authority reopened stopped group:", again)
						}
					}
				})
			}
		}
	}
}

func boundedReleaseAdmission(test *testing.T, candidate boundedCase) string {
	test.Helper()
	set, _ := loadContracts(test)
	release := normalizedBounded(test, candidate.Release)
	if checkRecord(canonicalObject(test, release), boundedShape(set, "swarma-lab-release-set/1"), set) != nil {
		return "release_shape"
	}
	if release["invocation_sha256"] != boundedTarget(test, candidate.Plan) {
		return "release_target"
	}
	if !reflect.DeepEqual(release["context"], normalizedBounded(test, candidate.Plan)["context"]) {
		return "release_context"
	}
	if !approvalTargetValid(release) {
		return "release_seal"
	}
	if candidate.ExpectedRelease != boundedDigest(test, release) {
		return "release_expected"
	}
	if candidate.Approval["release_set_sha256"] != boundedDigest(test, release) {
		return "release_digest"
	}
	approval := release["owner_approval"].(map[string]any)
	now, err := time.Parse(time.RFC3339Nano, candidate.Now)
	approved, _ := time.Parse(time.RFC3339Nano, approval["approved_at"].(string))
	expires, _ := time.Parse(time.RFC3339Nano, approval["expires_at"].(string))
	if err != nil || now.Before(approved) || !now.Before(expires) {
		return "release_freshness"
	}
	return "admitted"
}

// Claim: section 6's sealed release binds the same target and context as A/P, A hashes all release bytes, and release approval must remain fresh; subjects are re-sealed except the explicit seal-negative.
func TestLabBoundedReleasePairs(test *testing.T) {
	for _, name := range []string{"target", "context", "seal", "digest", "expected", "before-approved", "at-approved", "before-expiry", "at-expiry", "after-expiry"} {
		test.Run(name, func(test *testing.T) {
			candidate := boundedClone(test, boundedCases(test)[0])
			if got := boundedReleaseAdmission(test, candidate); got != "admitted" {
				test.Fatal("valid release control:", got)
			}
			want := "admitted"
			switch name {
			case "target":
				candidate.Release["invocation_sha256"] = "sha256:" + strings.Repeat("0", 64)
				want = "release_target"
			case "context":
				candidate.Release["context"].(map[string]any)["account"] = "PUBLIC-OTHER"
				want = "release_context"
			case "seal":
				candidate.Release["owner_approval"].(map[string]any)["approved_sha256"] = "sha256:" + strings.Repeat("0", 64)
				want = "release_seal"
			case "expected":
				candidate.ExpectedRelease = "sha256:" + strings.Repeat("0", 64)
				want = "release_expected"
			case "digest":
				candidate.Approval["release_set_sha256"] = "sha256:" + strings.Repeat("0", 64)
				want = "release_digest"
			default:
				times := map[string]string{"before-approved": "2026-11-20T07:59:59.999999999Z", "at-approved": "2026-11-20T08:00:00Z", "before-expiry": "2026-11-20T08:09:59.999999999Z", "at-expiry": "2026-11-20T08:10:00Z", "after-expiry": "2026-11-20T08:10:00.000000001Z"}
				candidate.Now = times[name]
				if name == "before-approved" || name == "at-expiry" || name == "after-expiry" {
					want = "release_freshness"
				}
			}
			if name != "seal" {
				resealClosure(test, candidate.Release)
			}
			if name != "expected" {
				candidate.ExpectedRelease = boundedDigest(test, candidate.Release)
			}
			if name != "digest" {
				candidate.Approval["release_set_sha256"] = boundedDigest(test, candidate.Release)
			}
			if got := boundedReleaseAdmission(test, candidate); got != want {
				test.Fatalf("release verdict: %s want %s", got, want)
			}
		})
	}
}

// Claim: the full admission path cannot omit the section 6 release join even when all updated approval, plan and launch hashes agree.
func TestLabBoundedReleaseIntegrationPair(test *testing.T) {
	control := boundedCases(test)[0]
	if got := boundedAdmission(test, control, control); got != "admitted" {
		test.Fatal("valid release integration:", got)
	}
	candidate := boundedClone(test, control)
	candidate.Release["invocation_sha256"] = "sha256:" + strings.Repeat("0", 64)
	resealClosure(test, candidate.Release)
	candidate.ExpectedRelease = boundedDigest(test, candidate.Release)
	candidate.Approval["release_set_sha256"] = candidate.ExpectedRelease
	resealClosure(test, candidate.Approval)
	candidate.Plan["approval_record_sha256"] = boundedDigest(test, candidate.Approval)
	candidate.ExpectedPlan = boundedDigest(test, candidate.Plan)
	candidate.Launch["pins"].(map[string]any)["release_set_sha256"] = candidate.ExpectedRelease
	candidate.Launch["pins"].(map[string]any)["off_vm_approval_sha256"] = candidate.Plan["approval_record_sha256"]
	for _, raw := range candidate.Launch["input_pins"].([]any) {
		pin := raw.(map[string]any)
		if pin["name"] == "bounded-invocation" {
			pin["sha256"] = candidate.ExpectedPlan
		}
	}
	if got := boundedAdmission(test, candidate, control); got != "release_target" {
		test.Fatalf("release integration: %s want release_target", got)
	}
}
