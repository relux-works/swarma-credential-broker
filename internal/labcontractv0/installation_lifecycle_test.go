package labcontractv0

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func installationPublication(test *testing.T, fixture installationFixtureCase, now string, authenticated, revoked, readback bool) string {
	if !authenticated || revoked {
		return "installation_authority"
	}
	if !readback {
		return "installation_readback"
	}
	if !installationTargetApproved(test, fixture.Binding) || !approvalTargetValid(fixture.Release) {
		return "installation_seal"
	}
	current, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		return "installation_window"
	}
	for _, raw := range []any{fixture.Binding["installation_approval"], fixture.Release["owner_approval"]} {
		approval := raw.(map[string]any)
		approved, errApproved := time.Parse(time.RFC3339Nano, approval["approved_at"].(string))
		expires, errExpires := time.Parse(time.RFC3339Nano, approval["expires_at"].(string))
		if errApproved != nil || errExpires != nil || current.Before(approved) || !current.Before(expires) {
			return "installation_window"
		}
	}
	return "apply"
}

func installationNewStart(test *testing.T, fixture *installationFixtureCase) {
	fixture.Bounded.Plan["operation_id"] = strings.Repeat("e", 32)
	fixture.Bounded.Launch["operation_id"] = fixture.Bounded.Plan["operation_id"]
	fixture.Bounded.Now = "2026-11-20T08:11:01Z"
	for _, approval := range []map[string]any{fixture.Bounded.Approval["approval"].(map[string]any), fixture.Bounded.Release["owner_approval"].(map[string]any)} {
		approval["approved_at"] = "2026-11-20T08:11:00Z"
		approval["expires_at"] = "2026-11-20T08:21:00Z"
	}
	fixture.Bounded.Approval["off_vm_now"] = "2026-11-20T08:11:00Z"
	fixture.Bounded.Approval["start_generation"] = int64(2)
	fixture.Bounded.Approval["heads"].(map[string]any)["manager"].(map[string]any)["sequence"] = int64(1)
	fixture.Bounded.Launch["predecessor_heads"] = cloneObject(test, fixture.Bounded.Approval["heads"].(map[string]any))
	boundedRebind(test, &fixture.Bounded)
	fixture.Bounded.Approval["release_set_sha256"] = boundedDigest(test, fixture.Bounded.Release)
	boundedRebind(test, &fixture.Bounded)
	fixture.Observation.Response["start"].(map[string]any)["plan_sha256"] = boundedDigest(test, fixture.Bounded.Launch)
	fixture.Observation.Expected["start"].(map[string]any)["plan_sha256"] = boundedDigest(test, fixture.Bounded.Launch)
}

// Claim: historical install approval permits a separately approved second start without rewriting I; stale or foreign per-start authority and installation revocation still refuse.
func TestLabInstallationApprovalLifecyclePairs(test *testing.T) {
	for _, name := range []string{"second-start-valid", "expired-start", "revoked-start", "foreign-start", "revoked-installation", "unknown-installation-owner", "unprotected-release", "invalid-installation-release-seal"} {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			bindingBefore, releaseBefore := boundedDigest(test, fixture.Binding), boundedDigest(test, fixture.Release)
			proof := installationControlProof(fixture)
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "admitted" {
				test.Fatalf("first start control: %s", got)
			}
			installationNewStart(test, &fixture)
			if boundedDigest(test, fixture.Binding) != bindingBefore || boundedDigest(test, fixture.Release) != releaseBefore || boundedDigest(test, fixture.Bounded.Release) == releaseBefore {
				test.Fatal("installation changed for next start")
			}
			if got := boundedAdmission(test, fixture.Bounded, fixture.Bounded); got != "admitted" {
				test.Fatalf("second start C0b control: %s", got)
			}
			latch := installationLatchFor(test, fixture)
			if got := installationRead(test, fixture, proof, &latch); got != "admitted" {
				test.Fatalf("second start valid control: %s", got)
			}
			want := "approval"
			switch name {
			case "second-start-valid":
				return
			case "expired-start":
				fixture.Bounded.Now = "2026-11-20T08:21:00Z"
			case "revoked-start":
				fixture.Bounded.Revoked = true
			case "foreign-start":
				fixture.Bounded.Plan["approval_record_sha256"] = "sha256:" + strings.Repeat("d", 64)
			case "revoked-installation":
				proof.InstallationRevoked = true
				want = "installation_authority"
			case "unknown-installation-owner":
				proof.InstallationOwnerVerified = false
				want = "installation_authority"
			case "invalid-installation-release-seal":
				fixture.Release["owner_approval"].(map[string]any)["approved_sha256"] = "sha256:" + strings.Repeat("d", 64)
				installationApprove(test, &fixture)
				latch = installationLatchFor(test, fixture)
				want = "installation_authority"
			case "unprotected-release":
				proof.ReleaseProtected = false
				want = "installation_authority"
			}
			if got := installationRead(test, fixture, proof, &latch); got != want || !latch.Closed {
				test.Fatalf("lifecycle refusal: %s want %s", got, want)
			}
		})
	}
}

// Claim: B5 consumes both installation approvals only inside their windows and after native readback; runtime values and epoch changes never rewrite tagged archive provenance.
func TestLabInstallationRuntimePublicationPairs(test *testing.T) {
	for _, name := range []string{"valid", "before", "at-expiry", "unknown-time", "owner", "revoked", "readback", "target-seal", "release-seal", "install-only-before", "install-only-expiry", "release-only-before", "release-only-expiry"} {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			if got := installationPublication(test, fixture, fixture.Bounded.Now, true, false, true); got != "apply" {
				test.Fatalf("publication control: %s", got)
			}
			now, owner, revoked, readback := fixture.Bounded.Now, true, false, true
			want := "installation_window"
			switch name {
			case "valid":
				return
			case "before":
				now = "2026-11-20T07:59:59Z"
			case "at-expiry":
				now = "2026-11-20T08:10:00Z"
			case "unknown-time":
				now = "not-time"
			case "owner":
				owner = false
				want = "installation_authority"
			case "revoked":
				revoked = true
				want = "installation_authority"
			case "readback":
				readback = false
				want = "installation_readback"
			case "target-seal":
				fixture.Binding["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
				want = "installation_seal"
			case "release-seal":
				fixture.Release["invocation_sha256"] = "sha256:" + strings.Repeat("d", 64)
				want = "installation_seal"
			case "install-only-before", "install-only-expiry", "release-only-before", "release-only-expiry":
				selected := fixture.Binding["installation_approval"].(map[string]any)
				if strings.HasPrefix(name, "release-") {
					selected = fixture.Release["owner_approval"].(map[string]any)
				}
				if strings.HasSuffix(name, "before") {
					selected["approved_at"] = "2026-11-20T08:00:02Z"
				} else {
					selected["expires_at"] = fixture.Bounded.Now
				}
				installationApprove(test, &fixture)
			}
			if got := installationPublication(test, fixture, now, owner, revoked, readback); got != want {
				test.Fatalf("publication refusal: %s want %s", got, want)
			}
		})
	}
	fixture := installationFixture(test)
	before := boundedDigest(test, fixture.Release)
	oldTarget := boundedDigest(test, installationTarget(test, fixture.Binding))
	fixture.Binding["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
	fixture.Binding["manager"].(map[string]any)["boot_id"] = "22222222-3333-4444-8555-666666666666"
	fixture.Binding["install_epoch"] = int64(2)
	installationApprove(test, &fixture)
	if boundedDigest(test, fixture.Release) != before || boundedDigest(test, installationTarget(test, fixture.Binding)) == oldTarget {
		test.Fatal("runtime target rewrote reproducible release")
	}
	if got := installationPublication(test, fixture, fixture.Bounded.Now, true, false, true); got != "apply" {
		test.Fatalf("runtime target control: %s", got)
	}
}

// Claim: current starts may vary invocation approval but never the installed release inventory/index; both comparisons use R0, with valid current-start seals.
func TestLabInstallationReleaseIdentityPairs(test *testing.T) {
	for _, name := range []string{"assets", "contract_index_sha256", "context", "current-context"} {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			proof := installationControlProof(fixture)
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "admitted" {
				test.Fatalf("release identity control: %s", got)
			}
			want := "release_inventory"
			switch name {
			case "assets":
				fixture.Release[name].([]any)[0].(map[string]any)["tag"] = "other-approved-tag"
			case "contract_index_sha256":
				fixture.Release[name] = "sha256:" + strings.Repeat("d", 64)
			case "context":
				fixture.Release[name].(map[string]any)["account"] = "other-account"
				want = "context"
			case "current-context":
				fixture.Bounded.Plan["context"].(map[string]any)["account"] = "other-account"
				fixture.Bounded.Approval["context"] = cloneObject(test, fixture.Bounded.Plan["context"].(map[string]any))
				fixture.Bounded.Launch["context"] = cloneObject(test, fixture.Bounded.Plan["context"].(map[string]any))
				want = "context"
			}
			resealClosure(test, fixture.Release)
			installationApprove(test, &fixture)
			if name == "current-context" {
				fixture.Bounded.Approval["release_set_sha256"] = boundedDigest(test, fixture.Bounded.Release)
				boundedRebind(test, &fixture.Bounded)
			}
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != want {
				test.Fatalf("release identity refusal: %s want %s", got, want)
			}
		})
	}
}

type installationAdoptionProof struct {
	Reader                                                             string
	NewGroup, Quiescent, FreshStart, FreshPair, FreshBaseline, Durable bool
}

func installationAdopt(test *testing.T, fixture installationFixtureCase, proof installationProof, transition installationAdoptionProof, latch *installationLatch) string {
	if !transition.NewGroup || !transition.Quiescent || (transition.Reader == "B1" && (!transition.FreshStart || !transition.FreshPair)) {
		return "adoption_gate"
	}
	next := installationLatchFor(test, fixture)
	if latch.Epoch == 0 {
		if !transition.FreshBaseline || next.Epoch != 1 || latch.Digest != "" || latch.Instance != "" {
			return "adoption_fresh"
		}
	} else if next.Epoch == latch.Epoch {
		if next.Digest != latch.Digest || next.Instance != latch.Instance {
			return "adoption_same"
		}
	} else {
		if latch.Epoch >= 9007199254740991 || next.Epoch != latch.Epoch+1 {
			return "adoption_epoch"
		}
		if next.Instance == latch.Instance {
			return "adoption_instance"
		}
	}
	if transition.Reader != "B1" && transition.Reader != "M1" {
		return "adoption_reader"
	}
	if transition.Reader == "M1" {
		if got := installationBindingResult(test, fixture, proof, next); got != "admitted" {
			return got
		}
		if !proof.NativeValidated {
			return "native"
		}
	} else if got := installationReadResult(test, fixture, proof, next); got != "admitted" {
		return got
	}
	if !transition.Durable {
		return "adoption_durable"
	}
	*latch = next
	return "adopted"
}

// Claim: each reader privately adopts fresh/identical/exactly-next epochs durably and quiescently; M1 uses setup readback without a start or pair, B1 needs a fresh approved native start/pair, and old groups stay closed.
func TestLabInstallationEpochAdoptionPairs(test *testing.T) {
	for _, reader := range []string{"B1", "M1"} {
		for _, name := range []string{"rotation-valid", "fresh-valid", "restart-valid", "not-new-group", "in-flight", "no-start", "no-pair", "not-durable", "lost-latch", "fresh-not-one", "fresh-dirty", "lower", "skip", "same-epoch-different", "reused-instance", "overflow", "unapproved", "foreign-native", "installation-only", "unknown-reader"} {
			test.Run(reader+"/"+name, func(test *testing.T) {
				fixture := installationFixture(test)
				old := installationLatchFor(test, fixture)
				fixture.Binding["install_epoch"] = int64(2)
				fixture.Binding["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
				fixture.Observation.Response["manager"] = normalizedBounded(test, cloneObject(test, fixture.Binding["manager"].(map[string]any)))
				installationApprove(test, &fixture)
				installationNewStart(test, &fixture)
				proof := installationControlProof(fixture)
				transition := installationAdoptionProof{Reader: reader, NewGroup: true, Quiescent: true, FreshStart: true, FreshPair: true, Durable: true}
				control := old
				if got := installationAdopt(test, fixture, proof, transition, &control); got != "adopted" || control != installationLatchFor(test, fixture) {
					test.Fatalf("adoption valid control: %s", got)
				}
				latch := old
				want := "adoption_gate"
				switch name {
				case "rotation-valid":
					return
				case "fresh-valid":
					latch = installationLatch{}
					transition.FreshBaseline = true
					fixture.Binding["install_epoch"] = int64(1)
					want = "adopted"
				case "restart-valid":
					latch = installationLatchFor(test, fixture)
					want = "adopted"
				case "not-new-group":
					transition.NewGroup = false
				case "in-flight":
					transition.Quiescent = false
				case "no-start":
					transition.FreshStart = false
					if reader == "M1" {
						want = "adopted"
					}
				case "no-pair":
					transition.FreshPair = false
					if reader == "M1" {
						want = "adopted"
					}
				case "not-durable":
					transition.Durable = false
					want = "adoption_durable"
				case "lost-latch":
					latch = installationLatch{}
					fixture.Binding["install_epoch"] = int64(1)
					want = "adoption_fresh"
				case "fresh-not-one":
					latch = installationLatch{}
					transition.FreshBaseline = true
					want = "adoption_fresh"
				case "fresh-dirty":
					latch = installationLatch{Digest: old.Digest}
					transition.FreshBaseline = true
					fixture.Binding["install_epoch"] = int64(1)
					want = "adoption_fresh"
				case "lower":
					latch.Epoch = 3
					want = "adoption_epoch"
				case "skip":
					fixture.Binding["install_epoch"] = int64(3)
					want = "adoption_epoch"
				case "same-epoch-different":
					fixture.Binding["install_epoch"] = int64(1)
					fixture.Binding["manager"].(map[string]any)["instance_id"] = old.Instance
					fixture.Observation.Response["manager"].(map[string]any)["instance_id"] = old.Instance
					fixture.Binding["installation_approval"].(map[string]any)["record_id"] = "other-installation-approval"
					want = "adoption_same"
				case "reused-instance":
					fixture.Binding["manager"].(map[string]any)["instance_id"] = old.Instance
					want = "adoption_instance"
				case "overflow":
					latch.Epoch = 9007199254740991
					want = "adoption_epoch"
				case "unapproved":
					proof.InstallationOwnerVerified = false
					want = "installation_authority"
				case "foreign-native":
					proof.NativeValidated = false
					want = "native"
				case "unknown-reader":
					transition.Reader = "G1"
					want = "adoption_reader"
				case "installation-only":
					transition.FreshPair, transition.FreshStart = false, false
					if reader == "M1" {
						want = "adopted"
					}

				}
				installationApprove(test, &fixture)
				if name == "installation-only" {
					fixture.Bounded.Plan = nil
					fixture.Observation.Response = nil
				}
				before := latch
				got := installationAdopt(test, fixture, proof, transition, &latch)
				if got != want {
					test.Fatalf("adoption refusal: %s want %s", got, want)
				}
				if want == "adopted" {
					if latch != installationLatchFor(test, fixture) {
						test.Fatal("adoption not persisted")
					}
				} else if latch != before {
					test.Fatal("refused adoption changed private state")
				}
			})
		}
	}
	fixture := installationFixture(test)
	closedGroup := installationLatchFor(test, fixture)
	fixture.Binding["install_epoch"] = int64(2)
	fixture.Binding["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
	fixture.Observation.Response["manager"] = normalizedBounded(test, cloneObject(test, fixture.Binding["manager"].(map[string]any)))
	installationApprove(test, &fixture)
	if got := installationRead(test, fixture, installationControlProof(fixture), &closedGroup); got != "epoch_changed" || !closedGroup.Closed {
		test.Fatalf("in-flight closure: %s", got)
	}
	private := closedGroup
	transition := installationAdoptionProof{Reader: "B1", NewGroup: true, Quiescent: true, FreshStart: true, FreshPair: true, Durable: true}
	if got := installationAdopt(test, fixture, installationControlProof(fixture), transition, &private); got != "adopted" {
		test.Fatalf("closed old group new admission: %s", got)
	}
	if got := installationRead(test, fixture, installationControlProof(fixture), &closedGroup); got != "closed" {
		test.Fatalf("old group reopened: %s", got)
	}
}

// Claim: each coherent observed/expected manager field and store generation is compared to approved I, never to a stale secondary Expected or the response's own sequence generation.
func TestLabInstallationExpectedJoinPairs(test *testing.T) {
	for _, field := range []string{"identity", "executable_sha256", "instance_id", "boot_id", "store_generation"} {
		test.Run(field, func(test *testing.T) {
			fixture := installationFixture(test)
			if got := observationAdmission(test, fixture.Observation, true); got != "valid" {
				test.Fatalf("coherent native control: %s", got)
			}
			if field == "store_generation" {
				fixture.Binding[field] = strings.Repeat("d", 32)
			} else {
				manager := fixture.Binding["manager"].(map[string]any)
				switch field {
				case "identity":
					manager[field] = "other-manager"
				case "executable_sha256":
					manager[field] = "sha256:" + strings.Repeat("d", 64)
					for _, release := range []map[string]any{fixture.Release, fixture.Bounded.Release} {
						asset := release["assets"].([]any)[1].(map[string]any)
						asset["members"] = append(asset["members"].([]any), map[string]any{"path": "libexec/other-manager", "mode": "0755", "sha256": manager[field]})
						resealClosure(test, release)
					}
					fixture.Bounded.Approval["release_set_sha256"] = boundedDigest(test, fixture.Bounded.Release)
				case "instance_id":
					manager[field] = strings.Repeat("d", 32)
				case "boot_id":
					manager[field] = "22222222-3333-4444-8555-666666666666"
				}
			}
			installationApprove(test, &fixture)
			proof := installationControlProof(fixture)
			want := "manager"
			if field == "store_generation" {
				want = "store_generation"
			}
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != want {
				test.Fatalf("independent expected refusal: %s want %s", got, want)
			}
			if field == "store_generation" {
				fixture.Observation.Response["store"].(map[string]any)["generation"] = fixture.Binding[field]
				fixture.Observation.Response["sequence_generation"] = fixture.Binding[field]
			} else {
				fixture.Observation.Response["manager"] = normalizedBounded(test, cloneObject(test, fixture.Binding["manager"].(map[string]any)))
			}
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "admitted" {
				test.Fatalf("independent expected valid control: %s", got)
			}
			if reflect.DeepEqual(fixture.Observation.Expected["manager"], fixture.Binding["manager"]) && field != "store_generation" {
				test.Fatal("secondary expected no longer stale")
			}
		})
	}
	fixture := installationFixture(test)
	fixture.Observation.Response["store"].(map[string]any)["generation"] = strings.Repeat("d", 32)
	fixture.Observation.Response["sequence_generation"] = strings.Repeat("d", 32)
	if got := installationReadResult(test, fixture, installationControlProof(fixture), installationLatchFor(test, fixture)); got != "store_generation" {
		test.Fatalf("coherent foreign store refusal: %s", got)
	}
}

// Claim: changed approved daemon UID/GID/image/socket pins are authoritative over stale actual facts and any secondary expected UID, beside the exact installed control.
func TestLabInstallationExpectedDaemonPairs(test *testing.T) {
	for _, field := range []string{"daemon_uid", "daemon_gid", "daemon_executable_sha256", "daemon_socket_path", "observation_socket_path"} {
		test.Run(field, func(test *testing.T) {
			fixture := installationFixture(test)
			oldProof := installationControlProof(fixture)
			switch field {
			case "daemon_uid", "daemon_gid":
				fixture.Binding[field] = fixture.Binding[field].(int64) + 1
			case "daemon_executable_sha256":
				fixture.Binding[field] = "sha256:" + strings.Repeat("d", 64)
				for _, release := range []map[string]any{fixture.Release, fixture.Bounded.Release} {
					asset := release["assets"].([]any)[0].(map[string]any)
					asset["members"] = append(asset["members"].([]any), map[string]any{"path": "bin/other-daemon", "mode": "0755", "sha256": fixture.Binding[field]})
					resealClosure(test, release)
				}
				fixture.Bounded.Approval["release_set_sha256"] = boundedDigest(test, fixture.Bounded.Release)
			default:
				fixture.Binding[field] = fixture.Binding[field].(string) + ".old"
			}
			installationApprove(test, &fixture)
			proof := installationControlProof(fixture)
			if strings.Contains(field, "socket") {
				baseline := installationFixture(test)
				if got := installationReadResult(test, baseline, installationControlProof(baseline), installationLatchFor(test, baseline)); got != "admitted" {
					test.Fatalf("socket literal control: %s", got)
				}
				if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "shape" {
					test.Fatalf("socket literal refusal: %s", got)
				}
				return
			}
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "admitted" {
				test.Fatalf("independent daemon valid control: %s", got)
			}
			switch field {
			case "daemon_uid":
				proof.DaemonUID = oldProof.DaemonUID
			case "daemon_gid":
				proof.DaemonGID = oldProof.DaemonGID
			case "daemon_executable_sha256":
				proof.DaemonExecutable = oldProof.DaemonExecutable
			}
			if got := installationReadResult(test, fixture, proof, installationLatchFor(test, fixture)); got != "daemon" {
				test.Fatalf("independent daemon refusal: %s", got)
			}
		})
	}
}

// Claim: a pre-binding setup plan can be shape-valid without I but is never a valid final C0f install; the finalized complete pin is the valid control.
func TestLabInstallationSetupPlanPairs(test *testing.T) {
	fixture := installationFixture(test)
	if got := installationInstallPlan(test, fixture, fixture.Install); got != "admitted" {
		test.Fatalf("final install plan control: %s", got)
	}
	pins := fixture.Install["input_pins"].([]any)
	fixture.Install["input_pins"] = pins[:len(pins)-1]
	set, _ := loadContracts(test)
	if checkRecord(canonicalObject(test, fixture.Install), boundedShape(set, "swarma-broker-lab-install-plan/1"), set) != nil {
		test.Fatal("pre-binding setup shape control")
	}
	if got := installationInstallPlan(test, fixture, fixture.Install); got != "binding_pin" {
		test.Fatalf("preliminary plan refused by final checker: %s", got)
	}
}
