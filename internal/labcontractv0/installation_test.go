package labcontractv0

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const installationFormat = "swarma-broker-lab-installation-binding/1"

type installationFixtureCase struct {
	Release     map[string]any     `json:"installation_release_set"`
	Binding     map[string]any     `json:"binding"`
	Bounded     boundedCase        `json:"bounded"`
	Install     map[string]any     `json:"install_plan"`
	Observation observationFixture `json:"observation"`
	Target      map[string]any     `json:"target"`
	Synthetic   bool               `json:"synthetic_only"`
	Live        bool               `json:"live_authority"`
	Cases       []struct {
		Name     string `json:"name"`
		Expected string `json:"expected"`
	} `json:"cases"`
}

func installationFixture(test *testing.T) installationFixtureCase {
	test.Helper()
	var fixture installationFixtureCase
	decodeContract(test, "installation-binding-fixtures.json", &fixture)
	if !fixture.Synthetic || fixture.Live || len(fixture.Cases) != 6 {
		test.Fatal("installation fixture inventory")
	}
	fixture.Binding = normalizedBounded(test, fixture.Binding)
	fixture.Release = normalizedBounded(test, fixture.Release)
	fixture.Install = normalizedBounded(test, fixture.Install)
	fixture.Bounded.Plan = normalizedBounded(test, fixture.Bounded.Plan)
	fixture.Bounded.Release = normalizedBounded(test, fixture.Bounded.Release)
	fixture.Bounded.Approval = normalizedBounded(test, fixture.Bounded.Approval)
	fixture.Bounded.Launch = normalizedBounded(test, fixture.Bounded.Launch)
	fixture.Observation.Request = normalizedBounded(test, fixture.Observation.Request)
	fixture.Observation.Response = normalizedBounded(test, fixture.Observation.Response)
	fixture.Observation.Expected = normalizedBounded(test, fixture.Observation.Expected)
	return fixture
}

func installationTarget(test *testing.T, binding map[string]any) map[string]any {
	record := cloneObject(test, binding)
	delete(record, "approval_record_sha256")
	delete(record, "installation_approval")
	return map[string]any{"domain": "swarma-broker-lab-installation-binding-target/1", "record": record}
}

func installationTargetApproved(test *testing.T, binding map[string]any) bool {
	approval := binding["installation_approval"].(map[string]any)
	return approval["approved_sha256"] == boundedDigest(test, installationTarget(test, binding))
}

func installationExecutable(release map[string]any, product string, expected any) bool {
	for _, raw := range release["assets"].([]any) {
		asset := raw.(map[string]any)
		for _, rawMember := range asset["members"].([]any) {
			member := rawMember.(map[string]any)
			if asset["product"] == product && member["mode"] == "0755" && member["sha256"] == expected {
				return true
			}
		}
	}
	return false
}

func installationInputPin(plan map[string]any, digest string) bool {
	seen := map[string]bool{}
	matches := 0
	for _, raw := range plan["input_pins"].([]any) {
		pin := raw.(map[string]any)
		name := pin["name"].(string)
		if seen[name] {
			return false
		}
		seen[name] = true
		if name == "installation-binding" {
			if pin["sha256"] != digest {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func installationInstallPlan(test *testing.T, fixture installationFixtureCase, plan map[string]any) string {
	binding := fixture.Binding
	set, _ := loadContracts(test)
	if checkRecord(canonicalObject(test, plan), boundedShape(set, "swarma-broker-lab-install-plan/1"), set) != nil {
		return "shape"
	}
	if !installationInputPin(plan, boundedDigest(test, binding)) {
		return "binding_pin"
	}
	if !reflect.DeepEqual(plan["context"], binding["context"]) || plan["pins"].(map[string]any)["off_vm_approval_sha256"] != boundedDigest(test, fixture.Bounded.Approval) || plan["pins"].(map[string]any)["release_set_sha256"] != binding["release_set_sha256"] {
		return "install_join"
	}
	return "admitted"
}

func installationRoles(uid, gid, managerUID int64) bool {
	return uid >= 1 && uid <= 4294967294 && gid >= 1 && gid <= 4294967294 && managerUID == 0
}

type installationProof struct {
	Present, Regular, Ancestors, NoACL, CurrentRead, NativeValidated bool
	Owner, GID, Mode, Links, ParentOwner, ParentGID, ParentMode      int64
	InstallationOwnerVerified, ReleaseProtected, InstallationRevoked bool
	DaemonUID, DaemonGID                                             int64
	DaemonExecutable, DaemonSocket, ObservationSocket, Boot          string
}

type installationLatch struct {
	Epoch    int64
	Digest   string
	Instance string
	Closed   bool
}

func installationControlProof(fixture installationFixtureCase) installationProof {
	binding := fixture.Binding
	return installationProof{InstallationOwnerVerified: true, ReleaseProtected: true, Present: true, Regular: true, Ancestors: true, NoACL: true, CurrentRead: true, NativeValidated: true,
		Owner: 0, GID: binding["daemon_gid"].(int64), Mode: 0640, Links: 1, ParentOwner: 0, ParentGID: binding["daemon_gid"].(int64), ParentMode: 0750,
		DaemonUID: binding["daemon_uid"].(int64), DaemonGID: binding["daemon_gid"].(int64), DaemonExecutable: binding["daemon_executable_sha256"].(string), DaemonSocket: binding["daemon_socket_path"].(string), ObservationSocket: binding["observation_socket_path"].(string), Boot: binding["manager"].(map[string]any)["boot_id"].(string)}
}

func installationRead(test *testing.T, fixture installationFixtureCase, proof installationProof, latch *installationLatch) string {
	result := installationReadResult(test, fixture, proof, *latch)
	if result != "admitted" {
		latch.Closed = true
	}
	return result
}

func installationBindingResult(test *testing.T, fixture installationFixtureCase, proof installationProof, latch installationLatch) string {
	test.Helper()
	if latch.Closed {
		return "closed"
	}
	binding := fixture.Binding
	if !proof.Present || !proof.Regular || !proof.Ancestors || !proof.NoACL || proof.Owner != 0 || proof.GID != binding["daemon_gid"] || proof.Mode != 0640 || proof.Links != 1 || proof.ParentOwner != 0 || proof.ParentGID != binding["daemon_gid"] || proof.ParentMode != 0750 {
		return "protection"
	}
	if !proof.CurrentRead {
		return "current_read"
	}
	set, _ := loadContracts(test)
	for _, record := range []struct {
		value  map[string]any
		format string
	}{{binding, installationFormat}, {fixture.Release, "swarma-lab-release-set/1"}} {
		if checkRecord(canonicalObject(test, record.value), boundedShape(set, record.format), set) != nil {
			return "shape"
		}
	}
	if latch.Epoch != binding["install_epoch"] || latch.Digest != boundedDigest(test, binding) || latch.Instance != binding["manager"].(map[string]any)["instance_id"] {
		return "epoch_changed"
	}
	if !reflect.DeepEqual(binding["context"], fixture.Release["context"]) {
		return "context"
	}
	if binding["approval_record_sha256"] != boundedDigest(test, binding["installation_approval"].(map[string]any)) {
		return "approval_digest"
	}
	if binding["release_set_sha256"] != boundedDigest(test, fixture.Release) {
		return "release_digest"
	}
	if !installationTargetApproved(test, binding) {
		return "target"
	}
	if !proof.InstallationOwnerVerified || proof.InstallationRevoked || !proof.ReleaseProtected || !approvalTargetValid(fixture.Release) {
		return "installation_authority"
	}
	manager := binding["manager"].(map[string]any)
	if !installationExecutable(fixture.Release, "manager", manager["executable_sha256"]) {
		return "manager_executable"
	}
	if !installationExecutable(fixture.Release, "broker", binding["daemon_executable_sha256"]) {
		return "daemon_executable"
	}

	if !installationRoles(binding["daemon_uid"].(int64), binding["daemon_gid"].(int64), manager["uid"].(int64)) {
		return "roles"
	}
	if proof.DaemonUID != binding["daemon_uid"] || proof.DaemonGID != binding["daemon_gid"] || proof.DaemonExecutable != binding["daemon_executable_sha256"] || proof.DaemonSocket != binding["daemon_socket_path"] || proof.ObservationSocket != binding["observation_socket_path"] {
		return "daemon"
	}
	if proof.Boot != manager["boot_id"] {
		return "boot"
	}
	return "admitted"
}

func installationReadResult(test *testing.T, fixture installationFixtureCase, proof installationProof, latch installationLatch) string {
	if result := installationBindingResult(test, fixture, proof, latch); result != "admitted" {
		return result
	}
	set, _ := loadContracts(test)
	if checkRecord(canonicalObject(test, fixture.Observation.Response), boundedShape(set, observationResponse), set) != nil {
		return "shape"
	}
	binding, candidate := fixture.Binding, fixture.Bounded
	if boundedAdmission(test, candidate, candidate) != "admitted" {
		return "approval"
	}
	if !reflect.DeepEqual(binding["context"], candidate.Plan["context"]) {
		return "context"
	}
	if !reflect.DeepEqual(fixture.Release["assets"], candidate.Release["assets"]) || fixture.Release["contract_index_sha256"] != candidate.Release["contract_index_sha256"] {
		return "release_inventory"
	}
	if !installationInputPin(candidate.Launch, boundedDigest(test, binding)) {
		return "binding_pin"
	}
	manager := binding["manager"].(map[string]any)
	if !reflect.DeepEqual(fixture.Observation.Response["manager"], manager) {
		return "manager"
	}
	if fixture.Observation.Response["store"].(map[string]any)["generation"] != binding["store_generation"] {
		return "store_generation"
	}
	if !proof.NativeValidated {
		return "native"
	}
	return "admitted"
}

func installationLatchFor(test *testing.T, fixture installationFixtureCase) installationLatch {
	return installationLatch{Epoch: fixture.Binding["install_epoch"].(int64), Digest: boundedDigest(test, fixture.Binding), Instance: fixture.Binding["manager"].(map[string]any)["instance_id"].(string)}
}

func installationApprove(test *testing.T, fixture *installationFixtureCase) {
	test.Helper()
	fixture.Binding["release_set_sha256"] = boundedDigest(test, fixture.Release)
	fixture.Binding["installation_approval"].(map[string]any)["approved_sha256"] = boundedDigest(test, installationTarget(test, fixture.Binding))
	fixture.Binding["approval_record_sha256"] = boundedDigest(test, fixture.Binding["installation_approval"].(map[string]any))
	boundedRebind(test, &fixture.Bounded)
	for _, plan := range []map[string]any{fixture.Install, fixture.Bounded.Launch} {
		for _, raw := range plan["input_pins"].([]any) {
			pin := raw.(map[string]any)
			if pin["name"] == "installation-binding" {
				pin["sha256"] = boundedDigest(test, fixture.Binding)
			}
		}
	}
	fixture.Observation.Response["start"].(map[string]any)["plan_sha256"] = boundedDigest(test, fixture.Bounded.Launch)
	fixture.Observation.Expected["start"].(map[string]any)["plan_sha256"] = boundedDigest(test, fixture.Bounded.Launch)
}

// Claim: the published synthetic install record has an embedded install-only approval and complete current start/native joins; each published refusal closes without changing the private latch.
func TestLabInstallationFixturePairs(test *testing.T) {
	fixture := installationFixture(test)
	if !reflect.DeepEqual(normalizedBounded(test, installationTarget(test, fixture.Binding)), normalizedBounded(test, fixture.Target)) {
		test.Fatal("typed target valid control")
	}
	if got := installationInstallPlan(test, fixture, fixture.Install); got != "admitted" {
		test.Fatalf("install fixture control: %s", got)
	}
	if got := observationAdmission(test, fixture.Observation, true); got != "valid" {
		test.Fatalf("native fixture control: %s", got)
	}
	for _, row := range fixture.Cases {
		test.Run(row.Name, func(test *testing.T) {
			current := installationFixture(test)
			proof := installationControlProof(current)
			latch := installationLatchFor(test, current)
			before := latch
			switch row.Name {
			case "root-placement-and-exact-native-join":
			case "wrong-owner":
				proof.Owner = 4001
			case "missing-installed-record":
				proof.Present = false
			case "observed-manager-not-expected":
				current.Observation.Response["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
			case "observed-store-not-expected":
				current.Observation.Response["store"].(map[string]any)["generation"] = strings.Repeat("d", 32)
				current.Observation.Response["sequence_generation"] = strings.Repeat("d", 32)
			case "new-epoch-in-flight":
				current.Binding["install_epoch"] = int64(2)
				installationApprove(test, &current)
			default:
				test.Fatal("undeclared fixture case")
			}
			if got := installationRead(test, current, proof, &latch); got != row.Expected {
				test.Fatalf("installation fixture refusal: %s want %s", got, row.Expected)
			}
			if latch.Epoch != before.Epoch || latch.Digest != before.Digest || latch.Closed != (row.Expected != "admitted") {
				test.Fatal("private latch mutation")
			}
		})
	}
}

// Claim: each opened-file protection fact is independently required beside its exact root-owned read-only control; failure cannot be repaired or reopen use.
func TestLabInstallationProtectionPairs(test *testing.T) {
	cases := map[string]func(*installationProof){
		"absence": func(proof *installationProof) { proof.Present = false }, "regular": func(proof *installationProof) { proof.Regular = false }, "ancestors": func(proof *installationProof) { proof.Ancestors = false }, "acl": func(proof *installationProof) { proof.NoACL = false },
		"owner": func(proof *installationProof) { proof.Owner = 4001 }, "group": func(proof *installationProof) { proof.GID++ }, "mode-read": func(proof *installationProof) { proof.Mode = 0644 }, "mode-write": func(proof *installationProof) { proof.Mode = 0660 }, "mode-execute": func(proof *installationProof) { proof.Mode = 0740 }, "mode-special": func(proof *installationProof) { proof.Mode = 04640 },
		"links-zero": func(proof *installationProof) { proof.Links = 0 }, "links-two": func(proof *installationProof) { proof.Links = 2 }, "parent-owner": func(proof *installationProof) { proof.ParentOwner = 4001 }, "parent-group": func(proof *installationProof) { proof.ParentGID++ }, "parent-read": func(proof *installationProof) { proof.ParentMode = 0755 }, "parent-write": func(proof *installationProof) { proof.ParentMode = 0770 }, "parent-special": func(proof *installationProof) { proof.ParentMode = 02750 },
	}
	for name, mutate := range cases {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			proof := installationControlProof(fixture)
			latch := installationLatchFor(test, fixture)
			if got := installationRead(test, fixture, proof, &latch); got != "admitted" {
				test.Fatalf("protection valid control: %s", got)
			}
			mutate(&proof)
			if got := installationRead(test, fixture, proof, &latch); got != "protection" || !latch.Closed {
				test.Fatalf("protection refusal: %s", got)
			}
			if got := installationRead(test, fixture, installationControlProof(fixture), &latch); got != "closed" {
				test.Fatalf("sticky binding refusal: %s", got)
			}
		})
	}
}

// Claim: every approved installation/daemon/native pin is checked independently of syntactic validity, with an adjacent valid chain and no latch advancement on mismatch.
func TestLabInstallationJoinPairs(test *testing.T) {
	run := func(name, want string, mutate func(*installationFixtureCase, *installationProof, *installationLatch)) {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			proof := installationControlProof(fixture)
			latch := installationLatchFor(test, fixture)
			if got := installationRead(test, fixture, proof, &latch); got != "admitted" {
				test.Fatalf("join valid control: %s", got)
			}
			mutate(&fixture, &proof, &latch)
			before := latch
			if got := installationRead(test, fixture, proof, &latch); got != want || !latch.Closed {
				test.Fatalf("installation join refusal: %s want %s", got, want)
			}
			if before.Epoch != latch.Epoch || before.Digest != latch.Digest {
				test.Fatal("join refusal changed private pins")
			}
		})
	}
	for _, name := range []string{"uid", "identity", "executable_sha256", "instance_id", "boot_id"} {
		run("observed-manager-"+name, map[bool]string{true: "shape", false: "manager"}[name == "uid"], func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
			manager := fixture.Observation.Response["manager"].(map[string]any)
			switch name {
			case "uid":
				manager[name] = int64(4001)
			case "boot_id":
				manager[name] = "22222222-3333-4444-8555-666666666666"
			case "instance_id":
				manager[name] = strings.Repeat("d", 32)
			case "executable_sha256":
				manager[name] = "sha256:" + strings.Repeat("d", 64)
			default:
				manager[name] = "other-manager"
			}
		})
	}
	run("store", "store_generation", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Observation.Response["store"].(map[string]any)["generation"] = strings.Repeat("d", 32)
		fixture.Observation.Response["sequence_generation"] = strings.Repeat("d", 32)
	})
	run("current-read", "current_read", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		proof.CurrentRead = false
	})
	run("native", "native", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		proof.NativeValidated = false
	})
	run("owner", "approval", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Bounded.OwnerVerified = false
	})
	run("revoked", "approval", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Bounded.Revoked = true
	})
	run("expired", "approval", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Bounded.Now = "9999-01-01T00:00:00Z"
	})
	for _, name := range []string{"approval_record_sha256", "release_set_sha256", "context"} {
		want := map[string]string{"approval_record_sha256": "approval_digest", "release_set_sha256": "release_digest", "context": "context"}[name]
		run(name, want, func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
			if name == "context" {
				fixture.Binding[name].(map[string]any)["account"] = "other-account"
			} else {
				fixture.Binding[name] = "sha256:" + strings.Repeat("d", 64)
			}
			*latch = installationLatchFor(test, *fixture)
		})
	}
	for _, name := range []string{"daemon-uid", "daemon-gid", "daemon-executable", "daemon-socket", "observation-socket", "boot"} {
		want := "daemon"
		if name == "boot" {
			want = "boot"
		}
		run(name, want, func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
			switch name {
			case "daemon-uid":
				proof.DaemonUID++
			case "daemon-gid":
				proof.DaemonGID++
			case "daemon-executable":
				proof.DaemonExecutable = "sha256:" + strings.Repeat("d", 64)
			case "daemon-socket":
				proof.DaemonSocket += ".old"
			case "observation-socket":
				proof.ObservationSocket += ".old"
			case "boot":
				proof.Boot = "22222222-3333-4444-8555-666666666666"
			}
		})
	}

	for _, name := range []string{"manager", "daemon"} {
		run(name+"-unapproved-executable", name+"_executable", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
			unknown := "sha256:" + strings.Repeat("d", 64)
			if name == "manager" {
				fixture.Binding["manager"].(map[string]any)["executable_sha256"] = unknown
			} else {
				fixture.Binding["daemon_executable_sha256"] = unknown
				proof.DaemonExecutable = unknown
			}
			installationApprove(test, fixture)
			*latch = installationLatchFor(test, *fixture)
		})
	}
	run("launch-binding-pin", "binding_pin", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		pins := fixture.Bounded.Launch["input_pins"].([]any)
		pins[len(pins)-1].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("d", 64)
	})
	run("unapproved-coherent-native-tuple", "target", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Binding["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
		fixture.Observation.Response["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
		*latch = installationLatchFor(test, *fixture)
	})

	run("coherent-root-daemon", "roles", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Binding["daemon_uid"] = int64(0)
		proof.DaemonUID = 0
		installationApprove(test, fixture)
		*latch = installationLatchFor(test, *fixture)
	})
	run("same-epoch-new-digest", "epoch_changed", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Binding["installation_approval"].(map[string]any)["record_id"] = "other-installation-approval"
		installationApprove(test, fixture)
	})
	run("new-epoch", "epoch_changed", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		fixture.Binding["install_epoch"] = int64(2)
		installationApprove(test, fixture)
	})
	run("old-epoch", "epoch_changed", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		latch.Epoch = 2
	})
	run("restart-lost-latch", "epoch_changed", func(fixture *installationFixtureCase, proof *installationProof, latch *installationLatch) {
		latch.Epoch = 0
		latch.Digest = ""
	})
}

// Claim: every runtime target field, including R0, is owner-bound before observation rather than fabricated as an archive member.
func TestLabInstallationTargetPairs(test *testing.T) {
	fixture := installationFixture(test)
	for name := range installationTarget(test, fixture.Binding)["record"].(map[string]any) {
		test.Run("field-"+name, func(test *testing.T) {
			current := installationFixture(test)
			if !installationTargetApproved(test, current.Binding) {
				test.Fatal("target valid control")
			}
			current.Binding[name] = "changed-target-field"
			if installationTargetApproved(test, current.Binding) {
				test.Fatal("target field refusal")
			}
		})
	}
}

// Claim: the typed complete I digest is a required unique install/launch pin; either plan missing/mistyped/duplicated pins refuses independently of later C0b duplicate checks.
func TestLabInstallationInputPinPairs(test *testing.T) {
	for _, kind := range []string{"install", "launch"} {
		for _, name := range []string{"missing", "duplicate", "wrong-digest", "unrelated-duplicate"} {
			test.Run(kind+"/"+name, func(test *testing.T) {
				current := installationFixture(test)
				plan := current.Install
				if kind == "launch" {
					plan = current.Bounded.Launch
				}
				digest := boundedDigest(test, current.Binding)
				if !installationInputPin(plan, digest) {
					test.Fatal("typed input pin control")
				}
				pins := plan["input_pins"].([]any)
				index := len(pins) - 1
				switch name {
				case "missing":
					plan["input_pins"] = pins[:index]
				case "duplicate":
					plan["input_pins"] = append(pins, pins[index])
				case "wrong-digest":
					pins[index].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("d", 64)
				case "unrelated-duplicate":
					plan["input_pins"] = append(pins, pins[0])
				}
				if installationInputPin(plan, digest) {
					test.Fatal("typed input pin refusal")
				}
			})
		}
	}
}

// Claim: native UID/GID bounds include both adjacent sides; root manager is valid but either/both swapped roles never authorize a root broker.
func TestLabInstallationRolePairs(test *testing.T) {
	for _, field := range []string{"uid", "gid"} {
		for _, value := range []int64{-1, 0, 1, 2, 4294967293, 4294967294, 4294967295} {
			test.Run(fmt.Sprintf("%s/%d", field, value), func(test *testing.T) {
				if !installationRoles(4001, 4101, 0) {
					test.Fatal("role valid control")
				}
				uid, gid := int64(4001), int64(4101)
				if field == "uid" {
					uid = value
				} else {
					gid = value
				}
				if got := installationRoles(uid, gid, 0); got != (value >= 1 && value <= 4294967294) {
					test.Fatalf("native role boundary: %s %d", field, value)
				}
			})
		}
	}
	for _, pair := range []struct {
		name            string
		daemon, manager int64
	}{{"daemon-only-swap", 0, 0}, {"manager-only-swap", 4001, 4001}, {"both-swapped", 0, 4001}} {
		test.Run(pair.name, func(test *testing.T) {
			if !installationRoles(4001, 4101, 0) {
				test.Fatal("paired role control")
			}
			if installationRoles(pair.daemon, 4101, pair.manager) {
				test.Fatal("paired role refusal")
			}
		})
	}
}

func installationRotation(old, next map[string]any, root, approved, quiescent, fresh, privateAccess bool) string {
	if !root {
		return "writer_root"
	}
	if privateAccess {
		return "private_recovery"
	}
	if !approved {
		return "writer_approval"
	}
	if !quiescent {
		return "quiescence"
	}
	epoch := next["install_epoch"].(int64)
	if old == nil {
		if !fresh || epoch != 1 {
			return "fresh"
		}
		return "apply"
	}
	previous := old["install_epoch"].(int64)
	if previous >= 9007199254740991 || epoch != previous+1 {
		return "epoch"
	}
	if old["manager"].(map[string]any)["instance_id"] == next["manager"].(map[string]any)["instance_id"] {
		return "instance_reuse"
	}
	return "apply"
}

// Claim: root alone cannot rotate without new approval and complete quiescence; epochs/instances never repeat and B5's private-recovery access is forbidden, including fresh initialization.
func TestLabInstallationRotationPairs(test *testing.T) {
	cases := []struct{ name, want string }{{"valid", "apply"}, {"not-root", "writer_root"}, {"unapproved", "writer_approval"}, {"in-flight", "quiescence"}, {"private-read-or-write", "private_recovery"}, {"same-epoch", "epoch"}, {"old-epoch", "epoch"}, {"skip-epoch", "epoch"}, {"overflow", "epoch"}, {"reused-instance", "instance_reuse"}, {"fresh-valid", "apply"}, {"missing-prior", "fresh"}, {"fresh-not-one", "fresh"}}
	for _, row := range cases {
		test.Run(row.name, func(test *testing.T) {
			old := installationFixture(test).Binding
			next := normalizedBounded(test, cloneObject(test, old))
			next["install_epoch"] = int64(2)
			next["manager"].(map[string]any)["instance_id"] = strings.Repeat("d", 32)
			root, approved, quiescent, fresh, privateAccess := true, true, true, false, false
			if got := installationRotation(old, next, root, approved, quiescent, fresh, privateAccess); got != "apply" {
				test.Fatalf("rotation valid control: %s", got)
			}
			switch row.name {
			case "not-root":
				root = false
			case "unapproved":
				approved = false
			case "in-flight":
				quiescent = false
			case "private-read-or-write":
				privateAccess = true
			case "same-epoch":
				next["install_epoch"] = int64(1)
			case "old-epoch":
				old["install_epoch"] = int64(2)
				next["install_epoch"] = int64(1)
			case "skip-epoch":
				next["install_epoch"] = int64(3)
			case "overflow":
				old["install_epoch"] = int64(9007199254740991)
				next["install_epoch"] = int64(9007199254740992)
			case "reused-instance":
				next["manager"].(map[string]any)["instance_id"] = old["manager"].(map[string]any)["instance_id"]
			case "fresh-valid":
				old = nil
				fresh = true
				next["install_epoch"] = int64(1)
			case "missing-prior":
				old = nil
				next["install_epoch"] = int64(1)
			case "fresh-not-one":
				old = nil
				fresh = true
			}
			before, err := json.Marshal(next)
			if err != nil {
				test.Fatal(err)
			}
			if got := installationRotation(old, next, root, approved, quiescent, fresh, privateAccess); got != row.want {
				test.Fatalf("rotation refusal: %s want %s", got, row.want)
			}
			after, err := json.Marshal(next)
			if err != nil {
				test.Fatal(err)
			}
			if string(after) != string(before) {
				test.Fatal("rotation mutated before installation commit")
			}
		})
	}
}

// Claim: both approved executable roles require a matching executable member; a wrong product, mode or digest never grants installed executable authority.
func TestLabInstallationExecutablePairs(test *testing.T) {
	for _, product := range []string{"broker", "manager"} {
		for _, name := range []string{"missing", "product", "mode", "digest"} {
			test.Run(product+"/"+name, func(test *testing.T) {
				fixture := installationFixture(test)
				expected := fixture.Binding["daemon_executable_sha256"]
				index := 0
				if product == "manager" {
					expected = fixture.Binding["manager"].(map[string]any)["executable_sha256"]
					index = 1
				}
				if !installationExecutable(fixture.Bounded.Release, product, expected) {
					test.Fatal("executable valid control")
				}
				asset := fixture.Bounded.Release["assets"].([]any)[index].(map[string]any)
				member := asset["members"].([]any)[0].(map[string]any)
				switch name {
				case "missing":
					asset["members"] = []any{}
				case "product":
					asset["product"] = "gateway"
				case "mode":
					member["mode"] = "0644"
				case "digest":
					member["sha256"] = "sha256:" + strings.Repeat("d", 64)
				}
				if installationExecutable(fixture.Bounded.Release, product, expected) {
					test.Fatal("executable member refusal")
				}
			})
		}
	}
}

// Claim: the complete literal/value catalogue attacks each target label/domain and typed input-pin name at its own gate.
func TestLabInstallationLiteralPairs(test *testing.T) {
	tokens := map[string]string{"domain": "swarma-broker-lab-installation-binding-target/1", "input-name": "installation-binding", "label-domain": "domain", "label-record": "record"}
	for element, token := range tokens {
		mutations := literalMutations(token)
		if !strings.HasPrefix(element, "label-") {
			mutations = append(mutations, wrongTypes(token)...)
		}
		for _, mutation := range mutations {
			test.Run(element+"/"+mutation.Name, func(test *testing.T) {
				fixture := installationFixture(test)
				if !installationTargetApproved(test, fixture.Binding) {
					test.Fatal("literal target control")
				}
				if !installationInputPin(fixture.Install, boundedDigest(test, fixture.Binding)) {
					test.Fatal("literal pin control")
				}
				var admitted bool
				if element == "input-name" {
					pins := fixture.Install["input_pins"].([]any)
					pins[len(pins)-1].(map[string]any)["name"] = mutation.Value
					set, _ := loadContracts(test)
					if checkRecord(canonicalObject(test, fixture.Install), boundedShape(set, "swarma-broker-lab-install-plan/1"), set) == nil {
						admitted = installationInputPin(fixture.Install, boundedDigest(test, fixture.Binding))
					}
				} else {
					target := installationTarget(test, fixture.Binding)
					if element == "domain" {
						target["domain"] = mutation.Value
					} else {
						value := target[token]
						delete(target, token)
						target[mutation.Value.(string)] = value
					}
					fixture.Binding["installation_approval"].(map[string]any)["approved_sha256"] = boundedDigest(test, target)
					admitted = installationTargetApproved(test, fixture.Binding)
				}
				if admitted != mutation.Admit {
					test.Fatalf("installation literal refusal: %s %s got %v want %v", element, mutation.Name, admitted, mutation.Admit)
				}
			})
		}
	}
}

// Claim: B5 validates the published install plan against I and its separate install-operation authority; B1 needs no root-only installer envelope.
func TestLabInstallationInstallPlanPairs(test *testing.T) {
	for _, name := range []string{"context", "off_vm_approval_sha256", "release_set_sha256", "binding-pin", "shape"} {
		test.Run(name, func(test *testing.T) {
			fixture := installationFixture(test)
			if got := installationInstallPlan(test, fixture, fixture.Install); got != "admitted" {
				test.Fatalf("install plan control: %s", got)
			}
			want := "install_join"
			switch name {
			case "context":
				fixture.Install[name].(map[string]any)["account"] = "other-account"
			case "binding-pin":
				pins := fixture.Install["input_pins"].([]any)
				pins[len(pins)-1].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("d", 64)
				want = "binding_pin"
			case "shape":
				fixture.Install["unexpected_field"] = "PUBLIC-UNKNOWN"
				want = "shape"
			default:
				fixture.Install["pins"].(map[string]any)[name] = "sha256:" + strings.Repeat("d", 64)
			}
			if got := installationInstallPlan(test, fixture, fixture.Install); got != want {
				test.Fatalf("install plan refusal: %s want %s", got, want)
			}
		})
	}
}
