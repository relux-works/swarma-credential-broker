//go:build linux && broker_lab

package labtimev0

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func frozen(test *testing.T, format string, target any) []byte {
	test.Helper()
	raw, err := os.ReadFile("../../contracts/lab-v0/fixtures.json")
	if err != nil {
		test.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Surface string          `json:"surface"`
			Valid   json.RawMessage `json:"valid"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		test.Fatal("fixture decode")
	}
	for _, fixture := range fixtures.Cases {
		if fixture.Surface != format {
			continue
		}
		var value any
		if json.Unmarshal(fixture.Valid, &value) != nil {
			test.Fatal("fixture value")
		}
		raw, err = Encode(value)
		if err != nil || Decode(raw, target) != nil {
			test.Fatal("frozen control", format, err)
		}
		return raw
	}
	test.Fatal("missing frozen control", format)
	return nil
}

func encoded(test *testing.T, value any) []byte {
	test.Helper()
	raw, err := Encode(value)
	if err != nil {
		test.Fatal(err)
	}
	return raw
}

func seal(test *testing.T, value any) []byte {
	test.Helper()
	raw := encoded(test, value)
	target, err := ApprovalTarget(raw)
	if err != nil {
		test.Fatal(err)
	}
	switch record := value.(type) {
	case *Decision:
		record.Approval.SHA256 = target
	case *OffVM:
		record.Approval.SHA256 = target
	default:
		test.Fatal("seal target")
	}
	return encoded(test, value)
}

func startFixture(test *testing.T) (Decision, OffVM, Fence, StartPins) {
	test.Helper()
	var decision Decision
	decisionRaw := frozen(test, DecisionFormat, &decision)
	var approval OffVM
	approvalRaw := frozen(test, ApprovalFormat, &approval)
	var fence Fence
	frozen(test, FenceFormat, &fence)
	fence.Heads, fence.ApprovalDigest, fence.Generation, fence.State, fence.Consumed = approval.Heads, Digest(approvalRaw), 1, "fresh", false
	pins := StartPins{Context: decision.Context, Heads: approval.Heads, DecisionDigest: Digest(decisionRaw), ApprovalDigest: Digest(approvalRaw), AccessDigest: approval.Access, ReleaseDigest: approval.Release, InvocationDigest: approval.Invocation, Generation: 1, Now: instant(approval.Now)}
	return decision, approval, fence, pins
}

// Claim: exact three-role C consent admits the inert control; every missing, duplicate, unaccepted role, text pin and residual fails after resealing.
func TestLabCOpening(test *testing.T) {
	control, _, _, pins := startFixture(test)
	cases := map[string]func(*Decision){
		"amendment":  func(value *Decision) { value.Amendment = Digest([]byte("other")) },
		"api":        func(value *Decision) { value.API = Digest([]byte("other")) },
		"joins":      func(value *Decision) { value.Joins = Digest([]byte("other")) },
		"residual":   func(value *Decision) { value.Residual = false },
		"expired":    func(value *Decision) { value.Approval.Expires = value.Recorded },
		"retargeted": func(value *Decision) { value.Context.Installation = "other-installation" },
	}
	for index, role := range control.Roles {
		position := index
		cases[role.Role+"-unaccepted"] = func(value *Decision) { value.Roles[position].Accepted = false }
		cases[role.Role+"-missing"] = func(value *Decision) { value.Roles = append(value.Roles[:position], value.Roles[position+1:]...) }
		cases[role.Role+"-duplicate"] = func(value *Decision) { value.Roles[position] = value.Roles[(position+1)%3] }
	}
	for name, mutate := range cases {
		test.Run(name, func(test *testing.T) {
			raw := seal(test, &control)
			if CheckDecision(raw, Digest(raw), pins.Context, pins.Now) != nil {
				test.Fatal("valid consent")
			}
			var candidate Decision
			if Decode(raw, &candidate) != nil {
				test.Fatal("clone")
			}
			mutate(&candidate)
			raw = seal(test, &candidate)
			if CheckDecision(raw, Digest(raw), pins.Context, pins.Now) == nil {
				test.Fatal("consent widened")
			}
		})
	}
}

// Claim: exact off-VM heads/clock and fresh generation admit; replay, changed pins, unknown stops and expiry refuse with no mutation.
func TestLabStartJoins(test *testing.T) {
	decision, approval, fence, pins := startFixture(test)
	decisionRaw, approvalRaw := encoded(test, decision), encoded(test, approval)
	control := encoded(test, fence)
	if CheckStart(decisionRaw, approvalRaw, control, nil, pins) != nil {
		test.Fatal("fresh start")
	}
	for name, mutate := range map[string]func(*Fence, *StartPins){
		"replay":               func(value *Fence, _ *StartPins) { value.Consumed = true },
		"head":                 func(value *Fence, _ *StartPins) { value.Heads.Manager.Sequence++ },
		"unknown-stop":         func(value *Fence, _ *StartPins) { value.State = "orderly-stop" },
		"expiry":               func(_ *Fence, value *StartPins) { value.Now = instant(value.Context.Expires) },
		"unknown-clock":        func(_ *Fence, value *StartPins) { value.Now = time.Time{} },
		"retired-floor-expiry": func(_ *Fence, value *StartPins) { value.RefusalFloors = []time.Time{instant(value.Context.Expires)} },
		"missing-comparison":   func(_ *Fence, value *StartPins) { value.RefusalFloors = []time.Time{{}} },
		"release":              func(_ *Fence, value *StartPins) { value.ReleaseDigest = Digest([]byte("other")) },
		"access":               func(_ *Fence, value *StartPins) { value.AccessDigest = Digest([]byte("other")) },
		"vm":                   func(_ *Fence, value *StartPins) { value.Context.VM = Digest([]byte("other")) },
		"approval":             func(_ *Fence, value *StartPins) { value.ApprovalDigest = Digest([]byte("other")) },
	} {
		test.Run(name, func(test *testing.T) {
			if CheckStart(decisionRaw, approvalRaw, control, nil, pins) != nil {
				test.Fatal("valid control")
			}
			candidate, nextPins := fence, pins
			mutate(&candidate, &nextPins)
			if CheckStart(decisionRaw, approvalRaw, encoded(test, candidate), nil, nextPins) == nil {
				test.Fatal("start admitted")
			}
		})
	}
	previous := fence
	previous.Consumed, previous.State = true, "orderly-stop"
	fence.Generation, fence.State, approval.Generation, pins.Generation = 2, "orderly-stop", 2, 2
	approvalRaw = seal(test, &approval)
	pins.ApprovalDigest, fence.ApprovalDigest = Digest(approvalRaw), Digest(approvalRaw)
	if CheckStart(decisionRaw, approvalRaw, encoded(test, fence), &previous, pins) != nil {
		test.Fatal("acknowledged restart")
	}
	previous.Consumed = false
	if CheckStart(decisionRaw, approvalRaw, encoded(test, fence), &previous, pins) == nil {
		test.Fatal("unacknowledged restart")
	}
}

// Claim: advancing acknowledged-stop heads admit only the exact next generation, current approval/invocation, ordered clocks and pinned owner decision.
func TestLabRestartChainRefusals(test *testing.T) {
	for _, fault := range []string{"generation", "stop-heads", "stop-state", "approval-heads", "approval-generation", "invocation", "clock-before", "clock-after", "decision-digest"} {
		test.Run(fault, func(test *testing.T) {
			decision, approval, fence, pins := startFixture(test)
			decisionRaw := encoded(test, decision)
			if CheckDecision(decisionRaw, pins.DecisionDigest, pins.Context, pins.Now) != nil {
				test.Fatal("decision pin control")
			}
			previous := fence
			previous.Consumed, previous.State = true, "orderly-stop"
			previous.Heads.Time.Sequence++
			previous.Heads.Time.SHA256 = Digest([]byte("advanced settled head"))
			previous.Heads.Floor.Sequence++
			previous.Heads.Floor.SHA256 = Digest([]byte("advanced floor head"))
			pins.Heads, approval.Heads, fence.Heads = previous.Heads, previous.Heads, previous.Heads
			fence.Generation, fence.State, approval.Generation, pins.Generation = 2, "orderly-stop", 2, 2
			approvalRaw := seal(test, &approval)
			pins.ApprovalDigest, fence.ApprovalDigest = Digest(approvalRaw), Digest(approvalRaw)
			if CheckStart(decisionRaw, approvalRaw, encoded(test, fence), &previous, pins) != nil {
				test.Fatal("advancing restart control")
			}
			switch fault {
			case "generation":
				fence.Generation, pins.Generation, approval.Generation = 3, 3, 3
			case "stop-heads":
				previous.Heads.Time.Sequence++
			case "stop-state":
				previous.State = "fresh"
			case "approval-generation":
				approval.Generation = 1
			case "approval-heads":
				approval.Heads.Time.Sequence++
			case "invocation":
				approval.Invocation = Digest([]byte("changed invocation"))
			case "clock-before":
				approval.Now = instant(approval.Approval.At).Add(-time.Nanosecond).Format(time.RFC3339Nano)
			case "clock-after":
				approval.Now = pins.Now.Add(time.Nanosecond).Format(time.RFC3339Nano)
			case "decision-digest":
				if CheckDecision(decisionRaw, Digest([]byte("wrong expected decision")), pins.Context, pins.Now) == nil {
					test.Fatal("decision digest pin bypass")
				}
				return
			}
			approvalRaw = seal(test, &approval)
			pins.ApprovalDigest, fence.ApprovalDigest = Digest(approvalRaw), Digest(approvalRaw)
			if CheckStart(decisionRaw, approvalRaw, encoded(test, fence), &previous, pins) == nil {
				test.Fatal("restart chain bypass", fault)
			}
		})
	}
}

// Claim: protected off-home fences consume once durably; replay, in-home, symlink and hardlink variants refuse beside the valid load.
func TestLabRootFenceOneUse(test *testing.T) {
	decision, approval, fence, pins := startFixture(test)
	root := test.TempDir()
	if os.Chmod(root, 0700) != nil {
		test.Fatal("fixture mode")
	}
	home := filepath.Join(root, "home")
	if os.Mkdir(home, 0700) != nil {
		test.Fatal("fixture home")
	}
	control := filepath.Join(root, "control")
	if os.Mkdir(control, 0700) != nil {
		test.Fatal("fixture control directory")
	}
	path := filepath.Join(control, "fence.json")
	if os.WriteFile(path, encoded(test, fence), 0644) != nil {
		test.Fatal("fixture fence")
	}
	if os.Chmod(path, 0644) != nil {
		test.Fatal("fixture fence mode")
	}
	owner, group := uint32(os.Geteuid()), uint32(os.Getegid())
	decisionRaw, approvalRaw := encoded(test, decision), encoded(test, approval)
	if !fenceLocation(path, home) {
		test.Fatal("fixture fence location")
	}
	fixtureRaw, readErr := readFence(context.Background(), path, owner, group)
	if readErr != nil {
		test.Fatal("fixture protected read", readErr)
	}
	if CheckStart(decisionRaw, approvalRaw, fixtureRaw, nil, pins) != nil {
		test.Fatal("fixture start join")
	}
	if consumeStartFence(context.Background(), path, home, decisionRaw, approvalRaw, nil, pins, owner, group) != nil {
		test.Fatal("root-policy fixture consume")
	}
	start, err := loadStart(context.Background(), path, home, decisionRaw, approvalRaw, nil, pins, owner, group)
	if err != nil || start.Current(context.Background()) != nil {
		test.Fatal("consumed fence load", err)
	}
	before, _ := os.ReadFile(path)
	if consumeStartFence(context.Background(), path, home, decisionRaw, approvalRaw, nil, pins, owner, group) == nil {
		test.Fatal("replayed fence")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		test.Fatal("replay mutated fence")
	}
	for _, location := range []string{filepath.Join(home, "fence.json"), filepath.Join(control, "link.json"), filepath.Join(control, "hard.json")} {
		if strings.Contains(location, "hard") {
			err = os.Link(path, location)
		} else {
			err = os.Symlink(path, location)
		}
		if err != nil {
			test.Fatal(err)
		}
		if _, err := loadStart(context.Background(), location, home, decisionRaw, approvalRaw, nil, pins, owner, group); err == nil {
			test.Fatal("unsafe fence admitted")
		}
		if err := os.Remove(location); err != nil {
			test.Fatal(err)
		}
	}
	if start.Current(context.Background()) != nil {
		test.Fatal("valid control after owned cleanup")
	}
	homeFence := filepath.Join(home, "fence.json")
	if err := os.WriteFile(homeFence, before, 0644); err != nil {
		test.Fatal(err)
	}
	if err := os.Chmod(homeFence, 0644); err != nil {
		test.Fatal(err)
	}
	if _, err := loadStart(context.Background(), homeFence, home, decisionRaw, approvalRaw, nil, pins, owner, group); err == nil {
		test.Fatal("regular home fence admitted")
	}
	if _, err := readFence(context.Background(), path, owner, group+1); err == nil {
		test.Fatal("wrong fence group admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		test.Fatal(err)
	}
	if _, err := readFence(context.Background(), path, owner, group); err == nil {
		test.Fatal("wrong fence mode admitted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		test.Fatal(err)
	}
	if start.Current(context.Background()) != nil {
		test.Fatal("restored valid fence")
	}
	if os.WriteFile(path, []byte("{}"), 0644) != nil {
		test.Fatal("substitution fixture")
	}
	if start.Current(context.Background()) == nil {
		test.Fatal("substitution retained admission")
	}
}

func managerJournal(test *testing.T) ([]byte, []byte, Head) {
	test.Helper()
	first, err := genjournal.Encode(genjournal.Record{Seq: 1, Prev: genjournal.ZeroHash, UID: 2001, Generation: strings.Repeat("1", 32), State: "creating", Writer: "user-manager", Time: "2026-11-20T08:00:00Z"})
	if err != nil {
		test.Fatal(err)
	}
	head := Head{1, Digest(first)}
	second, err := genjournal.Encode(genjournal.Record{Seq: 2, Prev: strings.TrimPrefix(head.SHA256, "sha256:"), UID: 2001, Generation: strings.Repeat("1", 32), State: "active", Writer: "user-manager", Time: "2026-11-20T08:00:01Z"})
	if err != nil {
		test.Fatal(err)
	}
	return first, append(append([]byte(nil), first...), second...), head
}

// Claim: the manager-owned verifier accepts a true prefix extension and refuses truncation, same-count forks and malformed history, not just head equality.
func TestLabManagerPrefix(test *testing.T) {
	first, journal, prior := managerJournal(test)
	forkFirst, err := genjournal.Encode(genjournal.Record{Seq: 1, Prev: genjournal.ZeroHash, UID: 2002, Generation: strings.Repeat("2", 32), State: "creating", Writer: "user-manager", Time: "2026-11-20T08:00:00Z"})
	if err != nil {
		test.Fatal(err)
	}
	forkNext, err := genjournal.Encode(genjournal.Record{Seq: 2, Prev: strings.TrimPrefix(Digest(forkFirst), "sha256:"), UID: 2002, Generation: strings.Repeat("2", 32), State: "active", Writer: "user-manager", Time: "2026-11-20T08:00:01Z"})
	if err != nil {
		test.Fatal(err)
	}
	fork := append(forkFirst, forkNext...)
	if _, err := ManagerExtension(fork, Head{SHA256: "sha256:" + genjournal.ZeroHash}); err != nil {
		test.Fatal("well-formed alternate history", err)
	}
	for name, candidate := range map[string][]byte{"truncated": {}, "partial": journal[:len(journal)-1], "fork": fork} {
		test.Run(name, func(test *testing.T) {
			head, err := ManagerExtension(journal, prior)
			if err != nil || head.Sequence != 2 {
				test.Fatal("prefix extension", err)
			}
			if _, err := ManagerExtension(candidate, prior); err == nil {
				test.Fatal("nonextension admitted")
			}
		})
	}
	if _, err := ManagerExtension(first, prior); err != nil {
		test.Fatal("unchanged exact prefix")
	}
}

// Claim: checkpoint settlement advances strict interval/watermark bounds, while rewind, boot regression and sticky-hold clearing fail after a good report.
func TestLabCheckpointContinuity(test *testing.T) {
	var old Checkpoint
	frozen(test, CheckpointFormat, &old)
	head := Head{1, Digest(encoded(test, old))}
	next := old
	next.Previous = head
	next.Lower, next.Upper, next.Watermark = "2026-11-20T08:00:02Z", "2026-11-20T08:00:03Z", "2026-11-20T08:00:03Z"
	next.Monotonic++
	for name, mutate := range map[string]func(*Checkpoint){
		"rewind":     func(value *Checkpoint) { value.Watermark = "2026-11-20T07:00:00Z" },
		"overlap":    func(value *Checkpoint) { value.Lower = old.Watermark },
		"monotonic":  func(value *Checkpoint) { value.Monotonic = 0 },
		"expired":    func(value *Checkpoint) { value.Watermark = value.Context.Expires },
		"unsettled":  func(value *Checkpoint) { value.Settled = false },
		"retargeted": func(value *Checkpoint) { value.Scope = "other" },
		"inventory":  func(value *Checkpoint) { value.Inventory = Digest([]byte("other")) },
	} {
		test.Run(name, func(test *testing.T) {
			if CheckCheckpoint(old, head, next, true) != nil {
				test.Fatal("valid settlement")
			}
			candidate := next
			mutate(&candidate)
			if CheckCheckpoint(old, head, candidate, true) == nil {
				test.Fatal("invalid settlement")
			}
		})
	}
	old.Incident, old.Settled, old.Holds = "held", false, []string{"sticky-incident"}
	head.SHA256 = Digest(encoded(test, old))
	next.Previous = head
	if CheckCheckpoint(old, head, next, true) == nil {
		test.Fatal("good report released sticky hold")
	}
	next.Incident, next.Settled, next.Holds = "held", false, []string{"sticky-incident"}
	if CheckCheckpoint(old, head, next, true) != nil {
		test.Fatal("sticky restart control")
	}
	old.Incident = "burned"
	head.SHA256 = Digest(encoded(test, old))
	next.Previous = head
	if CheckCheckpoint(old, head, next, true) == nil {
		test.Fatal("burned installation reopened")
	}
}

// Claim: A07 uses the protected exclusive earliest deadline with 1/900-second controls; 0/901, hold and reached-expiry cases refuse.
func TestLabQualificationDeadline(test *testing.T) {
	var checkpoint Checkpoint
	frozen(test, CheckpointFormat, &checkpoint)
	now := instant(checkpoint.Lower)
	for _, lifetime := range []int{1, 900} {
		until, err := Deadline(checkpoint, now, lifetime, now.Add(500*time.Millisecond))
		if err != nil || !until.Equal(now.Add(500*time.Millisecond)) {
			test.Fatal("earliest bound", err)
		}
	}
	for _, lifetime := range []int{0, 901} {
		if _, err := Deadline(checkpoint, now, lifetime); err == nil {
			test.Fatal("invalid lifetime")
		}
	}
	if _, err := Deadline(checkpoint, now, 1, now); err == nil {
		test.Fatal("exclusive authority")
	}
	checkpoint.Upper = now.Add(time.Second).UTC().Format(time.RFC3339Nano)
	checkpoint.Watermark = checkpoint.Upper
	checkpoint.Context.Expires = checkpoint.Watermark
	if _, err := Deadline(checkpoint, now, 1); err == nil {
		test.Fatal("exclusive qualification expiry")
	}
	checkpoint.Context.Expires = "2027-01-15T08:00:00Z"
	checkpoint.Incident = "held"
	if _, err := Deadline(checkpoint, now, 1); err == nil {
		test.Fatal("held use")
	}
}

// Claim: C1 only evaluates a new empty scope beyond retirement/refusal floors; ordinary incidents, reuse, imports and unqualified sticky sources remain closed.
func TestLabBurnedRecovery(test *testing.T) {
	var checkpoint Checkpoint
	frozen(test, CheckpointFormat, &checkpoint)
	old := checkpoint.Context
	checkpoint.Context.Installation = "fresh-installation"
	checkpoint.Scope = "fresh-scope"
	checkpoint.Watermark = checkpoint.Upper
	digest := Digest([]byte("off-vm-recovery-evidence"))
	recovery := Recovery{Old: old, New: checkpoint.Context, OldScope: "retired-scope", NewScope: checkpoint.Scope, EvidenceDigest: digest, RetirementDigest: digest, RevocationDigest: digest, ReplacementDigest: digest, PolicyDigest: digest, Reason: "restore", RetiredAt: instant(checkpoint.Lower).Add(-time.Second), Floors: []time.Time{instant(checkpoint.Lower).Add(-time.Nanosecond)}}
	for name, mutate := range map[string]func(*Recovery){
		"ordinary-hold":       func(value *Recovery) { value.Reason = "time-hold" },
		"missing-revocation":  func(value *Recovery) { value.RevocationDigest = "" },
		"shared-consumer":     func(value *Recovery) { value.OtherConsumers = 1 },
		"reused-installation": func(value *Recovery) { value.New.Installation = value.Old.Installation },
		"reused-scope":        func(value *Recovery) { value.NewScope = value.OldScope },
		"overlapping-floor":   func(value *Recovery) { value.Floors = []time.Time{instant(checkpoint.Lower)} },
		"missing-floor":       func(value *Recovery) { value.Floors = []time.Time{{}} },
		"expiry-extended":     func(value *Recovery) { value.New.Expires = "2028-01-15T08:00:00Z" },
		"sticky-source":       func(value *Recovery) { value.SourceIncident = true },
	} {
		test.Run(name, func(test *testing.T) {
			if CheckRecovery(recovery, checkpoint, true) != nil {
				test.Fatal("fresh recovery control")
			}
			candidate := recovery
			mutate(&candidate)
			if CheckRecovery(candidate, checkpoint, true) == nil {
				test.Fatal("invalid recovery")
			}
		})
	}
	if CheckRecovery(recovery, checkpoint, false) == nil {
		test.Fatal("imported history")
	}
}

// Claim: high-water metadata preserves the exact manager prefix, checkpoint, watermark and holds; every independently changed join refuses.
func TestLabFloorContinuity(test *testing.T) {
	var old Floor
	frozen(test, FloorFormat, &old)
	var checkpoint Checkpoint
	frozen(test, CheckpointFormat, &checkpoint)
	_, journal, prior := managerJournal(test)
	old.Manager, old.Previous, old.Persisted = prior, prior, true
	old.Context = checkpoint.Context
	old.Holds = []string{}
	old.Watermark = "2026-11-20T07:59:59Z"
	checkpoint.Watermark = checkpoint.Upper
	raw := encoded(test, checkpoint)
	manager, err := ManagerExtension(journal, prior)
	if err != nil {
		test.Fatal(err)
	}
	next := old
	next.Manager, next.Previous, next.Checkpoint, next.Watermark = manager, prior, Digest(raw), checkpoint.Watermark
	next.Holds = []string{}
	for name, mutate := range map[string]func(*Floor){
		"reset-prefix":         func(value *Floor) { value.Previous = Head{SHA256: "sha256:" + genjournal.ZeroHash} },
		"wrong-manager":        func(value *Floor) { value.Manager = prior },
		"wrong-checkpoint":     func(value *Floor) { value.Checkpoint = Digest([]byte("other")) },
		"not-persisted":        func(value *Floor) { value.Persisted = false },
		"watermark-regression": func(value *Floor) { value.Watermark = "2026-11-20T07:00:00Z" },
		"retargeted":           func(value *Floor) { value.Context.Installation = "other" },
	} {
		test.Run(name, func(test *testing.T) {
			if CheckFloor(old, next, raw, journal) != nil {
				test.Fatal("valid floor")
			}
			candidate := next
			mutate(&candidate)
			if CheckFloor(old, candidate, raw, journal) == nil {
				test.Fatal("floor join widened")
			}
		})
	}
	old.Holds = []string{"sticky"}
	if CheckFloor(old, next, raw, journal) == nil {
		test.Fatal("sticky hold cleared")
	}
}
