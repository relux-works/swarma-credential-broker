//go:build linux && broker_lab

package labtimev0

import (
	"bytes"
	"slices"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type StartPins struct {
	Context                                                                       Context
	Heads                                                                         Heads
	DecisionDigest, ApprovalDigest, AccessDigest, ReleaseDigest, InvocationDigest string
	Generation                                                                    uint64
	Now                                                                           time.Time
	RefusalFloors                                                                 []time.Time
}

func CheckDecision(raw []byte, expected string, scope Context, now time.Time) error {
	var decision Decision
	if Decode(raw, &decision) != nil || Digest(raw) != expected || decision.Context != scope || now.IsZero() || !now.Before(instant(scope.Expires)) || !approved(raw, decision.Approval, now) || instant(decision.Recorded).After(now) || decision.Amendment != AmendmentDigest || decision.API != APIDigest || decision.Joins != JoinsDigest || !decision.Residual || len(decision.Roles) != 3 {
		return ErrClosed
	}
	roles := map[string]bool{}
	for _, role := range decision.Roles {
		if !role.Accepted || roles[role.Role] {
			return ErrClosed
		}
		roles[role.Role] = true
	}
	if !roles["repository"] || !roles["time-contract"] || !roles["user-manager"] {
		return ErrClosed
	}
	return nil
}

func CheckStart(decisionRaw, approvalRaw, fenceRaw []byte, previous *Fence, pins StartPins) error {
	var decision Decision
	var approval OffVM
	var fence Fence
	if Decode(decisionRaw, &decision) != nil || Decode(approvalRaw, &approval) != nil || Decode(fenceRaw, &fence) != nil {
		return ErrClosed
	}
	if pins.Now.IsZero() || Digest(decisionRaw) != pins.DecisionDigest || Digest(approvalRaw) != pins.ApprovalDigest || decision.Context != pins.Context || approval.Context != pins.Context || fence.Context != pins.Context {
		return ErrClosed
	}
	if CheckDecision(decisionRaw, pins.DecisionDigest, pins.Context, pins.Now) != nil || !approved(approvalRaw, approval.Approval, pins.Now) {
		return ErrClosed
	}
	if approval.Access != pins.AccessDigest || approval.Release != pins.ReleaseDigest || approval.Invocation != pins.InvocationDigest || approval.Generation != pins.Generation || fence.Generation != pins.Generation || fence.ApprovalDigest != pins.ApprovalDigest || fence.Consumed || approval.Heads != pins.Heads || fence.Heads != pins.Heads {
		return ErrClosed
	}
	if instant(approval.Now).Before(instant(approval.Approval.At)) || instant(approval.Now).After(pins.Now) {
		return ErrClosed
	}
	if previous == nil {
		if fence.State != "fresh" || fence.Generation != 1 {
			return ErrClosed
		}
	} else {
		if previous.Context != pins.Context || !previous.Consumed || previous.State != "orderly-stop" || previous.Generation >= 9007199254740991 || fence.Generation != previous.Generation+1 || fence.State != "orderly-stop" || previous.Heads != pins.Heads {
			return ErrClosed
		}
	}
	for _, now := range append([]time.Time{pins.Now, instant(approval.Now)}, pins.RefusalFloors...) {
		if now.IsZero() || !now.Before(instant(pins.Context.Expires)) {
			return ErrClosed
		}
	}
	return nil
}

func ManagerExtension(journal []byte, prior Head) (Head, error) {
	if !patterns["digest"].MatchString(prior.SHA256) || prior.Sequence > 9007199254740991 {
		return Head{}, ErrClosed
	}
	view, err := genjournal.Verify(bytes.NewReader(journal), genjournal.Floor{Seq: int64(prior.Sequence), Hash: strings.TrimPrefix(prior.SHA256, "sha256:")})
	if err != nil || view.Capacity() != nil {
		return Head{}, ErrClosed
	}
	return Head{uint64(view.Tail.Seq), "sha256:" + view.Tail.Hash}, nil
}

func CheckFloor(old Floor, next Floor, checkpointRaw, journal []byte) error {
	var checkpoint Checkpoint
	if canonicalCopy(old, &Floor{}) != nil || canonicalCopy(next, &Floor{}) != nil || Decode(checkpointRaw, &checkpoint) != nil {
		return ErrClosed
	}
	head, err := ManagerExtension(journal, old.Manager)
	if err != nil || !old.Persisted || !next.Persisted || next.Context != old.Context || next.Context != checkpoint.Context || next.Previous != old.Manager || next.Manager != head || next.Checkpoint != Digest(checkpointRaw) || instant(next.Watermark).Before(instant(old.Watermark)) || next.Watermark != checkpoint.Watermark {
		return ErrClosed
	}
	if !slices.Equal(next.Holds, checkpoint.Holds) || !containsAll(next.Holds, old.Holds) || !unique(next.Holds) {
		return ErrClosed
	}
	return nil
}

func CheckCheckpoint(old Checkpoint, oldHead Head, next Checkpoint, rebootQualified bool) error {
	if canonicalCopy(old, &Checkpoint{}) != nil || canonicalCopy(next, &Checkpoint{}) != nil {
		return ErrClosed
	}
	raw, _ := Encode(old)
	if oldHead.SHA256 != Digest(raw) || oldHead.Sequence >= 9007199254740991 || next.Previous != oldHead || next.Context != old.Context || next.Scope != old.Scope || next.Inventory != old.Inventory || old.Incident == "burned" {
		return ErrClosed
	}
	if !unique(next.Holds) || !containsAll(next.Holds, old.Holds) || old.Incident == "held" && next.Incident != "held" && next.Incident != "burned" {
		return ErrClosed
	}
	if instant(next.Watermark).Before(instant(old.Watermark)) || next.Boot == old.Boot && next.Monotonic < old.Monotonic {
		return ErrClosed
	}
	if next.Boot != old.Boot && !rebootQualified {
		return ErrClosed
	}
	if next.Settled {
		if next.Incident != "none" || len(next.Holds) != 0 || !instant(next.Lower).After(instant(old.Watermark)) || instant(next.Upper).Before(instant(next.Lower)) || instant(next.Watermark).Before(instant(next.Upper)) || !instant(next.Watermark).Before(instant(next.Context.Expires)) {
			return ErrClosed
		}
	} else if next.Incident == "none" {
		return ErrClosed
	}
	return nil
}

func containsAll(next, prior []string) bool {
	for _, item := range prior {
		if !slices.Contains(next, item) {
			return false
		}
	}
	return true
}

func unique(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func Deadline(checkpoint Checkpoint, now time.Time, lifetime int, authorityBounds ...time.Time) (time.Time, error) {
	if canonicalCopy(checkpoint, &Checkpoint{}) != nil || lifetime < 1 || lifetime > 900 || !checkpoint.Settled || checkpoint.Incident != "none" || len(checkpoint.Holds) != 0 || now.IsZero() || now.Before(instant(checkpoint.Lower)) || now.After(instant(checkpoint.Upper)) {
		return time.Time{}, ErrClosed
	}
	until := now.Add(time.Duration(lifetime) * time.Second)
	for _, bound := range append(authorityBounds, instant(checkpoint.Context.Expires)) {
		if bound.IsZero() || !now.Before(bound) || !instant(checkpoint.Watermark).Before(bound) {
			return time.Time{}, ErrClosed
		}
		if bound.Before(until) {
			until = bound
		}
	}
	return until, nil
}

type Recovery struct {
	Old, New                                                                            Context
	OldScope, NewScope                                                                  string
	EvidenceDigest, RetirementDigest, RevocationDigest, ReplacementDigest, PolicyDigest string
	Reason                                                                              string
	RetiredAt                                                                           time.Time
	Floors                                                                              []time.Time
	OtherConsumers                                                                      int
	SourceIncident                                                                      bool
	SourceRequalified                                                                   bool
}

func CheckRecovery(recovery Recovery, first Checkpoint, newHistoryEmpty bool) error {
	if canonicalCopy(first, &Checkpoint{}) != nil || !newHistoryEmpty || recovery.Old.Installation == recovery.New.Installation || recovery.OldScope == recovery.NewScope || first.Context != recovery.New || first.Scope != recovery.NewScope || recovery.Old.Machine != recovery.New.Machine || recovery.Old.VM != recovery.New.VM || recovery.Old.Account != recovery.New.Account || recovery.Old.Expires != recovery.New.Expires || recovery.OtherConsumers != 0 || !slices.Contains([]string{"restore", "clone", "regression"}, recovery.Reason) {
		return ErrClosed
	}
	for _, digest := range []string{recovery.EvidenceDigest, recovery.RetirementDigest, recovery.RevocationDigest, recovery.ReplacementDigest, recovery.PolicyDigest} {
		if !patterns["digest"].MatchString(digest) {
			return ErrClosed
		}
	}
	if !patterns["id"].MatchString(recovery.OldScope) || !patterns["id"].MatchString(recovery.NewScope) || recovery.SourceIncident && !recovery.SourceRequalified || !first.Settled || first.Incident != "none" || len(first.Holds) != 0 || first.Previous.Sequence != 0 {
		return ErrClosed
	}
	for _, floor := range append([]time.Time{recovery.RetiredAt}, recovery.Floors...) {
		if floor.IsZero() || !instant(first.Lower).After(floor) || !floor.Before(instant(first.Context.Expires)) {
			return ErrClosed
		}
	}
	if instant(first.Upper).Before(instant(first.Lower)) || instant(first.Watermark).Before(instant(first.Upper)) || !instant(first.Watermark).Before(instant(first.Context.Expires)) {
		return ErrClosed
	}
	return nil
}
