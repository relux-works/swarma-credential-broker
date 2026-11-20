"""Replay bounded B2 source overlays; never modify the tested checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


MUTANTS = [
    ("format", "internal/labtimev0/records_linux.go", "if text != grammar[1:] {", "if false {", "./internal/labcontractv0", "TestLabB2CatalogueGrammarPairs", "A01", "closed singleton format"),
    ("owner-role", "internal/labtimev0/continuity_linux.go", "!role.Accepted || roles[role.Role]", "roles[role.Role]", "./internal/labtimev0", "TestLabCOpening", "A06", "every named owner role accepts"),
    ("fence-replay", "internal/labtimev0/continuity_linux.go", "|| fence.Consumed ||", "||", "./internal/labtimev0", "TestLabStartJoins", "A06", "consumed fence cannot authorize another start"),
    ("exact-heads", "internal/labtimev0/continuity_linux.go", "|| fence.Heads != pins.Heads", "", "./internal/labtimev0", "TestLabStartJoins", "A06", "off-VM and fence heads equal independent pins"),
    ("off-home", "internal/labtimev0/fence_linux.go", "return path != home && !strings.HasPrefix(path, home+\"/\") && !strings.HasPrefix(home, filepath.Dir(path)+\"/\") && filepath.Dir(path) != home", "return true", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "even a regular protected fence inside home refuses"),
    ("fence-mode", "internal/labtimev0/fence_linux.go", "before.Mode != unix.S_IFREG|0644", "before.Mode & unix.S_IFMT != unix.S_IFREG", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "fence mode must be exactly 0644"),
    ("fence-group", "internal/labtimev0/fence_linux.go", "|| before.Gid != group", "", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "fence group must match the protected root group"),
    ("watermark", "internal/labtimev0/continuity_linux.go", "!instant(next.Lower).After(instant(old.Watermark))", "instant(next.Lower).Before(instant(old.Watermark))", "./internal/labtimev0", "TestLabCheckpointContinuity", "A06", "lower bound must strictly exceed retained W"),
    ("manager-prefix", "internal/labtimev0/continuity_linux.go", "genjournal.Floor{Seq: int64(prior.Sequence), Hash: strings.TrimPrefix(prior.SHA256, \"sha256:\")}", "genjournal.Floor{Seq: 0, Hash: strings.TrimPrefix(\"sha256:\"+genjournal.ZeroHash, \"sha256:\")}", "./internal/labtimev0", "TestLabManagerPrefix", "A06", "well-formed alternate history is not an extension"),
    ("floor-prefix", "internal/labtimev0/continuity_linux.go", "|| next.Previous != old.Manager", "", "./internal/labtimev0", "TestLabFloorContinuity", "A06", "publication retains the prior verified prefix"),
    ("witness-cas", "internal/labtimev0/consumer_linux.go", "|| current != old ||", "|| current.Generation < old.Generation ||", "./internal/labtimev0", "TestLabWitnessDurableCAS", "A06", "CAS compares the exact old durable head"),
    ("floor-sync", "internal/labtimev0/consumer_linux.go", "|| session.LabSync(session.LabDir(), \"lab-floor-current\") != nil", "", "./internal/labtimev0", "TestLabFloorDurabilityFaults", "A06", "receipt release executes the directory sync boundary"),
    ("nts-only", "timeconf/provider.go", "!e.Sources.AllNTS ||", "", "./internal/labtimev0", "TestLabConsumerAuthenticatedNTS", "A06", "plain NTP cannot supply an authenticated settlement"),
    ("sticky-floor", "internal/labtimev0/consumer_linux.go", "floor.Holds, floor.Checkpoint = append([]string(nil), checkpoint.Holds...), sum(checkpointRaw)", "floor.Checkpoint = sum(checkpointRaw)", "./internal/labtimev0", "TestLabConsumerStickyRestart", "A06", "C0 incident publication retains the sticky hold"),
    ("burned-reopen", "internal/labtimev0/consumer_linux.go", "\"lab-burned\", &stat", "\"lab-no-burn\", &stat", "./internal/labtimev0", "TestLabBurnPersists", "A06", "durable burn closes reconstructed consumers"),
    ("start-burn", "internal/labtimev0/consumer_linux.go", "floor.Manager != expected.Manager {\n\t\treturn lab.burn(ctx)", "floor.Manager != expected.Manager {\n\t\treturn ErrUnavailable", "./internal/labtimev0", "TestLabStartContinuityBurn", "A06", "verified off-VM head mismatch durably burns"),
    ("c1-hold-reset", "internal/labtimev0/continuity_linux.go", "|| !slices.Contains([]string{\"restore\", \"clone\", \"regression\"}, recovery.Reason)", "", "./internal/labtimev0", "TestLabBurnedRecovery", "A06", "C1 is not an ordinary hold reset route"),
    ("qualification-expiry", "internal/labtimev0/continuity_linux.go", "|| !instant(checkpoint.Watermark).Before(bound)", "", "./internal/labtimev0", "TestLabQualificationDeadline", "A07", "settled W must be strictly below exclusive expiry"),
    ("build-graph", "internal/assemblyv0/importgraph_test.go", "if !allowed {", "if false && !allowed {", "./internal/assemblyv0", "TestInactiveImportGraphBuildTagControlsLabTime", "A01", "graph instrument detects a planted default import"),
    ('owner-deadline', 'internal/labtimev0/fence_linux.go', 'instant(decision.Approval.Expires), ', '', './internal/labtimev0', 'TestLabPublicApprovalExpiry', 'A06', 'earliest owner expiry survives start'),
    ('offvm-deadline', 'internal/labtimev0/fence_linux.go', ', instant(approval.Approval.Expires)', '', './internal/labtimev0', 'TestLabPublicApprovalExpiry', 'A06', 'earliest off-VM approval expiry survives start'),
    ('use-expiry', 'internal/labtimev0/consumer_linux.go', '|| lab.start != nil && !upper.Before(lab.start.Deadline())', '', './internal/labtimev0', 'TestLabPublicApprovalExpiry', 'A06', 'every fresh settled upper/W is below the exclusive approval deadline'),
    ('start-marker', 'internal/labtimev0/consumer_linux.go', 'if session.LabWrite(ctx, name, []byte(FenceFormat), "lab-start") != nil {', 'if _ = name; false {', './internal/labtimev0', 'TestLabPublicLifecycle', 'A06', 'each generation constructs once durably'),
    ('consume-current', 'internal/labtimev0/consumer_linux.go', '|| lab.start.Current(ctx) != nil {', '{', './internal/labtimev0', 'TestLabPublicLifecycle', 'A06', 'every public use rechecks the fence'),
    ('refusal-floors', 'internal/labtimev0/consumer_linux.go', 'request.JournalFloor = max(request.JournalFloor, floor.UnixNano())', '_ = floor', './internal/labtimev0', 'TestLabPublicRefusalFloors', 'A06', 'C1 floor participates in settlement'),
    ('provision-empty', 'internal/labtimev0/consumer_linux.go', 'if err != nil || len(entries) != 0 {', 'if _ = entries; err != nil {', './internal/labtimev0', 'TestLabPublicProvisionRefusals', 'A06', 'no adoption of nonempty roots'),
    ('prepare-decision', 'internal/labtimev0/consumer_linux.go', '|| CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, clock.Now) != nil', '|| false && CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, clock.Now) != nil', './internal/labtimev0', 'TestLabPublicProvisionRefusals', 'A06', 'consent verified before any genesis write'),
    ('start-heads-join', 'internal/labtimev0/consumer_linux.go', 'if err := lab.checkStartHeads(ctx, start.Heads()); err != nil {', 'if err := error(nil); err != nil {', './internal/labtimev0', 'TestLabPublicStartTransientRefusal', 'A06', 'public construction enforces off-VM continuity join'),
    ('start-unknown-burn', 'internal/labtimev0/consumer_linux.go', 'Decode(checkpointRaw, &checkpoint) != nil || ctx.Err() != nil {\n\t\treturn ErrUnavailable', 'Decode(checkpointRaw, &checkpoint) != nil || ctx.Err() != nil {\n\t\treturn lab.burn(ctx)', './internal/labtimev0', 'TestLabPublicStartTransientRefusal', 'A06', 'unknown read/lock failures are not verified burn evidence'),
    ('journal-unknown-burn', 'internal/labtimev0/consumer_linux.go', 'if errors.Is(err, ErrRegression) {', 'if err != nil {', './internal/labtimev0', 'TestLabUnverifiedJournalRefusal', 'A06', 'unverified journal error never burns'),
    ('journal-complete-first', 'internal/labtimev0/continuity_linux.go', 'if err != nil || complete.Capacity() != nil {', 'if false && (err != nil || complete.Capacity() != nil) {', './internal/labtimev0', 'TestLabUnverifiedJournalRefusal', 'A06', 'entire journal verified before interpreting prefix mismatch'),
    ('journal-regression-burn', 'internal/labtimev0/consumer_linux.go', 'if errors.Is(err, ErrRegression) {', 'if false && errors.Is(err, ErrRegression) {', './internal/labtimev0', 'TestLabPublicVerifiedForkBurn', 'A06', 'verified manager fork burns durably'),
    ('restart-generation', 'internal/labtimev0/continuity_linux.go', '|| fence.Generation != previous.Generation+1', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'restart cannot skip a generation'),
    ('restart-heads', 'internal/labtimev0/continuity_linux.go', '|| previous.Heads != pins.Heads', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'acknowledged stop heads equal advanced off-VM pins'),
    ('restart-state', 'internal/labtimev0/continuity_linux.go', '|| previous.State != "orderly-stop"', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'restart requires acknowledged orderly stop'),
    ('approval-generation', 'internal/labtimev0/continuity_linux.go', '|| approval.Generation != pins.Generation', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'per-start approval belongs to this generation'),
    ('approval-invocation', 'internal/labtimev0/continuity_linux.go', '|| approval.Invocation != pins.InvocationDigest', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'per-start approval binds exact invocation'),
    ('offvm-clock-order', 'internal/labtimev0/continuity_linux.go', '|| instant(approval.Now).After(pins.Now)', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'off-VM clock cannot exceed independent now'),
    ('offvm-clock-before', 'internal/labtimev0/continuity_linux.go', 'instant(approval.Now).Before(instant(approval.Approval.At))', 'false', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'off-VM clock cannot precede approval'),
    ('decision-digest', 'internal/labtimev0/continuity_linux.go', '|| Digest(raw) != expected', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'owner decision equals independent digest pin'),
    ('burn-persistence', 'internal/labtimev0/consumer_linux.go', 'errors.Join(ErrUnavailable, errBurnPersistence)', 'ErrUnavailable', './internal/labtimev0', 'TestLabBurnPersistenceRefusal', 'A06', 'burn persistence uncertainty is surfaced'),
    ('prepare-settled-lower', 'internal/labtimev0/consumer_linux.go', '|| CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, instant(checkpoint.Lower)) != nil', '', './internal/labtimev0', 'TestLabPublicProvisionRefusals', 'A06', 'settled lower cannot precede owner approval'),
    ('prepare-settled-upper', 'internal/labtimev0/consumer_linux.go', '|| CheckDecision(decisionRaw, enrollment.Authority.QualificationDigest, scope, instant(checkpoint.Upper)) != nil', '', './internal/labtimev0', 'TestLabPublicProvisionRefusals', 'A06', 'settled upper is below exclusive owner expiry'),
    ('heads-after-failure', 'internal/labtimev0/consumer_linux.go', 'defer lab.mu.Unlock()\n\tif lab.failed {', 'defer lab.mu.Unlock()\n\tif false && lab.failed {', './internal/labtimev0', 'TestLabPublicApprovalExpiry', 'A06', 'failed consumption cannot export stop-seal heads'),
    ('heads-after-burn', 'internal/labtimev0/consumer_linux.go', 'if unix.Fstatat(int(session.LabDir().Fd()), "lab-burned", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {\n\t\treturn Heads{}, ErrUnavailable', 'if unix.Fstatat(int(session.LabDir().Fd()), "lab-no-burn", &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {\n\t\treturn Heads{}, ErrUnavailable', './internal/labtimev0', 'TestLabPublicVerifiedForkBurn', 'A06', 'durable burn also closes head export after memory reconstruction'),
    ('restart-ack', 'internal/labtimev0/continuity_linux.go', '|| !previous.Consumed', '', './internal/labtimev0', 'TestLabStartJoins', 'A06', 'later start requires stop acknowledgement'),
    ('approval-heads', 'internal/labtimev0/continuity_linux.go', '|| approval.Heads != pins.Heads', '', './internal/labtimev0', 'TestLabRestartChainRefusals', 'A06', 'off-VM approval itself binds independent current heads'),
    ('enroll-authority-id', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif false || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Authority.ID != LabAuthority refuses before runtime selection or storage effects'),
    ('enroll-authority-version', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || false || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Authority.Version != "1" refuses before runtime selection or storage effects'),
    ('enroll-decision-pin', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || false || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Authority.QualificationDigest != start.DecisionDigest() refuses before runtime selection or storage effects'),
    ('enroll-trust-root', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || false || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Authority.TrustRootDigest != AmendmentDigest refuses before runtime selection or storage effects'),
    ('enroll-machine', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || false || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Scope.Machine != scope.Machine refuses before runtime selection or storage effects'),
    ('enroll-consumer', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || false || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Scope.Consumer != scope.Installation refuses before runtime selection or storage effects'),
    ('enroll-purpose', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || false || enrollment.Scope.ContinuityScope != scope.Installation {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Scope.Purpose != "broker-lab" refuses before runtime selection or storage effects'),
    ('enroll-continuity-scope', 'internal/labtimev0/consumer_linux.go', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || enrollment.Scope.ContinuityScope != scope.Installation {', '\tif enrollment.Authority.ID != LabAuthority || enrollment.Authority.Version != "1" || enrollment.Authority.QualificationDigest != start.DecisionDigest() || enrollment.Authority.TrustRootDigest != AmendmentDigest || enrollment.Scope.Machine != scope.Machine || enrollment.Scope.Consumer != scope.Installation || enrollment.Scope.Purpose != "broker-lab" || false {', './internal/labtimev0', 'TestLabPublicConstructorEnrollmentJoins', 'A06', 'public enrollment.Scope.ContinuityScope != scope.Installation refuses before runtime selection or storage effects'),
    ('construct-current', 'internal/labtimev0/consumer_linux.go', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', '\tif start == nil || false || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', './internal/labtimev0', 'TestLabPublicConstructorCurrentJoin', 'A06', 'public start.Current(ctx) != nil enforced before runtime selection'),
    ('construct-source', 'internal/labtimev0/consumer_linux.go', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', '\tif start == nil || start.Current(ctx) != nil || false || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', './internal/labtimev0', 'TestLabPublicConstructorInputJoins', 'A06', 'public policy.Source != NTSAuthData enforced before runtime selection'),
    ('construct-resync', 'internal/labtimev0/consumer_linux.go', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || false || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', './internal/labtimev0', 'TestLabPublicConstructorInputJoins', 'A06', 'public policy.Resync != "operator" enforced before runtime selection'),
    ('construct-roots', 'internal/labtimev0/consumer_linux.go', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || false || !digestPattern.MatchString(inventoryDigest) {', './internal/labtimev0', 'TestLabPublicConstructorInputJoins', 'A06', 'public !separateLabRoots(root, witnessRoot) enforced before runtime selection'),
    ('construct-inventory-format', 'internal/labtimev0/consumer_linux.go', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || !digestPattern.MatchString(inventoryDigest) {', '\tif start == nil || start.Current(ctx) != nil || policy.Source != NTSAuthData || policy.Resync != "operator" || !separateLabRoots(root, witnessRoot) || false {', './internal/labtimev0', 'TestLabPublicConstructorInputJoins', 'A06', 'public !digestPattern.MatchString(inventoryDigest) enforced before runtime selection'),
    ('inventory-join', 'internal/labtimev0/consumer_linux.go', '\tif checkpoint.Inventory != lab.inventory {\n\t\treturn ErrUnavailable\n\t}', '\tif false {\n\t\treturn ErrUnavailable\n\t}', './internal/labtimev0', 'TestLabPublicConstructorInventoryRefusal', 'A06', 'caller inventory must equal provisioned inventory'),
    ('inventory-burn', 'internal/labtimev0/consumer_linux.go', '\tif checkpoint.Inventory != lab.inventory {\n\t\treturn ErrUnavailable\n\t}', '\tif checkpoint.Inventory != lab.inventory {\n\t\treturn lab.burn(ctx)\n\t}', './internal/labtimev0', 'TestLabPublicConstructorInventoryRefusal', 'A06', 'caller inventory mismatch refuses without verified burn'),
    ('spent-start-first', 'internal/labtimev0/consumer_linux.go', '\tif markerErr != unix.ENOENT {', '\tif false && markerErr != unix.ENOENT {', './internal/labtimev0', 'TestLabPublicConstructorSpentStart', 'A06', 'spent generation refuses before stale-head burn join'),
    ('prepare-journal', 'internal/labtimev0/consumer_linux.go', '\tif err != nil {\n\t\treturn Heads{}, ErrUnavailable\n\t}\n\tif err := lab.provision(ctx, witnessRoot); err != nil {', '\tif false && err != nil {\n\t\treturn Heads{}, ErrUnavailable\n\t}\n\tif err := lab.provision(ctx, witnessRoot); err != nil {', './internal/labtimev0', 'TestLabPublicPrepareJournalJoin', 'A06', 'unverified prepare history refuses before genesis'),
    ('prepare-journal-before-write', 'internal/labtimev0/consumer_linux.go', '\tmanager, err := ManagerExtension(journal, Head{SHA256: "sha256:" + strings.Repeat("0", 64)})\n\tif err != nil {\n\t\treturn Heads{}, ErrUnavailable\n\t}\n\tif err := lab.provision(ctx, witnessRoot); err != nil {\n\t\treturn Heads{}, err\n\t}\n', '\tif err := lab.provision(ctx, witnessRoot); err != nil {\n\t\treturn Heads{}, err\n\t}\n\tmanager, err := ManagerExtension(journal, Head{SHA256: "sha256:" + strings.Repeat("0", 64)})\n\tif err != nil {\n\t\treturn Heads{}, ErrUnavailable\n\t}\n', './internal/labtimev0', 'TestLabPublicPrepareJournalJoin', 'A06', 'unverified prepare leaves both roots empty'),
    ('current-length-construct', 'internal/labtimev0/fence_linux.go', '!bytes.Equal(raw, start.raw)', 'len(raw) != len(start.raw) || bytes.Equal(raw, nil)', './internal/labtimev0', 'TestLabPublicConstructorCurrentJoin', 'A06', 'public construct currentness reduced to length only'),
    ('current-semantic-construct', 'internal/labtimev0/fence_linux.go', '!bytes.Equal(raw, start.raw)', 'func() bool { var fence Fence; return Decode(raw, &fence) != nil || !fence.Consumed || fence.Generation != start.Generation() || fence.Context != start.Context() || bytes.Equal(raw, nil) }()', './internal/labtimev0', 'TestLabPublicConstructorCurrentJoin', 'A06', 'public construct currentness reduced to valid fence grammar and same consumed/generation/context fields'),
    ('current-length-use', 'internal/labtimev0/fence_linux.go', '!bytes.Equal(raw, start.raw)', 'len(raw) != len(start.raw) || bytes.Equal(raw, nil)', './internal/labtimev0', 'TestLabPublicUseCurrentJoin', 'A06', 'public use currentness reduced to length only'),
    ('current-semantic-use', 'internal/labtimev0/fence_linux.go', '!bytes.Equal(raw, start.raw)', 'func() bool { var fence Fence; return Decode(raw, &fence) != nil || !fence.Consumed || fence.Generation != start.Generation() || fence.Context != start.Context() || bytes.Equal(raw, nil) }()', './internal/labtimev0', 'TestLabPublicUseCurrentJoin', 'A06', 'public use currentness reduced to valid fence grammar and same consumed/generation/context fields'),
]


EXPECTED_FAILURES = {'format': 'operator member-0-literal-empty admit false',
 'owner-role': 'consent widened',
 'fence-replay': 'start admitted',
 'exact-heads': 'start admitted',
 'off-home': 'regular home fence admitted',
 'fence-mode': 'wrong fence mode admitted',
 'fence-group': 'wrong fence group admitted',
 'watermark': 'invalid settlement',
 'manager-prefix': 'nonextension admitted',
 'floor-prefix': 'floor join widened',
 'witness-cas': 'stale CAS',
 'floor-sync': 'durability fault not enforced false <nil>',
 'nts-only': 'unqualified source admitted',
 'sticky-floor': 'C0 floor omitted sticky incident',
 'burned-reopen': 'burned scope reopened',
 'start-burn': 'missing durable burn',
 'c1-hold-reset': 'invalid recovery',
 'qualification-expiry': 'exclusive qualification expiry',
 'build-graph': 'default lab import plant not detected',
 'owner-deadline': 'exclusive approval deadline missing',
 'offvm-deadline': 'exclusive approval deadline missing',
 'use-expiry': 'expired approval released receipt',
 'start-marker': 'per-start replay admitted',
 'consume-current': 'changed fence admitted',
 'refusal-floors': 'C1 refusal floor bypass',
 'provision-empty': 'invalid public provision admitted',
 'prepare-decision': 'refused provisioning wrote genesis',
 'start-heads-join': 'transient start did not refuse',
 'start-unknown-burn': 'transient start burned installation',
 'journal-unknown-burn': 'unverified journal burned installation',
 'journal-complete-first': 'unverified journal burned installation',
 'journal-regression-burn': 'verified fork not burned',
 'decision-digest': 'decision digest pin bypass',
 'restart-generation': 'restart chain bypass',
 'restart-heads': 'restart chain bypass',
 'restart-state': 'restart chain bypass',
 'approval-generation': 'restart chain bypass',
 'approval-invocation': 'restart chain bypass',
 'offvm-clock-order': 'restart chain bypass',
 'offvm-clock-before': 'restart chain bypass',
 'burn-persistence': 'burn persistence error hidden',
 'prepare-settled-lower': 'invalid public provision admitted',
 'prepare-settled-upper': 'invalid public provision admitted',
 'heads-after-failure': 'failed use exported seal heads',
 'heads-after-burn': 'burned heads exported',
 'restart-ack': 'unacknowledged restart',
 'approval-heads': 'restart chain bypass',
 'enroll-authority-id': 'constructor enrollment join bypass',
 'enroll-authority-version': 'constructor enrollment join bypass',
 'enroll-decision-pin': 'constructor enrollment join bypass',
 'enroll-trust-root': 'constructor enrollment join bypass',
 'enroll-machine': 'constructor enrollment join bypass',
 'enroll-consumer': 'constructor enrollment join bypass',
 'enroll-purpose': 'constructor enrollment join bypass',
 'enroll-continuity-scope': 'constructor enrollment join bypass',
 'construct-current': 'constructor currentness join bypass',
 'construct-source': 'constructor input join bypass',
 'construct-resync': 'constructor input join bypass',
 'construct-roots': 'constructor input join bypass',
 'construct-inventory-format': 'constructor input join bypass',
 'inventory-join': 'constructor inventory join bypass',
 'inventory-burn': 'caller inventory burned installation',
 'spent-start-first': 'spent start replay burned installation',
 'prepare-journal': 'unverified prepare journal admitted',
 'prepare-journal-before-write': 'unverified prepare wrote genesis',
 'current-length-construct': 'constructor currentness join bypass',
 'current-semantic-construct': 'constructor currentness join bypass',
 'current-length-use': 'well-formed replacement admitted at use',
 'current-semantic-use': 'well-formed replacement admitted at use',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    work = Path.cwd().resolve()
    out = args.out.resolve()
    root = work.parent
    if work.name != "work" or root.name != ".temp" or not out.is_relative_to(root):
        parser.error("run from physical task .temp/work; outputs must be inside that .temp")
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR"):
        value = Path(os.environ.get(name, ""))
        if not value.is_absolute() or not value.resolve().is_relative_to(root):
            parser.error(name + " must be an absolute task-local path")
    out.mkdir(parents=True, exist_ok=False)
    results = []
    for name, relative, old, new, package, test, row, bound in MUTANTS:
        directory = out / name
        directory.mkdir()
        original = work / relative
        source = original.read_text()
        count = source.count(old)
        expected = {"burned-reopen": 3, "burn-persistence": 2}.get(name, 1)
        if count != expected:
            raise RuntimeError(name + ": source anchor count " + str(count))
        replacement = directory / original.name
        replacement.write_text(source.replace(old, new))
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(original): str(replacement)}}))
        command = [os.environ.get("GO", "go"), "test", "-count=1", "-tags", "broker_lab", "-overlay", str(overlay), package, "-run", "^" + test + "$"]
        with (directory / "test.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            (directory / "pid").write_text(str(process.pid) + "\n")
            exit_code = process.wait()
        text = (directory / "test.log").read_text(errors="replace")
        named = "--- FAIL: " + test + " " in text
        invalid = any(marker in text for marker in ("[build failed]", "[setup failed]", "panic:", "fatal error:", "qualified_time_refused: deadline"))
        intended = EXPECTED_FAILURES[name] in text
        verdict = "KILLED" if exit_code != 0 and named and intended and not invalid else "SURVIVED_OR_INVALID"
        result = dict(mutant=name, row=row, bound=bound, test=test, exit=exit_code, verdict=verdict,
                      command=command, expected_failure=EXPECTED_FAILURES[name], source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                      overlay_sha256=hashlib.sha256(replacement.read_bytes()).hexdigest())
        (directory / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
        results.append(result)
        print(name, verdict, "exit=" + str(exit_code), test, flush=True)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    lines = ["| Mutant | Row | Gate narrowed to | Named failing test | Exit | Verdict |", "|---|---|---|---|---|---|"]
    lines.extend("| {mutant} | {row} | {bound} | `{test}` | {exit} | {verdict} |".format(**result) for result in results)
    (out / "results.md").write_text("\n".join(lines) + "\n")
    return 0 if all(result["verdict"] == "KILLED" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
