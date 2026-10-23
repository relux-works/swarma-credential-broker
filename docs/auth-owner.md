# Contained refresh owner

The Linux `authowner.Engine` implements `owner.Owner`. It accepts protected
fresh-enrolment state, an approved executable tuple, a contained `Manager` and
independent `Confidence`. It never adopts an existing login, performs OAuth
itself, creates a qualification, or repairs a missing vendor store. The command
continues to use the stopped owner until separate activation gates are met.

The existing store holds its singleton and account locks for the lifetime of the
adapter; a stable per-home lock remains held through execution, absence, durable
reload and reconciliation. `Close` joins admitted work before releasing it.
Per-account gates serialize work without holding state mutexes over I/O.

The real manager requires a named active service, a successful token-free
empty-home echo probe for the exact boot/manager epoch, and membership of the
owner process in that daemon's cgroup. `Probe` reports its unique allocated name
for cleanup accounting. `Start` checks the executable digest immediately before
D-Bus submission. Readback checks required properties, argv, environment and
working directory before any managed-auth request. There is no shell launcher.

Every refresh publishes a pending checkpoint and immutable intent before service
admission. The pending marker detects loss of even an intent with no later
records. Immutable evidence uses increasing attempt revisions and account-wide
sequences; the checkpoint's retained count detects holes in old history. No
resolved history is discarded. Admission closes at the configured attempt bound
(default 1024), leaving retirement to a separate explicit administrative action.
An uncertain start is followed only by lookup of that recorded unit name.

The client sends `initialize`, `initialized`, and
`account/read {"refreshToken":true}` over private manager-passed pipes. It reloads
material only from the protected, flushed vendor home after correlated absence.
Raw vendor errors never leave the RPC boundary. Plan values are limited to the
pinned schema's enum. RPC success alone, exit zero, file change, file equality,
PID disappearance or expiry cannot establish safe nonrotation.

A confirmed stop requires the original boot, manager epoch, invocation and
property digest, `Restart=no`, a correlated `JobRemoved(result=done)`, and empty
recursive membership with `cgroup.events populated=0`. Removal of a previously
verified cgroup is accepted only after that stop and complete manager readback.
Unknown observations hold the account unavailable. Changed epochs, missing
records and contradictory identities require external operator reconciliation;
a new manager's empty inventory cannot clear them. Fresh-home admission checks
retained intent epochs as well; no operator reconciliation ceremony is shipped.
Restore compares stable invocation, cgroup path/identity and property digest
across every supplied observation, including checkpointed resolved attempts.

Creation's `AddRef` belongs to its D-Bus connection. `Stop` acquires the current
connection's `RefUnit` before observation and stop, and retains it until `Unload`
after durable terminal evidence/checkpoint publication. References are counted;
creation and repeated stops reuse the connection's tracked reference, and explicit
unload releases it once. A missing unit, failed reference or lost connection
stays unknown. Autonomous collection before takeover
cannot be reconstructed as absence. This follows systemd's
[transient-unit lifecycle](https://www.freedesktop.org/software/systemd/man/257/org.freedesktop.systemd1.html)
and [sender-scoped unit references](https://github.com/systemd/systemd/blob/v257/src/core/dbus-unit.c).
The real-manager connection replacement regression closes the original connection,
stops through its replacement, verifies retained terminal readback and explicitly
unloads; its connected control and collected-unit refusal exercise the boundary.

## Normative trusted-time model

Independent confidence MUST come from outside the restored store's rollback
domain; there is no shipped always-fresh provider. The process-wide effective
time E is the maximum of every nonzero independently trusted sample observed in
this process and every account watermark observed here. E MUST never decrease.
Each account's durable decision time D is its persisted checkpoint watermark.
Only trusted time may raise D; clock correction MUST NOT lower either floor.

**Rule of action: use durable time only.** Material release and expiry refusal,
admission, retry/proactive scheduling, writer timestamps and resolution MUST use
D, never a later unpersisted sample. Before using a newer effective time, the
owner MUST raise that account's watermark successfully. A failed or interrupted
raise MUST refuse the action. After replacement, D is restored before admission;
observations that have not affected an action need not survive the old process.

A time admission MAY perform one initial watermark raise and at most one
catch-up raise to incorporate an observed completion sample. Every successful
raise MUST retain the shared before/after confidence checks. The final postcheck
MUST update E and require fresh, trusted, nonzero evidence whose exclusive
AuthorityUntil covers E. It MUST NOT substitute its later Now for D in any
numeric decision. A later valid sample is carried forward to the next time
admission; there is no write-until-the-clock-stops loop. The write cost is zero
when D already covers the observed floor, otherwise at most two checkpoint
writes per time admission, in addition to the attempt's existing record writes.

**Non-revival.** Once material is refused as expired at D = T, that refusal
MUST be supported by a successful durable watermark of at least T. The same
material MUST never be served after any later correction or replacement restart.
This is the sticky-watermark rule of [R-TIME](../spec/broker.md#151-service-user-and-time),
imported by the refresher contract. No reset of this evidence is implemented.

Missing instants, provider errors, untrusted or stale evidence MUST refuse
admission without claiming a material-expiry verdict. A trusted correction is
bounded below by E and D. E at or beyond the current AuthorityUntil MUST refuse;
equality is outside authority. Such confidence refusals authorize no protected
effect and do not infer expiry of the material. Retained metadata supplies a
lower bound, never independent authority. Previously observed trusted time stays
in E even when the current confidence fails to cover it.


| Admission | Shared time rule call sites |
|---|---|
| Material snapshot | `Snapshot` → `snapshot` → `confidenceAt` → `admissionTime` |
| Fresh-home lifecycle prerequisite | `AdmitFreshHome` → `confidenceAt` → `admissionTime` |
| Refresh / retry decision | `Refresh` → `snapshot` and `confidenceAt` → `admissionTime` |
| New writer | `Refresh` → `attempt` → `confidenceAt` → `admissionTime`, revalidated before publishing intent or starting a unit |
| Proactive decision | `Due` → `snapshot` and `confidenceAt` → `admissionTime`; actual proactive work calls `Refresh` |
| Replacement recovery | `New` → `restore` → `recover` → `admissionTime`, before recovery effects; `restore` alone is history validation, not admission |
| Post-vendor / recovered resolution | `resolve` → `admissionTime` using the prospective generation before publishing resolved evidence or its checkpoint |

Every completed durable operation passes through `commitThenRevalidate`: the
shared `admissionTime` rule must hold before the operation and again after its
successful completion, before the next protected effect. The operation publishes
its completed record in memory before the recheck, so refusal cannot forget a
write that already happened. A failed operation never authorizes its successor.

| Durable operation | Effect requiring the completion recheck |
|---|---|
| Admission watermark checkpoint | Material release, fresh-home admission, refresh or proactive decision |
| Protected material flush and reload | Pending checkpoint or resolution publication |
| Pending checkpoint | Intent publication |
| Intent | Starting the recorded writer unit |
| Submitted evidence | Running evidence and managed exchange |
| Running evidence | Managed exchange and stopping evidence |
| Stopping evidence | Absence evidence; containment stop remains permitted |
| Confirmed absence evidence | Material reconciliation and resolved evidence |
| Resolved evidence | Final checkpoint |
| Final checkpoint | Material release or fresh-home admission; containment unload remains permitted |

These are boundaries between completed logical operations, not atomic revocation
of an operation already in progress. Refusal preserves every completed record
and prevents later protected writes or admission. Before the final checkpoint,
the pending prefix remains unavailable until independent confidence and retained
evidence permit recovery. If the final checkpoint itself completed before the
refusal, its settled history stays intact; it is never rolled back. An already
started writer on a time-admission refusal is stopped using its qualified identity,
without publishing new
evidence or unloading pending retention. Storage interruption keeps its existing
retained recovery path, including its live-child uncertainty; it is distinguished
from withdrawn time authority internally while both expose the same unavailable
error. An attempted stop is never retried to
compensate for an uncertain reference reply. Recovery preserves ambiguous prefixes
and reuses the recorded resolution time for scheduling conclusive outcomes.

No admission path checks independent time flags or authority bounds separately.
JWT expiry is a conservative bound on vendor-supplied material, not signature
verification or freshness evidence.
Unknown expiry is refused. The proactive window defaults to 48 hours; `Due`
uses durable half-remaining-lifetime spacing after success to avoid loops with
short vendor lifetimes. Scheduling calls the lease manager's shared proactive
gate. Qualified safe nonrotation uses completion-based 1/2/4/.../60-second
backoff. Successful reads with unchanged access-token material report `renew_failed`,
including stores with changed non-token metadata, and remain closed;
ambiguous exchange outcomes never enter automatic retry.

## Retained-chain validity contract

The whole chain MUST be validated against this table on load and before every
use: material snapshot, fresh-home admission, recovery and a new writer. This
includes resolved attempts already covered by the checkpoint. Any violation
makes the account `owner_unavailable`; later valid records cannot override an
earlier contradiction. Validation reads the protected records again before use.

All encoded fields are required, including explicit zero values. Records use
canonical closed-schema JSON. Every attempt carries one immutable binding:
`Installation`, `Account`, `Attempt`, `Sequence`, `Operation`, `Daemon`, `Policy`,
`Identity.Boot`, `Identity.UID`, `Identity.Epoch`, `Unit`, `Executable`, `Home`,
`StoreBefore`, `TokenBefore`, `Created`, and `Deadline`. These match configuration
and the intent, except that `Daemon` identifies the original owner instance.
Boot, manager UID and epoch match the current qualified manager. `Attempt` is a
unique 32-digit hexadecimal identifier; `Unit` is its configured prefix and
service suffix. `Operation` is `refresh`; generations and sequence are positive;
creation is nonzero and deadline is later. `Revision` is defined per phase below.

An observation's stable tuple is `Identity.Boot`, `Identity.UID`,
`Identity.Epoch`, `Unit`, `Invocation`, `Cgroup`, `CgroupID`, and `Properties`.
Every supplied observation has a complete read, `RestartNo=true`, a nonempty
invocation, absolute clean non-root cgroup path, cgroup identity and property
digest. It binds the intent identity/unit and every other observation in that
attempt. No later observation can replace this tuple. `MainPID`, `ProcessStart`,
`Substate`, `Result`, `ExitStatus`, and `Observed` have the phase-specific
classes below; none independently certifies absence.

| Phase | Required state and identity evidence | RPC, outcome and plan | Revisions, sequences and generations |
|---|---|---|---|
| intent | Kind `attempt-intent/1`; phase `intent`; immutable binding; no observation member | No RPC/outcome members | Revision 1; account-wide sequences contiguous from 1; before-generations equal the preceding resolved result, initially 1/1 |
| submitted | Kind `attempt-evidence/1`; same binding; zero observation allowed; any supplied observation obeys the stable tuple and running requirements | RPC/outcome `unknown`, empty plan; absence `unknown` | Revision 2; StoreAfter 0 |
| running | Same binding and stable tuple; Active `active`, Substate `running`, positive MainPID and ProcessStart; no stop/empty/removal flags | RPC/outcome `unknown`, empty plan; absence `unknown` | Next contiguous revision; StoreAfter 0; follows submitted |
| stopping | Same binding and running observation; stable tuple unchanged | RPC one of `committed`, `safe_no_rotation`, `reauth_required`, `unknown`; outcome `unknown`; valid plan for committed, otherwise empty; absence `unknown` | Next revision; StoreAfter 0; follows running |
| absent | Same binding and stable tuple; Active `inactive` or `failed`; Complete, RestartNo, StopCompleted, Empty and PopulatedZero all true; CgroupRemoved may be true only with this complete stop evidence | RPC and plan equal stopping; outcome `unknown`; absence `confirmed`; unknown RPC is ambiguous, never resolved or admitted | Next revision; StoreAfter 0; follows stopping, or running for recovery with RPC unknown and empty plan |
| resolved | Same binding and stable tuple; same complete stop evidence as absent, with Active `inactive` or `failed`; trusted `resolved_at` and known `token_expires_at` obey the scheduling table | RPC and plan equal stopping and absent; RPC equals outcome, one of committed/safe/rejected; absence `confirmed`; no unknown outcome-bearing evidence anywhere in a resolved chain | Next revision; follows absent; committed increments store/token generations by one each, safe/rejected leave both unchanged; StoreAfter is resulting store generation |
| checkpoint | Kind `account-checkpoint/1`; configured installation, account, vendor, home and policy; nonempty store/token digests, valid plan and nonzero watermark; active/transient/reauth follows committed/safe/rejected respectively | LastAttempt binds the last retained resolution; plan and material digests equal the last committed generation across safe/rejected/pending prefixes; pending account is unavailable, never material authority | Positive revision at least 1 + twice retained count + one if pending; retained count covers a contiguous resolved prefix; store/token generations equal that prefix; at most one additional pending intent, explicitly named; no pending means all attempts checkpointed |

Scheduling is authority under profile §§4 and 4.2, validated with the whole
chain before every admission. Resolution evidence carries `resolved_at`, sampled
from fresh trusted time after confirmed absence and durable material reload, and
`token_expires_at`, the reloaded generation's known expiry. Both fields are zero
in every earlier phase. Resolution time is at least intent creation and the
preceding resolution time; expiry is nonzero and unchanged on safe/rejected
outcomes. A committed expiry is later than resolution time. A settled chain's
last recorded expiry matches the protected current material. Checkpoint watermark
is at least its last retained resolution time. Trusted confidence is still
revalidated separately; metadata never establishes independent time authority.

| Scheduling field | Initial checkpoint | Cross-history rule, including pending checkpoints |
|---|---|---|
| `safe_failures` | Zero | Exactly the number of retained safe resolutions since the last commit; safe increments, commit resets to zero, rejected preserves. Pending evidence beyond the checkpointed prefix changes no checkpoint schedule. |
| `retry_at` | Zero | Zero until the first safe resolution and after each commit. Otherwise at least the last retained safe resolution's trusted `resolved_at` plus 1, 2, 4, 8, 16, 32, then 60 seconds for its consecutive-safe count. Rejected preserves this lower bound. Elapsed time does not erase the durable bound; retry still requires conclusive non-rotation, confirmed absence, store reconciliation and the lifecycle gate. |
| `next_proactive` | Zero; initial work still requires known expiry and the configured window | For the last retained committed generation, exactly the later of `resolved_at + (token_expires_at - resolved_at)/2` and `token_expires_at - configured_window`. Safe, rejected and pending preserve it; before any commit it remains zero. This enforces the window and conservative half-remaining-lifetime spacing even for lifetimes shorter than the window. |

A recovered resolution reuses its durable trusted time and expiry rather than
moving its schedule forward on each restart. Contradictory scheduling fields
make the account `owner_unavailable`; no material or fresh-home authority is
released and no writer or proactive work is admitted.


## Retained record field classification

This inventory is exhaustive for `Intent`, all five `Evidence` phases (including
`resolved`), `Checkpoint`, flattened `Binding`, and nested `Observation`/`Identity`.
There are no other owner record types. The generated inventory test reflects the
Go schemas and fails for a missing, duplicate, removed or newly unclassified path.
Identity fields must match their configured identity and/or immutable attempt
binding. Authority fields must obey the stated history rule; their ordinary type
or enum validity is insufficient. Bounded rules intentionally allow multiple
coherent values: a later conservative retry, a higher CAS revision after trusted
watermark writes, and legal terminal diagnostics are not contradictions.

The protected initial enrollment checkpoint is supplied by the separate trusted
ceremony. With no retained attempt its valid plan and digests are the initial
root, reconciled against protected material before admission. The first intent
captures that root's plan, digests and expiry; every evidence binding repeats it.
Subsequent generation metadata is derived only from complete resolved history.
No initial plan is hard-coded, and a genuine later committed plan change is valid.

| Record / phases | Field paths | Class | Rule and decision readers |
|---|---|---|---|
| Intent, all Evidence | `installation_id`, `account`, `policy_generation`, `boot_id`, `manager_uid`, `manager_epoch`, `executable_sha256`, `vendor_home_id` | identity | `Engine.binding` and `validateChain`: configured/current qualified identity, repeated immutable binding in every phase. |
| Intent, all Evidence | `attempt_id`, `unit_name`, `daemon_instance_id` | identity | Named intent/map key and never-reused derived unit; original daemon nonempty; every phase repeats original binding, not replacement daemon identity. |
| Intent, all Evidence | `attempt_sequence`, `revision`, `operation`, `created_at`, `deadline` | authority | Contiguous account sequence; intent revision 1 and evidence revisions contiguous from 2; refresh operation; nonzero creation, deadline later; all copies bind intent. `validateChain`, recovery and writer admission read these. |
| Intent, all Evidence | `store_generation_before`, `token_generation_before` | authority | Equal the preceding resolved generation, initially 1/1; all copies match intent. `validateChain`, `resolve`. |
| Intent, all Evidence | `store_digest_before`, `token_digest_before`, `plan_before`, `token_expires_before` | authority | Equal preceding resolved material metadata, initially enrollment root; valid digests/plan and known expiry; immutable across phases. `validateChain` reconstructs checkpoint authority and `resolve` reconciles material. |
| Intent | `kind`, `phase` | authority | Exactly attempt-intent/1 and intent; filename/revision and transition checks in restore/validateChain. |
| All Evidence | `kind`, `phase`, `absence` | authority | Exactly attempt-evidence/1, allowed next phase, confirmed absence only in absent/resolved; restore/validateChain/recover use these. |
| All Evidence | `observation` | authority | Required object; submitted may have no authority observation, other phases require the phase evidence. `validateChain` ignores diagnostic-only values when deciding whether submitted observation is supplied. |
| All Evidence | `observation.manager`, `observation.manager.boot_id`, `observation.manager.manager_uid`, `observation.manager.manager_epoch`, `observation.unit_name`, `observation.invocation_id`, `observation.cgroup_path`, `observation.cgroup_identity`, `observation.verified_property_digest` | identity | Empty only for unobserved submitted; otherwise complete stable writer tuple across supplied observations, matching intent manager/unit and an absolute clean non-root cgroup. `validRunning`, `sameWriter`, `confirmed`, validateChain and recovery. |
| All Evidence | `observation.complete_read`, `observation.restart_no` | authority | True whenever an authority observation is supplied; false in empty submitted. `validRunning`, `confirmed`, validateChain. |
| All Evidence | `observation.active_state` | authority | Active for running observations; inactive/failed for terminal observations, with resolved state identical to preceding absent state. validateChain/confirmed use it. |
| Submitted, running, stopping Evidence | `observation.main_pid`, `observation.process_start`, `observation.substate` | authority | Positive PID/start and running substate when supplied; same PID/start through running observations; empty submitted has zero/empty values. validateChain and attempt readiness read these. |
| Absent, resolved Evidence | `observation.main_pid`, `observation.process_start`, `observation.substate` | diagnostic | Retained values are only decoded/serialized; validateChain/confirmed/recover never branch on these terminal values, and they are never returned as material authority. Live Systemd.Observe reads typed properties before writing evidence. |
| Submitted, running, stopping Evidence | `observation.cgroup_removed_after_stop` | authority | False; an observed active writer cannot claim prior cgroup removal. validateChain reads it. |
| Absent, resolved Evidence | `observation.cgroup_removed_after_stop` | diagnostic | Only decoded/serialized in retained history; confirmed/validateChain/recover never use it to replace complete stop/empty evidence. Live Systemd.Stop may annotate it after qualified stop evidence. |
| All Evidence | `observation.stop_completed`, `observation.subtree_empty`, `observation.populated_zero` | authority | False for nonterminal observed phases, true for terminal phases; empty submitted is false. validateChain/confirmed use the complete stop tuple. |
| All Evidence | `observation.result`, `observation.exit_status`, `observation.observed_at` | diagnostic | Only decode/serialization in the retained-chain path; validRunning/sameWriter/confirmed/recover ignore them. Systemd.Observe obtains these live diagnostics; no retained diagnostic is used to classify RPC, time, outcome or absence. |
| All Evidence | `rpc_outcome`, `outcome`, `plan_type`, `store_generation_after` | authority | Phase-specific RPC/outcome/plan rules and exact generation transitions in the phase table; stopping/absent/resolved agree; unknown cannot resolve. validateChain/recover/resolve use these. |
| All Evidence | `resolved_at`, `token_expires_at`, `store_digest_after`, `token_digest_after` | authority | Explicit zero/empty before resolved. Resolution has trusted time, known expiry and matching current material digests; safe/rejected preserve before-metadata, commit replaces store/token digests and may change plan/expiry. validateChain/resolve use these; timing obeys scheduling table. |
| Checkpoint | `kind`, `revision` | authority | account-checkpoint/1; positive CAS revision at least phase-table floor, including additional trusted-watermark writes. restore/validateChain and Disk.Put read these. |
| Checkpoint | `installation_id`, `account`, `vendor_account_id`, `vendor_home_id`, `policy_generation` | identity | Exactly configured installation, account, vendor, home and policy. validateChain, confidence validation and material reload use these. |
| Checkpoint | `state`, `pending_attempt`, `retained_attempts`, `last_resolved_attempt` | authority | Exact contiguous resolved prefix and at most one named pending intent; state follows final prefix outcome or unavailable while pending. validateChain/retained/recover and admission use these. |
| Checkpoint | `store_generation`, `token_generation` | authority | Exact result of checkpointed prefix, initially 1/1. validateChain, confidence validation and material publication use these. |
| Checkpoint | `vendor_store_digest`, `current_token_digest`, `plan_type` | authority | Exact last checkpointed committed generation metadata, preserved across safe/rejected and pending prefixes; initial root captured by first intent; settled digests also equal protected current material. validateChain checks before Snapshot/fresh-home/recovery/writer admission; Snapshot returns only checked plan. |
| Checkpoint | `watermark` | authority | Nonzero trusted durable watermark at least all checkpointed resolution times; confidence validation must cover it before admission. validateChain/admissionTime/confidenceAt/resolve read it. |
| Checkpoint | `next_proactive`, `retry_at`, `safe_failures` | authority | Derived checkpointed-prefix schedule/count, including permitted conservative retry lower bound, as in scheduling table. validateChain checks; Refresh/Due/resolve consume only checked values. |

Unknown RPC placeholders before the response (`submitted` and `running`) are
expected, not successful RPC evidence. Unknown in `stopping` or `absent` makes
the attempt ambiguous: recovery may still stop the recorded writer and retain
absence, but neither Snapshot, AdmitFreshHome nor a new writer is admitted.
This also closes fresh-home admission after an interrupted pre-response writer;
external reconciliation is required even after that writer is confirmed absent.
An incomplete chain may be loaded only as a recovery prefix. It never certifies
material or administrative admission. Missing intermediate phases are forbidden,
except the explicit running-to-absent recovery edge above. Checkpointed history
cannot contain an incomplete or ambiguous attempt. Checkpoint revision counters
detect local inconsistencies; they are not independent restore freshness proof.

Connection references have a separate uncertainty boundary. A `RefUnit` call is
tracked as possibly applied before submission. Only its successful reply proves
one held reference. Cancellation or an uncertain reply keeps retention and
Unload unknown; Stop must not retry that reference acquisition. Unload may report
success only after complete terminal readback with exactly the tracked held
reference, or confirmed collection. A lost connection never proves historical
absence. The conservative implementation requires connection disposal and
external recovery after an uncertain reference reply; it does not infer counts
from an RPC error.

## Requirement coverage

These names identify executable claims, rather than native-vendor qualification.

| Contract | Code | Tests |
|---|---|---|
| §4 stable locks, approved vendor, managed RPC and durable reload | `engine_linux.go`, `vendor_linux.go`, existing store locks | `TestStableHomeLock`, `TestIntentBeforeStartAndCommittedControl`, `TestDuplicateConfiguredVendorRefused` |
| Completed persistence must revalidate before its successor | `commitThenRevalidate`, `commitCheckpoint`, `appendIntent`, `appendEvidence`, `durableMaterial` | `TestDurableEffectTimeBoundaryProbe`, `TestWatermarkCompletionAdmissionProbe`, `TestDurableStepTimeRevalidation`, `TestCommitTimeBoundary`, `TestMaterialDurabilityTimeRevalidation` |
| §4 proactive window, unknown expiry, trusted time and watermark | `Due`, `confidenceAt`, `load` | `TestProactiveShortLifetime`, `TestStoreTimeAndFreshnessFences` |
| §4 unchanged token and N=8/64 coalescing | `Refresh`, `resolve`, lease owner-error bridge | `TestUnchangedReportsRenewFailed`, `TestProbeUnchangedTokenMetadata`, `TestOwnerUnchangedRefusalPreserved`, `TestLeaseCoalescingCountsVendorUnits` |
| §4.2 safe backoff, rejection, ambiguity and cancellation | `resolve`, `managed` | `TestSafeBackoffRejectionAndExpiry`, `TestSafeBackoffCompletionAndReplacement`, `TestAmbiguousRotationNoRetry`, `TestCancelledRPCNoRetry` |
| §5 transient service properties, private FDs and readiness | `Systemd.Probe`, `Start`, `Observe`, `Owned` | `TestRealFDContainment`, `TestRealReadinessRefusesRequiredPropertyAndDigest` |
| §5 subtree teardown and dependency stop | `Systemd.job`, `Stop`, `readCgroup` | `TestRealGrandchildTimeoutAndDependencyStop`, `TestRealManagerConnectionRetention` |
| §5 intent before start and uncertain reply | `attempt`, immutable `Account.Append` | `TestIntentBeforeStartAndCommittedControl`, `TestUncertainStartSingleRecordedName` |
| §5.1 canonical records, expected revisions and retention | `records.go`, `restore`, `checkpoint`, `evidence` | `TestRecordClosureAndNull`, `TestOwnerAppendImmutableAndFenced`, `TestPendingAndRetainedRecordLoss`, `TestRetentionBound` |
| §5.1 unknown absence and no ambiguous retry | `confirmed`, `recover`, `resolve` | `TestAbsenceUnknownNoRetry`, `TestAmbiguousRotationNoRetry`, `TestDaemonDeathAndReplacementContention` |
| §5.1 boot/epoch, interrupted cleanup and recovery | `restore`, `recover` | `TestReplacementRecoveryFences`, `TestProbeFreshHomeEpochFence`, `TestProbeRetainedObservationBinding`, `TestCleanupInterruptedAndConfirmedRecovery` |
| No material in metadata, unit properties, owner output or status | enum-only RPC metadata and explicit child environment | `TestHygieneCanary`, `TestUntrustedPlanCannotEnterEvidence`, `TestLeaseCoalescingCountsVendorUnits` |

## Lifecycle vector map

| Vector IDs | Executable witnesses and limits |
|---|---|
| `daemon-death`, `replacement-contention` | `TestDaemonDeathAndReplacementContention` models daemon interruption with a live fake-vendor child and persisted running evidence; `TestStableHomeLock` rejects simultaneous replacement. Real dependency death is exercised separately by `TestRealGrandchildTimeoutAndDependencyStop`. |
| `normal-stop`, `resolved-replacement`, `rotation-committed` | `TestIntentBeforeStartAndCommittedControl` proves durable refresh and replacement without another child. |
| `rotation-crash` | `TestAmbiguousRotationNoRetry/rotate-crash` retains an external-exchange witness without vendor persistence and admits no retry. |
| `cleanup-interrupted`, `cleanup-confirmed` | `TestCleanupInterruptedAndConfirmedRecovery` interrupts absence, terminal and checkpoint publication; partial recovery remains closed, complete proof resolves once. |
| `absence-unreadable`, `absence-complete` | `TestAbsenceUnknownNoRetry` pairs not-found, missing path, PID-only, timeout, permission, partial and contradictory/epoch observations with the complete control. |
| `store-missing`, `store-current`, `store-rollback` | `TestStoreTimeAndFreshnessFences` and `TestPendingAndRetainedRecordLoss`; freshness comes from the injected independent confidence boundary. |
| `store-reconciled` | Deferred: the operator's external restore/reconciliation procedure is outside this refresh adapter. A trusted fresh current-store control is not evidence that this procedure exists. |
| `transient-ambiguous`, `transient-safe` | `TestAmbiguousRotationNoRetry`, `TestSafeBackoffRejectionAndExpiry`. Classification is qualified fake evidence, not a claim about native vendor errors. |
| `reenrol-unresolved` | `TestDaemonDeathAndReplacementContention` refuses the fresh-home prerequisite while a writer remains unresolved. |
| `reenrol-resolved` | Only the confirmed-absence admission prerequisite is covered by that same test; actual fresh-home ceremony is deferred. |
| `duplicate-account`, `distinct-account` | Deferred enrolment/publication ceremony. Static duplicate configuration is additionally rejected by `TestDuplicateConfiguredVendorRefused`. |
| `cutover-old-writer-live`, `cutover-old-writer-absent` | Deferred: cutover inventory, maintenance approval and old-login retirement are separate work. |

No rows are claimed for real accounts, real issuers, native-vendor durability,
external restore reconciliation, enrolment/device code, cutover or runner
integration. The real-manager runtime test uses a shortened control and verifies
the production 120-second property without measuring that full elapsed bound.
Exact-release native fixture rows remain PENDING until all vendor egress is
confined and the sandbox startup contract is qualified. A refresh endpoint
override alone is insufficient; no native test entry point is included here.

The attachment witness reads cgroup membership at the helper's first instrumented
entry before echoing any request, then compares it with manager readback. It does
not instrument instructions inside the Go runtime's earlier initialization.
