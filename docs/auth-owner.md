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

`Confidence.Validate` must supply trusted time and freshness outside the restored
store's rollback domain. There is no shipped always-fresh implementation. The
watermark is persisted before material release, advances only on trusted time,
and remains sticky after clock correction. JWT expiry is a conservative bound
on vendor-supplied material, not signature verification or freshness evidence.
Unknown expiry is refused. The proactive window defaults to 48 hours; `Due`
uses durable half-remaining-lifetime spacing after success to avoid loops with
short vendor lifetimes. Scheduling calls the lease manager's shared proactive
gate. Qualified safe nonrotation uses completion-based 1/2/4/.../60-second
backoff. Successful reads with unchanged access-token material report `renew_failed`,
including stores with changed non-token metadata, and remain closed;
ambiguous exchange outcomes never enter automatic retry.

## Requirement coverage

These names identify executable claims, rather than native-vendor qualification.

| Contract | Code | Tests |
|---|---|---|
| §4 stable locks, approved vendor, managed RPC and durable reload | `engine_linux.go`, `vendor_linux.go`, existing store locks | `TestStableHomeLock`, `TestIntentBeforeStartAndCommittedControl`, `TestDuplicateConfiguredVendorRefused` |
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
