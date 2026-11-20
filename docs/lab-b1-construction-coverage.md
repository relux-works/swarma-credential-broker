# B1 construction coverage and explicit non-acceptance

Status: **STOP:C0C_PROTECTED_INSTALLATION_BINDING**. See
[the exact required protected input](lab-b1-installation-binding-stop.md).
C0c native access and C0d current-RPC timing decisions are resolved, not
reopened. Source base is `9f1f90fa`. The first separate commit remains the
private B1 recovery addendum; all thirty external format/fixture definitions
are preserved. The authorized private envelope now recovers C0d S/F in the
same atomic CAS as the existing engine and external snapshot. No production
receipt, second lease engine, accepting factory or B1 attempt counter exists.

## Acceptance allocation

### PR #83 D1: observation-owned uncertainty

Round 2 distinguishes engine UNKNOWN from observation-owned uncertainty.
Both independently close `Snapshot`, `ServiceAccount` and `Publish`. An
observation CAS changes only its own reason; engine confirmation changes only
the engine reason. A recovered nonempty observation record reinstates the
observation fence, so restart plus engine confirmation cannot substitute for
the required pair. No new durable field or contract surface is introduced.

`publicationFor` alone passes the pair admission marker to the CAS helper, after its
two fresh, non-reused C0c reads, full proof comparison, protected envelope read
and epoch check. The ordinary `commit` path has no such marker. A timely
successful pair CAS reconciles observation uncertainty; it never clears engine
UNKNOWN. Existing pre/post-CAS, deadline and final reopening guards remain.
The basis is `observation.md` C0d (a new admitted pair reconciles durable state)
and `recovery.md` C0d/Atomic join (a new non-reused pair, protected complete read
and CAS durability confirmation). These refine implementation, not contracts.

| D1 direction / bound | Paired regression | Narrowing mutant / named failure |
| --- | --- | --- |
| A new pair reconciles own rename uncertainty or late CAS, commits F=S above recovered S and preserves the exact engine/external join | `TestReviewD1NewPairReconcilesObservationUncertainty` (control, rename-uncertain, late-cas); also restores projection/account and placeholder-only material | `observation-never-reconciles`; same test / rename-uncertain and late-cas |
| A fresh single or cached value cannot clear uncertainty or mutate the durable join | `TestReviewD1NonPairCannotReconcile` (valid single/pair beside single-cas, cached-cas, periodic, replayed-pair, partial-pair, restart refusals) | `observation-single-reconciles`, `observation-cache-reconciles`; same test / single-cas and cached-cas |
| Engine confirmation cannot clear the observation reason, and a later uncertain/rejected engine write blocks even a new pair | `TestReviewD1EngineUncertaintyAfterObservation` (engine-confirmation, engine-rename, engine-rejected; engine confirmation then a fresh pair is the positive recovery) | `observation-engine-clears-own`, `observation-engine-takeover-ignored`; same test / engine-confirmation and engine-rename |
| A recovered record plus engine confirmation still needs a new admitted pair | `TestReviewD1RestartRequiresPair` (control, rename-uncertain, late-cas, each followed by a valid non-reused pair) | `observation-restart-clears-own`; same test |

The prior two engine-UNKNOWN overlay names are retained. Their plants now
explicitly clear the engine reason at the observation guard, rather than only
skip it: observation CAS no longer owns or clears that flag on its normal path.
The original named engine-UNKNOWN and fence regressions remain in the catalogue.
Exact execution receipts and overlay exits belong in the current handoff.

Round-1 timing labels are bounded below: pair-budget/native-age direct tests
share one argument slot, not independent caller-wiring coverage. The review's
native-age caller-wiring mutant is an acknowledged non-blocking survivor from
that review, not a newly executed/covered gate here. The current-during-publish
ordering note is deferred to B1b; no runtime rule is invented for it here.

PR #83 B1a fix round 1 retains the whole-B1 non-acceptance boundary above.
The two reproduced bypasses are fixed before adding the missing-gate witnesses:

| Finding | Fix and paired regression | Source-overlay mutant | Test exit |
| --- | --- | --- | --- |
| r F1 sticky fence overwrite | Compare the pair epoch again under the reopening lock; `TestReviewFenceDuringPublishIsSticky` includes an unfenced publication and fences during CAS/publication | `publication-fence-overwrite`; `TestReviewFenceDuringPublishIsSticky/during-publish` | 1, named intended failure |
| s F1 observation clears engine UNKNOWN | Refuse observation-only CAS on engine-owned UNKNOWN; `TestReviewProbeObservationCommitClearsEngineUnknown` and `TestReviewProbePublicationCommitClearsEngineUnknown` use an actual rename-uncertain lease write after a valid single/projection | `observation-clears-engine-unknown`, `publication-clears-engine-unknown`; respectively the two named probes | 1 each, named intended failures |

The unmutated three-test regression command exits 0. These controls establish
the tagged adapter interaction, not installed transport publication or native
qualification. The publication callback cannot retract already emitted bytes;
the new guard prevents that pair from reopening continued use.

Every B1 row from profile sections 5/5.1 remains **incomplete**. The named
controls are paired valid/negative library and fake-server construction tests,
not a substitute for the missing installed/composed path. No allocated B1 row
is waived or treated as out of contract. Other units' rows A04/A06/A10/A11/A12
are outside this B1 unit by section 5.1; no completion of them is claimed.

| Row | Paired construction tests | Killed narrowing mutants | Remaining composed-path obligation |
| --- | --- | --- | --- |
| A01 | `TestLabCommittedBootstrapAndCrossRead`, `TestLabRuntimeSurfacePairs`, `TestLabRecoveryPrivateInventory` | `store-domain`, `runtime-closure`, `private-export-reader`, `private-audience` | Accepting tagged daemon and activation/fence/floor cross-import assembly; the default suite is separately reported, not presumed green. |
| A02 | `TestLabRuntimeCataloguePairs`, `TestLabRecoveryReplayPairs` | `runtime-range`, `bounded-usd-ceiling`, `bounded-invocation-count`, `replay-variants` | Real daemon API-key response and measured gateway header/body/policy routes. The C0b reader is shape parsing, not invocation approval; the gateway alone counts attempts. |
| A03 | `TestLabManagedAuthorityPairs`, `TestLabObservationClientPairs`, `TestLabObservationKernelPeerAndPath`, `TestLabRecoveryJoinTampering/caller` | `managed-cold-worker-kind`, `managed-worker-class`, `managed-manager-head`, `caller-join`, `observation-kernel-peer`, `observation-debit-join` | Independently approved installation pins, composed native caller facts, kernel worker service/legacy refusal and real root control; synthetic facts are not installed authority. |
| A05 | `TestLabCommittedBootstrapAndCrossRead`, `TestLabRecoveryHistoricalReplay`, `TestLabRecoveryCASAndImmutableBudget`, `TestLabFiniteNarrowingReserve`, `TestLabObservationRecoveryCounterPairs` | `joined-digest`, `drop-restored-replay`, `stale-cas-one-layer`, `count-reserve`, `physical-operation-reserve`, `byte-reserve`, `recovery-observation-floor` | Root operation/status bridge, final native finite-plan accounting and G1b reservation/settlement consumption. No B1 lease/count substitute is implemented. |
| A07 | `TestLabLifetimeAndEarlierDeadline`, `TestLabRecoveryHistoricalReplay` | `replay-narrowed-authority`, `latest-replay-deadline` | Qualified B2 time and complete earliest-ceiling/facts assembly; existing engine arithmetic alone is not the released path. |
| A08 | `TestLabHoldUnknownAtomicJoin`, `TestLabReleaseHoldBoundary`, `TestLabLiftAndUnbindContainment`, `TestLabB1ReleaseTimeRequiredForHoldBoundary`, `TestLabObservationContainmentDoesNotQueue` | `unknown-projection`, `release-timestamp`, `lift-resurrection`, `containment-no-queue` | Whole-needle gateway/root matcher, authenticated lift/confirmation and actual transport closure. `containment-no-queue` kills a mutex held across native I/O/cooldown; this is still not installed transport acceptance. |
| A09 | `TestLabObservationConsumptionDurablePairs`, `TestLabObservationPeriodicAdversarialPairs`, `TestLabObservationPublicationAtomicPairs`, `TestLabObservationIndependentAgeFence`, `TestLabObservationComposedPeriodicCurrent`, `TestLabObservationNarrowingPublicationPairs` | `periodic-floor`, `restart-admission`, `publication-fresh-final`, `publication-final-proof`, `periodic-proof`, `independent-age-fence`, `narrowing-pending`, `narrowing-stays-closed` | Installed root/current/unbind transport, independent <=500 ms affected stream/listener closure, 750 ms gateway watchdog and native <=3000 ms qualification. Current C0d construction no longer pairs on each current RPC. |

Original replay/hold regression test names are retained. Historical pre-C0d
200/500 ms pair-per-current diagnostics are explicitly labelled historical;
they are not current acceptance controls. The independent age closer and
local current check do not depend on a periodic I/O result returning. Pairs
and singles never hold the account mutex during native I/O/cooldown. The
publication callback is not an installed deadline-bound socket writer.

## Source-overlay mutations

Original producer evidence at `2751169d` (historical, not a fresh fix-round
replay): **67 runtime/actual-reader overlays**, 65 named intended
failures and two bounded survivors, plus **7 private contract overlays**, all
with named intended failures. Commands are standalone `go test` executions in
absolute isolated scratch, with canonical own-format/valid controls retained.
No crash, compiler error, absent test or unapplied plant counts as a kill.
The earlier unused-variable size-plant compile failure is a diagnostic only;
the corrected plant fails its intended semantic test. The warm-kind expression
is anchored exactly: without that anchor a cold-kind subtest also matches.
`stale-cas-one-layer` now dies: the independent outer CAS revision makes the
adapter's engine-revision check necessary; the earlier pre-C0d survivor is
not reused as current evidence.

| Mutant | Gate narrowed | Named failing test (actual log) | Exit / survival bound |
| --- | --- | --- | --- |
| runtime-closure | Exact runtime field set | `TestLabRuntimeSurfacePairs/swarma-broker-lab-activation/1` | 1; intended assertion |
| private-export-reader | B1-only recovery reader | `TestLabRuntimeSurfacePairs/swarma-broker-lab-service-recovery/1` | 1; intended assertion |
| runtime-range | Closed lifetime upper bound | `TestLabRuntimeCataloguePairs/swarma-broker-lab-activation/1` | 1; intended assertion |
| store-domain | Disjoint store identities | `TestLabCommittedBootstrapAndCrossRead/lab-to-production` | 1; intended assertion |
| joined-digest | Embedded external digest join | `TestLabRecoveryJoinTampering/digest` | 1; intended assertion |
| caller-join | Recovered caller generation join | `TestLabRecoveryJoinTampering/caller` | 1; intended assertion |
| latest-replay-deadline | Original replay deadline, not latest renewal | `TestLabRecoveryHistoricalReplay` | 1; intended assertion |
| drop-restored-replay | Retained replay operations on restart | `TestLabRecoveryHistoricalReplay` | 1; intended assertion |
| release-timestamp | Inclusive release-time hold boundary | `TestLabReleaseHoldBoundary/late=true` | 1; intended assertion |
| count-reserve | Remaining operation slots | `TestLabFiniteNarrowingReserve/count` | 1; intended assertion |
| byte-reserve | Private byte headroom | `TestLabFiniteNarrowingReserve/private-bytes` | 1; intended assertion |
| reconciliation-reserve | Revision headroom for reconciliation | `TestLabFiniteNarrowingReserve/revision` | 1; intended assertion |
| unknown-projection | No external view before durable confirmation | `TestLabHoldUnknownAtomicJoin` | 1; intended assertion |
| lift-resurrection | Lift does not resurrect ended leases | `TestLabLiftAndUnbindContainment` | 1; intended assertion |
| unbind-closure | Registered affected connection closure | `TestLabLiftAndUnbindContainment` | 1; intended assertion |
| replay-narrowed-authority | Retry revalidates current earlier bound | `TestLabLifetimeAndEarlierDeadline/authority` | 1; intended assertion |
| stale-cas-one-layer | Adapter CAS alone | `TestLabRecoveryCASAndImmutableBudget` | 1; intended assertion |
| stale-cas-two-layer | Joined adapter/store CAS boundary | `TestLabRecoveryCASAndImmutableBudget` | 1; intended assertion |
| observation-kernel-peer | Actual kernel UID equality | `TestLabObservationKernelPeerAndPath` | 1; intended assertion |
| observation-daemon-uid | Dedicated client UID binding | `TestLabObservationKernelPeerAndPath` | 1; intended assertion |
| observation-socket-mode | Exact protected socket mode | `TestLabObservationPathChanges/socket-mode` | 1; intended assertion |
| observation-symlink | Lstat refuses a substituted symbolic link | `TestLabObservationPathChanges/symlink` | 1; intended assertion |
| observation-parent-mode | Both generic and exact parent mode guards | `TestLabObservationPathChanges/parent-mode` | 1; intended assertion |
| observation-current | Protected generation currentness | `TestLabObservationClientPairs/not-current` | 1; intended assertion |
| observation-complete | Complete locked projection | `TestLabObservationClientPairs/incomplete` | 1; intended assertion |
| observation-manager | Approved manager incarnation | `TestLabObservationClientPairs/wrong-manager` | 1; intended assertion |
| observation-store-generation | Installed native store generation | `TestLabObservationClientPairs/store-generation` | 1; intended assertion |
| observation-counter-generation | Counter scoped to that store | `TestLabObservationClientPairs/counter-generation` | 1; intended assertion |
| observation-start-pins | Complete expected start binding, including UID | `TestLabObservationClientPairs/wrong-start-uid` | 1; intended assertion |
| observation-terminal-start | No use after terminal launch | `TestLabObservationClientPairs/stopped` | 1; intended assertion |
| observation-observed-window | Observation inside local BOOTTIME interval | `TestLabObservationClientPairs/old-observation` | 1; intended assertion |
| observation-debit-join | Receipt/debit incarnation agreement | `TestLabObservationClientPairs/debit-mismatch` | 1; intended assertion |
| observation-invalidation | Invalidation closes use | `TestLabObservationClientPairs/invalidation` | 1; intended assertion |
| observation-pending-stop | Pending exec.stop closes use | `TestLabObservationClientPairs/pending-stop` | 1; intended assertion |
| observation-initial-floor | First sequence above supplied replay floor | `TestLabObservationSequenceFloor` | 1; intended assertion |
| observation-final-sequence | Strictly fresh final sequence | `TestLabObservationClientPairs/final-sequence` | 1; intended assertion |
| observation-final-snapshot | Identical native snapshot at revalidation | `TestLabObservationClientPairs/final-mismatch` | 1; intended assertion |
| observation-no-half-close | Request EOF before response | `TestLabObservationCurrentRPCBudget` | 1; intended assertion |
| observation-frame-length | Framer length equality alone | None; survivor | 0; canonical parser independently rejects concatenated/trailing frames; this does not establish the length check alone. |
| observation-trailing-frame-two-layer | Length check plus discard of trailing bytes | `TestLabObservationClientPairs/two-frames` | 1; intended assertion |
| observation-transport-window | Nonextendable 250 ms connection window | `TestLabObservationTransportWindow` | 1; intended assertion |
| observation-ancillary | No received descriptors | `TestLabObservationClientPairs/ancillary` | 1; intended assertion |
| bounded-usd-ceiling | Exact safe-integer micro-USD ceiling | `TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1` | 1; intended assertion |
| bounded-invocation-count | At most 256 invocations | `TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1` | 1; intended assertion |
| bounded-output-tokens | At most 128000 output tokens | `TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1` | 1; intended assertion |
| bounded-wall-time | At most 900000 ms per wall-time bound | `TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1` | 1; intended assertion |
| bounded-usd-grammar | Exactly six decimal places | `TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1` | 1; intended assertion |
| observation-native-id | Alphanumeric-first native IDs | `TestLabRuntimeCataloguePairs/swarma-broker-lab-observation-request/1` | 1; intended assertion |
| observation-native-executor | Closed native executor grammar | `TestLabRuntimeCataloguePairs/swarma-broker-lab-observation-response/1` | 1; intended assertion |
| periodic-floor | Allow a periodic single to advance F/baseline rather than S only | `TestLabObservationConsumptionDurablePairs` | 1; intended assertion |
| restart-admission | Reopen use from cached recovery before a new pair | `TestLabObservationConsumptionDurablePairs` | 1; intended assertion |
| publication-fresh-final | Reuse the initial observation as the final instead of a second connection | `TestLabObservationConsumptionDurablePairs` | 1; intended assertion |
| publication-final-proof | Ignore complete native snapshot movement at final revalidation | `TestLabObservationPublicationAtomicPairs/revalidation-mismatch` | 1; intended assertion |
| periodic-proof | Ignore movement from the published native comparison baseline | `TestLabObservationPeriodicAdversarialPairs/moved-proof` | 1; intended assertion |
| independent-age-fence | Move the independent native closer from 1150 to 1800 ms | `TestLabObservationIndependentAgeFence/absent-single` | 1; intended assertion |
| narrowing-operation | Accept another native stop operation as the requested stop | `TestLabObservationNarrowingPublicationPairs/terminal-wrong-stop` | 1; intended assertion |
| narrowing-pending | Accept a still-admitted pending stop as terminal evidence | `TestLabObservationNarrowingPublicationPairs/terminal-pending-stop` | 1; intended assertion |
| narrowing-stays-closed | Allow terminal narrowing to reopen continued use | `TestLabObservationNarrowingPublicationPairs/terminal-stop` | 1; intended assertion |
| recovery-observation-floor | Ignore durable S>=F | `TestLabObservationRecoveryCounterPairs/seen` | 1; intended assertion |
| recovery-observation-generation | Ignore installed store/counter/baseline generation equality | `TestLabObservationRecoveryCounterPairs/generation` | 1; intended assertion |
| recovery-observation-size | Ignore the embedded 65536-byte native response ceiling | `TestLabObservationRecoveryCounterPairs/baseline-size` | 1; intended assertion |
| managed-worker-kind | Ignore the worker native-agent kind (warm-view control) | None; survivor | 0; protected managed authority remembers native kinds and independently refuses a warm kind change; the cold-kind plant is killed separately. |
| managed-cold-worker-kind | Ignore the worker native-agent kind after a fresh authority construction | `TestLabManagedAuthorityPairs/cold-worker-kind` | 1; intended assertion |
| managed-worker-class | Ignore the worker trusted class | `TestLabManagedAuthorityPairs/worker-class` | 1; intended assertion |
| managed-manager-head | Ignore the independently pinned manager journal hash | `TestLabManagedAuthorityPairs/manager-head` | 1; intended assertion |
| private-audience | Broaden recovery readers beyond B1 | `TestLabRecoveryPrivateInventory` | 1; intended assertion |
| recovery-digest | Ignore the atomic external snapshot digest | `TestLabRecoveryJoinPairs/digest` | 1; intended assertion |
| replay-variants | Allow multiple typed replay variants | `TestLabRecoveryReplayPairs/bind` | 1; intended assertion |
| recovery-closure | Allow extra private recovery members | `TestLabGeneratedClosedFieldPairs/RecoveryState` | 1; intended assertion |
| private-observation-floor | Reference recovery join ignores S>=F | `TestLabRecoveryObservationJoinPairs/seen` | 1; intended assertion |
| private-observation-generation | Reference recovery join ignores native store/counter generation equality | `TestLabRecoveryObservationJoinPairs/generation` | 1; intended assertion |
| private-observation-size | Reference recovery join ignores embedded response byte ceiling | `TestLabRecoveryObservationJoinPairs/baseline-size` | 1; intended assertion |

| containment-no-queue | Hold the account mutex across both native reads and their cooldown | `TestLabObservationContainmentDoesNotQueue` | 1; hold queued behind native pair, after the valid admitted-pair control |

| physical-operation-reserve | Ignore the physical 256-entry array capacity when an approved scalar operation limit is larger | `TestLabFiniteNarrowingReserve/physical-cap` | 1; valid control retains exactly eight slots, one further operation consumes the reserve |

## PR #83 B1a fix-round delivered-gate witnesses

Scope is the delivered B1a slice, not completion of B1b or any whole acceptance
row. Review records 5998029277 (r) and 5998127088 (s) are addressed without a new
contract surface. The two bypass fixes were committed first, separately.

| Finding | Fix or independently exercised predicate | Tests (valid control beside negatives) | Mutants / actual test exits |
| --- | --- | --- | --- |
| r F1 | Recheck the epoch under the final reopening lock; a fence before or during CAS/publication wins | `TestReviewFenceDuringPublishIsSticky`, `TestLabReviewFenceBeforeObservationCAS` | `publication-fence-overwrite`, `publication-pre-cas-epoch`, `publication-post-cas-epoch`: 1 each |
| s F1 | Reject observation-only CAS when engine UNKNOWN was already set; only engine reconciliation can resolve it | `TestReviewProbeObservationCommitClearsEngineUnknown`, `TestReviewProbePublicationCommitClearsEngineUnknown` | `observation-clears-engine-unknown`, `publication-clears-engine-unknown`: 1 each |
| r F2 | Preserve initial cooldown/lateness, independent current-age interval and both CAS deadline checks | `TestLabReviewInitialObservationWindow`, `TestLabReviewCurrentAgePredicate`, `TestLabReviewObservationCommitDeadlines` | Two initial-window, two current-age and six before/after-CAS deadline overlays: 1 each |
| r F3 | Independently re-seal and CAS-write held, revoked, gateway UID/generation and state-revision mismatches; real account projection/material stays UNKNOWN with no repair write | `TestLabReviewRecoveryJoinPredicates` | Five `recovery-*` overlays below: 1 each |
| s F2 | Before/after-CAS time checks, successful-but-late pair/single durability and post-callback final deadline | `TestLabReviewObservationCommitDeadlines`, `TestLabReviewPublicationDeadlines`, `TestLabReviewPeriodicLateCAS` | Six explicit deadline overlays plus `late-cas-publishes`, `late-single-cas`, `late-publication-reopens`: 1 each |
| s F3 | Top-level operation/start IDs independently match request pins although nested start is unchanged | `TestLabReviewObservationResponseJoins`, `TestLabObservationPeriodicAdversarialPairs` | `response-operation-id`, `response-start-id`: 1 each |
| s F4 | Observed time cannot exceed the local receipt; shape-valid future answers refuse on pair and periodic paths | `TestLabReviewObservationResponseJoins`, `TestLabObservationPeriodicAdversarialPairs` | `future-observation`, `future-periodic-two-layer`: 1 each |
| r N7 (cheap note) | Invoke a currentness closer outside the account lock; a callback can acquire the lock | `TestLabReviewContainmentCallbackLockOrder` | `containment-callback-under-lock`: 1 |

The control families run unmutated with exit 0. A source-overlay catalogue is
committed at `tests/lab-b1/mutants.py`: it requires green unmutated controls,
unique exact plants and the intended named assertion. The corrected catalogue
contains **28 overlays**, each with an intended named failure (test exit 1),
not 28 green tests. No new survivor is claimed as coverage.
The corrected full catalogue replay exits 0, including its unmutated control;
that orchestration success is distinct from each expected-red Go test exit 1.

The complete round-1 per-overlay map follows. `deadline-*` tests exercise two
deadline slots: connection at slot zero; pair-budget/native-age labels both
use slot one and duplicate the same two source plants. These labels do not
independently isolate caller-side budget/native-age wiring. Thus the original
28 overlays represent 24 distinct source plants, not 28 distinct gates.
Full pair/single late-durability tests separately exercise the real store hook,
original connection deadline and fenced result.

| Mutant | What it narrows the gate to | Named failing test selection | Exit |
| --- | --- | --- | --- |
| `publication-fence-overwrite` | Ignore a fence in the final reopening critical section | `TestReviewFenceDuringPublishIsSticky/during-publish` | 1 |
| `observation-clears-engine-unknown` | Single CAS overwrites pre-existing engine UNKNOWN | `TestReviewProbeObservationCommitClearsEngineUnknown` | 1 |
| `publication-clears-engine-unknown` | Pair CAS overwrites pre-existing engine UNKNOWN | `TestReviewProbePublicationCommitClearsEngineUnknown` | 1 |
| `publication-pre-cas-epoch` | Ignore epoch change before the CAS | `TestLabReviewFenceBeforeObservationCAS` | 1 |
| `publication-post-cas-epoch` | Ignore epoch change after the CAS but before callback | `TestReviewFenceDuringPublishIsSticky/during-cas` | 1 |
| `initial-lateness` | Accept initial reads >=300 ms after the receipt | `TestLabReviewInitialObservationWindow` | 1 |
| `initial-cooldown` | Accept initial reads <250 ms after the receipt | `TestLabReviewInitialObservationWindow` | 1 |
| `current-age-ceiling` | Allow local current proof at age >=1200 ms without guard masking | `TestLabReviewCurrentAgePredicate` | 1 |
| `current-age-future` | Allow negative local native age | `TestLabReviewCurrentAgePredicate` | 1 |
| `containment-callback-under-lock` | Run the currentness closer under the account mutex | `TestLabReviewContainmentCallbackLockOrder` | 1 |
| `deadline-before-cas-connection` | Ignore only the connection passed deadline before CAS | `TestLabReviewObservationCommitDeadlines/connection/` | 1 |
| `deadline-before-cas-pair-budget` | Ignore only the pair-budget passed deadline before CAS | `TestLabReviewObservationCommitDeadlines/pair-budget/` | 1 |
| `deadline-before-cas-native-age` | Ignore only the native-age passed deadline before CAS | `TestLabReviewObservationCommitDeadlines/native-age/` | 1 |
| `deadline-after-cas-connection` | Ignore only the connection passed deadline after CAS | `TestLabReviewObservationCommitDeadlines/connection/` | 1 |
| `deadline-after-cas-pair-budget` | Ignore only the pair-budget passed deadline after CAS | `TestLabReviewObservationCommitDeadlines/pair-budget/` | 1 |
| `deadline-after-cas-native-age` | Ignore only the native-age passed deadline after CAS | `TestLabReviewObservationCommitDeadlines/native-age/` | 1 |
| `late-cas-publishes` | Acknowledge successful-but-late CAS and enter the publication callback | `TestLabReviewPublicationDeadlines/late-cas` | 1 |
| `late-single-cas` | Acknowledge late single persistence and install S | `TestLabReviewPeriodicLateCAS` | 1 |
| `late-publication-reopens` | Reopen after a callback crosses its final connection deadline | `TestLabReviewPublicationDeadlines/late-publish` | 1 |
| `recovery-held` | Ignore disagreement between private active holds and external held bit | `TestLabReviewRecoveryJoinPredicates/held` | 1 |
| `recovery-revoked` | Ignore disagreement between private binding removal and external tombstone | `TestLabReviewRecoveryJoinPredicates/revoked` | 1 |
| `recovery-gateway-uid` | Ignore exact private/external gateway UID join | `TestLabReviewRecoveryJoinPredicates/gateway-uid` | 1 |
| `recovery-gateway-generation` | Ignore exact private/external gateway generation join | `TestLabReviewRecoveryJoinPredicates/gateway-generation` | 1 |
| `recovery-state-revision` | Permit engine revision above the envelope revision | `TestLabReviewRecoveryJoinPredicates/state-revision` | 1 |
| `response-operation-id` | Trust nested start without joining the response operation ID | `TestLabReviewObservationResponseJoins/response-operation-id` | 1 |
| `response-start-id` | Trust nested start without joining the response start ID | `TestLabReviewObservationResponseJoins/response-start-id` | 1 |
| `future-observation` | Remove the client receipt-time upper bound only | `TestLabReviewObservationResponseJoins/future-observation` | 1 |
| `future-periodic-two-layer` | Remove both the client upper bound and independent private observed<=receipt check | `TestLabObservationPeriodicAdversarialPairs/future-observation` | 1 |

The periodic future-time plant is deliberately two-layer: removing only the
client predicate still leaves the independent private recovery receipt-time
bound. Its pair counterpart isolates and kills the client predicate alone.
The pre-CAS direct fixture adds 5 ms to its wait solely to avoid nanosecond vs
persisted-millisecond rounding; no runtime timing bound is widened. Initial
setup/compile diagnostics are retained but excluded from the 28 corrected
kills. The older producer's two survivors remain explicit historical bounds.

The publication callback witness proves sticky refusal after a late callback;
it cannot retract already emitted bytes and is not an installed deadline-bound
transport. The first-read witness calls the same extracted Unix-read/window
method as the publication path; it is not OS scheduler qualification.

Non-blocking notes: the stale timing-stop paragraph and blanket-tag wording
are corrected in this fix. Cross-boot receipt liveness, historical head-chain
reconstruction, sealed historical format-count prose, socket-path swap and
root-native peer/owner qualification remain outside this bounded fix round;
none is silently promoted to native evidence or a new acceptance waiver.

## Evidence limits and scope

The actual C0 reader executes the C0 operator catalogue on frozen surfaces;
the private reference contract also applies the generated grammar/closure/size
catalogue to every recovery structure. Contract controls do not authenticate
B5 pins or native ledgers. C0/C0b/C0c/C0d/C0e and landed B2 coverage in
`internal/labcontractv0/coverage-map.md` is preserved, not replaced.

Validation commands and exact exit codes, signatures, source identity and
retained log paths are in the requested `out/HANDOFF.md` outside this checkout.
Default production tests were run, not omitted; their environment failures
must not be described as green or as a proved causal equivalence to main.
The owner published the original B1a head as PR #83. This fix round performs
no push or PR mutation, live key act, vendor network call or installed adoption.

The finite-plan reserve is bounded by both the approved scalar limit and the
frozen 256-entry array capacity, without altering/clamping the approved record.
Count arithmetic remains int64 and refuses impossible reserve sizes before
byte/revision arithmetic. This does not qualify a native finite plan.
