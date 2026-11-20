# B1 construction coverage and explicit non-acceptance

Status: **STOP:C0C_CURRENT_RPC_BUDGET**. See the
[timing decision needed](lab-b1-observation-budget-stop.md). Native evidence
access is resolved by C0c in PR #81; that prior stop is not reopened. This is a bounded
construction delta, not an accepting daemon, installation, live qualification
or delivery of any whole acceptance row. The OPTION 2 private recovery addendum
is the first separate commit. The combined inventory retains the landed C0,
C0b and C0c external bytes from eef0f9f3, plus B1 private recovery. The private
surface is B1-only; no external observation/invocation field was changed.

## Acceptance allocation

Every row allocated to B1 by lab profile sections 5 and 5.1 remains **incomplete**.
Tests below pair an inert valid control with a specific negative. They do not
replace the missing installed native authority or a released consumer assembly.

| Row | Construction tests | Narrowing mutants | Unimplemented acceptance boundary |
| --- | --- | --- | --- |
| A01 | TestLabCommittedBootstrapAndCrossRead; TestLabRuntimeSurfacePairs; TestLabRecoveryPrivateInventory | store-domain; runtime-closure; private-export-reader; private-audience | Tagged daemon/build-graph authority and all activation/fence/floor cross-import refusals are not assembled. Store-domain and reader separation alone do not prove the full row. |
| A02 | TestLabRuntimeCataloguePairs; TestLabRecoveryReplayPairs | runtime-range; replay-variants; bounded-usd-ceiling; bounded-invocation-count | Actual C0b shape parsing is covered, not invocation approval. No daemon API-key response mapping, measured gateway transformation or credential-free policy route is supplied. |
| A03 | TestLabRecoveryJoinTampering/caller; TestLabObservationClientPairs; TestLabObservationKernelPeerAndPath; TestLabObservationPathChanges | caller-join; observation-kernel-peer; observation-daemon-uid; observation-current; observation-start-pins; observation-debit-join; observation-pending-stop | Real Unix transport/kernel fixture peers and full fixture joins are covered. No installed managed gateway/caller factory, worker/legacy material refusal or privileged root-native qualification is supplied. |
| A05 | TestLabCommittedBootstrapAndCrossRead; TestLabRecoveryHistoricalReplay; TestLabRecoveryCASAndImmutableBudget; TestLabRecoveryJoinTampering; TestLabFiniteNarrowingReserve | joined-digest; drop-restored-replay; latest-replay-deadline; stale-cas-two-layer; count-reserve; byte-reserve; reconciliation-reserve | Fresh bootstrap and one-object CAS adapter are construction-only. Root operation/status bridge and complete native finite-plan proof remain absent. |
| A07 | TestLabLifetimeAndEarlierDeadline; TestLabRecoveryHistoricalReplay | replay-narrowed-authority; latest-replay-deadline | Existing-engine arithmetic covers 1..900 and earlier subsecond bounds in inert tests, not qualified native B2 time or cross-component ceiling agreement. |
| A08 | TestLabHoldUnknownAtomicJoin; TestLabReleaseHoldBoundary; TestLabLiftAndUnbindContainment; TestLabB1ReleaseTimeRequiredForHoldBoundary | unknown-projection; release-timestamp; lift-resurrection | Durable injected ack-loss fencing and engine containment do not implement the whole-needle gateway matcher or installed root lift protocol. |
| A09 | TestLabLiftAndUnbindContainment; TestLabObservationCurrentRPCBudget; TestLabObservationComposedCurrentBudget; TestLabObservationRecurringWatchdogBudget; TestLabObservationTransportWindow | unbind-closure; observation-no-half-close; observation-transport-window | Existing-engine and Unix diagnostic controls prove the new timing stop, not valid A09 timing. Root controls, affected stream/listener closure and independent native 500+500 ms measurements remain absent. |

No allocated row is treated as out of contract. The observation/current-check
budget conflict is a blocking decision, not an exclusion. A04/A06/A10/A11/A12 have no B1 allocation
in section 5.1; their C0 shape tests carry no behavioral acceptance claim.

## Implementation source-overlay mutations

The named Go tests ran against source overlays in the same isolated copied
checkout as their green controls. Expected-red exit 1 is a failed test, not a
passing gate. The handoff retains full commands, source hashes and real exits.

| Mutant | Narrows the gate to | Named failing test | Exit / limit |
| --- | --- | --- | --- |
| runtime-closure | Exact runtime field set | TestLabRuntimeSurfacePairs | 1 |
| private-export-reader | B1-only recovery reader | TestLabRuntimeSurfacePairs | 1 |
| runtime-range | Closed lifetime upper bound | TestLabRuntimeCataloguePairs/swarma-broker-lab-activation | 1 |
| store-domain | Disjoint store identities | TestLabCommittedBootstrapAndCrossRead/lab-to-production | 1 |
| joined-digest | Embedded external digest join | TestLabRecoveryJoinTampering/digest | 1 |
| caller-join | Recovered caller generation join | TestLabRecoveryJoinTampering/caller | 1 |
| latest-replay-deadline | Original replay deadline, not latest renewal | TestLabRecoveryHistoricalReplay | 1 |
| drop-restored-replay | Retained replay operations on restart | TestLabRecoveryHistoricalReplay | 1; restart refuses rather than losing the history |
| release-timestamp | Inclusive release-time hold boundary | TestLabReleaseHoldBoundary/late=true | 1 |
| count-reserve | Remaining operation slots | TestLabFiniteNarrowingReserve/count | 1 |
| byte-reserve | Private byte headroom | TestLabFiniteNarrowingReserve/private-bytes | 1 |
| reconciliation-reserve | Revision headroom for reconciliation | TestLabFiniteNarrowingReserve/revision | 1 |
| unknown-projection | No external view before durable confirmation | TestLabHoldUnknownAtomicJoin | 1 |
| lift-resurrection | Lift does not resurrect ended leases | TestLabLiftAndUnbindContainment | 1 |
| unbind-closure | Registered affected connection closure | TestLabLiftAndUnbindContainment | 1; not a native socket timing measurement |
| replay-narrowed-authority | Retry revalidates current earlier bound | TestLabLifetimeAndEarlierDeadline/authority | 1 |
| stale-cas-one-layer | Adapter CAS alone | None: survivor | 0; existing protected store independently refuses the stale revision. This does not prove the adapter check alone is necessary. |
| stale-cas-two-layer | Joined adapter/store CAS boundary | TestLabRecoveryCASAndImmutableBudget | 1; deliberately removes both independently enforcing revision checks |

The contract-only private-audience, recovery-digest, replay-variants and
recovery-closure mutants have named failing tests in the
[C0 coverage map](../internal/labcontractv0/coverage-map.md).
The historical native-access-mode diagnostic mutant fails
TestLabB1NativeLaunchAccessBoundary, exit 1, beside its unmodified native reader
control, exit 0. It proves native exact-mode enforcement only, not an installed
different-UID denial or permission to change native manager behavior.

## C0b/C0c actual client and reader construction

The fresh resume run re-executed all 18 adapter mutations above against the
rebased source, and 31 C0b/C0c mutations: **49 overlays, 47 intended named
test failures (real exit 1), two survivors (real exit 0)**. No build failure,
panic or setup failure is counted as a killed gate. Result manifests and logs
are retained under the isolated scratch `logs/b1-c0c-mutant-results-final.json`
(corrected run 02, added grammar-bound runs 03 and 04).
Every adversarial client mode has an adjacent complete valid pair; transport
window and initial-floor tests also have independent valid single observations.

| Mutant | Narrows the gate to | Named failing test | Exit / limit |
| --- | --- | --- | --- |
| observation-kernel-peer | Actual kernel UID equality | TestLabObservationKernelPeerAndPath | 1; fixture UID, not root-native qualification |
| observation-daemon-uid | Dedicated client UID binding | TestLabObservationKernelPeerAndPath | 1 |
| observation-socket-mode | Exact protected socket mode | TestLabObservationPathChanges/socket-mode | 1 |
| observation-symlink | Lstat refuses a substituted symbolic link | TestLabObservationPathChanges/symlink | 1 |
| observation-parent-mode | Both generic and exact parent mode guards | TestLabObservationPathChanges/parent-mode | 1; two independently enforcing mode checks removed together |
| observation-current | Protected generation currentness | TestLabObservationClientPairs/not-current | 1 |
| observation-complete | Complete locked projection | TestLabObservationClientPairs/incomplete | 1 |
| observation-manager | Approved manager incarnation | TestLabObservationClientPairs/wrong-manager | 1 |
| observation-store-generation | Installed native store generation | TestLabObservationClientPairs/store-generation | 1 |
| observation-counter-generation | Counter scoped to that store | TestLabObservationClientPairs/counter-generation | 1 |
| observation-start-pins | Complete expected start binding, including UID | TestLabObservationClientPairs/wrong-start-uid | 1 |
| observation-terminal-start | No use after terminal launch | TestLabObservationClientPairs/stopped | 1 |
| observation-observed-window | Observation inside local BOOTTIME interval | TestLabObservationClientPairs/old-observation | 1 |
| observation-debit-join | Receipt/debit incarnation agreement | TestLabObservationClientPairs/debit-mismatch | 1 |
| observation-invalidation | Invalidation closes use | TestLabObservationClientPairs/invalidation | 1 |
| observation-pending-stop | Pending exec.stop closes use | TestLabObservationClientPairs/pending-stop | 1 |
| observation-initial-floor | First sequence above supplied replay floor | TestLabObservationSequenceFloor | 1; floor is a fixture input, not persisted publication |
| observation-final-sequence | Strictly fresh final sequence | TestLabObservationClientPairs/final-sequence | 1 |
| observation-final-snapshot | Identical native snapshot at revalidation | TestLabObservationClientPairs/final-mismatch | 1 |
| observation-no-half-close | Request EOF before response | TestLabObservationCurrentRPCBudget | 1; sufficient-budget valid control fails, so dead transport cannot satisfy a timeout-only negative |
| observation-frame-length | Framer length equality alone | None: survivor | 0; strict canonical parser independently refuses the extra frame bytes. Not proof that the framer equality alone is necessary. |
| observation-trailing-frame-two-layer | Length check plus discard of trailing bytes | TestLabObservationClientPairs/two-frames | 1; both frame preservation and length guard narrowed |
| observation-transport-window | Nonextendable 250 ms connection window | TestLabObservationTransportWindow | 1; valid payload with late EOF |
| observation-ancillary | No received descriptors | TestLabObservationClientPairs/ancillary | 1 |
| bounded-usd-ceiling | Exact safe-integer micro-USD ceiling | TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1/[max_total_cost_usd]/usd-boundary-9007199254.740992 | 1 |
| bounded-invocation-count | At most 256 invocations | TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1/[max_invocations]/integer-257 | 1 |
| bounded-output-tokens | At most 128000 output tokens | TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1/[max_output_tokens_per_invocation]/integer-128001 | 1 |
| bounded-wall-time | At most 900000 ms per wall-time bound | TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1/[max_wall_time_total_ms]/integer-900001 | 1 |
| bounded-usd-grammar | Exactly six decimal places | TestLabRuntimeCataloguePairs/swarma-broker-lab-bounded-invocation/1/[max_total_cost_usd]/usd-boundary-1.0000001 | 1 |
| observation-native-id | Alphanumeric-first native IDs | TestLabRuntimeCataloguePairs/swarma-broker-lab-observation-request/1/[start_id]/native-byte-0-95 | 1 |
| observation-native-executor | Closed native executor grammar | TestLabRuntimeCataloguePairs/swarma-broker-lab-observation-response/1/[start_executor]/native-confusable-a_b | 1 |

The earlier stale-cas-one-layer survivor remains declared in the first table.
The initial mutation-driver diagnostic also exposed an uncombined parent-mode
plant and a floor plant masked by the later final-sequence guard. The corrected
driver accumulates same-file edits; the new first-observation test isolates the
floor gate. Only the corrected run above is claimed, not those earlier plants.
Framing/EOF timeout regressions initially found a wrapped-EOF handling bug and
a negative ReadMsgUnix count panic; both were repaired and the complete client
suite rerun. Those failed development runs are not successful refusal evidence.

`TestLabObservationComposedCurrentBudget` traverses the real existing-engine
poll method using a test-only observation authority wrapper and the existing
durable fixture account. It asserts no publication or journal change on the
200 ms negative. Its one-second positive and the recurring test's 750 ms
positive are diagnostics, explicitly NOT compliant A09 valid timing controls.
The actual client remains tentative: no installed accepting factory, atomic
observation-floor commit, post-commit publication or root-native authority is
claimed. The new tests do not turn an incomplete acceptance row green.

## Strict readings and evidence limits

- Missing recovery after enrollment, orphan bootstrap, partial/mismatched join,
  changed operation budget, contradictory retry and unknown durability fail
  closed. Recovery preserves operation results and exact release timestamps.
- One protected Account.Put commits the private envelope and its external
  snapshot together. No external sidecar is authoritative. Private recovery is
  never a consumer export. Generic Read refuses it; only B1 uses ReadRecovery.
- The lab constructor selects a separate credential kind, irreversible ended
  leases and narrowed-authority replay checks. Production constructors select
  their original kind and behavior; no new lab constant enters the default
  build. No tagged factory accepts synthetic authority for an installed daemon.
- Reserve arithmetic is conservative construction policy: two baseline slots
  for account hold/reconciliation plus active bindings/leases, with 8192 private
  bytes and 2048 external bytes per reserved operation. This is not yet a proof
  against a complete native admitted plan. No pruning or rollover is allowed.
- Only new credential material is ssh-placeholder. Clearing owned byte buffers
  does not claim zeroization of Go string/map copies or qualified native custody.
- Native qualification, C-OPEN-OWNERS and all DN-09 C live gates remain closed.
  No real credential, vendor call, installed daemon or production activation is
  part of this construction evidence. No push is authorized.
