# B1 construction coverage and explicit non-acceptance

Status: **STOP:NATIVE_EXECUTION_EVIDENCE_ACCESS**. See the
[access decision](lab-b1-native-execution-access-stop.md). This is a bounded
construction delta, not an accepting daemon, installation, live qualification
or delivery of any whole acceptance row. The OPTION 2 private recovery addendum
is the first separate commit; its external C0 surface inventory and fixtures
remain byte-identical to the original freeze. The private surface is B1-only.

## Acceptance allocation

Every row allocated to B1 by lab profile sections 5 and 5.1 remains **incomplete**.
Tests below pair an inert valid control with a specific negative. They do not
replace the missing native authority or a released consumer assembly.

| Row | Construction tests | Narrowing mutants | Unimplemented acceptance boundary |
| --- | --- | --- | --- |
| A01 | TestLabCommittedBootstrapAndCrossRead; TestLabRuntimeSurfacePairs; TestLabRecoveryPrivateInventory | store-domain; runtime-closure; private-export-reader; private-audience | Tagged daemon/build-graph authority and all activation/fence/floor cross-import refusals are not assembled. Store-domain and reader separation alone do not prove the full row. |
| A02 | TestLabRuntimeCataloguePairs; TestLabRecoveryReplayPairs | runtime-range; replay-variants | No daemon API-key lease response mapping, measured gateway flag/body/header transformation or credential-free policy route is supplied by this delta. Other components own their allocated portions. |
| A03 | TestLabRecoveryJoinTampering/caller | caller-join | No actual managed current-caller/gateway authority, native receipt/debit join, worker/legacy material refusal or root-spoof boundary is installed. Synthetic join tests are not kernel caller evidence. |
| A05 | TestLabCommittedBootstrapAndCrossRead; TestLabRecoveryHistoricalReplay; TestLabRecoveryCASAndImmutableBudget; TestLabRecoveryJoinTampering; TestLabFiniteNarrowingReserve | joined-digest; drop-restored-replay; latest-replay-deadline; stale-cas-two-layer; count-reserve; byte-reserve; reconciliation-reserve | Fresh bootstrap and one-object CAS adapter are construction-only. Root operation/status bridge and complete native finite-plan proof remain absent. |
| A07 | TestLabLifetimeAndEarlierDeadline; TestLabRecoveryHistoricalReplay | replay-narrowed-authority; latest-replay-deadline | Existing-engine arithmetic covers 1..900 and earlier subsecond bounds in inert tests, not qualified native B2 time or cross-component ceiling agreement. |
| A08 | TestLabHoldUnknownAtomicJoin; TestLabReleaseHoldBoundary; TestLabLiftAndUnbindContainment; TestLabB1ReleaseTimeRequiredForHoldBoundary | unknown-projection; release-timestamp; lift-resurrection | Durable injected ack-loss fencing and engine containment do not implement the whole-needle gateway matcher or installed root lift protocol. |
| A09 | TestLabLiftAndUnbindContainment | unbind-closure | Registered callback closure is exercised; root current control, actual socket/stream/listener shutdown, polling and independently measured 500+500 ms timing are not implemented. |

No allocated row is treated as out of contract. Missing native access is a
blocking decision, not an exclusion. A04/A06/A10/A11/A12 have no B1 allocation
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
The native-access-mode diagnostic mutant fails
TestLabB1NativeLaunchAccessBoundary, exit 1, beside its unmodified native reader
control, exit 0. It proves native exact-mode enforcement only, not an installed
different-UID denial or permission to change native manager behavior.

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
