# B2 acceptance and mutation coverage

The brief supplies rows A01, A06 and A07 from the unit table, not every clause
owned by the other units. This map reports B2 fixture coverage only. Every test
has a concise claim comment and an adjacent valid control. All previously
committed tests retain their names and source; no existing test is removed.

| Row | B2 positive/negative tests | Source-overlay mutants killed |
|---|---|---|
| A01 | `TestLabB2FrozenSurfacePairs`, `TestLabB2CatalogueGrammarPairs`, `TestLabProductionConstructionClosed`, `TestLabProductionCrossReadTime`, `TestInactiveImportGraphBuildTagControlsLabTime`; untagged full tests/build | format, build-graph |
| A06 | `TestLabCOpening`, `TestLabStartJoins`, `TestLabRootFenceOneUse`, `TestLabManagerPrefix`, `TestLabFloorContinuity`, `TestLabCheckpointContinuity`, `TestLabWitnessDurableCAS`, `TestLabConsumerSettlementAndFloor`, `TestLabFloorDurabilityFaults`, `TestLabConsumerAuthenticatedNTS`, `TestLabNTSInventory`, `TestLabConsumerStickyRestart`, `TestLabBurnPersists`, `TestLabStartContinuityBurn`, `TestLabBurnedRecovery` | owner-role, fence-replay, exact-heads, off-home, fence-mode, fence-group, watermark, manager-prefix, floor-prefix, witness-cas, floor-sync, nts-only, sticky-floor, burned-reopen, start-burn, c1-hold-reset |
| A07 | `TestLabQualificationDeadline`: 1/900, earliest deadline, 0/901, reached exclusive bound and held time | qualification-expiry |

## Per-mutant evidence

The checked-in `tests/lab-b2/mutants.py` specifies each exact replacement,
named test, row and narrowed gate. The handoff includes its generated table
and exit receipts. These are selected gate witnesses, not an exhaustive
mutation-equivalence claim. The first expiry mutation survived because the
original zero-width fixture made the now and W expiry assertions overlap.
The retained regression uses a nonzero valid interval; the same mutant then
fails `TestLabQualificationDeadline`. No survivor is reclassified as a kill.

## Limits and out-of-contract clauses

- A01 is limited by B2’s section 5.1 row to the five consumed byte surfaces,
  time factory, local storage and tagged import control. The graph plant is
  an instrument fixture, not qualification of a future daemon assembly. The
  production receipt codec remains reusable; a lab-owned receipt is not a new
  invented production authority. B1/B3/G1/M1/RB own their other cross-read,
  activation, journal, packaging and command admission paths.
- A06 native NTS/root protection/fsync/boot/load and live enrollment, activation
  and post-bind access readback belong to B4/B5/Q and remain unrun under
  C-OPEN-OWNERS (sections 4.1, 4.3 and 5.1). Root ownership tests use the same
  descriptor policy with synthetic expected ownership, not root execution.
  The floor-sync overlay proves execution/refusal at the fault boundary, not
  power-loss behavior. No live key, real vendor or installed witness is used.
- A07 B2 supplies the deadline predicate only. Actual issue/renew, ceiling
  mismatch, duplicate/replayed/retargeted effects and UNKNOWN reconciliation
  are B1/G1/B4/Q clauses in section 5.1, not independently implemented here.
- C1 checks are metadata/admission predicates under section 4.2, not live
  revocation/replacement, Infra provisioning or a privileged no-restore claim.
  Never-reused scope and owner provenance require external authenticated acts.
- This is initial producer work, not rework; there is no wider-module rework
  delta. Shared documentation files are listed explicitly in the handoff.
