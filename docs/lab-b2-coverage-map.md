# B2 acceptance and mutation coverage

The brief supplies rows A01, A06 and A07 from the unit table, not every clause
owned by the other units. This map reports B2 fixture coverage only. Every test
has a concise claim comment and an adjacent valid control. Previously committed
test names are retained. Lab consumer tests move from `timeconf` into
`internal/labtimev0` with the inverted dependency; production tests are unchanged.

| Row | B2 positive/negative tests | Source-overlay mutants killed |
|---|---|---|
| A01 | `TestLabB2FrozenSurfacePairs`, `TestLabB2CatalogueGrammarPairs`, `TestLabProductionConstructionClosed`, `TestLabProductionCrossReadTime`, `TestInactiveImportGraphBuildTagControlsLabTime`, `TestInactiveImportGraphLabTimeRealTree`; tagged/untagged full tests/builds and production dependency graphs | format, build-graph |
| A06 | `TestLabCOpening`, `TestLabStartJoins`, `TestLabRootFenceOneUse`, `TestLabManagerPrefix`, `TestLabFloorContinuity`, `TestLabCheckpointContinuity`, `TestLabWitnessDurableCAS`, `TestLabConsumerSettlementAndFloor`, `TestLabFloorDurabilityFaults`, `TestLabConsumerAuthenticatedNTS`, `TestLabNTSInventory`, `TestLabConsumerStickyRestart`, `TestLabBurnPersists`, `TestLabStartContinuityBurn`, `TestLabBurnedRecovery` | owner-role, fence-replay, exact-heads, off-home, fence-mode, fence-group, watermark, manager-prefix, floor-prefix, witness-cas, floor-sync, nts-only, sticky-floor, burned-reopen, start-burn, c1-hold-reset |
| A07 | `TestLabQualificationDeadline`: 1/900, earliest deadline, 0/901, reached exclusive bound and held time; `TestLabPublicApprovalExpiry`: fresh upper equality, both approval bounds and exposed issuance deadline | qualification-expiry, owner-deadline, offvm-deadline, use-expiry |

Additional A06 fix-round gate coverage:

| Tests (valid controls and negatives) | Narrowing overlays |
|---|---|
| `TestLabPublicLifecycle`, `TestLabPublicProvisionRefusals`, `TestLabPublicRefusalFloors` | start-marker, consume-current, provision-empty, prepare-decision, prepare-settled-lower, prepare-settled-upper, refusal-floors |
| `TestLabPublicApprovalExpiry` | owner-deadline, offvm-deadline, use-expiry, heads-after-failure |
| `TestLabStartJoins`, `TestLabRestartChainRefusals` | restart-ack, restart-generation, restart-heads, restart-state, approval-heads, approval-generation, approval-invocation, offvm-clock-order, offvm-clock-before, decision-digest |
| `TestLabPublicStartTransientRefusal`, `TestLabStartContinuityBurn` | start-heads-join, start-unknown-burn, start-burn |
| `TestLabUnverifiedJournalRefusal`, `TestLabPublicVerifiedForkBurn`, `TestLabBurnPersistenceRefusal` | journal-unknown-burn, journal-complete-first, journal-regression-burn, burn-persistence, heads-after-burn |
| `TestLabPublicStickyRestart`, `TestLabConsumerStickyRestart` | sticky-floor |

Fix-round-2 public constructor joins (each negative has a restored valid
construction/use control):

| Public constructor gate | Named test / subcase | Narrowing overlay |
|---|---|---|
| lab authority ID | `TestLabPublicConstructorEnrollmentJoins/authority-id` | enroll-authority-id |
| authority version | `TestLabPublicConstructorEnrollmentJoins/authority-version` | enroll-authority-version |
| start owner decision equals receipt-named enrollment decision | `TestLabPublicConstructorEnrollmentJoins/decision-pin` | enroll-decision-pin |
| amendment trust root | `TestLabPublicConstructorEnrollmentJoins/trust-root` | enroll-trust-root |
| machine scope | `TestLabPublicConstructorEnrollmentJoins/machine` | enroll-machine |
| consumer scope | `TestLabPublicConstructorEnrollmentJoins/consumer` | enroll-consumer |
| broker-lab purpose | `TestLabPublicConstructorEnrollmentJoins/purpose` | enroll-purpose |
| continuity scope | `TestLabPublicConstructorEnrollmentJoins/continuity-scope` | enroll-continuity-scope |
| loaded fence still current | `TestLabPublicConstructorCurrentJoin` | construct-current |
| NTS-authdata source | `TestLabPublicConstructorInputJoins/source` | construct-source |
| operator resync | `TestLabPublicConstructorInputJoins/resync` | construct-resync |
| separate roots | `TestLabPublicConstructorInputJoins/roots` | construct-roots |
| inventory digest grammar | `TestLabPublicConstructorInputJoins/inventory` | construct-inventory-format |
| inventory equality, without unverified burn | `TestLabPublicConstructorInventoryRefusal` | inventory-join, inventory-burn |
| spent start refuses before stale-head burn | `TestLabPublicConstructorSpentStart` | spent-start-first |
| prepare history verified before genesis writes | `TestLabPublicPrepareJournalJoin` | prepare-journal, prepare-journal-before-write |

These are A06/A07 constructor acceptance witnesses. For redundant enrollment
and input guards, a private test-only runtime-selection counter pins rejection
before runtime/store access; a killed deletion is not automatically a use
bypass. The decision-pin case uses a provisioned D1 enrollment and valid later
D2 start; it cannot be masked by changing the enrollment's store binding. The
nil-Start negative shares the currentness guard, not a separate field join.
All earlier test names are retained. C0b/C0c's independent coverage map and
sealed contract index are preserved exactly from `eef0f9f3`.

## Fence currentness regression (fix round 3)

A06 requires exact loaded-fence bytes at public construction and every use.
`TestLabPublicConstructorCurrentJoin/reissued` and
`TestLabPublicUseCurrentJoin` replace the consumed fence with a canonical,
same-length fence carrying a different approval digest, leaving its generation,
context and consumed bit intact. The record decoder accepts the replacement;
it is not evidence of a newly approved start. Restoring the original bytes is
an adjacent positive control. Refusal leaves the floor and burn state unchanged;
construction also leaves the generation unspent.

| Currentness gate | Named regression | Narrowing overlays |
|---|---|---|
| construction | `TestLabPublicConstructorCurrentJoin/reissued` | current-length-construct, current-semantic-construct |
| each use | `TestLabPublicUseCurrentJoin` | current-length-use, current-semantic-use |

The length overlays accept any same-length replacement; semantic overlays
accept well-formed consumed fences matching generation and context while
ignoring the changed approval identity. Both are weaker than byte identity.
No product code or frozen surface is changed by this regression-only round.

## Per-mutant evidence

The checked-in `tests/lab-b2/mutants.py` specifies each exact replacement,
named test, row and narrowed gate. The handoff includes its generated table
and exit receipts, including the intended assertion (not any named failure).
Deadline/setup failures are invalid evidence. These are selected gate witnesses, not an exhaustive
mutation-equivalence claim. The first expiry mutation survived because the
original zero-width fixture made the now and W expiry assertions overlap.
The retained regression uses a nonzero valid interval; the same mutant then
fails `TestLabQualificationDeadline`. No survivor is reclassified as a kill.
Fix-round driver 06 also retained a `consume-current` survivor: a reused clock
let the settlement watermark refuse before the missing fence gate mattered.
The lifecycle regression now advances to a fresh interval for each changed or
removed fence. Its rerun must fail the intended fence assertion to count.

## Limits and out-of-contract clauses

- A01 is limited by B2’s section 5.1 row to the five consumed byte surfaces,
  time factory, local storage and tagged import control. The graph now checks
  the actual shipped tree in both configurations; its retained negative plants
  test the instrument. This is not qualification of a future lab daemon. The
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
- This is fix round 1. The only code outside `internal/labtimev0` is the tagged
  `timeconf` engine seam, the tagged assembly graph test and the overlay driver;
  dependency inversion requires those paths. Shared docs are listed in the handoff.
