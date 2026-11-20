# C0 construction coverage map

Scope: the 24 byte formats in lab profile section 5.2, not runtime A01–A12 acceptance.
No separate attack-surface catalog was supplied; the profile inventory is the
bounded construction surface. Own-format controls are canonical public fixtures.
The source overlay mutant `foreign-format` disables string-singleton checking;
every listed format then fails its named foreign-discriminator assertion.
This proves format discrimination only, not kernel identity, native effects or
actual production-reader cross-read integration. Those remain assigned by section 5.1.

| Surface | Named test / own-format control | Killed narrowing mutant |
| --- | --- | --- |
| `swarma-broker-lab-activation/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-activation/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-authority/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-authority/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-preparation/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-preparation/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-owner-decision/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-owner-decision/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-off-vm-approval/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-off-vm-approval/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-access-attestation/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-access-attestation/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-start-fence/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-start-fence/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-consumer-high-water/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-consumer-high-water/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-time-checkpoint/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-time-checkpoint/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-custody/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-custody/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-account/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-account/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-service-journal/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-service-journal/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-install-plan/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-install-plan/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-launch-plan/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-launch-plan/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-retire-plan/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-retire-plan/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-next-plan/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-next-plan/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-stop-plan/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-stop-plan/1`; adjacent canonical valid fixture | `foreign-format` |
| `anthropic-api-key-lab/1` | `TestLabClosedSurfacePairs/anthropic-api-key-lab/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-hold/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-hold/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-operation/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-operation/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-root-control/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-root-control/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-match/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-match/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-broker-lab-q-evidence/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-q-evidence/1`; adjacent canonical valid fixture | `foreign-format` |
| `swarma-lab-release-set/1` | `TestLabClosedSurfacePairs/swarma-lab-release-set/1`; adjacent canonical valid fixture | `foreign-format` |

| Additional contract surface | Named valid/negative test | Control / narrowing bound |
| --- | --- | --- |
| API-key header/beta/body and policy GET | `TestLabAPIKeyWireFixturePairs` | `duplicate-beta` mutant fails duplicate beta/key field cases; other closed-profile negatives are separate fixtures. |
| Owner-role opening | `TestLabOwnerRolePairs` | `missing-owner-role` mutant admits missing/residual-only roles and is killed. Synthetic consent only. |
| Endpoint/vendor/privileged access metadata | `TestLabAccessAttestationPairs` | Owner-only positive beside endpoint, agent-controller and changed/incomplete roster plants. No native access exclusion proof. |
| Whole-version/encoding completeness | `TestLabMatcherSummaryPairs` | Complete summary beside missing-version/alignment, initialization and UNKNOWN-hold plants. No real-key scan. |
| Lease lifetime/earliest deadline | `TestLabLeaseDeadlinePairs` | 1/900 valid beside 0/901 and each ignored earlier subsecond deadline. No native clock witness. |
| Acyclic approval/journal pins | `TestLabApprovalTargetPairs`, `TestLabJournalHeadPairs` | Correct complete images beside changed input/lease without re-approval/reseal. |
| Inert Unix/no-egress probe | `ProbeTests.test_unix_valid_and_network_refused`, `ProbeTests.test_trace_audit_pairs` | Real Unix control and unfiltered socket-creation control beside EPERM and synthetic successful-egress/foreign-Unix/incomplete trace plants. |

All three source-overlay mutants were killed by intended named assertions;
none survived. This is a bounded mutation set, not an exhaustive mutation score.
No runtime, native Q, vendor compatibility, privileged fixture or production
acceptance row is treated as covered by these constructor/metadata controls.
That exclusion follows the C0-only scope in lab profile section 5.1.

## Revision 2 refusal controls

Every one of the 24 rows above additionally runs
`TestLabNestedClosurePairs` (all instantiated types per surface, including array
elements), `TestLabFieldGrammarPairs` (each primitive field), and
`TestLabPayloadLimitPairs` (at-limit preflight and size-specific over-limit).
Activation has no nested fields; its primitive/size controls still run.
`TestLabExactLimitRecordPairs` adds full grammar-valid frame/file boundary
controls; `TestLabArrayLimitPairs` admits 256 and refuses 257 account versions.
Fixed-field records cannot fill their transport ceiling with grammar-valid bytes;
preflight acceptance is not mislabeled schema acceptance.

| Contract | Named paired test | Narrowing mutant |
| --- | --- | --- |
| Recursive closure, all nested types | TestLabNestedClosurePairs | nested-closure-skip |
| Required coupled body fields | TestLabAPIKeyWireFixturePairs/body-strip-diagnostics | wire-body-subset-sentinel-unchecked |
| Measured body values and POST user agent | TestLabAPIKeyWireFixturePairs/body-value-model; /body-value-cache-scope; /post-user-agent | wire-body-values-unchecked; wire-cache-values-unchecked; wire-ua-unchecked |
| Every payload ceiling | TestLabPayloadLimitPairs | size-limit-off |
| 256-member bound | TestLabArrayLimitPairs | array-limit-off |
| Primitive field grammar | TestLabFieldGrammarPairs | time-noncanonical; enum-any-string; digest-uppercase; id-any-length; lifetime-1000; poll-any; material-limit-off; root-any; capture-timeout-any; exit-any; alignment-any; operation-short; uuid-uppercase; commit-uppercase; numeric-minimum-off; boolean-any |
| Principal tuple separation | TestLabPrincipalDisjointPairs | principal-generation-shared |
| Header credential guard, no request export | ProbeTests.test_header_credential_guards | header-credential-guard-off |
| Credential argument guard, no run directory | ProbeTests.test_extra_environment_credential_guards | argument-credential-guard-off |

Each mutant is applied only in the isolated candidate copy. Its handoff log
must name the failing test and intended assertion; a crash or unrelated setup
failure is not a killed control. Foreign-format, duplicate-beta and
missing-owner-role controls from revision 1 remain required. No native
B/G/M qualification or production reader acceptance is inferred.

## Revision 3 refusal isolation

Closure vectors carry freshly computed approval-target/journal-content seals,
not stale seals from their valid controls. The composed reader checks closure
before seals and must report field_set. All six sealed root negatives and
all 84 sealed nested negatives pass their independent seal-only controls.
No cryptographic approval or runtime consumer acceptance is claimed.

| Contract | Named paired test | Narrowing source-overlay mutant |
| --- | --- | --- |
| Empty-array tools, not a path-set approximation | TestLabAPIKeyWireFixturePairs/body-value-tools-nonempty; /body-value-tools-type | wire-tools-unchecked |
| String metadata/diagnostic sentinels | TestLabAPIKeyWireFixturePairs/body-value-metadata-user-id-type; /body-value-diagnostics-id-type | wire-sentinel-type-unchecked |
| Two-sided fixed hex length, algorithm, ASCII and enum case | TestLabFieldGrammarPairs | digest-overlong; digest-any-algorithm; operation-overlong; commit-overlong; uuid-overlong; id-non-ascii; material-non-ascii; enum-case-insensitive |
| Closure before valid seals | TestLabClosedSurfacePairs; TestLabNestedClosurePairs | top-level-closure-skip; nested-closure-skip; closure-drop-approval-reseal; closure-drop-journal-reseal |
| Gateway service / caller worker kind | TestLabPrincipalDisjointPairs/wrong-kind-gateway; /wrong-kind-caller | principal-kind-unchecked |

The primitive-field controls exercise both ASCII endpoints, each hex alphabet
edge, each UUID group at length minus/plus one, identifier/material length
minus/plus one, enum/singleton exact spelling, canonical post-epoch and four-digit
year bounds, and each integer lower/upper bound. The safe-integer upper refusal
is at the shared canonical gate, not mislabeled as a field range refusal.

The former wire-body-subset mutant now survives the 72 wire fixtures: the new
metadata/diagnostic typed readers independently require the missing fields.
That is a bounded redundancy observation, not a killed mutant or a universal
equivalence claim. Removing both the path-presence and sentinel-reader gates
(wire-body-subset-sentinel-unchecked) fails the required-field negative; the
wire-sentinel-type-unchecked mutant separately fails the new type negatives.
