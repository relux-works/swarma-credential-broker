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
