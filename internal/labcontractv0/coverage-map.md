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

The wire-body-subset mutant is equivalent under recursive closure and value readers:
each measured body path is independently required by its typed/value check.
It is reported as a survivor, never counted as a killed mutant. Removing both the path-presence and sentinel-reader gates
(wire-body-subset-sentinel-unchecked) fails the required-field negative; the
wire-sentinel-type-unchecked mutant separately fails the new type negatives.


## Mechanically generated grammar controls

`generated_test.go` derives the matrix from every field grammar in the closed
inventory, including element grammars of empty arrays. Each mutation runs beside
its accepted control. It does not infer admissibility from the reference checker.
The direct field checks isolate grammar/count limits from unrelated frame ceilings
and seals; the existing canonical-record and re-sealed closure controls remain.
All literal bytes are altered and removed individually, all fixed-case letters
are flipped individually, and all separators are altered/removed; UUID separators
also move at constant total length. There is no case operation on a digit.

| Normative rule | Generated cases / named test | Narrowing source overlays |
| --- | --- | --- |
| Every field and array-element grammar: JSON kinds | null and every other wrong JSON kind beside a same-type control; TestLabGeneratedGrammarPairs | grammar-<node>-null; grammar-<node>-type |
| Every singleton and every enum member | per-byte alteration/removal, suffix/empty, per-letter case, each separator alternative; TestLabGeneratedGrammarPairs | singleton-prefix-only; singleton-case-insensitive; enum-prefix-only; enum-case-insensitive |
| Digest label/prefix | each sha256: byte altered/removed, complete prefix removed, letter case and colon variants; TestLabFieldGrammarPairs; TestLabGeneratedGrammarPairs | digest-prefix-byte-0..6; digest-prefix-optional; digest-prefix-caseless; digest-prefix-separator-any |
| Each independent hex group | 0/9/a/f accepted, slash/colon/backtick/g/uppercase refused; group length minus/plus one refused; TestLabFieldGrammarPairs; TestLabGeneratedGrammarPairs | <kind>-g<group>-uppercase/alpha-g/slash/colon/backtick/no0/no9/noa/nof/short/long |
| Every UUID dash | altered, removed, doubled, replaced by hex and shifted at constant length; TestLabFieldGrammarPairs | uuid-separator-1..4-any/optional/underscore; uuid-hex-or-dash-36; uuid-four-dashes-anywhere |
| ASCII and string lengths | 0/1/2/max-1/max/max+1 bytes; 0x20/21/22/7d/7e/7f and non-ASCII; TestLabGeneratedGrammarPairs | id-empty; id-127; id-lower-inside; material-empty; material-4095; material-upper-inside |
| Every integer range | min-1/min/min+1/max-1/max/max+1, fractional number and wrong JSON kinds; TestLabGeneratedGrammarPairs | <range>-low/high--1/1; uint-min-minus1/plus1; integer-max-minus1/plus1 |
| Canonical time | epoch and four-digit-year bounds at nanosecond precision, component bounds, fractional count, fixed T/Z case, every separator and offset/redundant-fraction refusals; TestLabGeneratedGrammarPairs | time-epoch-off; time-noncanonical |
| Every array grammar | 0/1/255/256 accepted, 257 refused, plus all wrong JSON kinds; TestLabGeneratedGrammarPairs | array-limit-255; array-limit-257; grammar-<array-node>-null/type |
| Every measured body occurrence | null/all wrong JSON kinds; literal mutations for retained closed values; count minus/exact/plus one; numeric minus/exact/plus one; Boolean opposite; TestLabGeneratedWirePairs | wire-tools-null-as-empty; wire-sentinel-null-as-string; wire-body-values-unchecked |
| Envelope/header literals and each beta token | per-byte/case/separator mutations; original value and case-insensitive header-name controls; TestLabGeneratedWireEnvelopePairs | wire-ua-unchecked; duplicate-beta |
| Three principal pairs | gateway only, caller only and both kinds swapped; exact service/worker valid pair; TestLabPrincipalDisjointPairs | principal-kinds-distinct-only; principal-kinds-not-both-wrong; principal-kinds-swapped-also |
| Composed approval/journal seals | closed stale-seal record refuses approval_seal/journal_seal beside original record; TestLabComposedSealPairs | composed-approval-seal-off; composed-journal-seal-off |

The three exported null-leaf wire fixtures preserve the other 72 cases and bring
the corpus to 75 cases (2 admitted, 73 refused) in revision 3; revision 4 adds one alias refusal. Sentinel/prompt string contents
were not retained by the measurement: they are type-checked, not frozen to the
public reconstructed strings. There is no negative array count in JSON; zero is
the lower count control. Fixed-length hex groups have one accepted length, so
both immediately neighboring lengths refuse rather than inventing an interior.
Native multi-record joins, custody/effects and live qualification remain outside
C0; these construction checks make no production acceptance claim.

The same mechanical label matrix also runs for every root/nested JSON member
name (`TestLabGeneratedClosedFieldPairs`), with specific field_set refusals and
no seal gate. Both admitted HTTP profiles run the envelope/header matrix, not
only POST. Header names retain their case-insensitive valid controls; JSON
member names remain case-sensitive. Reconstructed open string fields admit
empty, changed and non-ASCII strings, rather than freezing the public markers.

## Revision 4: exact members and explicit operators

The normative finite operator list is now **README.md, Normative negative
operator catalogue**. It replaces the narrower earlier per-byte-only description.
The same literal operators run on digest labels, entire fixed hex values, enum
members, both HTTP envelopes, beta tokens, and all record/body member names.
Unicode label aliases, leading insertions and single-/double-sided wrappers are
included. Significant time-fraction leading zeros remain admitted controls;
redundant all-zero and nonzero trailing-zero forms refuse. CCJ lexical controls
cover zero and nonzero seeds as well as both accepted range endpoints.

| Rule / former gap | Paired named test and intended refusal | Narrowing source overlay |
| --- | --- | --- |
| Exact recursive body closure, including dotted path aliases | `TestLabGeneratedWireClosurePairs`, `body_fields`; exported `body-extra-path-alias` | `wire-dotted-paths-only` |
| Every body member's literal/case/Unicode aliases | `TestLabGeneratedWireClosurePairs`, `body_fields` | `wire-body-keys-caseless` |
| Whole digest label, start/end anchoring | `TestLabGeneratedGrammarPairs`, digest node | `digest-label-upper-alternative`, `digest-unanchored-start`, `digest-unanchored-end` |
| Whole UUID case, braces, URN, quotes, brackets, whitespace | `TestLabGeneratedGrammarPairs`, UUID node | `uuid-all-upper-alternative`, `uuid-braces-accepted`, `uuid-urn-prefix-accepted`, `uuid-quoted-accepted`, `uuid-bracketed-accepted`, `uuid-whitespace-wrapped` |
| Every beta separator; reversed order remains valid | `TestLabGeneratedBetaSeparatorPairs`, `beta` | `beta-separator-semicolon`, `beta-separator-space` |
| Redundant nonzero fraction and date/time separator | `TestLabGeneratedGrammarPairs`, time node | `time-trailing-zero-fraction-admitted`, `time-space-separator-admitted` |
| Every owner's role accepted, independent residual consent | `TestLabGeneratedOwnerSetPairs`, semantic owner-set check | `owner-accepted-first-role-only`, `owner-residual-unchecked` |
| Every member's duplicate bytes before map projection | `TestLabGeneratedObjectBytePairs`, duplicate parser gate | `wire-duplicate-member-guard-off`; `ccj-duplicate-and-canonical-guards-off` removes both redundant CCJ guards |
| Canonical object bytes, distinct from equivalent decoded values | `TestLabGeneratedCanonicalBytePairs`, canonical round trip | `ccj-canonical-byte-guard-off` |
| Zero/nonzero numeric canonical spelling, each lexical operator | `TestLabGeneratedNumberLexemePairs`, canonical parser or negative range | `ccj-leading-zero`, `ccj-redundant-zero`, `ccj-all-zero-leading`, `ccj-all-zero-redundant`, `ccj-plus-sign`, `ccj-minus-sign`, `ccj-negative-zero`, `ccj-fraction`, `ccj-exponent`, `ccj-plus-exponent`, `ccj-minus-exponent` |
| Raw envelope/body-root/header-cell JSON kinds | `TestLabGeneratedWireJSONTypePairs`, typed decode or envelope/member refusal | Existing source-scheme, method, header and body-closure overlays; null is never projected into an admitted empty default. |

The wire corpus is now **76 cases, 2 admitted and 74 refused**; the original 75
are unchanged. The reference now exposes `wireRefusal`: closure is checked before
value gates, generated label/alias cases require `body_fields`, and beta-list
cases require `beta`. Generated body-value cases also pin their expected stage.
A duplicate-body test uses raw JSON before map projection; fixture maps cannot
represent duplicate members. GET's absent-body versus `{}` representation is
still outside this map-based fixture model, not claimed to be distinguished.

`TestLabIndependentAdversarialPairs` retains twelve separately enumerated
interaction attacks, outside the unary generator. None is an allowed widening;
the handoff records each actual result. The earlier equivalent `wire-body-subset`
overlay remains explicitly bounded: recursive closure and typed readers enforce
the same required paths; it is not counted as killed. Production readers, native
qualification and the owner-only admission gates remain outside C0 acceptance.
