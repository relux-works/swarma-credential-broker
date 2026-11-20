# C0 construction coverage map

Scope: the 31 byte formats (24 base, C0b, two C0c frames, three C0e records and C0f) in lab profile section 5.2, not runtime A01–A12 acceptance.
No separate attack-surface catalog was supplied; the profile inventory is the
bounded construction surface. Own-format controls are canonical public fixtures.
The source overlay mutant `foreign-format` disables string-singleton checking;
every listed format then fails its named foreign-discriminator assertion.
This proves format discrimination only, not kernel identity, native effects or
actual production-reader cross-read integration. Those remain assigned by section 5.1.

| Surface | Named test / own-format control | Killed narrowing mutant |
| --- | --- | --- |
| `swarma-broker-lab-model-price/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-model-price/1`; canonical valid fixture | `c0e-format`; `c0e-member-closure` |
| `swarma-broker-lab-attempt-group/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-attempt-group/1`; canonical valid fixture | `c0e-format`; `c0e-member-closure` |
| `swarma-broker-lab-attempt-ledger/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-attempt-ledger/1`; canonical valid fixture | `c0e-format`; `c0e-member-closure` |
| `swarma-broker-lab-installation-binding/1` | `TestLabClosedSurfacePairs/swarma-broker-lab-installation-binding/1`; canonical synthetic control | `c0f-format`; `c0f-member-closure` |
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


## Revision 5 HTTP byte-class regression

| Rule | Generated cases / valid controls | Intended refusal and narrowing overlay |
| --- | --- | --- |
| ASCII header-name token and fold | `headerNameCases` applies label/Unicode operators plus every byte insertion/substitution to each POST/GET header; uppercase measured names remain valid. `TestLabASCIIHeaderTokenPairs` independently checks every byte against all RFC `tchar` characters. | `TestLabGeneratedWireEnvelopePairs`, `envelope`; `header-unicode-fold-restored`. `TestLabASCIIHeaderTokenPairs`, token refusal; `header-token-byte-guard-off`. |
| Beta SP/HTAB-only OWS | `TestLabGeneratedBetaOWSBytePairs` inserts each forbidden control/non-ASCII byte at every position, beside SP/HTAB token-boundary controls; SP/HTAB inside tokens refuse too. Existing token-wrapper and separator cases now classify CR/LF as negatives. | `beta` in `TestLabGeneratedBetaOWSBytePairs`, `TestLabGeneratedBetaSeparatorPairs` and `TestLabGeneratedWireEnvelopePairs`; `beta-crlf-as-ows`. |

Only ASCII case folding applies to header names. SP and HTAB, not CR/LF, are
beta OWS. The reference sees decoded fixture maps: raw duplicate-member checks
remain test-local parser evidence, not end-to-end wire-reader acceptance.


## C0b bounded invocation

| Surface / rule | Cases and adjacent valid control | Intended gate / test | Source-overlay control |
| --- | --- | --- | --- |
| `swarma-broker-lab-bounded-invocation/1`, B5 → M1/B4 | Every required root/Context member; catalogue labels, missing/extra/alias/null/wrong kind, duplicate and wrong nesting; foreign format; 65536/65537-byte preflight | `TestLabClosedSurfacePairs`, `TestLabGeneratedClosedFieldPairs`, `TestLabGeneratedObjectBytePairs`, `TestLabPayloadLimitPairs` | `c0b-discriminator`, `c0b-closure`, `c0b-payload-limit` |
| All 15 field grammars | Existing catalogue traversal includes each new field and Context; new count 1..256, output 1..128000 and wall 1..900000 endpoints and neighbors, number-lexeme operators | `TestLabFieldGrammarPairs`, `TestLabGeneratedGrammarPairs`, `TestLabGeneratedNumberLexemePairs` | `c0b-count-range`, `c0b-output-range`, `c0b-wall-range` |
| Positive canonical USD | Independent big-integer/byte oracle; min-1/min/min+1/max-1/max/max+1, every literal and decimal-separator operator, both leading/redundant-zero sides, scale, sign, exponent, non-ASCII, null/all wrong kinds | `TestLabBoundedUSDPairs`, `TestLabGeneratedGrammarPairs`, intended `usd` grammar gate | `c0b-usd-zero`, `c0b-usd-upper`, `c0b-usd-scale`, `c0b-usd-leading-zero` |
| No default approval; exact owner target/full digest | Published 22-case corpus; false/unverified/revoked/expired and mismatch witnesses; every mutable plan bound/pin/context/operation/generation retaining original approval | `TestLabBoundedAdmissionPairs`, `TestLabBoundedJoinPairs` | `c0b-approval-flag`, `c0b-owner`, `c0b-revocation`, `c0b-approval-digest`, `c0b-approval-seal`, `c0b-target`, `c0b-full-plan` |
| Fresh current protected observations | Both approval window endpoints, off-VM ordering, qualification expiry, every current observation field, unknown clock and missing enforcement controls | `TestLabBoundedAdmissionPairs`, `TestLabBoundedJoinPairs` | `c0b-freshness`, `c0b-clock`, `c0b-controls`, `c0b-current`, `c0b-context` |
| Reviewed client/wire/model/output/executor/cap | Re-sealed mismatches avoid stale-approval masking; original client remains inert | `TestLabBoundedAdmissionPairs`, `TestLabBoundedProfileOperatorPairs` | `c0b-model-casefold`, `c0b-output-neighbor`, `c0b-client-pin`, `c0b-wire-pin`, `c0b-wire-values`, `c0b-client-binary`, `c0b-executor`, `c0b-wall-relation`, `c0b-vendor-cap` |
| Launch/context/operation/generation/head joins and four unique pins | Each input pin missing/changed/duplicated; each joined launch member changed independently | `TestLabBoundedJoinPairs` | `c0b-launch-join`, `c0b-input-value`, `c0b-input-missing`, `c0b-input-duplicate` |
| Durable ledger identity, ordinal and reservation model | Wrong operation/plan, active retry status-only, exact/over/zero/unknown reservation; settlement preserves actual debit/count, second start consumes final ordinal | `TestLabBoundedExecutorPairs` | `c0b-ledger-join`, `c0b-active-retry`, `c0b-quote`, `c0b-reservation`, `c0b-ordinal`, `c0b-reserve-before-start` |
| First-bound stop and sticky UNKNOWN model | Each count/output/USD/per-wall/total-wall bound one below/at/above, no retry after stop, gaps, regression of each observed counter, incomplete response/settlement and retained reservation/ordinal | `TestLabBoundedExecutorPairs` | `c0b-count-stop`, `c0b-output-stop`, `c0b-cost-stop`, `c0b-per-wall-stop`, `c0b-total-wall-stop`, `c0b-known-overshoot`, `c0b-observed-debit`, `c0b-unknown-observe`, `c0b-unreserved-charge`, `c0b-unknown-settle`, `c0b-unknown-sticky` |

The new reference is test-only and accepts synthetic provenance facts, not actual
owner authority. Native hard cost/output/deadline controls, persistent/recovered
ledgers, process-tree teardown and authenticated off-VM observation remain M1,
B5 and B4 obligations. No live budget, production or native acceptance is claimed.
The handoff records actual overlay exits and named failing assertions; an overlay
not killed there is not silently covered by this planned allocation.

## C0c observation construction coverage

The native source/disposition and complete wire/transport contract are in
`contracts/lab-v0/observation.md`. All functions below are reference-only test
models. Input booleans stand for independently verified native facts; they are
not socket fields or installed constructor parameters. No kernel peer, native
lock/fsync, protected journal currentness or real publication is proved here.

| Rule / operator cases | Named test with adjacent valid control | Narrowing overlays |
| --- | --- | --- |
| Exact three-member request; closed response/nested types; every label/null/type/missing/alias/duplicate/wrong nesting | TestLabClosedSurfacePairs; TestLabNestedClosurePairs; TestLabGeneratedClosedFieldPairs; TestLabGeneratedObjectBytePairs | c0c-request-closure; c0c-response-closure |
| Both lab discriminators, every literal/case/separator; own formats only | TestLabClosedSurfacePairs; TestLabGeneratedGrammarPairs | c0c-request-discriminator; c0c-response-discriminator |
| Request 4096 / response 65536: at-limit and over-limit; zero/truncated/multiple-frame facts | TestLabPayloadLimitPairs; TestLabObservationTransportPairs | c0c-request-payload; c0c-response-payload; c0c-frame-size; c0c-one-frame |
| Every receipt/debit/invalidation/stop array 0/1/255/256/257; null and wrong types | TestLabGeneratedGrammarPairs | c0c-array-count |
| Native request/start/owner/manager IDs: every catalogue operator and all byte positions/classes; 0/1/2/63/64/65 | TestLabGeneratedGrammarPairs | c0c-native-id-first; c0c-native-id-length |
| Native executor/profile IDs: fixed lowercase/first character, separators and all byte classes; 0/1/2/31/32/33 | TestLabGeneratedGrammarPairs | c0c-native-executor-case; c0c-native-executor-length |
| Shared native lock provenance, never a second mutex | TestLabObservationLockPair; TestLabObservationTransportPairs | c0c-native-lock; c0c-lock-provenance |
| Native request/start + protected expected owner/generation/UID/epoch/executor/plan/profile joins | TestLabObservationJoinPairs | c0c-request-join; c0c-start-pins |
| Manager identity/boot/executable/instance, store generation/head, currentness/completeness | TestLabObservationJoinPairs | c0c-manager-identity; c0c-store-generation; c0c-manager-head; c0c-currentness; c0c-completeness |
| Exactly one receipt/debit; absent/duplicate/any invalidation; individual and joined incarnation changes | TestLabObservationJoinPairs | c0c-receipts-uniqueness; c0c-debits-uniqueness; c0c-invalidation; c0c-incarnation-pair; c0c-incarnation-target |
| Native UID/PID/session bounds, debit <= observation, full debit-prefix count | TestLabObservationJoinPairs; TestLabObservationNativeBoundaries | c0c-native-bounds; c0c-debit-time; c0c-debit-prefix |
| Counter > durable floor; both interval edges and 249/250 deadline | TestLabObservationJoinPairs; TestLabObservationTransportPairs | c0c-observation-high-water; c0c-boot-interval; c0c-deadline |
| Exact daemon-only peer, root client denied, root server required, path provenance; each/both role swaps | TestLabObservationTransportPairs | c0c-root-client-exception; c0c-daemon-binding; c0c-server-peer |
| Fresh final observation, same complete snapshot, increasing sequence/floor, no publish on UNKNOWN/CAS/deadline failure | TestLabObservationPublicationPairs | c0c-publication-transport; c0c-publication-observation; c0c-publication-freshness; c0c-publication-sequence; c0c-publication-snapshot; c0c-publication-deadline; c0c-publication-cas |
| Durable installed counter, no missing-store/restart default, safe-integer exhaustion | TestLabObservationSequencePairs | c0c-counter-installed; c0c-counter-durable; c0c-counter-reset; c0c-counter-exhaustion |

Canonical integer signs/fractions/exponents and zero spelling are inherited
`TestLabGeneratedNumberLexemePairs`; CCJ-1 duplicates/canonical spelling use
`TestLabGeneratedObjectBytePairs` and `TestLabGeneratedCanonicalBytePairs`.
These are construction gates only; native runtime proof remains M1/B1.

Out of contract for this addendum: installed server/client, real SO_PEERCRED
readback and UID isolation, actual same-inode native locking, ledger decoding
through the new endpoint, fsync/crash behavior, release installation and live
Q/production acceptance. They remain required implementation/qualification
obligations, not exclusions from their A03/A05 acceptance rows.


## C0b/C0c review corrections: intended-step pairs

The release corpus explicitly carries the sealed section 6 release and its
protected expected digest; no admission helper fabricates approval. Phase is
observed state, never a protected static pin. The response adds only stops and
sequence_generation; the request remains three members. The recursive C0
catalogue reaches each new member/type at its own grammar/closure gate.

| Rule / generated cases | Named paired test | Source-overlay witness |
| --- | --- | --- |
| stops: labels/aliases/missing/null/all wrong kinds, array 0/1/255/256/257; every native stop field and phase literal/case/separator | TestLabNestedClosurePairs; TestLabGeneratedClosedFieldPairs; TestLabGeneratedObjectBytePairs; TestLabGeneratedGrammarPairs | r1-stop-closure; r1-stop-array-count; r1-stop-phase-case |
| sequence_generation: operation alphabet, length, case, literal/separator, null/wrong kinds; labels/aliases/missing/duplicates/nesting | TestLabGeneratedGrammarPairs; TestLabGeneratedClosedFieldPairs; TestLabGeneratedObjectBytePairs | r1-sequence-generation-grammar |
| adds a terminal-launch exception with no protected phase pin (negative), unchanged admitted control | TestLabObservationStopPairs | r1-terminal-admission |
| ignores pending stops but retains terminal-stop refusal (negative), unchanged admitted control | TestLabObservationStopPairs | r1-pending-stop |
| ignores terminal stops but retains pending-stop refusal (negative), unchanged admitted control | TestLabObservationStopPairs | r1-terminal-stop |
| matches only execution ID, discarding the generation join (negative), unchanged admitted control | TestLabObservationStopPairs | r1-stop-generation |
| matches only generation, discarding the execution join (negative), unchanged admitted control | TestLabObservationStopPairs | r1-stop-execution |
| omits only the locked current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-locked |
| omits only the found current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-found |
| omits only the latest current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-latest |
| omits only the account-terminal current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-account-terminal |
| omits only the active-check current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-active-check |
| omits only the row-uid current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-row-uid |
| omits only the account-uid current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-account-uid |
| omits only the row-generation current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-row-generation |
| omits only the account-generation current-account conjunct (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-account-generation |
| adds pending as a current-account state (negative), unchanged admitted control | TestLabObservationCurrentnessPairs | r1-current-state |
| retains only the upper concurrency bound (negative), unchanged admitted control | TestLabObservationLoadPairs | r1-concurrency |
| admits negative hold time -1 (negative), unchanged admitted control | TestLabObservationLoadPairs | r1-hold-negative |
| admits 25 ms at the closed hold deadline (negative), unchanged admitted control | TestLabObservationLoadPairs | r1-hold-ceiling |
| admits hold equal to the native wait budget (negative), unchanged admitted control | TestLabObservationLoadPairs | r1-native-wait |
| admits an acquisition one ms before cooldown (negative), unchanged admitted control | TestLabObservationLoadPairs | r1-cooldown |
| adds a cross-installation sequence-generation exception (negative), unchanged admitted control | TestLabObservationSnapshotSequencePairs | r1-sequence-scope |
| adds a cross-installation durable-counter exception (negative), unchanged admitted control | TestLabObservationSnapshotSequencePairs | r1-counter-scope |
| compares generation only, not the remaining native snapshot proof (negative), unchanged admitted control | TestLabObservationSnapshotSequencePairs | r1-snapshot-unchanged |
| omits reauthorization at boundedStart while retaining budget checks (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-boundedStart-authority |
| omits reauthorization at boundedObserve while retaining budget checks (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-boundedObserve-authority |
| omits only the owner authority gate (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-owner |
| omits only the clock authority gate (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-clock |
| omits only the access authority gate (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-access |
| omits only the approval-start authority gate (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-approval-start |
| admits the release approval one unit before its start (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-release-start |
| omits only the revocation group stop (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-revocation |
| omits only the approval-expiry group stop (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-approval-expiry |
| omits only the release-expiry group stop (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-release-expiry |
| admits equality at qualification expiry (negative), unchanged admitted control | TestLabBoundedAuthorityPairs | r1-authority-qualification-expiry |
| narrows the target release join to a documented mismatched exception (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-target |
| narrows the context release join to a documented mismatched exception (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-context |
| narrows the seal release join to a documented mismatched exception (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-seal |
| narrows the expected release join to a documented mismatched exception (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-expected |
| narrows the digest release join to a documented mismatched exception (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-digest |
| admits release approval one nanosecond before its opening boundary (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-before |
| admits release approval at expiry equality (negative), unchanged admitted control | TestLabBoundedReleasePairs | r1-release-expiry |
| omits only the four-field ObservationStop closure gate (negative), unchanged admitted control | TestLabNestedClosurePairs | r1-stop-closure |
| admits after budget/client/launch gates but omits the release chain (negative), unchanged admitted control | TestLabBoundedReleaseIntegrationPair | r1-release-integration |
| omits the stop-array ceiling, retains element validation (negative), unchanged admitted control | TestLabGeneratedGrammarPairs | r1-stop-array-count |
| adds uppercase ADMITTED as a native stop-phase exception (negative), unchanged admitted control | TestLabGeneratedGrammarPairs | r1-stop-phase-case |
| admits uppercase in the counter-generation grammar (negative), unchanged admitted control | TestLabGeneratedGrammarPairs | r1-sequence-generation-grammar |

All witnesses concern test-only reference functions, not an installed executor,
server or client. M1/B1/B4 must supply real enforcement evidence; no native or
production acceptance is inferred. The existing out-of-contract list applies.


## C0d consumption and timing clarification

No field, discriminator, bound in a wire grammar, fixture payload, native lock
mode/cooldown, or production source is changed. The full existing recursive C0
catalogue exercised the unchanged 27 formats at the C0d freeze; C0e below adds three formats without changing those existing wire grammars. Additional rule operators
below apply at the intended consumption/timing gate, with nearby valid controls.
All functions are test-only references; installed M1/B1/G1/B4 proof is pending.

| Rule / cases | Named tests | Narrowing overlays |
| --- | --- | --- |
| Exact publication role set; all literal/null/wrong-type operators; current/single/revocation never publish | TestLabObservationConsumptionPairs | c0d-role; c0d-role-type |
| New non-reusable pair; both then-current floor and seen counter; initial/final replay, previous-final reuse and pipelined obsolete floor | TestLabObservationConsumptionPairs; TestLabObservationCurrentPairs; TestLabObservationPublicationPairs | c0d-floor; c0d-legacy-initial-floor; c0d-seen; c0d-final-counter; c0d-fresh |
| Pair joins/snapshot/effect binding, actual stop/invalidation selectors, CAS, original final deadline; no stopped-use grant | TestLabObservationConsumptionPairs; TestLabObservationNarrowingJoins | c0d-pair-join; c0d-pair-snapshot; c0d-effect; c0d-narrowing-proof; c0d-stop-join; c0d-invalidation-join; c0d-cas; c0d-final-deadline; c0d-narrowing-use |
| Periodic single validates completeness, generation, native sequence/digests and strictly increasing observation counter; failed/late/partial/pending/terminal stop closes use | TestLabObservationPeriodicPairs | c0d-single-answer; c0d-single-join; c0d-single-counter; c0d-single-snapshot; c0d-single-baseline-reset; c0d-single-receipt |
| Single never advances publication floor or native baseline, never grants a publication; successful current never refreshes native age; failed reads irreversibly fence use | TestLabObservationPeriodicPairs; TestLabObservationCurrentPairs | c0d-single-floor; c0d-current-age-refresh; c0d-sticky; c0d-fence |
| Timing both boundaries: age [0,1200), periodic [500,550), waits [250,300), pair [0,1250), current RPC [0,300), current spacing [250,300), watchdog [0,750), closure [0,500]; watchdog dispatch [0,50) | TestLabObservationTimingBoundaries | c0d-age-low; c0d-age-high; c0d-schedule-low; c0d-schedule-high; c0d-wait-low; c0d-wait-high; c0d-pair-low; c0d-pair-high; c0d-current-low; c0d-current-high; c0d-current-schedule-low; c0d-current-schedule-high; c0d-watchdog-low; c0d-watchdog-high; c0d-closure-low; c0d-closure-high; c0d-dispatch-low; c0d-dispatch-high |
| Independent native-age fence/current check, final publication and periodic gates actually invoke timing rules; no optimistic result on stale/late facts | TestLabObservationPeriodicPairs; TestLabObservationCurrentPairs; TestLabObservationConsumptionPairs | c0d-current-age; c0d-single-schedule; c0d-pair-wait; c0d-final-wait; c0d-pair-budget; c0d-pair-order; c0d-pair-entry-fence |
| Prior response tail + single cadence/jitter/RPC = 1050; native age 1200; current success gap <600 <750; in-flight old success + watchdog + closure = 2750 <3000; pair <1100 <1250 | TestLabObservationBudgetArithmetic; TestLabObservationSlowControls; TestLabTimingContractPairs | c0d-arithmetic; c0d-timing-text |

No installed cadence, socket load, atomic publication, failover or closure timing
is claimed from these integer/reference controls. The C0d design changes the
lab ceiling explicitly; it does not reopen the pending native/owner gates.

## C0e sole gateway accounting boundary

The complete C0 catalogue runs recursively on all new surfaces, including
GatewayPrices/GatewayUsage/GatewayAttempt: every literal/member/operator, all
wrong kinds/null, duplicate/missing/alias/extra/nested members, both count and
number bounds, canonical spellings and coupled receipt/debit role swaps.
Shape fixtures are inert: admitted C0b sample plans may be too small for C0e's
conservative reservation and do not authorize a forward. Separate joined tests
construct a freshly re-sealed synthetic release/approval/plan; they are not owner
acts. Native byte ordering, usage provenance, file access, fsync/CAS, clock/timer
enforcement and actual retry-path exclusion remain G1b/M1/B1/B4/B5 obligations.
No production or native acceptance is claimed by these test-only references.

| Rule / generated cases | Named tests / adjacent valid controls | Narrowing overlays |
| --- | --- | --- |
| Closed record/member/type/label/canonical-number and nested closure catalogue; 65536/262144 preflight bounds, ledger arrays 0/1/255/256/257 | TestLabClosedSurfacePairs; TestLabNestedClosurePairs; TestLabGeneratedGrammarPairs; TestLabGeneratedClosedFieldPairs; TestLabGeneratedObjectBytePairs; TestLabGeneratedCanonicalBytePairs; TestLabPayloadLimitPairs; TestLabGatewayArrayPairs | c0e-format; c0e-member-closure; c0e-null-closure; c0e-array-bound; c0e-byte-bound |
| Every scalar operator attacks the exact published price identity; every price-member/source/model/tier/ceiling/rate and approved R/A/P/L join | TestLabGatewayPriceCataloguePairs; TestLabGatewayPriceIdentityPairs; TestLabGatewayJoinPairs; TestLabGatewayIndependentPricePairs | c0e-price-identity; c0e-price-member-missing; c0e-price-member-unique; c0e-model; c0e-approval-chain |
| Each immutable group/ledger/native-incarnation join, either/both receipt-debit retargetings and original group-clock future/expiry boundaries | TestLabGatewayGroupPairs; TestLabGatewayJoinPairs; TestLabGatewayPairedRolePairs | c0e-group-plan_sha256; c0e-group-future; c0e-group-expiry; c0e-group-ledger-digest; c0e-join-start_receipt; c0e-join-start_debit |
| Five disjoint usage terms, cache-partition total/aggregate ceiling, integer upward rounding and checked overflow | TestLabGatewayPricePairs; TestLabGatewayIndependentPricePairs | c0e-price-term-input_tokens; c0e-price-term-output_tokens; c0e-price-term-cache_creation_5m_input_tokens; c0e-price-term-cache_creation_1h_input_tokens; c0e-price-term-cache_read_input_tokens; c0e-usage-partition; c0e-usage-aggregate; c0e-ceil; c0e-overflow |
| Before-forward fresh authority/currentness, sole route, qualified ceiling, count/cost/time, single active attempt, durable prefix/CAS/fsync/sequence/ordinal; unchanged accounting plus a closed-use latch after refusal | TestLabGatewayReservationPairs | c0e-reserve-approval; c0e-reserve-current; c0e-reserve-route; c0e-reserve-ceiling; c0e-reserve-count; c0e-reserve-cost; c0e-reserve-wall; c0e-reserve-active; c0e-reserve-head; c0e-reserve-cas; c0e-reserve-durable; c0e-reserve-ordinal |
| Complete authoritative settlement, reserved/settled/unknown sentinels, timeout/disconnect/partial usage, full-reservation UNKNOWN, no refund/reopen, independent retry ordinal | TestLabGatewaySettlementPairs; TestLabGatewayRecordPairs; TestLabGatewayFixturePairs | c0e-settle-terminal; c0e-settle-tier; c0e-unknown-full-reservation; c0e-unknown-sticky; c0e-retry-ordinal; c0e-record-unknown-charge; c0e-record-settled-digest |
| Shared first-bound output/cost/per-attempt/total stop, equality and both adjacent sides; independent total-wall witness does not hit the per-attempt bound | TestLabGatewayMonitorPairs; TestLabGatewaySettlementPairs | c0e-monitor-output; c0e-monitor-cost; c0e-monitor-per-wall; c0e-monitor-total-wall; c0e-settle-stop-total-wall |
| Exact protected accounting head, B4 effect/release joins and fresh C0d pair only for a claimed start-affecting publication; copies/singles never enable it | TestLabGatewayEvidencePairs | c0e-evidence-head; c0e-evidence-effect; c0e-evidence-release; c0e-evidence-publication |

Every overlay below was applied to the final candidate in an isolated checkout,
ran with real exit 1 at the named intended assertion, and passed a source/witness
correlation audit. Baseline contract suites exit 0. A failed compile is not a
kill; earlier diagnostics are listed in the handoff. C0d's 53 unchanged-rule
overlays were also replayed against this candidate; all fail their named tests.

| Mutant | Gate narrowed | Named failing test |
| --- | --- | --- |
| c0e-join-context | Ignore ledger context while retaining all other approval/start joins | TestLabGatewayJoinPairs/context |
| c0e-join-operation_id | Ignore ledger operation_id while retaining all other approval/start joins | TestLabGatewayJoinPairs/operation_id |
| c0e-join-plan_sha256 | Ignore ledger plan_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/plan_sha256 |
| c0e-join-approval_record_sha256 | Ignore ledger approval_record_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/approval_record_sha256 |
| c0e-join-release_set_sha256 | Ignore ledger release_set_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/release_set_sha256 |
| c0e-join-model_price_sha256 | Ignore ledger model_price_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/model_price_sha256 |
| c0e-join-launch_plan_sha256 | Ignore ledger launch_plan_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/launch_plan_sha256 |
| c0e-join-start_observation_sha256 | Ignore ledger start_observation_sha256 while retaining all other approval/start joins | TestLabGatewayJoinPairs/start_observation_sha256 |
| c0e-join-start_operation_id | Ignore ledger start_operation_id while retaining all other approval/start joins | TestLabGatewayJoinPairs/start_operation_id |
| c0e-join-start_id | Ignore ledger start_id while retaining all other approval/start joins | TestLabGatewayJoinPairs/start_id |
| c0e-join-store_generation | Ignore ledger store_generation while retaining all other approval/start joins | TestLabGatewayJoinPairs/store_generation |
| c0e-join-manager_instance_id | Ignore ledger manager_instance_id while retaining all other approval/start joins | TestLabGatewayJoinPairs/manager_instance_id |
| c0e-join-boot_id | Ignore ledger boot_id while retaining all other approval/start joins | TestLabGatewayJoinPairs/boot_id |
| c0e-join-start_receipt | Ignore ledger start_receipt while retaining all other approval/start joins | TestLabGatewayJoinPairs/start_receipt |
| c0e-join-start_debit | Ignore ledger start_debit while retaining all other approval/start joins | TestLabGatewayJoinPairs/start_debit |
| c0e-approval-chain | Omit authenticated C0b chain admission | TestLabGatewayJoinPairs/approval-denied |
| c0e-admission-pair | Treat an unaccepted/single observation as start admission | TestLabGatewayJoinPairs/publication-not-single |
| c0e-native-stop | Omit native stop closure | TestLabGatewayJoinPairs/native-stops |
| c0e-native-invalidation | Omit native invalidation closure | TestLabGatewayJoinPairs/native-invalidations |
| c0e-native-phase | Omit native phase closure | TestLabGatewayJoinPairs/native-phase |
| c0e-native-current | Omit native current closure | TestLabGatewayJoinPairs/native-generation_current |
| c0e-native-complete | Omit native complete closure | TestLabGatewayJoinPairs/native-complete |
| c0e-price-member-missing | Ignore approved price-member missing requirement | TestLabGatewayJoinPairs/price-missing |
| c0e-price-member-unique | Ignore approved price-member unique requirement | TestLabGatewayJoinPairs/price-duplicate |
| c0e-price-member-product | Ignore approved price-member product requirement | TestLabGatewayJoinPairs/price-product |
| c0e-price-member-mode | Ignore approved price-member mode requirement | TestLabGatewayJoinPairs/price-mode |
| c0e-price-member-digest | Ignore approved price-member digest requirement | TestLabGatewayJoinPairs/price-digest |
| c0e-price-identity | Use only model/field count, not the exact published source/rates/ceilings | TestLabGatewayPriceIdentityPairs/[source_sha256] |
| c0e-model | Ignore the independently supplied approved model | TestLabGatewayIndependentPricePairs/model |
| c0e-group-context | Ignore protected preauthorization group context | TestLabGatewayGroupPairs/join-context |
| c0e-group-operation_id | Ignore protected preauthorization group operation_id | TestLabGatewayGroupPairs/join-operation_id |
| c0e-group-plan_sha256 | Ignore protected preauthorization group plan_sha256 | TestLabGatewayGroupPairs/join-plan_sha256 |
| c0e-group-approval_record_sha256 | Ignore protected preauthorization group approval_record_sha256 | TestLabGatewayGroupPairs/join-approval_record_sha256 |
| c0e-group-release_set_sha256 | Ignore protected preauthorization group release_set_sha256 | TestLabGatewayGroupPairs/join-release_set_sha256 |
| c0e-group-model_price_sha256 | Ignore protected preauthorization group model_price_sha256 | TestLabGatewayGroupPairs/join-model_price_sha256 |
| c0e-group-launch_plan_sha256 | Ignore protected preauthorization group launch_plan_sha256 | TestLabGatewayGroupPairs/join-launch_plan_sha256 |
| c0e-group-start_operation_id | Ignore protected preauthorization group start_operation_id | TestLabGatewayGroupPairs/join-start_operation_id |
| c0e-group-start_id | Ignore protected preauthorization group start_id | TestLabGatewayGroupPairs/join-start_id |
| c0e-group-boot_id | Ignore protected preauthorization group boot_id | TestLabGatewayGroupPairs/join-boot_id |
| c0e-group-future | Admit future total-clock boundary | TestLabGatewayGroupPairs/group-clock-future |
| c0e-group-expiry | Admit expiry total-clock boundary | TestLabGatewayGroupPairs/group-clock-expiry |
| c0e-group-ledger-digest | Do not bind ledger to protected group digest | TestLabGatewayGroupPairs/ledger-digest |
| c0e-group-ledger-clock | Do not bind ledger to protected group clock | TestLabGatewayGroupPairs/ledger-clock |
| c0e-reserve-approval | Permit a forward without approval proof | TestLabGatewayReservationPairs/approval |
| c0e-reserve-current | Permit a forward without current proof | TestLabGatewayReservationPairs/current |
| c0e-reserve-ceiling | Permit a forward without ceiling proof | TestLabGatewayReservationPairs/ceiling |
| c0e-reserve-route | Permit a forward without route proof | TestLabGatewayReservationPairs/route |
| c0e-reserve-group | Remove or weaken pre-forward group gate | TestLabGatewayReservationPairs/status |
| c0e-reserve-boot | Remove or weaken pre-forward boot gate | TestLabGatewayReservationPairs/boot |
| c0e-reserve-clock | Remove or weaken pre-forward clock gate | TestLabGatewayReservationPairs/clock |
| c0e-reserve-wall | Remove or weaken pre-forward wall gate | TestLabGatewayReservationPairs/wall |
| c0e-reserve-active | Remove or weaken pre-forward active gate | TestLabGatewayReservationPairs/active |
| c0e-reserve-count | Remove or weaken pre-forward count gate | TestLabGatewayReservationPairs/count |
| c0e-reserve-cost | Remove or weaken pre-forward cost gate | TestLabGatewayReservationPairs/cost |
| c0e-reserve-head | Remove or weaken pre-forward head gate | TestLabGatewayReservationPairs/head |
| c0e-reserve-cas | Remove or weaken pre-forward cas gate | TestLabGatewayReservationPairs/cas |
| c0e-reserve-durable | Remove or weaken pre-forward durable gate | TestLabGatewayReservationPairs/durable |
| c0e-reserve-sequence | Remove or weaken pre-forward sequence gate | TestLabGatewayReservationPairs/sequence |
| c0e-reserve-ordinal | Remove or weaken pre-forward ordinal gate | TestLabGatewayReservationPairs/ordinal |
| c0e-prefix-chain | Commit a head without its exact predecessor | TestLabGatewayReservationPairs/valid |
| c0e-sequence-increment | Reuse the durable sequence | TestLabGatewayReservationPairs/valid |
| c0e-retry-ordinal | Count every retry as the first forward | TestLabGatewaySettlementPairs/valid |
| c0e-worst-cache | Reserve only the base input price, not the worst cache write | TestLabGatewayPricePairs |
| c0e-worst-output | Omit output from worst-case reservation | TestLabGatewayPricePairs |
| c0e-price-term-input_tokens | Omit the input_tokens billable component | TestLabGatewayPricePairs/input_tokens |
| c0e-price-term-output_tokens | Omit the output_tokens billable component | TestLabGatewayPricePairs/output_tokens |
| c0e-price-term-cache_creation_5m_input_tokens | Omit the cache_creation_5m_input_tokens billable component | TestLabGatewayPricePairs/cache_creation_5m_input_tokens |
| c0e-price-term-cache_creation_1h_input_tokens | Omit the cache_creation_1h_input_tokens billable component | TestLabGatewayPricePairs/cache_creation_1h_input_tokens |
| c0e-price-term-cache_read_input_tokens | Omit the cache_read_input_tokens billable component | TestLabGatewayPricePairs/cache_read_input_tokens |
| c0e-ceil | Round fractional micro-USD down | TestLabGatewayPricePairs/cache_read_input_tokens |
| c0e-overflow | Drop checked safe-integer arithmetic | TestLabGatewayPricePairs |
| c0e-usage-output | Admit output usage over its reserved ceiling | TestLabGatewayPricePairs/ceiling-output_tokens |
| c0e-usage-partition | Do not reconcile cache creation total with disjoint TTL counts | TestLabGatewayPricePairs/ceiling-cache_creation_input_tokens |
| c0e-usage-aggregate | Allow individually valid input/cache terms to exceed their shared ceiling | TestLabGatewayIndependentPricePairs/aggregate-input |
| c0e-settle-terminal | Settle as authoritative despite missing terminal proof | TestLabGatewaySettlementPairs/timeout |
| c0e-settle-tier | Settle as authoritative despite missing tier proof | TestLabGatewaySettlementPairs/model-tier |
| c0e-settle-request | Settle as authoritative despite missing request proof | TestLabGatewaySettlementPairs/request-id |
| c0e-settle-clock | Settle as authoritative despite missing clock proof | TestLabGatewaySettlementPairs/clock |
| c0e-unknown-full-reservation | Treat an uncertain response as zero charge | TestLabGatewaySettlementPairs/timeout |
| c0e-unknown-sticky | Keep the group open after uncertain settlement | TestLabGatewaySettlementPairs/timeout |
| c0e-settle-stop-output | Remove the shared first-bound output predicate used by settlement and ongoing monitoring | TestLabGatewaySettlementPairs/output |
| c0e-settle-stop-per-wall | Remove the shared first-bound per-wall predicate used by settlement and ongoing monitoring | TestLabGatewaySettlementPairs/per-wall |
| c0e-settle-stop-total-wall | Remove the shared first-bound total-wall predicate used by settlement and ongoing monitoring | TestLabGatewaySettlementPairs/total-wall |
| c0e-settle-stop-count | Do not retain the first reached count bound after settlement | TestLabGatewaySettlementPairs/count |
| c0e-settle-stop-cost | Remove the shared first-bound cost predicate used by settlement and ongoing monitoring | TestLabGatewayMonitorPairs/cost/0 |
| c0e-settle-stop-revoked | Do not retain the first reached revoked bound after settlement | TestLabGatewaySettlementPairs/revoked |
| c0e-settle-stop-current | Do not retain the first reached current bound after settlement | TestLabGatewaySettlementPairs/current |
| c0e-settle-stop-boot | Do not retain the first reached boot bound after settlement | TestLabGatewaySettlementPairs/boot |
| c0e-monitor-output | Delay the in-flight output stop past equality | TestLabGatewayMonitorPairs/output/0 |
| c0e-monitor-cost | Delay the in-flight cost stop past equality | TestLabGatewayMonitorPairs/cost/0 |
| c0e-monitor-per-wall | Delay the in-flight per-wall stop past equality | TestLabGatewayMonitorPairs/per-wall/0 |
| c0e-monitor-total-wall | Delay the in-flight total-wall stop past equality | TestLabGatewayMonitorPairs/total-wall/0 |
| c0e-monitor-partial | Ignore in-flight partial evidence | TestLabGatewayMonitorPairs/partial |
| c0e-monitor-regression | Ignore in-flight regression evidence | TestLabGatewayMonitorPairs/regression |
| c0e-monitor-boot | Ignore in-flight boot evidence | TestLabGatewayMonitorPairs/boot |
| c0e-monitor-negative-output | Ignore in-flight negative-output evidence | TestLabGatewayMonitorPairs/negative-output |
| c0e-monitor-negative-cost | Ignore in-flight negative-cost evidence | TestLabGatewayMonitorPairs/negative-cost |
| c0e-monitor-approval | Ignore in-flight approval evidence | TestLabGatewayMonitorPairs/approval |
| c0e-monitor-current | Ignore in-flight current evidence | TestLabGatewayMonitorPairs/current |
| c0e-record-usage-complete | Omit state-dependent usage-complete check | TestLabGatewayRecordPairs/reserved/usage_complete |
| c0e-record-empty-usage | Omit state-dependent empty-usage check | TestLabGatewayRecordPairs/reserved/usage.input_tokens |
| c0e-record-request-sentinel | Omit state-dependent request-sentinel check | TestLabGatewayRecordPairs/reserved/upstream_request_id |
| c0e-record-digest-sentinel | Omit state-dependent digest-sentinel check | TestLabGatewayRecordPairs/reserved/usage_sha256 |
| c0e-record-reserved-cost | Omit state-dependent reserved-cost check | TestLabGatewayRecordPairs/reserved/settled_micro_usd |
| c0e-record-reserved-time | Omit state-dependent reserved-time check | TestLabGatewayRecordPairs/reserved/settled_monotonic_ms |
| c0e-record-unknown-charge | Omit state-dependent unknown-charge check | TestLabGatewayRecordPairs/unknown/settled_micro_usd |
| c0e-record-settled-usage | Omit state-dependent settled-usage check | TestLabGatewayRecordPairs/settled/usage_complete |
| c0e-record-settled-cost | Omit state-dependent settled-cost check | TestLabGatewayRecordPairs/settled/settled_micro_usd |
| c0e-record-settled-digest | Omit state-dependent settled-digest check | TestLabGatewayRecordPairs/settled/usage_sha256 |
| c0e-record-settled-request | Omit state-dependent settled-request check | TestLabGatewayRecordPairs/settled/upstream_request_id |
| c0e-record-settled-time | Omit state-dependent settled-time check | TestLabGatewayRecordPairs/settled/settled_monotonic_ms |
| c0e-evidence-head | Allow B4 evidence without exact head join | TestLabGatewayEvidencePairs/head |
| c0e-evidence-effect | Allow B4 evidence without exact effect join | TestLabGatewayEvidencePairs/effect |
| c0e-evidence-release | Allow B4 evidence without exact release join | TestLabGatewayEvidencePairs/release |
| c0e-evidence-publication | Allow B4 evidence without exact publication join | TestLabGatewayEvidencePairs/single |
| c0e-format | Ignore lab format discriminator | TestLabClosedSurfacePairs/swarma-broker-lab-model-price/1 |
| c0e-member-closure | Allow extra/aliasing members | TestLabClosedSurfacePairs/swarma-broker-lab-model-price/1 |
| c0e-null-closure | Delegate null closure to a later grammar check | TestLabNestedClosurePairs/swarma-broker-lab-model-price/1/GatewayPrices/null |
| c0e-array-bound | Admit 257 attempt members | TestLabGatewayArrayPairs/257 |
| c0e-byte-bound | Admit one byte above the frozen ceiling | TestLabPayloadLimitPairs/swarma-broker-lab-model-price/1 |

## C0f protected installation binding

Scope: one new external format, reusing Context and ObservationManager, no runtime
installer/client/server or private recovery surface. Every C0 recursive operator
applies to I; the semantic catalogue additionally attacks the typed target
domain/member labels, member selectors and installation-binding InputPin name.
The target/member/pin helpers are exercised directly so their negatives do not
fail merely because another release seal would reject the mutation. Native
stat/peer/provisioning/fsync/quiescence and timing remain B5/B1/M1 qualification
obligations under the construction-only clause, not synthetic acceptance.

| Rule / cases | Named paired tests | Narrowing overlays |
| --- | --- | --- |
| Exact format/member closure, null/all wrong kinds, every literal/member operator, both numeric/byte bounds and nested closure; valid controls on I | TestLabClosedSurfacePairs; TestLabNestedClosurePairs; TestLabGeneratedClosedFieldPairs; TestLabGeneratedGrammarPairs; TestLabGeneratedObjectBytePairs; TestLabGeneratedCanonicalBytePairs; TestLabPayloadLimitPairs | c0f-format; c0f-member-closure; c0f-null-closure; c0f-nested-closure; c0f-byte-bound; c0f-epoch-positive |
| Root owner, exact file/group/mode/link/ancestor/ACL facts; absent/stale/unreadable/partial current path, no repair and sticky close | TestLabInstallationProtectionPairs; TestLabInstallationJoinPairs/current-read | c0f-protection-*; c0f-current-read; c0f-sticky |
| Typed target excludes only A/R, exact complete I pins in both plans, unique approved broker member, exact executable products/modes/digests; full literal/value catalogue | TestLabInstallationTargetPairs; TestLabInstallationInputPinPairs; TestLabInstallationExecutablePairs; TestLabInstallationLiteralPairs | c0f-target-*; c0f-pin-*; c0f-executable-* |
| Complete C0b owner/expiry/revocation chain, Context and A/R digests, install-plan joins, no response TOFU; every manager/daemon/store/boot pin | TestLabInstallationFixturePairs; TestLabInstallationJoinPairs; TestLabInstallationInstallPlanPairs | c0f-chain; c0f-context; c0f-approval; c0f-release; c0f-manager-*; c0f-store; c0f-daemon-*; c0f-boot; c0f-native |
| UID/GID both sides 0/1/2 and max-1/max/max+1; each role and both swapped beside nonroot daemon/root manager | TestLabInstallationRolePairs | c0f-role-* |
| Same/new/old/missing-latch epoch invalidates in-flight use without advancing private state; approved root-only rotation, complete quiescence, exact next epoch, fresh instance, absent prior and overflow; no B5 private recovery access | TestLabInstallationJoinPairs; TestLabInstallationRotationPairs | c0f-epoch; c0f-writer-*; c0f-rotation-* |

### C0f replay evidence

Each row below is a source overlay at this candidate's exact bytes. Its Go
process exits 1 at the named intended assertion; compile/setup failures and
no-tests runs do not count. There are 73 narrowing gate overlays and one
separate frozen-domain construction regression control (c0f-target-domain).
All 74 fail a named test, with zero survivors. Stage-specific joins may retain
independent later gates: a wrong refusal step is a regression, not a claim that
every such overlay would admit bad authority. Native filesystem, peer,
installation and concurrency qualification are not supplied by these references.
Logs and independent source/witness reconciliation: `.temp/lab-c0f/mutants/`
and `.temp/lab-c0f/mutation-audit-01.log`. Historical C0b–C0e overlay reports above
are not claimed replayed here; their committed test names remain in the suites.

| Source overlay | Narrowed gate / regression control | Named failing test | Exit |
| --- | --- | --- | --- |
| `c0f-protection-present` | Ignore opened-file protection present | `TestLabInstallationProtectionPairs/absence` | 1 |
| `c0f-protection-regular` | Ignore opened-file protection regular | `TestLabInstallationProtectionPairs/regular` | 1 |
| `c0f-protection-ancestors` | Ignore opened-file protection ancestors | `TestLabInstallationProtectionPairs/ancestors` | 1 |
| `c0f-protection-acl` | Ignore opened-file protection acl | `TestLabInstallationProtectionPairs/acl` | 1 |
| `c0f-protection-owner` | Ignore opened-file protection owner | `TestLabInstallationProtectionPairs/owner` | 1 |
| `c0f-protection-group` | Ignore opened-file protection group | `TestLabInstallationProtectionPairs/group` | 1 |
| `c0f-protection-mode` | Ignore opened-file protection mode | `TestLabInstallationProtectionPairs/mode-read` | 1 |
| `c0f-protection-links` | Ignore opened-file protection links | `TestLabInstallationProtectionPairs/links-two` | 1 |
| `c0f-protection-parent-owner` | Ignore opened-file protection parent-owner | `TestLabInstallationProtectionPairs/parent-owner` | 1 |
| `c0f-protection-parent-group` | Ignore opened-file protection parent-group | `TestLabInstallationProtectionPairs/parent-group` | 1 |
| `c0f-protection-parent-mode` | Ignore opened-file protection parent-mode | `TestLabInstallationProtectionPairs/parent-write` | 1 |
| `c0f-current-read` | Trust a cached or replaced path instead of a fresh complete protected read | `TestLabInstallationJoinPairs/current-read` | 1 |
| `c0f-sticky` | Reopen the same group after its binding check failed | `TestLabInstallationProtectionPairs/absence` | 1 |
| `c0f-fence` | Refuse without closing the active group | `TestLabInstallationProtectionPairs/absence` | 1 |
| `c0f-epoch` | Adopt a new epoch in an active group | `TestLabInstallationJoinPairs/new-epoch` | 1 |
| `c0f-epoch-only` | Ignore the private epoch high-water | `TestLabInstallationJoinPairs/old-epoch` | 1 |
| `c0f-digest-only` | Ignore a changed full installation image at the same epoch | `TestLabInstallationJoinPairs/same-epoch-new-digest` | 1 |
| `c0f-chain` | Treat unverified owner provenance as sufficient | `TestLabInstallationJoinPairs/owner` | 1 |
| `c0f-context` | Omit installation context validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/context` | 1 |
| `c0f-approval` | Omit installation approval validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/approval_record_sha256` | 1 |
| `c0f-release` | Omit installation release validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/release_set_sha256` | 1 |
| `c0f-target-read` | Omit installation target-read validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/unapproved-coherent-native-tuple` | 1 |
| `c0f-manager-executable-read` | Omit installation manager-executable-read validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/manager-unapproved-executable` | 1 |
| `c0f-daemon-executable-read` | Omit installation daemon-executable-read validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/daemon-unapproved-executable` | 1 |
| `c0f-pin-read` | Omit installation pin-read validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/launch-binding-pin` | 1 |
| `c0f-roles-read` | Omit installation roles-read validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/coherent-root-daemon` | 1 |
| `c0f-boot` | Omit installation boot validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/boot` | 1 |
| `c0f-native` | Omit installation native validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/native` | 1 |
| `c0f-store` | Omit installation store validation (remaining independent gates stay enabled) | `TestLabInstallationJoinPairs/store` | 1 |
| `c0f-daemon-daemon-uid` | Ignore the actual daemon daemon_uid | `TestLabInstallationJoinPairs/daemon-uid` | 1 |
| `c0f-daemon-daemon-gid` | Ignore the actual daemon daemon_gid | `TestLabInstallationJoinPairs/daemon-gid` | 1 |
| `c0f-daemon-daemon-executable` | Ignore the actual daemon daemon_executable_sha256 | `TestLabInstallationJoinPairs/daemon-executable` | 1 |
| `c0f-daemon-daemon-socket` | Ignore the actual daemon daemon_socket_path | `TestLabInstallationJoinPairs/daemon-socket` | 1 |
| `c0f-daemon-observation-socket` | Ignore the actual daemon observation_socket_path | `TestLabInstallationJoinPairs/observation-socket` | 1 |
| `c0f-manager-identity` | Ignore observed manager identity while comparing every other member | `TestLabInstallationJoinPairs/observed-manager-identity` | 1 |
| `c0f-manager-instance_id` | Ignore observed manager instance_id while comparing every other member | `TestLabInstallationJoinPairs/observed-manager-instance_id` | 1 |
| `c0f-manager-executable_sha256` | Ignore observed manager executable_sha256 while comparing every other member | `TestLabInstallationJoinPairs/observed-manager-executable_sha256` | 1 |
| `c0f-manager-boot_id` | Ignore observed manager boot_id while comparing every other member | `TestLabInstallationJoinPairs/observed-manager-boot_id` | 1 |
| `c0f-target-domain` | Construct a different target domain than the frozen approved preimage | `TestLabInstallationFixturePairs` | 1 |
| `c0f-target-product` | Ignore target member product | `TestLabInstallationTargetPairs/product` | 1 |
| `c0f-target-mode` | Ignore target member mode | `TestLabInstallationTargetPairs/mode` | 1 |
| `c0f-target-digest` | Ignore target member digest | `TestLabInstallationTargetPairs/digest` | 1 |
| `c0f-target-unique` | Ignore target member unique | `TestLabInstallationTargetPairs/duplicate` | 1 |
| `c0f-target-missing` | Ignore target member missing | `TestLabInstallationTargetPairs/missing` | 1 |
| `c0f-pin-unique` | Ignore typed I pin unique | `TestLabInstallationInputPinPairs/install/unrelated-duplicate` | 1 |
| `c0f-pin-digest` | Ignore typed I pin digest | `TestLabInstallationInputPinPairs/install/wrong-digest` | 1 |
| `c0f-pin-missing` | Ignore typed I pin missing | `TestLabInstallationInputPinPairs/install/missing` | 1 |
| `c0f-role-uid-low` | Widen installation native role uid-low | `TestLabInstallationRolePairs/uid/0` | 1 |
| `c0f-role-uid-high` | Widen installation native role uid-high | `TestLabInstallationRolePairs/uid/4294967295` | 1 |
| `c0f-role-gid-low` | Widen installation native role gid-low | `TestLabInstallationRolePairs/gid/0` | 1 |
| `c0f-role-gid-high` | Widen installation native role gid-high | `TestLabInstallationRolePairs/gid/4294967295` | 1 |
| `c0f-role-manager` | Widen installation native role manager | `TestLabInstallationRolePairs/manager-only-swap` | 1 |
| `c0f-executable-product` | Accept unapproved executable product | `TestLabInstallationExecutablePairs/manager/product` | 1 |
| `c0f-executable-mode` | Accept unapproved executable mode | `TestLabInstallationExecutablePairs/manager/mode` | 1 |
| `c0f-executable-digest` | Accept unapproved executable digest | `TestLabInstallationExecutablePairs/manager/digest` | 1 |
| `c0f-install-context` | Skip B5 root-only install-plan context join | `TestLabInstallationInstallPlanPairs/context` | 1 |
| `c0f-install-approval` | Skip B5 root-only install-plan approval join | `TestLabInstallationInstallPlanPairs/off_vm_approval_sha256` | 1 |
| `c0f-install-release` | Skip B5 root-only install-plan release join | `TestLabInstallationInstallPlanPairs/release_set_sha256` | 1 |
| `c0f-install-pin` | Skip B5 root-only install-plan pin join | `TestLabInstallationInstallPlanPairs/binding-pin` | 1 |
| `c0f-writer-root` | Permit B5 rotation without root boundary | `TestLabInstallationRotationPairs/not-root` | 1 |
| `c0f-writer-approval` | Permit B5 rotation without approval boundary | `TestLabInstallationRotationPairs/unapproved` | 1 |
| `c0f-writer-quiescence` | Permit B5 rotation without quiescence boundary | `TestLabInstallationRotationPairs/in-flight` | 1 |
| `c0f-writer-private` | Permit B5 rotation without private boundary | `TestLabInstallationRotationPairs/private-read-or-write` | 1 |
| `c0f-rotation-fresh` | Weaken rotation fresh guard before any write | `TestLabInstallationRotationPairs/missing-prior` | 1 |
| `c0f-rotation-first` | Weaken rotation first guard before any write | `TestLabInstallationRotationPairs/fresh-not-one` | 1 |
| `c0f-rotation-overflow` | Weaken rotation overflow guard before any write | `TestLabInstallationRotationPairs/overflow` | 1 |
| `c0f-rotation-next` | Weaken rotation next guard before any write | `TestLabInstallationRotationPairs/skip-epoch` | 1 |
| `c0f-rotation-instance` | Weaken rotation instance guard before any write | `TestLabInstallationRotationPairs/reused-instance` | 1 |
| `c0f-format` | Treat fixed discriminator/literal fields as arbitrary values | `TestLabClosedSurfacePairs/swarma-broker-lab-installation-binding/1` | 1 |
| `c0f-member-closure` | Check named fields but accept additional members | `TestLabClosedSurfacePairs/swarma-broker-lab-installation-binding/1` | 1 |
| `c0f-null-closure` | Delegate null refusal to type checks instead of the required closure gate | `TestLabClosedSurfacePairs/swarma-broker-lab-installation-binding/1` | 1 |
| `c0f-nested-closure` | Check nested JSON kind only, not nested closure | `TestLabNestedClosurePairs/swarma-broker-lab-installation-binding/1/Context/unknown` | 1 |
| `c0f-byte-bound` | Skip pre-decode 16384-byte bound | `TestLabPayloadLimitPairs/swarma-broker-lab-installation-binding/1` | 1 |
| `c0f-epoch-positive` | Accept zero positive install epoch | `TestLabGeneratedGrammarPairs/swarma-broker-lab-installation-binding/1/[install_epoch]/positive/integer-0` | 1 |
