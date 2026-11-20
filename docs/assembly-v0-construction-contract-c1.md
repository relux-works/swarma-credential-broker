# Assembly v0 construction contract C1

## Repository-owner authorization and limits

On 2026-11-19 the repository owner authorizes **INACTIVE construction of U02
only**, against the exact published DN-05 amendment text in
[operator and activation v0 section 4.4](../spec/operator-and-activation-v0.md#44-required-ownership-amendments-dn-05-conflict).
This extends [C0](assembly-v0-construction-contract.md) only for that bounded
unit; it is not a second implementation plan or specification acceptance.

DN-05 = A remains a declared **CONFLICT**, not a refinement. Its six amendments
are published in broker sections 4.2, 12.4, 15.1 and 15.2 and service dialect
section 1 and section 5.1 step 5, at section 4.4's clause links. The exact
[equality-or-refusal joins](../spec/broker.md#42-principals) apply; neither config
nor root authority takes precedence over a mismatched duplicate. Absent or
disabled activation retains the existing baseline behavior and texts verbatim.
The six clause preambles and three "Here, this profile/proposal means" glosses are non-normative applicability notes.

C1 authorizes **no daemon wiring, no default change, no activation and no
installation**. Curator Core acceptance of O-01 remains required before any
activation; all other activation and qualification gates also remain. If the
acceptor later changes the published amendment text or construction seam, U02
reopens for an explicit fix round and fresh exact-head review of the affected
implementation, contract and tests, never silent drift or grandfathering.

Book-first disposition: C0 names **Operator and interfaces**
(`book/ru/16-interfeysy.md`) and **OS user per agent and network**
(`book/ru/04-polzovatel-i-set.md`). Their narrow-entry and observation boundaries
remain the same. C1 refines the repository's construction-stage scope only;
it neither reclassifies the DN-05 ownership conflict nor publishes or accepts
any outstanding upstream book/specification amendment.

## U02 construction slice and seam

The [U01 seam sheet in C0](assembly-v0-construction-contract.md#seam-sheet),
specifically I02/I03 and their I01 value/port declarations, is the construction
seam for U02. O-19 final acceptance stays with the acceptor; compilation and
this construction permission are not that acceptance. Keep current identity-only
reads separate from pinned enabled-use reads, with no authority-history,
activation, managed-evidence or trusted-UTC prerequisite added to unmanaged
identity-only narrowing.

The authorized U02 slice **does not wait for O-03** to check equality of the
configured UID, name and home pins against current protected directory facts
and enforce the protected-directory joins. It includes the specified protected
file/ancestor checks, configuration-lock continuity, exact current authority
bytes and equality-or-refusal configuration joins. Matching configured pins
establish this bounded equality only, not their creation or history provenance.
No file is installed and no live reader is wired by this specification unit.

The dedicated-human creation/history provenance of O-03 remains **open** and
belongs to later units **U15, U16, U24 and U25**. U02 must neither decide it nor
substitute a guessed account history, an accepting filesystem stub or fixture
identity for it. A protected equality check does not prove that the account was
created or used only by a dedicated human.

For the supplied implementation plan section 3 U02 extra gate, **Accepted
DN-05 amendments**, C1 separates inactive construction permission from acceptor
approval: the published exact text is sufficient for this inactive U02 slice
only. It does not satisfy acceptance for activation, close O-01/O-03/O-19,
waive any other plan gate or authorize U03 or any other unit. C0's existing
U00/U01 authorization remains unchanged. Every other O-point stays open in
[the applicability register](assembly-v0-applicability.md#open-o-points).

## Required counterexamples and positive controls

These are construction-contract requirements, not claimed executable U02
results. U02 must preserve the paired refusals and valid controls; this
publication supplies no runtime, native or protected-provenance qualification.

| Counterexample that must stay unaccepted | Permitted control and boundary |
| --- | --- |
| Config-wins or root-wins precedence after a duplicated fact differs; accepting an extra observer, contradictory account selection or a mismatched configured UID/name/home or protected-directory join. | Equal duplicated facts, exact configured pins and valid protected-directory joins permit only the bounded inactive U02 construction checks; unmatched facts refuse. |
| Calling DN-05 a refinement or assuming publication means acceptor approval. | DN-05 remains a declared CONFLICT with published, PROPOSED amendments and separate Curator Core acceptor review. |
| Activating before acceptor review, or using C1 to wire the daemon, change a default or install files. | Inactive U02 construction only; no activation even after review unless every other required gate also holds. |
| U02 deciding or claiming O-03 dedicated-human creation/history provenance from equal pins or fixtures. | U02 checks current protected equality; provenance remains open with U15, U16, U24 and U25. |
| Another unit citing C1 as its construction authorization. | C1 names U02 only; every other unit needs its own applicable authorization, with C0's prior U00/U01 scope unchanged. |
| Adopting a later acceptor change without reopening the affected U02 work. | An explicit U02 fix round updates the affected contract, implementation and tests with fresh exact-head review. |

## Source-pin revision for DN-05 publication

On 2026-11-19 the repository owner authorized the two whole-file source-pin
revisions below for **DN-05 publication**. Fix round 1 also authorizes rebasing
the sealed vector citations to those amended bytes and adding per-excerpt
seals and regression checks. The constants in `fixtures_test.go` and metadata
in `testdata/construction-v0/index.json` remain synchronized. Vector payloads
and the historical C0 construction scope do not change.

| Source | Old SHA-256 | New SHA-256 | Reason |
| --- | --- | --- | --- |
| `spec/broker.md` | `e069ccf61e89b2f6efa27227eb80349f5379181f64b6ce46d960a64a609a6834` | `616d58599f78d4ef0e69920198a179d104313299c2cb4d66138e0ff1becc259a` | DN-05 publication |
| `spec/operator-and-activation-v0.md` | `d242db6d897ffe7a6fc662df9c47f9d67a035ddcbaffbcc245b87b13ad9d7c79` | `c3d3bdfa9a12fe6e7fbc459474259f1f3a8f34600b46dc8b6a6e0ac85b1ec47d` | DN-05 publication |

The DN-05 revision set the index's `spec_commit` to publishing commit
`a864e2665a15a22b59964633d6691b86e5737c00`; both new digests exist at that
commit. The old digests and the historical C0/applicability S and broker line
references resolve only at `e295b4c7c0dc397ecdaa89e73c057d53d2e3f533`.
Neither the unchanged "Revision: 4" heading nor a bare revision number selects
between those two byte contents: the explicit commits and digests do.

All 76 index citations now resolve to the same exact excerpt bytes as before
publication. Seventeen citations move; the other 59 keep their line numbers.
The complete moved-span inventory is below; repeated vector citations count
separately. No cited excerpt is widened to include a new amendment.

| Source | Vectors | Historical lines | Published lines | Citation count |
| --- | --- | --- | --- | --- |
| operator spec | `activation-1.json`, `activation-900.json`, `activation-default.json`, `activation-enabled-synthetic.json` | 1405–1427 | 1415–1437 | 4 |
| operator spec | `activation-default.json` | 1446–1456 | 1456–1466 | 1 |
| operator spec | `activation-enabled-synthetic.json` | 1466–1486 | 1476–1496 | 1 |
| operator spec | `activation-1.json`, `activation-900.json`, `activation-default.json` | 1506–1515 | 1516–1525 | 3 |
| operator spec | `session-unbind.json`, `session-widening.json` | 1589–1591 | 1599–1601 | 2 |
| broker spec | `grant-envelope.json` | 367–389 | 391–413 | 1 |
| broker spec | `revocation-grant.json`, `revocation-key.json`, `revocation-key-reason.json` | 417–429 | 441–453 | 3 |
| broker spec | `session-unbind.json`, `session-widening.json` | 900 | 957 | 2 |

Each citation includes `excerpt_sha256`: SHA-256 of the exact UTF-8 bytes from
`first_line` through `last_line`, inclusive, retaining each line's LF when
present. The 26 distinct expected excerpt seals are independently frozen in
`source_index_test.go` from the historical excerpts, not recomputed from the
current file during a check or vector regeneration. A missing or invalid seal,
invalid line range, unpinned path, changed excerpt or shifted line refuses.
Future edits therefore require an explicit rebase even if someone refreshes
the whole-file digest. The existing independent whole-file drift guards remain.

Run `go test -count=1 ./internal/assemblyv0` for the vectors, citation checks and
paired line-shift refusals/valid controls. `TestConstructionSourceCitations`
checks every stored citation against the current source independently of the
whole-file pins. `TestConstructionSourceCitationLineShift` inserts one line in
each pinned source in memory and requires the specific excerpt-drift refusal.
`TestConstructionSourceCitationBoundaries` checks seals and bounds beside valid
LF and no-terminal-LF controls. Regeneration uses
`go test ./internal/assemblyv0 -run '^TestConstructionVectors$' -update-assembly-vectors`
only after reviewing source spans and expected excerpt seals; it writes the
vector directory, not new expected excerpt seals. Capture command logs and
throwaway mutation evidence in task-owned `.temp/` scratch.

This rebase neither supplies Curator Core acceptance nor changes any C1
authority limit. It is index/vector-test evidence, not U02 implementation.

## Evidence boundary

No production Go code, daemon behavior or previously committed reviewer test
is removed or renamed. This fix changes only documentation and source-index
metadata/test logic; no vector payload or amended specification byte changes.
The brief supplies no attack-surface table: this is a declared brief gap, not a
waiver of later U02 coverage. O-03 provenance, O-19 final acceptance and all
other open O-points are outside this unit's contract, not implicitly covered.
The Go suite is a no-production-code-change control, not U02 implementation
evidence or specification acceptance. Publication review is limited to exact
amendment bytes, conditional applicability, links, sealed citations and these
C1 boundaries.

## Non-semantic lab cross-reference source pins

The lab cross-reference revision of 2026-11-20 places each pointer after all
pre-existing specification text. Every original line and sealed excerpt is
byte-identical to the DN-05 source above; no existing citation moves. The
whole-file digests necessarily change, so the test constants and index metadata
select the following exact source revision instead of accepting
unsealed source changes:

| Source | Source commit | SHA-256 | Change |
| --- | --- | --- | --- |
| `spec/broker.md` | `ca520990ff4a390864a8d8f2155e6a0eff9f1d8f` | `e45be31c8b3701806b628d9fe6ca011c8a55e17969892a2e2f95b29bdeeeea87` | Non-normative lab link at EOF only |
| `spec/operator-and-activation-v0.md` | `ca520990ff4a390864a8d8f2155e6a0eff9f1d8f` | `feacdfe6e6cb551b9f175800ccd45eb8e09b299533bfad86e2607dace2834eb4` | Non-normative lab link at EOF of section 9 only |

The current index's `spec_commit` names that revision. Only
`baseline_spec_sha256`, `spec_commit` and `spec_sha256` change in the index; all
vector payloads, source spans and excerpt seals remain unchanged. The literal
whole-file comparisons in `TestConstructionVectors`, and the valid and
line-shift refusal controls in `TestConstructionSourceCitations` and
`TestConstructionSourceCitationLineShift`, remain enforced. This metadata
revision neither amends the production grammar nor accepts the lab exception.
