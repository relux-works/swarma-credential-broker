# P2 production Authority/View provider: contract stop

**Historical finding, resolved for P2 by the binding owner decision of
2026-11-19.** The separate managed-identity projection is implemented by the
[production service identity provider](managed-identity-provider.md). The
original finding below is retained as checkpoint evidence, not a current STOP.
Installation, trusted time, restore/high-water and other activation gates remain.

**STOP: P2-UM-LEDGER-CONTRACT.** This is a bounded contract finding, not a
production implementation, accepting stub, qualification result or activation.
No runtime source, provider interface, daemon wiring or specification changes.

## Contract and source identity

The broker source examined is
`698d9e40f57058addd80a82d56c356009239dea6` (landed S3a, inactive).
The user-manager source examined is
`ebea7d32a89be5b9330e91a8d1387e9456afc04a`; statements about its writer
below are bound to that commit, not to the outcome of the parallel service
account unit.

- Book: `swarma-docs` at `bb2ebfd6e1bad435ca05c62a4f79cd22a5a3104e`,
  `book/ru/09-uchetnye-dannye.md`, section "Режим без секретов у агента",
  and `book/ru/05-polzovatel-i-set.md`. These keep custody outside agent
  accounts and describe managed identities; they do not publish a new ledger
  encoding. This finding makes no design change to them.
- [Service dialect §§2.1–2.2](../spec/secret-free-service-v0.md#22-service-principal)
  requires kernel peer UID, the current managed service-account generation,
  admitted local placement, a class other than untrusted and disjoint service
  and agent roles. Missing, ambiguous, unreadable, retired or wrong-kind
  evidence refuses `principal_ledger_mismatch`, effect none. §5.1 step 3
  repeats this at bind; §5.3 step 1 repeats the record check at lease issue.
- [Broker §4.2](../spec/broker.md#42-principals) delegates managed-principal
  evidence to the user manager and requires rechecking on bind, lease and
  renewal. It explicitly says the admission-class encoding and the
  membership/placement/role evidence formats are unpublished (§§18.16,18.23).
- User-manager `spec/helper.md` §4.0 gives the installation layout
  `/opt/swarma/lib/user-manager/ledger.json`, root-owned mode `0644`,
  atomically replaced in a protected root-owned directory. §4.5 sketches
  per-generation records
  `{generation,username,uid,gid,kind,label,state,created_at,created_by,retired_at?}`.
  This sketch is not a published envelope: the same section explicitly
  leaves store-epoch envelope/floor encoding unpublished and requires
  alignment with the generation reader before implementation.
- User-manager `spec/helper.md` §4.5 and `spec/stations-v0.md` §§3,8 make
  `gen-journal/1` authoritative, not `ledger.json`. Divergence requires
  rebuilding the derived view under the shared lock. Unavailable/corrupt
  journal or missing protected non-generation metadata closes admission.
- User-manager `spec/generation-journal.md` §§5–6 requires an external
  restore fence, a durable consumer high-water and a bounded shared read
  window through final publication. `WithEvidence` is a lock/verifier
  primitive, not an accepting production adapter; `View.Active` checks each
  exact identity pair. A cached JSON snapshot does not provide that window.

These user-manager paths and sections refer to the exact source identity
above. No protected live ledger or credential was opened for this finding.

## Concrete contradiction

At that user-manager commit,
`internal/manager/store_linux.go:245` implements `DiskStore.Ledger` by
canonicalizing `genjournal.View` and atomically writing it as `ledger.json`.
`tools/genjournal/journal.go:49` defines each row as exactly
`uid,generation,state,seq`; `View` serializes only `tail` and `rows` at line 57.
Neither record kind nor admitted placement nor admission class is present.
`spec/stations-v0.md` §§1–2 still excludes service provisioning and refuses
non-agent kinds; the parallel service-account work is not assumed delivered.

Reading this actual ledger as the helper §4.5 full-record sketch would require
inventing a different envelope and absent fields. Conversely, treating an
`active` generation row as a service-account record would admit agent rows and
violate §2.2. Treating the ledger as lifecycle authority would also contradict
the user-manager journal-over-ledger rule. Root ownership and no-follow opens
cannot repair missing authority semantics.

| Required fact | Exact missing or conflicting representation | Status |
|---|---|---|
| Service-account record kind | `kind` in the helper §4.5 sketch is absent from the writer projection; its protected metadata join is not defined for this broker consumer | PENDING-UM |
| Admitted local placement | No published ledger member or protected per-generation evidence encoding; do not invent a `placement` member | PENDING-UM |
| Current admission class | No published ledger member or protected per-generation evidence encoding; do not reuse the manager policy `class` as individual evidence or invent a member | PENDING-UM |
| Ledger rollback protection | Helper §4.5 leaves the store-epoch envelope and durable floor encoding unpublished; do not equate a journal tail with a newly invented ledger epoch | PENDING-UM |
| Current generation | `uid,generation,state,seq` exists, but authoritative journal/restore-fence/high-water evidence and the bounded publication window must accompany it | Integration required; ledger-only admission forbidden |
| Disjoint roles | Requires protected current agent and service binding evidence for the same `(uid,generation)`, in addition to the record kind | Broker/provider integration required; no role-string substitute |

## Resumption inputs and activation boundary

1. The user-manager/spec owners publish the exact supported protected record
   projection or metadata join, including `kind`, placement and admission-class
   evidence, path/permissions and its atomic relationship to the authoritative
   generation journal. Publish or explicitly resolve the ledger epoch/floor
   contract. A new projection must be versioned by its owner, not guessed here.
2. Resolve the direct-ledger broker wording against the journal-over-ledger
   reader contract. The valid direction is journal-backed evidence with the
   published restore-fence/high-water and exclusion requirements, not a waiver
   allowing a stale ledger to override retirement. Identify its actual
   protected lifecycle and binding-lock integration before implementing it.
3. Re-read the accepted contracts and the parallel service-account delivery
   at their new exact heads. Implement and test the production provider only
   against those supported bytes and authority sources.
4. Keep the standalone daemon inactive. The existing seam is
   `service.New(authority, accounts, now)` and `service.Authority` /
   `service.View` in `internal/service/broker.go`; there is no provider CLI
   selector or permission to activate from a configured UID. Future activation
   must explicitly install the accepted protected provider at that seam and
   satisfy the other gates in `docs/claude-custody.md` and the README. This
   unit adds no switch, fixture fallback, network call or material-release path.

The alternatives are to wait for those owner contracts and resume P2, or to
rescope this task explicitly to a non-authoritative protected-file primitive.
The latter is not the requested production Authority/View provider and cannot
close S3a §2.2. This task does not choose or implement that substitute.

## Coverage and negative-test limits

No surface table was supplied in the brief; that remains a handoff brief gap.
The requested negatives define the following acceptance map. All production
provider rows are **unimplemented / NOT RUN**, with no killed-plant credit.
There is no valid production control to pair with a negative until the missing
authority representation is resolved; a provider that refuses everything is
not a valid control.

| Clause / negative | Required code surface | Test / positive control | Narrowing plant |
|---|---|---|---|
| Broker §4.2: missing ledger | Protected descriptor reader | NOT RUN: absent ledger versus valid protected record | NOT RUN: omit required-open refusal |
| Helper §§4.0,8: symlink ledger or ancestor | No-follow descriptor walk | NOT RUN: symlink versus regular protected file | NOT RUN: follow a replaced component |
| Helper §§4.0,8: wrong owner or mode | File and ancestor metadata validation | NOT RUN: wrong owner/mode versus root-owned protected path | NOT RUN: bypass owner or write-mode check |
| Service §2.2: agent/workplace as service | Protected record-kind admission | NOT RUN: wrong kind versus exact service record | NOT RUN: accept any active row |
| Service §2.2; journal §§5–6: retired generation | Authoritative current-generation window | NOT RUN: retired/stale pair versus current active pair | NOT RUN: trust derived active over journal retirement |
| Service §2.2: mixed roles | Current protected binding exclusions | NOT RUN: active agent+service conflict versus exclusive service role | NOT RUN: skip opposite-role binding check |
| Service §2.2; broker §4.2: untrusted class | Protected per-generation class/placement evidence | NOT RUN: untrusted/nonlocal/unknown versus admitted local non-untrusted | NOT RUN: default missing class or placement to accepting |
| Broker §4.2: malformed/ambiguous record | Closed published record decoder | NOT RUN: malformed/duplicate/conflicting record versus valid encoding | NOT RUN: ignore malformed or duplicate evidence |

Existing `TestServiceIdentityReaderRefusals`,
`TestServiceRefusalsBeforeMaterial` and `TestServiceAuthorityPublicationFence`
exercise synthetic supplied authorities, not this absent production reader.
Their green results can establish baseline regression evidence only; they
cannot prove root ownership, no-follow, record kind, placement/class encoding,
disjoint-role ledger admission or authoritative journal integration.
No production provider plant was applied. There are no mutant results to
report as killed, and no production acceptance claim.
