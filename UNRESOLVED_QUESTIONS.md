# Unresolved questions

## Inactive assembly construction

[Construction contract C0](docs/assembly-v0-construction-contract.md) supplies
U00/U01 inactive declarations, closed record sum codecs and source-derived
synthetic vectors only. All O-01 through O-21 remain explicitly recorded in the
[applicability register](docs/assembly-v0-applicability.md#open-o-points).
O-07 enrollment result/reply types and O-09 producer/principal/effect/replacement
schemas are absent, without placeholder members or accepting stubs. O-01/O-19
acceptance remains a review/publication gate; the supplied owner's construction
assignment is not final specification acceptance. No daemon, custody, live
authority or C selector is enabled by these artifacts.

U05 adds only the [inactive journal and shared-gate bridge](docs/assembly-v0-service-journal.md).
It does not close any O-point or supply the U19 enrollment-intent recovery proof,
the later constructor/catalog integration, or native qualification. O-19 still
gates complete version-aware runtime plumbing and the provenance/assignment of
unchanged binding/hold timestamps when operation `at` is null; no timestamp is
fabricated by this storage implementation.

## Production assembly contract stop

**STOP:operator-act-contract.** Broker §14 explicitly leaves the operator
entry-point grammar, wire format, domain and canonical act bytes unpublished.
The managed service-identity provider does not supply operator principals or
authenticated operator acts. A peer UID check alone cannot satisfy widening-act
authentication and exact-content confirmation. Activation schema/custody,
protected nonidentity facts, owner enrollment transport, installer paths and
bootstrap ordering also require publication before implementation. The
[source-backed stop and resume decisions](docs/production-assembly-stop.md)
bound the missing work; broker §3.2 is **PROPOSED**, not an activation decision.
The [operator and activation v0 candidate](spec/operator-and-activation-v0.md)
now proposes all six missing contracts. Its
[Owner decisions (2026-11-19)](spec/operator-and-activation-v0.md#9-owner-decisions-2026-11-19)
record A for DN-01 through DN-08 with their conditions, and DN-09 A for production;
Curator Core acceptor review, required amendments and qualification remain open.
C stays a PROPOSAL pending the owners' residual-risk and exact time-amendment
decisions; nothing in C is in force. The stop remains pending acceptance, not
a claim that no candidate text exists. Revision 4 names password-only PAM/sudo,
fresh never-agent caller,
root-owned composer/sealed candidate and launcher/trusted path, SSH-only login,
witnessed single-launcher freeze/thaw/refreeze, compatible root-witness FD0
access, root-witness rendezvous and every-exit TTY queue/mode
cleanup with no successor reader decisions; their implementation
and native qualification are still absent. DN-05 is explicitly a **CONFLICT**
with broker-owned principal
and machine-policy rules, requiring the listed broker/dialect amendments and
equality-or-refusal joins. DN-06 proposes versioned service receipt metadata,
nonsticky refusals and independent revocation/caller-binding storage, not an
installed migration. Issuer revocation needs verified grant history; only
root/operator-key revocation is independent of it. Both unbind routes retain
their own identity/storage requirements without widening gates.
DN-09 keeps A for production and proposes C only for an explicitly accepted,
time-boxed, qualified-VM-bound TEST-PROFILE v0 **CONFLICT** with the time
contract, requiring its exact exception text and clause disposition audit.
C1 explicitly **conflicts** with the time contract's no-replacement-history,
scope and hold-continuity rules: only the exact accepted amendment retires the
old installation/time scope permanently and permits a fresh never-reused
installation/consumer scope and qualified checkpoint. Retired W/hold bounds and
the off-VM retirement instant are refusal-only floors for first consumption
and expiry, never imported/admitting or revived. A held same-source reinstall
still needs protected recovery qualification; off-VM pre-start checks expiry
against an off-VM clock. Ordinary restart retains current history. C also
requires an every-start
outside-home root fence, persisted consumer high-water, authenticated NTS under
existing policy, a protected test-subscription marker and fresh independent VM
identity evidence, with live whole-VM rollback risk still awaiting the owners'
decision. No C result
may be promoted to production. Exact amendment acceptance, the VM verifier,
initial root-to-dispatcher grant and narrowing revocation ceremonies,
collector/witness, hold-capacity/isolation,
native publication, gateway routes and teardown remain qualification gates.

## Claude secret-free service integration

The accepted service dialect is the landed 0.13
[secret-free service specification](spec/secret-free-service-v0.md).
Its closed broker fields, operation replay, durable records, hold window,
refusal codes and operator act requirements supersede the earlier provisional
choices. The implementation and scope are described in `docs/claude-custody.md`.
No code site retains a provisional broker dialect choice. Accepted section 10
still leaves the unavailable revocation-sequence encoding to the broker and
placeholder format/delivery and listener binding to the gateway; the source
requires a provider-owned sequence encoding and invents no placeholder dialect.

Production integration still requires the protected current user-manager and
independent-authority reader, qualified time and publication settlement. The
`service.Authority` interface holds these facts current through material
publication; it has no default accepting implementation. The standalone daemon
does not install this controller. This is an explicit integration gate, not
permission to derive authority from a static UID, name, request or placeholder.
Explicit activation gates: the provider enforces spec §2.2 (service-account
record, disjoint roles), including a user-manager service-account record rather
than an agent or workplace record, admitted local placement, a class other than
untrusted and disjoint service and agent roles (§5.1 step 3, row 10); protected
identity-reader availability for hold admission (§5.8 steps 1–2), including the
fact that unbind closes connections and an unbound generation cannot reconnect
as a service to place a hold; journal retention and resource admission must keep
a durable hold placeable at exhaustion, with protected hold headroom. These gates
are not discharged by a fixture role or the current protected record-size ceiling.
An unrelated journal failure still fences all accounts until restart unless the one pending hold is
reconciled by its identical retry; account-scoped failure isolation remains open.
Gateway listener/placeholder mapping, matcher inventory and actual stop/use
closure, deployment and exact harness/vendor qualification remain separate.
Fixture success grants no live account permission or activation.

The binding managed-identity projection decision of 2026-11-19 resolves the
historical **P2-UM-LEDGER-CONTRACT** stop. The [production service identity
provider](docs/managed-identity-provider.md) consumes that separate protected
artifact joined to the verified generation journal; it does not reinterpret
the derived ledger. Shared producer/consumer fixture-byte reconciliation and
specification-acceptor review remain separate owner gates. Activation still
requires installation, independently protected operator/use facts, trusted
time/continuity, external restore-fence custody and a durable consumer
high-water. The identity-only reader supplies neither that independent
rollback evidence nor a daemon activation selector. The producer retains the
lifetime UID-kind invariant across consumer restarts.

## Owner close diagnostic mitigation

[Issue #63](https://github.com/relux-works/swarma-credential-broker/issues/63)
remains open. PR #62 provides [diagnostic regression coverage](docs/owner-close-diagnostics.md),
preserving UNKNOWN without completion credit; it does not establish the root
cause or a reduction in the frequency of the reported owner-close race.

## Separately proposed secret-free mode

The [new contract](spec/secret-free-mode.md) is **PROPOSED/inactive**, independent
of v0 activation. Its settled dispositions are: API keys/test subscriptions
first; configured endpoints with TLS interception closed; minimal lifecycle
broker and separate gateway, action service as trusted effect executor; gateway
model-provider/code-hosting classes only, every external shared-state write in
the action service; whole-account possible-leak hold lifted only by the owner,
confirmed leak additionally vendor rotation; local-only first, donor B/C closed
as separate later steps. These are resolved choices, not questions reopened by
the remaining implementation gates.

[Publication and activation](spec/secret-free-mode.md#13-publication-and-activation-gates)
retain protected service/client policy and installation, gateway and
adapter implementations, exact harness qualification, matcher inventory/bounds,
outside-gateway matcher custody, confirmed-leak criteria and owned alert route.
None is assigned speculative active v0 fields or methods. Existing time, peer,
release, cleanup and owner-account prerequisites below retain their scope.

## Existing profile and integration gates

The [Codex refresher v0 profile](spec/v0-codex-refresher.md#11-accepted-curator-rulings)
has resolved curator rulings R1 and R2:

- **R1 accepted:** a static, operator-owned UID allowlist per account, checked
  by `SO_PEERCRED`, replaces grants in v0.
- **R2 accepted as an interim mode:** the daemon runs under the launches' OS
  user with §2.1's reduced guarantees. Leaving this mode requires the dedicated
  service-user step in Appendix A after the migration tool is reviewed.

R3 fresh-home owner enrolment remains accepted; the standalone headless runner
and extraction ahead of slice 0 are confirmed in scope. The cutover ruling
requires a maintenance window scheduled in advance through the platform curator,
every Codex launch on the machine quiesced for that window, and owner-performed
fresh-home device-code enrolment inside it.

The profile remains inactive until the mandatory
[0.163.0 qualification procedure](spec/v0-codex-refresher.md#82-mandatory-01630-qualification-procedure)
is satisfied. Complete containment/durable recovery, approved live-account
cases, safe old-login retirement during [cutover](spec/v0-codex-refresher.md#31-cutover-from-a-shared-native-login),
and optional thread resume remain evidence gates. The full broker's
[publication gates](spec/broker.md#18-open-questions) remain open for other deployments.

The daemon core intentionally ships with an unavailable owner adapter. Activation
still requires exact-release qualification, durable attempt recovery and time
watermarking, writer containment, approved live-account cases, safe old-login
retirement and any optional thread-resume evidence. The core's fake-owner tests
provide no real vendor or lifecycle qualification credit.

Implementation integration questions:

- The selected foreign-peer design uses an owner-installed supervisor as the
  direct case parent and waiter. Its [proposed contract](docs/peer-supervisor.md)
  still needs an approved independent witness of the supervisor initial exec,
  image, argv/environment and launch ancestry across test identities. Existing
  test-role sudo permission, pidfds and socket credentials alone do not supply
  all those facts. Installation and activation remain pending; the peer row
  remains UNRUN. The two runner rows have an accepted
  [measured-code testimony contract](docs/runner-testimony.md) with passing
  synthetic pairs, an explicit report class and private artifact binding.
  This supplies no live-source or production release qualification.

- `authowner.New` now validates and reconciles `owner-*.json` before snapshots.
  Activation still needs protected fresh-enrolment checkpoints, an independently
  implemented time/restore confidence provider, configured service identities,
  and installation of the approved empty-home echo helper for manager readiness.
  No existing login is adopted and no qualification is manufactured locally.
- Deployments must provision the protected peer mapping, helper and intended
  shared group for genuine foreign-UID qualification. The group-only fixture now
  checks a real configured pair; unavailable mappings still remain PENDING, and
  same-UID coverage does not substitute for that deployment evidence.
- Which release evidence will establish safe transient backoff and unknown-expiry
  handling? The core rejects unknown expiry and delegates retries to the owner.

- Protected `qualification/1` records, evidence-first publication, current-input
  observer contracts and the command frame are implemented. Production version,
  experimental schema and model catalog remain unavailable until the next
  qualification slice supplies a network-isolated candidate launcher and row
  bodies. Applied unit properties remain unavailable until the contained owner
  supplies its template and current-property observer. Ten transport/admission
  fixture rows have attested paired execution; the peer row needs an independently
  trusted inner-case waiter and image identity. Both runner rows now have the
  accepted measured-code testimony contract with an implemented post-Command
  exchange, bounded parent effect observations and private artifact proof gate.
  Both synthetic pairs pass under the explicit measured-code testimony class;
  live-source and production release qualification remain pending. The peer authority decision remains open; no kernel-observed
  Command call is claimed for the runner contract. Other rows stay pending, live
  execution remains refused, and no production tuple qualifies.
  See [qualification](docs/qualification.md). An interrupted-run fence, missing activation or recovered pending activation
  requires operator reconciliation while closed; an automatic recovery tool is
  not shipped.
- The runner currently reads the same broker-owned 0600 configuration as the
  daemon in interim R2 mode. A dedicated-service deployment needs a protected
  client-readable policy contract; unreadable policy remains refused, with no
  copied policy or permission weakening in this slice.

- Native 0.163.0 fixture qualification remains PENDING. The refresh URL override
  alone does not confine unsolicited model-service requests; a clean, complete
  vendor egress boundary is needed before retrying. Sandbox startup capability
  also needs qualification under the required service properties. No live
  account or issuer evidence is supplied by fake-vendor success.
- Refresh RPC error codes are ambiguous without exact-release classification.
  The default owner treats them as unknown; qualified nonrotation/rejection
  classification is an integration input, not an operator retry override.
- Protected executable installation and approved routing configuration remain
  installation/enrolment gates. The refresh library rechecks the pinned digest
  and uses an explicit minimal environment; it adds no endpoint override path.

- The [platform time policy](docs/time-policy.md) selects configuration-based NTS
  evidence for v0, with matching selected source and the published bounds.
  Authdata is required before the dedicated service identity. Production source
  selection and owner wiring stay off until activation. Activation must establish
  protected shared upper bounds, the complete running source inventory and
  monitoring permission. A backward step spanning process replacement within the
  same boot remains an activation integration gate. The
  [qualified-time contract](docs/time-contract.md) requires durable consumed-time
  and hold continuity across restart and reboot; the owner's watermark alone
  is insufficient. The [provider fixture API](docs/qualified-time-api.md) ships
  with production consumption inactive. Before production activation, select the
  independent local rollback witness backend and enforce storage/restore exclusions for both checkpoint and
  witness. No missing or restored history may be reset. A proposed off-node
  witness protocol is only a conditional candidate, not the selected backend.
  It would require a separate time-continuity stream (not the consumer journal
  stream), fresh authenticated reads, and durable begin and end records. Its
  off-node acknowledgment round trips conflict with the current local-CAS
  assumption and a registry consumer's five-second decision budget until a
  bounded, lock-compatible protocol is qualified. Further prerequisites are an
  approved consumer profile; versioned record and domain schemas for begin,
  settle and recovery; exact generation/challenge mapping; provisioning, ACLs,
  rotation and administration. Each confirmed head needs independent protected
  custody that cannot roll back when either the provider or witness, or both,
  are restored. Keeping only the signing key separately is insufficient. Require
  exclusion of the old instance and fresh authenticated reads. Mutual-TLS and
  custodian acknowledgment round trips count against the original consumer
  budgets, including the 250, 1000 and 2000 ms paths; clock bootstrap dependencies
  must also be resolved. The time-provider and platform owners must resolve that
  latency/authority decision before activation; no
  remote-to-local adapter is assumed. Native pre-pin qualification and consumer
  review are also pending. Broker backward tolerance is zero.

- The `time-untrusted` qualification row needs a bounded durable synthetic-owner
  enrollment/restart fixture using the real time provider, adapter and retained
  watermark admission. The snapshot-only admission fixture has no owner
  watermark and cannot prove the no-advance invariant. Its account, release and
  ended-lease evidence supplies no time-row credit; see
  [qualification](docs/qualification.md#fixture-row-dispatch-and-limits).

- The approved [qualified-time handoff](docs/time-handoff.md) remains inactive.
  Consumer-owned versioned use transitions, frozen-content/completion bridges,
  independent currentness/custody and enforced read-to-durable-act mechanisms
  still need review and qualification. Each consumer publishes its own
  [window profile](docs/time-window-profile.md), including undefined budgets
  rather than inferred universal limits. The shipped original reader and
  witness both refuse; no codec, pure verifier or adapter is supplied here.
- [Mandatory macOS parity](docs/time-handoff-macos.md) is unimplemented in
  `timeconf` and the rest of the broker. It requires a reviewed receipt/platform
  version, native continuous clock/timebase/boot mapping, source/collector,
  reader/witness/settlement, protected storage, directory/rename durability,
  process/service/exclusion/stop equivalents and native act/use timing proof.
  Apple API documentation does not qualify APFS/device power-loss behavior,
  directory full-sync semantics, restore custody or the post-read bound. Unknown
  guarantees keep admission closed; Linux-only evidence cannot waive parity.

## U02 review boundaries

- Spec 4.4 duplicate identity facts versus I03/C1 identity-only independence
  still needs the acceptor to settle which config joins apply to that leg.
  The identity callback also receives use-only schema members not validated
  by that leg; full schema validation versus a narrowed return type is a
  contract decision, not permission to add a use gate to identity narrowing.
- Gate failures currently expose `ErrIdentityChanged`, `protectedio.ErrProtection`
  or `fs.ErrNotExist`; later wire integration must map all gate refusals to
  `principal_identity_changed`, never interpret a missing pinned lock as
  authority absence. Callback-error preservation and the public mapping remain
  explicit integration work, not an assertion that these classes are identical.
- The source-walk import-guard integration note is resolved by retaining the
  landed toolchain-graph guard unchanged and adding exactly the two U02 rows.
  No fixture-helper production import requires a further consumer grant.
- The direct byte-count comparison now has an isolated task-owned proc-stat
  witness, and descriptor mode/mtime/ctime comparisons have direct pin controls.
  The privileged `/` check, read-I/O-error injection and some post-read timing
  clauses still lack isolated narrowing witnesses. No unprivileged fixture
  claims to replace the root check or to prove a surviving mutation equivalent.
  Descriptor close releases flock even without the redundant explicit unlock.
- Ancestor special-bit refusal is an intentionally stricter current reader
  bound, documented in its README; it is not a relaxed spec or a new authority
  source. Directory alias/blank/NIS refusals and repeatable `Load` pins are also
  documented as current behavior, not provisioning or startup enforcement.

### Mechanical mutation qualification boundary

The round-seven driver enumerates both complete target files rather than a
hand-selected comparison list. Its checked-in `internal/protectedio/testdata/
mutation/results.tsv` distinguishes named kills, mathematical equivalences and
remaining survivors. A healthy root-owned `/` cannot distinguish removing its
owner/mode refusal from the correct implementation: an unsafe root inode is
required. Changing the host root is neither permitted nor available to this
non-root producer. These mutants are not equivalent and are not reported green.
Other unproved owner/IO boundaries are stated per surviving row in that table.
The whole-class handoff remains stopped pending an authorized isolated
qualification environment or an explicit acceptance-scope decision. No new
production seam is introduced merely to make the tests pass; the production
implementation remains unchanged and no production defect is asserted.

## Lab C0 execution gates

B1 construction is stopped at
[native execution-evidence access](docs/lab-b1-native-execution-access-stop.md):
the dedicated nonroot broker must verify current native launch debits, while the
pinned manager requires its launch directory/ledger to remain root-only
0700/0600. A receipt alone is not a committed start. Choose an explicitly
specified privileged observation capability or revise the privilege split;
do not widen native permissions or substitute fixture authority. The prior
private recovery-envelope question is resolved by OPTION 2, not reopened.

The [closed lab contract](contracts/lab-v0/README.md) supplies inert construction
bytes only. C-OPEN-OWNERS, native joined-start/NTS/protection evidence, the exact
owner-approved live model/output/spend bounds and released consumer assemblies
remain unsupplied execution gates. The recorded 2026-11-20 direction/residual act
is not consent for all owner roles. No production acceptance or live Q result is
inferred from a content seal, synthetic fixture or local exact-client probe.

## Lab B2 native and integration gates

The [B2 producer](docs/lab-b2-time.md) implements only the tagged library and
fixture-tested gates. C-OPEN-OWNERS remains unrecorded; neither a fixture seal
nor the dedicated lab authority identifier establishes consent or native
qualification. B5 must independently authenticate current owner/off-VM inputs,
release/VM/invocation pins and C1 retirement/revocation/replacement acts. B1
must join B2’s durable time/floor/manager heads to its own heads and call the
deadline predicate before release; B4/Q must measure root-only every-start
protection, real NTS/bootstrap inventory, adapter closure, fsync/crash behavior,
boot/monotonic continuity and bounded collection under qualified load. C1
metadata acceptance is not a privileged restore/reset route. The whole-VM live
rollback residual remains, and no production witness/default is opened.

Fix round 1 preserves the frozen C0 bytes. A later-start `previous *Fence`
must be authenticated by B5 as the acknowledged orderly-stop evidence; C0 has
no stop-record digest field in off-VM approval and B2 supplies no live stop
writer. The canonical stop fixtures prove the predicate, not that provenance.
C0/B5 owners must settle that binding before live construction. B1 must pass
`Start.Deadline()` into issuance/renewal bounds; B2 now independently checks
both approval expiries against every fresh settled upper/W. Missing/corrupt
metadata and uncertain two-pointer publication refuse without inferring burn
or a replacement baseline. The non-native reboot, load and home-alias/root
qualification observations remain open; fixture tests do not close them.
