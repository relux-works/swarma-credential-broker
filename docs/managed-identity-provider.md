# Managed service identity provider

## Sources and scope

This is the consumer implementation of the binding owner decision
`DECISION-managed-identity-projection-v1.md`, dated 2026-11-19. The decision
resolves `P2-UM-LEDGER-CONTRACT` for the two producer units only; specification
acceptor review on or after 2026-11-22 is still separate from that decision.
The previous [contract stop](service-provider-contract-stop.md) is historical.

Contract classification:

- **Same:** Swarma book `book/ru/05-polzovatel-i-set.md`, managed identities,
  and `book/ru/09-uchetnye-dannye.md`, "Режим без секретов у агента" and
  "Два полномочия на каждое использование": a service identity is not agent
  identity or permission to use credentials.
- **Same:** [service dialect section 2.2](../spec/secret-free-service-v0.md#22-service-principal):
  only the current admitted service-account triple maps to role `service`.
- **Same:** user-manager `spec/generation-journal.md` sections 2, 4, 5 and 6:
  protected descriptor walks, the gate/data read protocol, complete chain and
  lifecycle validation, and a bounded read window. The original
  `tools/genjournal` verifier is imported, not reimplemented.
- **Refines:** the binding decision supplies the separate protected projection,
  exact closed members and values, and its equality join to the journal head.
  It does not redefine `ledger.json`, grant policy, restore evidence or time.
  Broader specification acceptance remains with the specification owner.

The dependency pins the published user-manager commit
`ebea7d32a89be5b9330e91a8d1387e9456afc04a`. Its generation verifier is identical
to the checked decision-time source. Reusing it raises this module minimum to
Go 1.26.0 and selects its required `golang.org/x/sys v0.47.0`; development uses
the private Go 1.26.10 toolchain. No local copy or weakened journal parser is used.

## Read and mapping

`service.NewManagedAuthority(root, facts)` constructs the Linux production
service identity provider behind `Authority` and `View`. It accepts only an
absolute normalized platform root. Production ownership is fixed at UID/GID
zero, with no flag or environment override. Package tests alone use a private
policy seam and synthetic files owned by the testing user.

Each `WithIdentity`/`WithCurrent` pass:

1. Walks every ancestor from `/` with descriptor-relative `O_NOFOLLOW` opens;
   rejects symlinks, wrong directory ownership and group/world write access.
2. Opens the existing `<root>/lib/user-manager/generations/` directory (0755)
   and its existing `gate.lock` and `data.lock` read-only. It creates nothing,
   refuses a pending writer, takes shared gate then shared data nonblocking,
   and releases gate only after acquiring data. Data stays locked through the
   consumer callback; a writer-held lock refuses instead of queueing.
3. Reads `<root>/lib/user-manager/identities.json` and `generations/journal`
   once each in that same pass. Both files and the locks must be regular,
   root:root, exact 0644 including special bits, and single-linked. Reads are
   bounded and descriptor metadata must stay unchanged. A pending marker of
   any shape, including a symlink, closes admission conservatively.
4. Validates the full bounded `gen-journal/1` chain, lifecycle and retirement
   reserve with the format-owner library. Parses one exact CCJ-1 projection
   with required members, no unknown members, no duplicate keys or floats,
   and checks `journal_head == verified.Tail.Hash` (the last complete journal
   record including LF; zero hash only for the empty journal).
5. Rejects duplicate UIDs and duplicate active `(service,name)` records. Every
   kind, class, placement, state and service name is checked against its closed
   set, including records other than the selected service. Observed UID kinds
   may not change in one provider instance; the all-lifetime/no-kind-change
   invariant, including across broker restarts, belongs to the producer.
6. `View.Principal(uid)` accepts only `service`, `active`, `trusted`, `local`,
   the closed name `credential-gateway`, and the exact active journal
   `(uid,generation)`. It returns
   `Principal{UID: uid, Generation: generation, Service: name, Role: "service"}`.
   Every other identity case returns only `principal_ledger_mismatch`, with no
   material or state change. The broker preserves that refusal at connection
   admission as well as calls. An unknown UID never falls back to supplied
   facts, `ledger.json`, a configured UID or a previous snapshot.

The library read-window bound is 250 ms. A canceled, expired or retained view
cannot authorize a later lookup. Broker state-lock waits use that window, and
issuance and replay recheck the exact lease principal inside the custody callback
immediately before handing material to the transport. Expiry refuses with
`principal_ledger_mismatch` before publication. A durable outcome saved before
expiry remains replayable under fresh evidence; effect none here means no
material release, not rollback of the existing durable replay transaction.
A successful material handoff is never retrospectively relabelled an effect-none
identity refusal. The transport callback must itself complete within the window;
its synchronous interface cannot enforce a write deadline. Native transport
deadline propagation and bounded-publication qualification remain activation
gates, not properties proved by the in-memory publication tests.
The callback is bounded local work; this is
not permission to do network calls while holding the journal lock. Projection
parsing has an 8 MiB safety bound; the journal keeps its format-owner 1 MiB bound.
Installation must qualify ACL restrictions and prohibit lock/journal inode
replacement; descriptor hardening does not defend against a malicious root.

## Selection and inactive activation

Future installation explicitly supplies this service-identity leg through
`service.NewManagedAuthority(platformRoot, protectedFacts)` and passes the
result at the existing `service.New(authority, accounts, now)` seam. Nonidentity
`View` methods delegate only to the supplied protected facts view under its
`WithIdentity` or `WithCurrent` window. They never infer operator ownership,
acts, bindings, caller grants, events or revocation sequence from the projection.
The provider admits service principals only; independently protected operator
admission remains an assembly requirement, not a guessed account kind.

With `facts == nil`, identity lookup works but `WithCurrent` refuses with
`revocation_state_unavailable` before its callback. Other missing facts refuse
or return false; an unavailable sequence stays absent rather than receiving a
locally invented encoding. With supplied facts, their errors remain errors.
An identity snapshot is never a substitute for both current-use authorities.

The default daemon installs neither this provider nor a service controller.
There is no new CLI selector, fixture fallback, automatic installation or
activation. Installation, protected policy/operator/use-facts integration,
trusted time and its restart continuity, external restore-fence custody and
durable consumer high-water, native bounded-publication qualification and the
remaining [custody gates](claude-custody.md) stay closed. The identity-only
reader verifies from genesis; it does not create a durable floor or claim
independent rollback protection. Those gates must be satisfied before material
release is activated. This unit never starts a daemon or opens live credentials.

## Shared compatibility fixtures

`internal/service/testdata/identities-v1/` contains the consumer copy. The
projection documents have canonical sorted-key JSON with no trailing LF;
`journal.jsonl` has canonical LF-terminated records. Deliberately malformed,
duplicate-key and noncanonical cases are negative byte fixtures, not claimed
canonical documents. The final producer-owned `cases.json` accepted at snapshot `e26eaff`
identifies each check kind, its consumer operation, exact verdict, transition
history and filesystem condition. `SHA256SUMS` seals every case including that
manifest and all journals; the producer README and
checksum list itself are the only unsealed metadata. All files, including those
two metadata files, are copied unchanged from the canonical producer set.

The broker consumes decode checks directly through `decodeManaged`, service
checks through UID-only `View.Principal(uid)` using each case's separate verified
journal and exact expected UID, generation and service, and custody checks
through temporary filesystem conditions. Decode accepts do not promise a
Principal. Producer-only transitions declare `consumer=none` and are skipped
with a recorded reason; they do not claim a broker pairwise transition API.
The shared decode refusals include zero UID, zero generation and NUL names;
`TestManagedIdentityScalars` also checks these bounds across all supported kinds.
The exact 8 MiB decode accept and 8 MiB + 1 refusal exercise the production
decoder limit directly, as well as the protected reader's independent bound.
All 43 manifest matrix rules retain adjacent ACCEPT/REFUSE controls. The
`not-regular` custody row uses a FIFO with expected UID/GID, 0644 mode, one
link and buffered valid projection bytes; only its file type violates custody.
The separate directory row retains its multi-rule refusal. A custody refusal
must preserve the FIFO buffer, not merely return no Principal.

The broker consumes the fixtures in `TestManagedSharedFixtures`, verifies the
seal in `TestManagedFixtureChecksums`, checks complete case-file coverage in
`TestManagedFixtureInventory`, and rejects closed-schema violations independently
in `TestManagedClosedDocument`. The inventory checker has added-file, missing-file,
nonregular-file, duplicate-case and missing-history negative controls.
`TestManagedFixtureFileSet` removes every listed file in turn, including the
per-service journals and metadata, and rejects an extra file beside intact
controls. `TestManagedFixtureConsumerContract` checks per-kind metadata and
rejects missing service journals, UID/output mismatches and invalid promises.
Manifest custody cases apply the named condition to temporary copies, not the checked-in
files; valid bytes alone do not represent a filesystem refusal. Additional
consumer-only schema and filesystem negatives generate their own temporary data.
Service rows explicitly supply the lookup UID and case journal/head; accepting
rows also supply the exact Principal and repeated expected generation, never a
generation lookup argument. Consumer-only controls exercise a different active
journal tuple without changing shared fixture bytes.
`TestManagedNonselectedRecords` drives closed values, members and uniqueness
outside the selected record. `TestManagedPendingAtReadBoundary`,
`TestManagedGateDataOrdering`, `TestManagedReadDeadlineBeforeEffects` and
`TestManagedReadMetadataChange` drive the private nil-by-default read boundaries,
including marker publication before gate acquisition and metadata changes on the
opened descriptor. These are package-private test seams, not runtime overrides.
`TestManagedRefusalsBeforeMaterial` also consumes every consumer-expressible
refusing manifest row, skips producer-only transitions with a reason, and
checks that connection admission and lease requests leave publication, custody,
lease count, durable state and identity evidence unchanged. Effect none is an
observed invariant, not an invented wire-error member.
Root installation and ACL/durability qualification are not claimed by tests
using the private unprivileged ownership seam. The producer copy belongs at
user-manager `testdata/identities-v1/`; this consumer copy was compared byte for
byte with the draft producer set. Landing requires a fresh comparison against
the accepted producer commit. Consumer tests alone do not attest a
different producer checkout or installed deployment.

Run from an isolated private checkout with absolute HOME/caches, the selected
`GO`, and TMPDIR/GOTMPDIR set to the task-owned scratch. Useful narrow entry:
`"$GO" test ./internal/service -run "^TestManaged" -count=1`.
Plant overlays, command receipts and real exit codes are task evidence outside
versioned source; no mutated production implementation is installed.
