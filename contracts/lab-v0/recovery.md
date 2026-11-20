# Private B1 recovery addendum, revision 1

Authority: the broker owner delegate selected OPTION 2 on 2026-11-20.
This refines lab profile sections 3.3 and 5.2; it changes neither the 24
external C0 formats nor the production service dialect. DN-09 C remains closed.
The module design is `docs/lab-profile-v0.md`, the reused engine is
`internal/service`, and the reused atomic/CAS store is `internal/store`.

## Inventory and encoding

`recovery-surfaces.json` is an additive, closed inventory with exactly one
surface, `swarma-broker-lab-service-recovery/1`. Its only writer and reader are
**B1**. It is private protected broker state, never an API result, evidence
export, release asset, gateway input, or B2/B3/B4/G1 input. The public projection
is still exactly `swarma-broker-lab-service-journal/1`. No external consumer
should learn or parse this addendum to use that projection.

The existing CCJ-1 encoding and C0 operator catalogue apply without exception.
Every object is closed; every field is required; null, duplicates, aliases,
noncanonical integer/time/string encodings, unknown fields and trailing bytes
refuse. Existing C0 scalar and array limits apply (arrays at most 256 elements).
The complete recovery envelope is at most 524288 bytes. The embedded external
snapshot independently satisfies its unchanged 65536-byte limit and grammar.
No raw JSON, opaque payload, base64 blob, material, key hash, or free-form event
is admitted. The published fixture uses only synthetic metadata.

Top-level fields are `format`, `installation_id`, `revision`,
`previous_revision`, `external`, `external_sha256`, `state`, and `observation`.
`revision` is a positive safe integer, at most 9007199254740990;
`previous_revision + 1 == revision`. Both installation IDs equal the external
Context installation. `external_sha256` is `sha256:` plus the lowercase SHA-256
of the exact CCJ-1 encoding of `external`. The external journal head uses the
unchanged C0 head domain and preimage. The state discriminator is private
`swarma-broker-lab-service-state/1`, not a production journal discriminator.
Its revision is positive and no greater than the envelope revision. Engine mutations advance it exactly once; observation-only commits leave it unchanged. The envelope revision advances on EVERY protected CAS, including periodic seen-counter updates. Watermark is canonical UTC time.

`RecoveryState` retains existing-engine bindings, leases, holds, operations and
watermark losslessly. Field names correspond to `wire.ServiceState` and its
record types. Nullable existing-engine fields are encoded as arrays containing
zero or one value, never null. Active bindings have no removal metadata;
removed bindings have exactly one removal operation/time. Active holds have
no lift metadata; lifted holds have exactly one lift principal/operation/time.
Lease renewal correlation similarly contains zero or one operation ID.
Binding/lease/hold arrays are sorted by their stable ID and have no duplicates.

Each operation retains `principal`, `operation_id`, `at`, and eight closed
variant arrays: `bind`, `unbind`, `request`, `renew`, `release`, `hold`, `lift`,
`event`. Exactly one variant has one element; all others are empty. Each variant
has its exact singleton `method`, closed typed `arguments`, and closed typed
metadata `result` as listed in the inventory. No result contains material.
The canonical argument/result bytes reconstructed from those objects equal
the original engine bytes. The ordered operations array is append-only; keys
`(principal, method, operation_id)` are unique. Bind/request/renew/hold/lift
argument IDs equal the outer operation ID. Release/event IDs are the existing
engine internal identities, not a new caller replay API. A retry must match
the original method, principal and complete canonical arguments, not merely
its request digest. Issue/renew replay returns the **original operation**
deadline, never the latest lease deadline. Release `at` is the durable inclusive
hold-boundary endpoint; it must never be inferred from lease expiry.

## Atomic join, recovery and cross-read

One existing protected store record, `owner-lab-service.json`, contains the
entire envelope, including the exact external object. There is no independently
authoritative external sidecar. `store.Account.Put` with expected old revision
is the sole CAS/commit operation; its existing staging, fsync, rename and
directory-fsync path is reused, not replaced with another journal engine.
Only after that operation acknowledges durability may B1 publish an external
snapshot, acknowledge a mutation, or publish material authorized by it.
External readers receive only a copy of the committed `external` member through
the broker projection boundary. This is one atomic join, not two file writes.

A missing record after committed enrollment, orphan staging record, unreadable
record, foreign format, mismatched installation/revision/head/digest/context,
partial write, contradictory retry, rollback or CAS conflict is **UNKNOWN**.
UNKNOWN closes widening, projection and material; it is never an empty initial
state or a fresh operation. Initialization is permitted exactly once after
durable enrollment and explicit fresh-account checks, before constructing the
nonempty controller. No production record is adopted. Production readers must
continue to reject this private discriminator and lab readers production state.

After an uncertain write, the same operation may be reconciled by a protected
read of the complete envelope and another CAS durability confirmation before
acknowledgment. A new ID cannot substitute for a pending hold. A recovered
in-memory state is installed only after that confirmation. A read racing a
commit observes one whole old or new envelope, never a mixed pair. Readback
validates both independent encodings and their complete semantic join before
using either member. A bare exported snapshot is not recovery authority.

The external entries are in the same order as private operations, with identical
IDs and SHA-256 of canonical arguments; all persisted engine operations project
as `committed`. Each previous head is the preceding committed external head.
The last head seals the current external object, with its unchanged C0 domain.
Committed operations are never deleted to fit capacity. Bindings join by stable
ID, exact gateway UID/generation, caller tuple and account; leases join by stable
ID/binding, latest exact bound, issue/renew identities and terminal state.
The external held bit equals presence of an active private account hold.
Removed bindings and released/expired/revoked leases remain tombstones. A lift
does not resurrect a removed binding or an ended/revoked lease. Restoring older
envelopes requires the independent B2 floor/fence refusal, not a fabricated U05
receipt or a second local mutex presented as production rollback protection.

## Capacity and narrowing

External `operation_limit` is an immutable finite-plan ceiling in 1..256;
`narrowing_reserve` is an immutable positive reserved count below that ceiling.
Both are fixed at explicit fresh bootstrap. Every widening candidate must first
fit the operation count and both encoded byte limits **with its complete
remaining finite narrowing plan reserved**: account hold, every remaining
binding unbind, every remaining lease end, and pending reconciliation. Each
reserved operation includes its typed replay outcome and all resulting
tombstone/lift metadata. Reserve at least one reconciliation revision as well;
revision overflow closes admission. Check and commit are under the same engine
serialization/CAS boundary; concurrent widening cannot consume the same reserve.
If count, bytes or a conservative complete upper bound cannot be established,
refuse before widening. Hold/unbind/reconciliation may consume only their
reserved capacity. Lifts are widening. Recovery confirmation alone appends no
operation and cannot replenish capacity. Exhaustion closes new widening, never
prunes replay, holds, IDs, timestamps, or tombstones. No presumed compression or
future garbage collection counts as reserve.

## Controls and limits of evidence

`recovery-fixtures.json` supplies a valid joined empty committed snapshot and
adjacent material/unknown-field negative. Reference tests apply the existing C0
literal, separator, type, numeric, time, closure and raw-object operators to all
new structures, plus semantic joined-pair controls. Runtime B1 must additionally
exercise actual store faults, CAS, replay and reserve effects. Reference shape
tests are not native custody, current-manager evidence, protection or time
qualification. No live activation, key handling or vendor call is authorized.

## C0d private observation recovery

The closed envelope additionally requires `observation`, an array of zero or one
`RecoveryObservation` object. Empty is permitted only before initial admission;
it grants no use. This field is PRIVATE B1 recovery, never exported or consumed
by another component. `RecoveryObservationResponse` has exactly the frozen C0c
response fields. No external C0/C0b/C0c/C0d/C0e field changes.

The object binds installed `store_generation`, positive publication `floor` F,
replay `seen` S, the complete last published native `baseline`, last validated
`observed_monotonic_ms` and local `receipt_monotonic_ms`, `publication` kind
(start/commit/debit/stop/invalidation), and `result_sha256` of the exact material-free
publication result. S >= F, baseline.sequence = F, both generation fields match
the installed generation, and last observed <= receipt. Baseline is derived
comparison data, NEVER native authority. No material or credential result bytes
are retained. All existing array/CCJ/safe-integer/524288-byte limits apply.

A pair first fences use and commits its final S=F together with the current
external snapshot, engine recovery, result digest and baseline by ONE envelope
CAS. Periodic singles require the identical native proof, advance only S and
last observed/receipt, and preserve F/baseline/publication/result exactly. No
other result may be published by that commit. Tentative/failed pair reads never
advance either counter. Generation changes, malformed/missing state, partial
writes or CAS uncertainty are UNKNOWN. After restart every in-memory use is
fenced regardless of recovered counters; a new non-reused admitted pair must
reconcile them. Neither a single nor counter reset opens use. Final pair
publication stays inside its original final 250-ms deadline and 1250-ms pair
budget; uncertain or late persistence fences and publishes nothing, even if the
CAS may have reached disk. No shared ledger copy is authoritative.

The canonical `recovery-observation-fixtures.json` supplies a material-free
nonempty observation join beside the original empty/bootstrap control. The
in-process recovery join tests mutate each counter/generation/time boundary.
The adapter reserves 67584 bytes (the maximum 65536-byte C0c response plus
2048 bytes for the fixed observation wrapper) in addition to the existing
8192 bytes per remaining private narrowing operation. This is conservative
headroom, not permission to enlarge either frozen external limit.
