# Qualified time for consumers

This is the normative integration contract for time-dependent consumer decisions.
The durable store and bounded consumption API below are **not implemented**.
Today's `Sample` and `StartSample` alone do not satisfy this contract. The
[shared policy](time-policy.md) still bounds all confidence; qualification cannot
relax its limits or establish correctness of an incorrect authenticated server.

## Facts and binding

The **provider receipt** below is distinct from the executor's closed logical
`TimeFacts` (§6.1). Its eleven facts supply that record through the validated
adapter below; it is not an executor wire codec or journal extension.
The provider wire envelope is exactly `{version,facts}`: `version` is the
16-byte ASCII literal `qualified-time/1`; `facts` has the eleven members below.
All are required, including nested members; unknown versions,
missing/null values, duplicate members, invalid encodings and arithmetic overflow
refuse. UTC instants use signed 64-bit Unix nanoseconds; durations use nonnegative
signed 64-bit nanoseconds. If serialized as JSON, these integers are decimal
strings matching `0|-?[1-9][0-9]*`, without plus signs, leading zeroes,
negative zero, fractions or exponents. Generations use unsigned 64-bit decimal
strings matching `0|[1-9][0-9]*`; no wrap is permitted. Digests are
`sha256:` followed by 64 lowercase hex digits. Unless a narrower type is listed, enrolled IDs are
1–128 ASCII bytes matching `[A-Za-z0-9._:-]+`, compared exactly; owner versions
are 1–32 bytes in that alphabet. Git revisions are full lowercase hex object
IDs of the pinned repository's object format; boot UUIDs are canonical nonzero
lowercase UUIDs. No truncation, coercion or Unicode normalization is allowed.
The envelope is at most 65536 bytes, nesting at most 16; reject before allocation
on excess. Encode it as UTF-8 JSON with ASCII lexicographic member order, no
whitespace or final LF, and no escapes for the admitted ASCII string values;
booleans are `true`/`false`. Decode strictly and require byte-identical re-encoding.
These provider wire rules do not change consumer Scope's integer/ref codecs.

| Provider receipt fact | Representation and meaning |
| --- | --- |
| `authority` | `{id, version, trust_root_digest, qualification_digest}`: enrolled time authority, exact owner contract/validator version, enrolled trust-root digest, and protected qualification record. The consumer authenticates the provider/channel against that enrollment; caller-supplied hashes or confidence flags confer no authority. |
| `evidence` | `{qualified, source, nts_config, nts_association, reference, digest}`: qualified is boolean true; source is `chrony-nts-config` or `chrony-nts-authdata`; `nts_config` must be true; `nts_association` is `verified` or `unproven`; reference is a UTC instant; digest binds the collected evidence. Configuration-only evidence does not prove negotiated association authentication; a policy requiring authdata refuses `unproven`. |
| `adapter` | `{revision, collector_entry, image_digest, chronyc_digest, closure_digest}`: full pinned `timeconf` Git commit, exact entry `timeconf.CollectorEntry`, embedding executable, actual descriptor-pinned collector executable, and transitive provider/executable qualification manifest. They must match the deployed qualified closure. |
| `policy` | `{shared_digest, service_digest, effective_digest}`: hashes of protected shared bytes, protected override bytes (literal `none` if absent), and the versioned canonical effective-policy manifest. The manifest binds all applied inputs and stricter bounds. |
| `scope` | `{machine, consumer, purpose, continuity_scope, operation_digest}`: protected provider enrollment plus the exact consumer operation binding defined below. A caller cannot choose a new enrollment or operation to escape prior time or a hold. |
| `sample` | `{id, challenge, generation, fresh}`: new random 128-bit lowercase hex observation ID, current operation's 128-bit lowercase hex challenge, unsigned 64-bit store generation, and boolean true. One consumption only; retries require new collection and a new challenge. A recent earlier pass is not fresh. |
| `clock` | `{boot, wall, monotonic, before_ns, observed_ns}`: current kernel boot UUID, literal `CLOCK_REALTIME/UTC`, literal `CLOCK_BOOTTIME`, and within-boot elapsed observations bracketing collection. Elapsed values are nonnegative nanoseconds; they cannot be compared across boots. |
| `observed` | UTC instant `O`, the post-collection observed time (`Sample.Now`). |
| `uncertainty` | Duration `δ`, conservative and within the effective policy; preserve upward rounding, including skew in ppm. The observation interval is `[L,U] = [O−δ,O+δ]`. |
| `authority_until` | UTC instant `A` (`Sample.AuthorityUntil`), exclusive, no later than `min(O + policy authority window, reference + policy max sync age)`. The shared ceilings remain 300 and 2048 seconds. |
| `continuity` | `{store, generation, record_digest, witness_digest, prior_high_water, high_water, journal_floor, prior_boot, transition, held}`: matching durable checkpoint receipt; high-waters/floor are UTC upper bounds, transition is `same-boot` or `qualified-reboot`, and held is boolean false for a successful receipt. Generation must equal `sample.generation`. |

### Executor adapter and operation binding

The executor fills its own closed `Scope` exactly as defined in its §2:
`{deployment,boot,attempt,old_state,candidate_state,transactions,plan}`.
Deployment is its protected deployment identity, boot is the intended current
kernel UUID, attempt is the reserved intent sequence, and the remaining members
are the complete frozen-object references, including both SHA-256 and size.
Derive these values independently from the retained intent and protected inputs;
validate the referenced original objects in their owning codecs. Preserve
historical recorder boot tokens inside those objects; never replace them with
the sampling boot.

For this adapter, the provider receipt's `scope.operation_digest` is exactly
`sha256:` plus the lowercase hex SHA-256 of the ASCII bytes
`qualified-time/executor-scope/1`, one zero byte, then `CCJ-1(Scope)` without LF.
Use the executor journal §2.1 pinned canonicalizer and its closed types/bounds;
include all seven members and complete references, with no normalization or
omission. Missing published bounds, unknown fields or invalid references refuse.
This digest is a provider binding, **not a new field in executor Scope**. The
consumer independently recomputes it; the authenticated receipt must match it,
the enrolled provider scope and the current one-use challenge. Changing even a
reference size, an attempt or current boot requires a new bound observation.
The provider authenticates its enrolled consumer; a supplied digest alone gives
no authority. A new operation digest never selects a new continuity history.

The adapter constructs exactly the existing eleven-field logical `TimeFacts`:
`scope` is the consumer-derived Scope above; `authority` and `evidence` are
produced by the enrolled owner's identity/authenticity and retained-evidence
validators, not by copying an unverified hash into those logical types. The
other eight fields (`adapter`, `policy`, `sample`, `clock`, `observed`,
`uncertainty`, `authority_until`, `continuity`) preserve the corresponding
validated provider facts and their exact source representations. All fields
refer to this same authenticated receipt. This adds no fields to the executor's
closed records, reports, journal entries or frozen intent links. Provider wire
codec/validator publication and consumer review remain prerequisites to code.

The protected enrollment pins `authority.id`, owner `version`,
`trust_root_digest`, qualification, receipt version and exact validator/codec.
Authenticate them against the independently installed trust root; receipt
values cannot select their own root or validator. For logical `Evidence`, the
provider durably retains the exact canonical receipt bytes before reply; the
executor retains a checked protected descriptor and constructs its existing
`Ref={sha256,size}` over those exact bytes (bare lowercase SHA-256 and byte
count, without adding LF). The inline `evidence` is validated inside this owner
object, not substituted for `Ref`. Its `digest` binds retained original source
evidence; `continuity.record_digest` and `continuity.witness_digest` bind the
checkpoint and witness proofs. The owner's published closed codec validates
those original records together, without a record hashing its own receipt. Bound that retained closure to 64 objects and 8 MiB total, each
object at most 8 MiB, with no cycles and depth at most 16. All original bytes,
authenticity and semantic bindings must be independently validated through
retained descriptors; a receipt hash alone is insufficient. Missing bytes,
unknown codec or unqualified validator refuses. This retention adds no journal
field or replacement frozen report; later pre-pin evidence remains provider-owned.
Receipt retention and validation share the single operation deadline below.

Paired binding example: let `S` contain deployment `d`, current boot `b`,
attempt 7 and the four validated frozen references `r_old`, `r_candidate`,
`r_transactions`, `r_plan`. A fresh receipt for the enrolled consumer, challenge
and digest of exactly `S` maps to `TimeFacts.scope=S`. With the same receipt,
attempt 8, a changed plan reference or a changed reference size refuses; it
cannot be made valid by copying the receipt's digest into expected Scope.

These facts are bound together by the protected receipt, not recombined from
separate samples. The consumer checks its expected authority, adapter, policy,
scope, challenge and **current** kernel boot. Missing or unknown confidence,
negative/unbounded uncertainty or any mismatch refuses, without falling back to
wall time. `CollectorEntry()` must run first in the embedding `main`; a matching
revision string alone does not prove this execution path or its provenance.

A successful receipt is usable only immediately before its bound operation and
while the consumer retains its exclusions and same-boot monotonic deadline.
The qualified δ must cover source error, rate growth and the bounded remaining
storage/return/pin delay; reserve that entire interval before persisting `U`.
If it cannot fit within the effective uncertainty cap or the operation exceeds
that bound, refuse. Never advance an old interval using an unqualified clock-rate
assumption. Require `U < A`; equality or a decision at/past `A` refuses. Reuse,
intervening work, another attempt, negative elapsed time, boot transition, known
step or hold requires refusal and new qualification. `AuthorityUntil` is not
permission to cache a passing decision.

Uncertainty only narrows a consumer's permitted interval. For an exclusive
release expiry `R` and nonnegative `FreshnessMarginSeconds` converted exactly to
nanoseconds `M`, require `U+M < R`. Never extend `R`, reduce `M`, or subtract δ
from the upper bound. For certification/registry issue window `[B,E)`, require
`L ≥ B` and `U < E`; registry intake and final publication each consume new
evidence. An act valid for at most 60 seconds uses an exclusive deadline
`D ≤ L_issue + 60 seconds`, plus `U_current < D` and a same-boot monotonic cap
of at most 60 seconds. Other consumer checks, including its durable watermark
and release validity, still apply. A consumer may narrow these rules, never
widen them; a time-control pass is not acceptance of the enclosing operation.

### Interval-preserving consumer projections

A smaller consumer time view requires an adapter over the complete validated
`TimeFacts`; it cannot replace that record. First bind the full receipt, current
boot, one-use challenge and confirmed durable acknowledgment. In continuity,
`prior_high_water` is the provider's previous consumed bound, `high_water` is
its newly consumed upper bound, and `journal_floor` is the imported consumer
floor. They are distinct quantities. Refusing the later consumer operation
leaves the provider's consumed bound intact. Derive availability flags from
confirmed protected continuity, never from a request's claimed availability.

Keep the original nanosecond facts and check their predicates. When projecting
to coarser units, round interval lower bounds down, interval upper bounds and
retained upper-bound floors up, and exclusive endpoints down. The converted
predicates must pass too: conversion can cause extra refusals, never convert an
original refusal into acceptance. Reject overflow, values the target cannot
represent and unusable converted intervals. A lone `observed` value cannot
stand in for `[observed−δ,observed+δ]`. Each consumer must publish its complete
interval-aware adapter mapping before activation.

## Durable continuity

There is one enrolled continuity history per authority/clock scope, shared by its
permitted consumers. Its record contains a monotonically increasing generation,
the maximum **upper bound of every consumed effective time** `W`, the sticky
backward-step hold and its incident/reference bounds, the last wall/monotonic
pair and boot, provider/policy identities, an in-flight observation marker, and
its previous record digest.

**The provider owns durable retention of later consumed continuity for each
consumer and operation scope.** In the same final settlement that advances `W`,
its protected history retains the consumer enrollment, continuity scope,
operation digest, sample ID/challenge, current boot, provider/policy identities,
generation, imported floor `J`, observation/uncertainty/authority and consumed
upper bound. The authenticated receipt identifies that committed record; there
is no separate consumer write needed to make its association durable. Retain
these associations under the same witness/restore protections as `W`; replacing
an operation or retrying cannot discard them or partition the shared high-water.

Executor-style consumers keep their **closed journal unchanged**, including
frozen intent links and earlier reports. They import its §3.3 floor, but the
later pre-pin receipt is not inserted into that journal and is not claimed to
be encoded in an older report. The provider history supplies that later bound
across failure/reboot. A journal is not a substitute for this history: it can
omit an attempt that failed after consuming time. Consumers that own a durable
watermark retain their required `W` (at least the previous decision's effective
upper bound) and boot identity in their own published format, outside rollback,
before acknowledging their decision. No blanket requirement adds receipt
fields to any consumer's journal. Both consumer-owned floors and provider `W`
apply; neither can reset or replace the other.

For example, leave the frozen executor floor at 140. Immediately before pin,
consume observed 200 with δ=1: the provider durably retains `W=201` and its
consumer/operation association before replying, while the journal remains at
140. After a crash or reboot, new `[170,172]` refuses against 201;
`[210,212]` may pass only with confirmed provider continuity, fresh current-boot
evidence, sufficient authority and valid releases. An intact journal at 140
cannot authorize either interval if provider history is missing or rolled back.

Consumption has this order:

1. Verify the checkpoint/witness and identities, then durably mark the new
   observation in flight before starting collection. An unfinished marker blocks
   competing calls; after a crash it is held, never silently discarded. Obtain
   new qualified evidence and verify current boot, non-held state and authority.
   Import executor journal floor
   `J = max(imported A3b LastTime, ObservedTime of every authenticated retained report through the accepted checkpoint)`
   (§3.3), derived from original source evidence, not Q's audit timestamp; or
   import a watermark-owning consumer's stricter previous decision upper bound.
   Require
   **`L > max(W,J)`**; equality refuses. Compare against the checkpoint preceding
   this consumption, not the receipt's newly raised high-water.
2. Atomically advance the checkpoint generation and `W` to `U`, persisting the
   clock baseline and the consumer/operation association, and settling the
   in-flight marker. A detected step instead
   latches the hold with no time receipt; qualification failure cannot erase it.
   Uncertain writes or incomplete incident bounds remain held and cannot use
   automatic resynchronization. A failed collection may settle as refused with
   unchanged `W` only when its clock baseline is complete and consistent.
   Serialize competing consumers with compare-and-swap; contention refuses
   within the deadline rather than waiting or losing an update.
3. Only after durable acknowledgment return the bound receipt. Then the consumer
   evaluates its release/window predicates and performs its operation. An
   expired release, later refusal, crash, cancellation or lost reply **never
   undoes** the consumed upper bound. A candidate that never passes qualification
   is not a consumed sample; a committed reservation with no delivered reply
   still burns its upper bound. No executor journal write is required by this
   step. Never retry it as a cached pass.

### Storage and crash ordering plan

Place records in a service-owned mode-0700 directory, using mode-0600 regular
single-link files and protected ancestors on persistent storage excluded from
**all** consumer and provider rollback/restore domains. The rollback witness is
a separate protected local authority retaining a monotonically increasing
`(generation, record_digest)` outside that storage's restore domain. It needs a
bounded local compare-and-swap interface; no network acquisition under consumer
locks. A hash chain, file permissions or fsync on the checkpoint alone cannot
detect restoration of an older, internally consistent copy.

Both the in-flight begin and final settlement use this transaction: write a
complete new immutable record, fsync its file and containing directory,
then durably compare-and-swap the independent witness to its generation/digest.
Atomically replace the local current-record pointer and fsync its directory
before acknowledging consumption. Startup requires an exact match with the
witness; it may finish publishing an already fsynced matching record after a
crash, but cannot roll the witness back. A crash before witness advancement can
leave an unused prepared record; the previously committed in-flight marker
still closes admission if collection had begun. A committed final record burns
its upper bound even if no reply or consumer journal update exists. Missing,
unreadable, corrupt, stale or conflicting records/witnesses refuse and are never
reset to a journal floor or zero. A deadline expiring during a write returns refusal;
any subsequently committed reservation remains consumed, and indeterminate
storage state stays closed until reconciled against the witness.

Initial enrollment must establish the authoritative checkpoint before enabling
consumption; error recovery cannot create a replacement history. Changing a
provider, policy or scope requires an authorized migration that retains the
maximum high-water and all holds, never a new empty store. The concrete witness
backend and enforceable restore exclusions are deployment decisions required
before implementation/activation. Shared snapshots are rollback domains too:
a file, directory or daemon restored with the checkpoint cannot be this witness.
Until the independent monotonic CAS authority and its restore boundary are
selected and qualified, consumption **refuses**. If both history and its witness
can be rolled back together, this contract cannot be met and qualification
must refuse. A proposed off-node witness remains a conditional alternative,
not a selected backend; its acknowledgments do not satisfy the local-CAS plan
without separate lock/deadline qualification. The latency decision is recorded
in [unresolved questions](../UNRESOLVED_QUESTIONS.md).

### Restart and reboot guarantees

Within one boot, a replacement process recovers `W`, the hold, any unfinished
observation and the last clock pair before sampling; it cannot clear them through replacement or a failed
attempt. Comparisons include elapsed time across the gap between processes.
Across reboot, retain `W` and holds, discard cross-boot elapsed comparisons, and
record a verified transition to the **current** boot with new qualified evidence.
An old-boot sample never gains credit; a later current-boot interval must still
have `L > max(W,J)`. Reboot alone neither clears a hold nor supplies fresh time.
Hold release requires the protected recovery policy and a durably recorded
qualification beyond the saved incident/reference bounds; operator-only policy
stays closed until its authorized recovery path exists.

With a non-rollbackable witness, these rules prevent a consumed effective-time
upper bound or observed hold from disappearing across process failure or reboot.
They do not promise availability, measure elapsed time across power loss, detect
a transient clock excursion wholly between observations, or prove uninterrupted
UTC correctness. They do not protect against rollback of the trusted witness
itself or make a later clock change impossible. Such lost trust cannot be
repaired by sleeping, an ordinary good report or the journal's older floor.

## Bounded sample immediately before the pin

The planned `ConsumeBeforePin(deadline, expected identities, challenge, J)` API
includes the enrolled scope and independently derived operation digest in
`expected identities`. It runs while the executor retains its
external exclusions F, B, W, root-writer exclusion and exclusive D, immediately
before the pin. Here W names the worker exclusion, not the time high-water.
Release effects/core, gate, data, recorder R and journal append before this call;
none may overlap it. The entire provider graph must have no acquisition or wait
back to F, B, W, root-writer exclusions, D or R, directly or indirectly.
It performs a **new local chronyd query** through the protected collector child and bracketing clock reads, then the durable consumption above.
The source has already been enrolled and qualified; its previous sample is not
reused. This specifies fresh collection, replacing the earlier proposal to read
an already-qualified cached sample under the lock.

General synchronization, network source acquisition, enrollment, binary
qualification, policy preparation and service startup occur outside consumer
locks. Under locks, the fixed collector commands contact only the already-running
local daemon: no remote acquisition, DNS, service restart or attempt to obtain
fresh synchronization. The protected configuration inventory is bounded and
rechecked; changed/unqualified inputs refuse. The proposed API uses
**one absolute operation deadline**, at most ten seconds and no later than the
stricter caller deadline. It budgets all commands together,
connect/queue waits, contention, collection, store/witness/receipt writes, output
drain, teardown and fence verification. The existing per-command policy timeout
(currently at most ten seconds) does not establish this aggregate bound.
Timeout, missing daemon, blocked storage or busy provider refuses;
the caller returns refusal by its deadline even if cleanup remains unresolved.
No pass is possible without completed cleanup and durable acknowledgment. No
sleeping for a better sample, unbounded mutex wait, background success reply or
restart is allowed. No implementation may claim this path until the deadline and child
cleanup properties are qualified on its target platform.

Consumption remains a refusal until the installed path has a reviewed full
executor §7 `CallContract`, exactly
`{id,target,entry,argv,environment,cwd,identity,inputs,outputs,leases,deadline,graph,completion,failure,fence}`,
including §5.1 and §7.4 completion/fencing. Pin the embedding initialization,
collector, loader/libraries/configuration, cwd `/`, local daemon endpoint,
chronyd and all store/witness dependencies, IPC, helper and failure paths.
Chronyd is a separately qualified long-lived dependency, not a child the caller
can kill. An unknown daemon/store/witness graph or back edge refuses.
Reuse the [collector execution contract](time-confidence.md#source-selection-and-policy):
`CollectorEntry()` first, descriptor-pinned native execution, only
`chronyc -c tracking`, `chronyc -c -N tracking`, `chronyc -c authdata -a`,
only `LC_ALL=C`, `LANG=C`, `TZ=UTC`, no stdin, and the policy's shared
stdout/stderr per-command limit (256–65536 bytes); overflow refuses.

Success needs authenticated terminal evidence for the **whole subtree** and a
bounded output drain. Direct-child exit, `CommandContext`, `WaitDelay`, byte
caps or a successful unit result do not prove that completion. Qualify retained
subtree identity from launch, no escape/reactivation, post-cancellation fence
and resolution or owner-fencing of every delegated effect, including lost
acknowledgments and delayed work, as required by executor §5.1. A subtree fence
must preserve that identity and prevent repopulation through recovery; process
absence or one empty observation cannot authorize replacement. If completion,
drain, cleanup or fencing is unresolved at the absolute deadline, refuse and
keep the path fenced with no overlapping retry. No activation or accepting
fixture may substitute for these unpublished native qualification results.

The provider takes no lock shared with a consumer. Its private state/storage
locks are leaves: no consumer callback, incident handler, consumer lock or
consumer RPC may be reached while held. Use bounded child/local-storage requests;
never invoke application code inside the leaf. Deliver fixed-code incidents only
after releasing it. A stalled storage operation may burn time but cannot deliver
a later pass or reopen admission; unresolved teardown keeps the path closed.

**A time failure never blocks emergency stop.** Stop dispatch does not acquire
the time-provider leaf, collect evidence, await continuity storage or validate an
expiry. Consumer integration must also keep stop runnable while a pre-pin call
retains its exclusions; no lock holder waiting on time may indirectly gate stop.
Existing stop authority still applies; time failure grants no new powers.

## Consumer vectors

All intervals below use arbitrary UTC seconds, with exact nanosecond arithmetic
at boundaries. Unless varied, identities, challenge and current boot match,
qualification/continuity are confirmed, hold is clear, `W=200`, `J=140`,
`[L,U]=[210,212]`, `A=230`, and releases remain valid. The interval already
covers the qualified delivery/pin delay. A pass is a
**time control only**. Each row changes only the named condition.

| Rule | Refusal | Positive control |
| --- | --- | --- |
| Consumed sample, failed attempt and restart | Begin with `W=J=140`; consume observed time 200 with δ=1, then crash before pin or fail the attempt. Recovered `W=201`; `[170,172]` refuses despite exceeding 140. | Same durable `W=201`, new `[210,212]` passes. |
| Consumed sample and reboot | Same consumed time 200, δ=1 and journal 140; persisted `W=201` makes new current-boot `[170,172]` refuse after reboot. | Verified current-boot transition with the same `W=201`, fresh `[210,212]` and valid releases passes. |
| Strict floor | `L=200` equals `W`; or `L=210` equals a stricter `J=210`. | `L=max(W,J)+1 ns` with a valid upper bound/authority passes. |
| Exclusive authority | `A=212` equals `U`; observed time at or beyond `A` also refuses. | `A=U+1 ns` passes; `A=230` passes for the base case. |
| Bounded delivery | Unknown delay/rate allowance, exceeded monotonic deadline or negative elapsed time refuses; nominal `O < A` cannot save a reserved `U=A`. | The entire storage/return/pin delay fits in the reserved `[210,212]` interval and deadline; `U < A`. |
| Boot and domains | Receipt boot differs from current kernel boot, or monotonic domain is unknown. | Current boot and the enrolled wall/monotonic domains match, with a verified persisted boot transition when needed. |
| Known bounded time | Nil/unknown time, unknown version, duplicate/null member, invalid encoding, negative/over-policy δ or overflowing `O+δ` refuses. | Base interval, qualified evidence and finite nonnegative δ within policy pass. |
| Provenance and NTS | `qualified=false`, unauthenticated authority, changed executable closure, non-NTS configuration, or `unproven` authdata under an authdata-required policy refuses. | Enrolled closure and policy-approved configuration-only evidence pass; authdata-required policy passes only verified association evidence. |
| Identity and scope | Changed revision, entry, policy digest or consumer/purpose scope refuses; rebinding to an empty history also refuses. | Exact enrolled bindings pass; authorized migration preserves `W` and holds before use. |
| New observation | Old challenge, repeated sample ID, false fresh flag or cached pass refuses. | Newly collected evidence with the current one-use challenge and matching committed generation passes. |
| Continuity required | Absent/unconfirmed continuity or missing checkpoint/witness refuses; journal 140 cannot recreate consumed 200. | Both durable records match and recover `W=200`; base interval passes. |
| Unreadable store | Permission/read/fsync failure, corruption or ambiguous commit refuses. | Confirmed durable checkpoint and witness acknowledgment precede the returned receipt. |
| Rollback detection | Restored generation with `W=140` disagrees with witness committing `W=200`; refuse. A jointly restorable witness cannot qualify. | Matching independent witness/record retains 200 and permits `[210,212]`. |
| Sticky hold | Held record refuses after process restart and after reboot; an ordinary report or clock wait does not clear it. | Non-held record passes; policy-authorized, durably committed recovery with new evidence beyond saved bounds may release a hold. |
| In-flight crash | Crash after the durable begin but before a detected step's hold is saved: the unfinished marker recovers as held. Incomplete incident bounds cannot auto-clear it. | A new observation settles its marker durably with complete clock/hold state; no unfinished observation remains before the pass. |
| Write before reply | Crash before durable acknowledgment gives no usable receipt; lost reply after commit cannot undo `W`. | Persisted record, witness CAS and current-pointer fsync complete before receipt; failed later operation retains `U`. |
| Freshness margin | With `R=220`, `M=8`, `U+M=220` refuses; δ cannot be removed from this comparison. | Same interval and margin with `R=221` passes the expiry check. |
| Issue window | `[B,E)=[210,212)` excludes `U=212`; or `B=211` excludes `L=210`. | `[210,213)` contains the entire `[210,212]` interval. |
| Short act | `D=271` exceeds `L_issue+60=270`; a current upper bound equal to `D` also refuses. | `D=270`, current upper bound 212 and same-boot monotonic budget at most 60 seconds pass this deadline check. |
| Stricter consumer | A local policy cannot increase source-age/uncertainty ceilings, extend expiry or reduce a required margin. | An extra local restriction may refuse the base case; retaining the shared bounds may pass it. |
| Local bounded call | Busy leaf, deadline/teardown failure, attempted remote acquisition or service restart refuses without waiting under consumer locks. | New bounded local daemon query plus durable receipt and child cleanup completes before the caller deadline, with no consumer callback under the leaf. |
| Emergency stop | Unavailable time must refuse issuance/pin/publication. Requiring time or its leaf for stop is forbidden. | The same unavailable/held state, including a pending pre-pin call, still dispatches an otherwise authorized emergency stop without awaiting the provider, store or their indirect lock holders. |
| Executor operation binding | Receipt for `S` with attempt 7 is presented for attempt 8, another plan, or a changed frozen-reference size: the independently recomputed operation digest differs; refuse. | Same consumer-derived closed `S`, complete frozen references, current boot and challenge match the authenticated receipt's operation digest; map `TimeFacts.scope=S` without extra executor fields. |
| Intact frozen journal, lost provider history | Frozen executor journal and reports remain intact at floor 140; after consuming 200 with δ=1, provider history is missing or restored to 140 against the witness for 201. Refuse even for `[210,212]`; the journal cannot reconstruct continuity. | Journal remains unchanged at 140; confirmed provider history and consumer/operation association retain `W=201`. Fresh current-boot `[170,172]` refuses; `[210,212]` with sufficient authority and valid releases passes as a time control only. |
| Receipt codec and authority mapping | Request-asserted availability, unknown version/root/validator, overlong identifier, excess receipt/evidence bounds, noncanonical integer/generation, or unavailable original evidence refuses; an inline hash cannot stand in for retained `Ref`. | Confirmed protected continuity, enrolled version/root and canonical bounded owner receipt plus original evidence authenticate; its exact retained bytes map to the existing logical `Evidence` Ref without changing frozen journal objects. |
| Qualified full call and completion | Missing any CallContract field, unknown init/daemon/store/witness dependency, consumer-lock back edge, per-command-only deadline, or direct-child-only completion refuses. | Exact installed closure and all fifteen fields qualified, stated inner locks released, whole-subtree terminal evidence and bounded drain/fencing complete within one absolute deadline; independently reachable stop remains required. |
| Conservative coarse projection | With `W=200.2`, `[L,U]=[200.1,200.3]`, `A=230.9`, exact `L>W` fails. Ceil-L/floor-W would falsely give `201>200`; refuse. Required floor-L/ceil-W gives `200>201`, also refusing. | With the same `W`, fresh `[202.1,202.3]`, `A=230.9` and `J=140`, exact predicates pass; coarse lower 202, upper 203, floor 201 and exclusive authority 230 also pass. Retain and check both representations. |

## Existing code and implementation slice

Existing code supplies strict protected policy and executable checks, bounded
collector commands, selected-source confidence, `Now`, δ, `AuthorityUntil`, boot
identity, and a serialized in-instance step hold. `StartSample` collects anew.
Qualification must still bind actual deployed provenance; there is no complete
consumer receipt, durable high-water/hold store, rollback witness or end-to-end
bounded pre-pin consumption API. Existing serialization and incident callbacks
do not establish the new leaf/deadline guarantee.

Implement the versioned receipt and identity validation, checkpoint/witness
transaction with restart/boot recovery, and callback-free bounded consumption
path, then turn every paired vector into isolated tests. Add crash/fault controls
at every fsync/CAS boundary and a control that catches a consumer callback under
the leaf. Test that a previous pass never suppresses a collector call, while a
refusal cannot delay emergency stop. Qualify cleanup/deadline behavior against
blocked child and storage operations; no mocked success can qualify unavailable
platform guarantees. Estimate: 700–1100 Go lines plus 900–1400 test lines,
roughly four to six developer days after the storage authority is agreed;
backend provisioning and consumer integrations are separate. Consumer review
must accept this contract before that code slice begins.
