# Qualified time for consumers

This is the normative integration contract for time-dependent consumer decisions.
The durable store and bounded consumption API below are **not implemented**.
Today's `Sample` and `StartSample` alone do not satisfy this contract. The
[shared policy](time-policy.md) still bounds all confidence; qualification cannot
relax its limits or establish correctness of an incorrect authenticated server.

## Facts and binding

The receipt has exactly the eleven fields of the executor contract's §6.1
`TimeFacts`, below. All are required, including nested members; unknown versions,
missing/null values, duplicate members, invalid encodings and arithmetic overflow
refuse. UTC instants use signed 64-bit Unix nanoseconds; durations use nonnegative
signed 64-bit nanoseconds. If serialized as JSON, these integers are decimal
strings, without fractions or exponents. Digests are `sha256:` followed by 64
lowercase hex digits. IDs are enrolled opaque strings, compared exactly.

| `TimeFacts` field | Representation and meaning |
| --- | --- |
| `authority` | `{id, qualification_digest}`: enrolled time authority and protected qualification record. The consumer authenticates the provider/channel against that enrollment; caller-supplied hashes or confidence flags confer no authority. |
| `evidence` | `{qualified, source, nts_config, nts_association, reference, digest}`: qualified is boolean true; source is `chrony-nts-config` or `chrony-nts-authdata`; `nts_config` must be true; `nts_association` is `verified` or `unproven`; reference is a UTC instant; digest binds the collected evidence. Configuration-only evidence does not prove negotiated association authentication; a policy requiring authdata refuses `unproven`. |
| `adapter` | `{revision, collector_entry, image_digest, chronyc_digest, closure_digest}`: full pinned `timeconf` Git commit, exact entry `timeconf.CollectorEntry`, embedding executable, actual descriptor-pinned collector executable, and transitive provider/executable qualification manifest. They must match the deployed qualified closure. |
| `policy` | `{shared_digest, service_digest, effective_digest}`: hashes of protected shared bytes, protected override bytes (literal `none` if absent), and the versioned canonical effective-policy manifest. The manifest binds all applied inputs and stricter bounds. |
| `scope` | `{machine, consumer, purpose, continuity_scope}`: exact protected enrollment for this operation. A caller cannot choose a new scope to escape prior time or a hold. |
| `sample` | `{id, challenge, generation, fresh}`: new random 128-bit lowercase hex observation ID, current operation's 128-bit lowercase hex challenge, unsigned 64-bit store generation, and boolean true. One consumption only; retries require new collection and a new challenge. A recent earlier pass is not fresh. |
| `clock` | `{boot, wall, monotonic, before_ns, observed_ns}`: current kernel boot UUID, literal `CLOCK_REALTIME/UTC`, literal `CLOCK_BOOTTIME`, and within-boot elapsed observations bracketing collection. Elapsed values are nonnegative nanoseconds; they cannot be compared across boots. |
| `observed` | UTC instant `O`, the post-collection observed time (`Sample.Now`). |
| `uncertainty` | Duration `δ`, conservative and within the effective policy; preserve upward rounding, including skew in ppm. The observation interval is `[L,U] = [O−δ,O+δ]`. |
| `authority_until` | UTC instant `A` (`Sample.AuthorityUntil`), exclusive, no later than `min(O + policy authority window, reference + policy max sync age)`. The shared ceilings remain 300 and 2048 seconds. |
| `continuity` | `{store, generation, record_digest, witness_digest, prior_high_water, high_water, journal_floor, prior_boot, transition, held}`: matching durable checkpoint receipt; high-waters/floor are UTC upper bounds, transition is `same-boot` or `qualified-reboot`, and held is boolean false for a successful receipt. Generation must equal `sample.generation`. |

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

## Durable continuity

There is one enrolled continuity history per authority/clock scope, shared by its
permitted consumers. Its record contains a monotonically increasing generation,
the maximum **upper bound of every consumed effective time** `W`, the sticky
backward-step hold and its incident/reference bounds, the last wall/monotonic
pair and boot, provider/policy identities, an in-flight observation marker, and
its previous record digest.
Consumers durably bind their own decision journal to the receipt's `W`, boot,
generation, sample ID and identities. A decision journal is not a substitute for
this history: it can omit an attempt that failed after consuming time.

Consumption has this order:

1. Verify the checkpoint/witness and identities, then durably mark the new
   observation in flight before starting collection. An unfinished marker blocks
   competing calls; after a crash it is held, never silently discarded. Obtain
   new qualified evidence and verify current boot, non-held state and authority.
   Import executor journal floor `J` (its §3.3 maximum of retained prior time
   facts), or
   the consumer's stricter previous decision upper bound. Require
   **`L > max(W,J)`**; equality refuses. Compare against the checkpoint preceding
   this consumption, not the receipt's newly raised high-water.
2. Atomically advance the checkpoint generation and `W` to `U`, persisting the
   clock baseline and settling the in-flight marker. A detected step instead
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
   still burns its upper bound. Never retry it as a cached pass.

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
before implementation/activation. If both history and its witness can be rolled
back together, this contract cannot be met and qualification must refuse.

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
runs while the executor retains its package/journal/state exclusions, immediately
before the pin. It performs a **new local chronyd query** through the protected
collector child and bracketing clock reads, then the durable consumption above.
The source has already been enrolled and qualified; its previous sample is not
reused. This specifies fresh collection, replacing the earlier proposal to read
an already-qualified cached sample under the lock.

General synchronization, network source acquisition, enrollment, binary
qualification, policy preparation and service startup occur outside consumer
locks. Under locks, the fixed collector commands contact only the already-running
local daemon: no remote acquisition, DNS, service restart or attempt to obtain
fresh synchronization. The protected configuration inventory is bounded and
rechecked; changed/unqualified inputs refuse. The effective operation deadline
is at most the policy timeout (currently capped at ten seconds), or the stricter
caller deadline, including contention, collection, child teardown and durable
acknowledgment. Timeout, missing daemon, blocked storage or busy provider refuses;
the caller returns refusal by its deadline even if cleanup remains unresolved.
No pass is possible without completed cleanup and durable acknowledgment. No
sleeping for a better sample, unbounded mutex wait, background success reply or
restart is allowed. No implementation may claim this path until the deadline and child
cleanup properties are qualified on its target platform.

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
