# Consumer window-profile schema and template

This is a **documentation schema**, not a JSON/YAML wire format, runtime API or
activation record. Each consumer publishes its own approved profiles in its own
repository. Its native codecs, lock names, refusal codes and versioned use-state
format remain authoritative. This shared template adds no consumer record field.
Read the [handoff contract](time-handoff.md) and [macOS binding](time-handoff-macos.md).

## Profile schema

One document may contain multiple windows and shared requirements. Every window
must resolve all seven groups below, directly or through exact versioned
references. Narrative/symbol tables and field-per-row tables are equally valid.
The published field labels below are documentation requirements, not a shared
wire record. Each consumer names **its own transition version**; byte formats,
migration, genesis and capacity remain consumer-owned. Similar semantic labels
never imply an interoperable universal use record.

### 1. Versioned identity and dependency graph

| Required field | Content and rejection condition |
| --- | --- |
| Profile identity and status | Owning profile/version/approval/source pins, consumer enrollment and original operation classes; each logical window/profile/version and fixed authorized slot set. Separate original operation identity from receipt challenge, H, run, use revision and publication sequence. Multiple phases are distinct windows. |
| Native operation and expected read set | Exact native operation codec/version and canonical preimage/domain; authority generation or incarnation, exact predecessor revisions, candidate/base/checkpoint/snapshot and independently expected read set. Derive expectations from protected original intent and current locked state, never from the receipt. Bind exact owner/arguments/purpose without truncation or normalization. |
| Logical window identity | Exact original operation/owner/phase/action/sequence/slot uniqueness tuple, with allocation controlled by the original owner before preparation. A scheduled occurrence is an independently authorized operation, not a new slot selected by H/challenge/run. State abandonment/retirement and no checked candidate surviving final-lock release. |
| Dependency graph | Specify acyclic dependencies among original operation, already frozen/signed artifacts, receipt/closure, H and later completion/use/outcome. Operation identity cannot depend on H or on a post-state digest containing H. A sole final capture occurs later and is not a receipt claim or future value required in the preparation commitment. Native profile names containing `/` need explicit protected representation/mapping; do not copy them into the provider's restricted enrolled-ID alphabet. |

### 2. Canonical timing meanings

The canonical symbols are **s** (original receipt observation), **p** (optional
last qualified pre-lock capture, otherwise s), and **m** (sole local final
capture). These are three distinct meanings. A native symbol `c` must be mapped
to exactly one meaning in that native profile: pre-lock c maps to p; a native
final c or n maps to m. Never alias the pre-lock capture to the final capture or
infer one from the other. Their meanings, not their spelling, are authoritative.

| Required field | Content and rejection condition |
| --- | --- |
| Original start and deadline mapping | Independently retained original boot/domain/start/absolute exclusive D/UTC deadline/budget and conservative mapping-rule identity. Bind to original durable intent before mutation. Specify exact integer units, rounding, nonrepresentability and boot/restart policy; receipts lacking these fields cannot invent them. |
| Original budget | Intersect every applicable original start/limit/deadline; effective D is the earliest qualified mapped deadline. Preserve each native timeout, reader data window and enclosing writer/observation limit from its original start, only where actually applicable. No universal 250/1000/2000 ms defaults. |
| Budget gaps | `undefined` names an unspecified operation budget and missing owner input; `pending qualification` names a specified bound lacking proof. Both refuse admission. Neither means unlimited, inherited by analogy or optional. |
| Read point and allowance | T is the finite positive original allowance **from s through the full endpoint**, never a new remainder at admission. Use checked same-boot/domain nanoseconds, epsilon>=0, f>0, T>0; require m>=p>=s, m-s+f+epsilon<=T and m+f+epsilon<D. Equality at D refuses; original deadline intersections remain mandatory. The sole m is local input to the pure check, not receipt-supplied freshness. |

### 3. Uncertainty coverage

| Required field | Content and rejection condition |
| --- | --- |
| Original settlement reserve | Bind the original reserve, rate/error rule and qualification to the authentic receipt settlement **before W advances**. Cover elapsed preparation/admission since s plus the entire residual through act/use durability exactly once. No refreshed reserve, reduced delta, shifted O, double charging or transfer of already spent reserve to another act. |
| Uncertainty | Preserve O/delta and original interval, effective cap, U<A, L>max(prior provider W, imported J), stricter locked floors, consumer expiry/release predicates and both raw/coarse projections. Reserve must fit under the cap together with source uncertainty, not merely fit the operation deadline. T and reserve cannot grow. |
| Composition of reserves | Distinct nested or sequential windows require distinct fresh settlement/challenge/candidate/use and their own qualified reserve within the same original operation deadlines. A parent's f includes the whole nested span. Never reuse a capture or spend one interval's reserve twice. |

### 4. Preparation authenticity and bounded ownership

| Required field | Content and rejection condition |
| --- | --- |
| Trust and preparation | Trusted process/host boundary; exact receipt, settlement, original closure and witness association; protected reader/validator versions, enrollment and actual checked descriptor/object identities. Require authoritative current checkpoint and ancestry acknowledgment, not a head digest or structural decode. Preparation/publication domains and canonical owning bytes stay versioned without widening the closed receipt. |
| Retention and invalidation | Bound count/bytes/depth/history before allocation/traversal; authenticate every original and ancestry link, retain immutable disjoint owned bytes and a qualified live custody/invalidation/fencing model. All external reads, provider/witness/signing work precede final locks. Missing or excessive ancestry/originals returns no bundle: never truncate. No publicly forgeable prepared authority from bytes/hash, boot UUID or run nonce. |

### 5. Final admission, durable use and recovery

| Required field | Content and rejection condition |
| --- | --- |
| Final locks | Exact ordered exclusions, modes, persistence admission and consuming use/CAS admission **before the sole read**; select protected exact head/epoch/unused revision before m. List held/released locks at collection, initial use admission, read/check, burn, act and completion. A nonwaiting initial append/CAS admission after m is forbidden even if budgeted in f. Later completion reentry is allowed only under continuous outer exclusion/live fence and within the same enforced f/original D, with no new read. Specify forbidden acquisitions/upgrades/RPC beneath terminal locks. |
| Pure check inputs and output | After all initial admissions, take exactly one fixed qualified suspend-aware read outside VerifyWindow. The pure check receives bounded owned prepared data, independently expected original operation/window/boot/deadline, current protected read set/authority/use revision, floors and m. No clock/callback/provider/descriptor/I/O/mutation inside it. Output is a candidate or typed refusal, never dispatch/use authority. |
| Versioned consumer use transition | Name this consumer's own durable transition/version/home and exact operation/window predecessor+unused CAS under retained serialization. Every H for a burned slot refuses. Burn before a separable act, or demonstrate a genuinely atomic act/use commit. State H retention/binding without requiring all consumers to persist H. Closed records/frozen inventory cannot be repurposed; schema/migration/genesis/capacity stay native and reviewed. A separate ledger needs owner approval. |
| Act and Deadline endpoint | Exact authoritative effect, every file/namespace barrier, readback, committed use/outcome and required cleanup before authority opens, strictly before D. Choose proved atomic act/use or an ordered recoverable multi-file burn-intent/act/completion graph; rename alone is not multi-file atomicity. Later delivery/visibility needs its own bounded window. |
| Crash/retry mapping | Retain exact outcome/tombstones after cleanup. Cuts before/ambiguous/after burn, partial/late act, unknown durability, lost reply, missing/restored use and old/delegated executor resumption must not refund, redispatch or renew D. Independent consumer rollback authority and live-instance fence are required. Distinguish safe stored-outcome retrieval from new time-dependent exposure. |
| Public refusals | Map precise internal activation/predicate/persistence reasons to existing native public codes; no template label creates a new public code. Unknown outcome remains held/burned and contained, not automatically late-published. |

### 6. Enforcement and per-platform qualification

| Required field | Content and rejection condition |
| --- | --- |
| Post-read mechanism | Finite workload-specific T, f, epsilon and reserve, their units/rate/error rule and enforced bound or deadline-aware commit through the full endpoint. Specify maximum history, bytes and files; OS/filesystem/device; installed qualification revision and native evidence. Include GC/preemption/faults, pause, suspend, contention, storage faults, nested work, readback and cleanup. Missing proof is handoff_unqualified; no percentile, post-effect clock check or withheld reply supplies enforcement. |
| Linux and macOS parity | Per-window clock/boot/deadline/store/exclusion/act/stop, reviewed platform representation, exact source/closure and qualification. Linux BOOTTIME and macOS continuous time are distinct domains; no receipt relabeling. Both platform bindings are mandatory with explicit unknowns; one cannot waive the other's gaps. |
| Stop behaviour | Independent emergency dispatch and old/delegated-writer fence through retained lock holders and unknown storage outcomes. It cannot wait for provider/store leaves or lose burn evidence/reopen authority. Ordinary transactional revoke is not presumed independent stop. |

### 7. Paired controls and composition

| Required field | Content and rejection condition |
| --- | --- |
| Future controls and open gates | Shared feasible arithmetic/strict boundaries, stale admission and post-read pause, duplicate CAS, H replacement, original deadline substitution, lost acknowledgment, missing/restored use state and unavailable originals. Pair every negative with a positive under the same declared qualification, exact provider/use/act post-state and narrowing plant. Add the initial use-admission-before-read order assertion. Arithmetic does not qualify native timing. Distinguish specified/executed/qualified/pending and list missing owner inputs. |
| Window composition | Specify how nested audit/publication and sequential commit/visibility windows retain original deadlines and live authority, with independent evidence/challenge/use and no reused final capture or double-spent reserve. Each window gets one read after its own full admission; all nested work remains inside the parent's already enforced f. Failure fences the parent; private builders and stored-outcome retrieval grant no later release permission. |

## Optional native extensions

These fields are optional because some consumers have neither staged signing
nor an independently witnessed frozen candidate. If a native operation uses
one of these mechanisms, its field is required for that window. Otherwise mark
it inapplicable with the owning contract clause; omission is not a waiver.

| Optional field | Why it is separate and what it preserves |
| --- | --- |
| Scheduled action and workload | A protected schedule occurrence and `publish`/`revalidate` action may replace a caller request identity. Publish and revalidate can have different T/f/epsilon/reserve and bounded history workloads; cadence is not an execution budget. Existing request-only profiles need no scheduled occurrence. |
| Staged signed artifact | Where signing is external, finish it before final locks, freeze exact bytes/ID, purpose and original issuance provenance, then collect final time bound to that artifact. Revalidation preserves original issued_at and projections; it neither resigns nor forms a receipt/H-dependent operation digest. Consumers without external signed publication need no signing stage. |
| Witnessed content/completion bridge | Where an immutable acknowledged candidate precedes later H, identify the separate content inventory, completion/use root and exact resulting act/pointer. Specify atomic selection of content+use metadata in one committed root, independent monotonic completion/visibility authority, fresh bridge authentication of actual content and associated use, and recovery of full lineage. A content witness alone cannot establish unused completion state. Consumers without that split retain their native intent/outcome recovery instead. Owner approval remains a gap, never inferred from this field. |

## Reusable template

Copy and fill the following **prose template** in the owning repository. Bracketed
placeholders are required inputs, never defaults. Retain all native identifiers
and source clauses; shared paragraphs can serve several explicitly named windows.

```text
Profile identity and status: [version, source revisions, approvals, gaps]
Trust and preparation: [operation/native codec, reader/witness, originals, custody]

Windows: [repeat the following for every logical phase/slot]
  Profile/window/sequence: [enrolled native identity, authorized allowed set]
  Logical window identity: [exact operation/owner/phase/slot uniqueness tuple]
  Final locks:
    Collection: held [..], released [..], lock order/fence [..]
    Initial persistence/use admission: [held before m, exact head/epoch/unused]
    Read/check: held [..], released [..]
    Burn admission / act / completion: held [..], released [..], differences [..]
    Forbidden acquisitions, upgrades and calls: [..]
  Original start and deadline mapping:
    boot, clock, start_ns, absolute_ns, original_utc_ns,
    original_budget_ns, mapping_digest: [native retained tuple/types]
    Original protected intent/window-plan binding: [..]
  Original budget:
    Intersection:
      - [original operation start, limit, mapped exclusive deadline]
      - [applicable original reader start and limit]
      - [other actually applicable enclosing deadline]
    Effective D: [earliest conservative mapped deadline]
    Undefined paths and refusing disposition: [none, or exact gap + owner]
  Read point: [approved single-read amendment after ALL initial admissions]
    Captures: s [receipt], p [optional pre-lock], m [sole local final]
    Native symbol mapping: [each symbol maps to exactly one capture meaning]
    T / f / epsilon: [finite qualified bounds or explicit pending gap]
    Predicates: m>=p>=s; epsilon>=0; T>0; f>0; m-s+f+epsilon<=T; m+f+epsilon<D
  Post-read mechanism: [enforced bound/deadline act, native evidence or closed]
  Uncertainty: [original interval/cap/floors/reserve and nested accounting]
  Act: [exact authoritative effect; private builders are not publication]
  Deadline endpoint:
    Commit model: [atomic act/use OR ordered recoverable multi-file protocol]
    Ordered durable components/readback/cleanup: [..]
    Authority/public visibility gate: [..]
    Later distinct release/visibility windows: [..]
  Versioned consumer use transition:
    Consumer-owned transition version/home, migration/genesis/capacity: [..]
    Expected revision and independent currentness/epoch: [..]
    State graph: unused -> burned -> committed or held; never unused again
    Optional native extensions: [scheduled action/workload, staged artifact,
      witnessed content/completion bridge; applicable or owning-clause exclusion]
    H retention/binding: [persist exact H OR approved native intent/use binding]
    Frozen content versus later completion/use bridge: [..]
    Tombstones/outcome retention and no new slot via H/run: [..]
  Crash/retry mapping: [all cuts, retained state and forbidden effects]
  Stop behaviour: [independent path, old/delegated writer fence, unknown act]
  Public refusals: [exact existing native codes mapped to internal reasons]
  Linux binding: [clock/boot/deadline/store/exclusion/act/stop + evidence/gaps]
  macOS binding: [equivalent dimensions + primary sources/evidence/gaps]
  Future controls and open gates: [names, exact expected outcomes and plants]
  Window composition: [nested/sequential evidence, deadlines, reserve, captures]
```

The deadline tuple above preserves existing published field labels; it does not
impose their spelling or representation on another native codec. For example,
intent/head checkpoints may be `{seq,line_sha256}` or a native `(seq,hash)` pair,
and an owning transition may retain H or only its exact logical operation/use
binding. Preserve that distinction instead of translating it into a provider
wire field. An allowed audit slot set must remain fixed; an ordinal is not a
caller-controlled retry counter. A committed pre-pin window cannot authorize
later acceptance, and an audit window cannot authorize a root or transport act.

Budget example without defaults: an enclosing deadline and a reader's original
start+250 ms yield their minimum if both apply. A standalone publication tool
with no specified original budget is **undefined, admission closed**; it does
not inherit a writer's 1000 ms by analogy. Likewise a versioned policy/journal
burn-act-completion protocol and an intent/participants/root/use/cleanup
protocol both fit the multi-file endpoint field without claiming atomic rename
of the whole transaction. These are schema examples, not consumer profiles.
