# Consumer window-profile schema and template

This is a **documentation schema**, not a JSON/YAML wire format, runtime API or
activation record. Each consumer publishes its own approved profiles in its own
repository. Its native codecs, lock names, refusal codes and versioned use-state
format remain authoritative. This shared template adds no consumer record field.
Read the [handoff contract](time-handoff.md) and [macOS binding](time-handoff-macos.md).

## Profile schema

One document may contain multiple windows and shared requirements. Every window
must resolve all rows below, directly or through an exact versioned reference.
Use the published labels `Final locks`, `Original budget`, `Read point`,
`Post-read mechanism`, `Deadline endpoint`, `Uncertainty`, `Public refusals` and
`Versioned consumer use transition`; expand them rather than inventing another
set of native lock/identity names. A narrative profile with symbol tables and
use-member tables is equally valid if every requirement is explicit.

| Required field | Content and rejection condition |
| --- | --- |
| Profile identity and status | Owning version/codec, original operation classes, each enrolled window profile/phase/sequence, scope exclusions, source pins and approval state. Multiple audit/publication or preparation/publication windows are separate entries, not one broad permission. Explicit implementation/qualification gaps keep admission closed. |
| Trust and preparation | Single-process/host boundary, protected enrollment and original-reader/witness versions, exact owning identity/argument/base/candidate/authority binding, complete original closure and live custody/invalidation. Expected state is independently derived. No H-dependent operation digest or final-result-dependent identity cycle. |
| Logical window identity | Exact native uniqueness tuple and how the original owner allocates its complete allowed phase/action/sequence/slot set before preparation, including scheduled occurrences and later revalidation when applicable. H/challenge/run cannot allocate another slot. Distinguish original operation, logical slot, one live candidate and local use revision. State abandonment/retirement and no candidate crossing final-lock release. |
| Final locks | Exact ordered exclusions, ownership and modes held throughout each stage, including outer locks, separate in-process gates and delegated-writer fences. List locks released at collection, final read/check, burn admission, act and completion; forbidden acquisition/upgrade/RPC beneath terminal locks. If append admission occurs later, name it and include its bounded nonwaiting cost in f. Similar lock letters across consumers imply no equivalence. |
| Original start and deadline mapping | Independently retained original boot/domain/start/absolute exclusive D/UTC deadline/budget and conservative mapping rule identity. Bind to the original durable intent before mutation, not a new receipt/context. Specify checked integer units, rounding, nonrepresentability and boot/restart policy. A receipt without deadline fields cannot invent these values. |
| Original budget | Every applicable original start/limit/deadline as an intersection. Effective D is the earliest qualified mapped deadline, preserving each original identity and limit independently. Include original caller/native timeout, reader data window, enclosing writer/observation bounds only where actually applicable. Never assign one consumer's 250/1000/2000 ms limits to another by analogy. |
| Budget gaps | `undefined` explicitly identifies an unspecified operation budget; name the missing owner input and refusing disposition. `pending qualification` identifies a specified bound lacking proof. Neither means unlimited, zero, inherited by guesswork or an optional gate. A profile may be published with gaps but cannot admit those paths. |
| Read point | Repeat the approved amendment: exactly one fixed qualified suspend-aware read after all applicable final-lock admission, outside pure VerifyWindow; Linux BOOTTIME or separately versioned macOS continuous domain. Define s and optional pre-entry c, final m (native n/c aliases allowed), T, f, epsilon. Require m>=c>=s, f>0, m-s+f+epsilon<=T and m+f+epsilon<D; checked same-boot arithmetic. No clock callback/provider/I/O in the pure check. |
| Post-read mechanism | Concrete enforceable f or deadline-honoring act through the full endpoint, including pause/suspend/GC, faults, contention, every nested window, storage, readback and cleanup. Finite values/units, maximum qualified workload (bytes, files, retained history and device), action-specific rate/error/reserve calculation, qualification identity and native evidence, or `handoff_unqualified`. A post-effect check or withheld reply cannot prevent a late act. |
| Uncertainty | Immutable original interval, effective cap, floors/authority/release and coarse projection checks; pre-reserved work/conversion/rate allowance and exact accounting without double spending. T and reserve never restart or grow. Each nested logical window needs its own fresh evidence/challenge/use, while enclosing deadlines and full work bounds remain in force. |
| Act and Deadline endpoint | Exact authoritative effect, required file/namespace barriers and readbacks, durable committed use/outcome, cleanup and when authority becomes visible. Choose genuine atomic act/use commit or an explicitly recoverable multi-file burn-intent/act/completion graph. Enumerate every component; rename or append alone is not multi-file atomicity. Separate later external delivery/visibility windows and their remaining deadlines. |
| Versioned consumer use transition | Exact owning durable home/version, uniqueness key, independently current expected predecessor, CAS/serialization, burn-before-separable-act, committed/held outcomes, H retention policy, rollback/epoch custody and retention after cleanup. Existing frozen/witnessed inventories and closed wire bytes cannot be repurposed. Version/migration/genesis/capacity changes need review; a separate ledger needs owner approval. |
| Crash/retry mapping | Cuts before/ambiguous/after burn, partial act, unknown namespace durability, missing use, lost reply, restored consumer/provider/witness and old/delegated writer resumption after burn. No unburn, redispatch, deadline renewal or invented completion. Recover exact original outcome only. Distinct new operation/window requires independent authorization. |
| Stop behaviour | Independent emergency dispatch and exclusion/fence path, including retained lock holders/descendants; no waiting on provider/store leaves. Specify how unsafe/late/unknown effect is contained without reopening admission or losing burn evidence. Ordinary transactional revoke is not assumed to be an independent stop path. |
| Public refusals | Map future internal activation/predicate reasons to existing native public codes, including clean contention/expiry, untrusted time, replay, ambiguous persistence and authority mismatches. A template/internal code does not extend the public refusal vocabulary. |
| Linux and macOS parity | Per-window clock/boot/deadline/store/exclusion/act/stop bindings, exact native OS/filesystem/device/closure and qualification state, primary references and explicit unknowns. Both are mandatory; the Linux implementation cannot waive a macOS gap. |
| Future controls and open gates | Named nearby positive/negative controls from the shared list plus native-specific lock, crash, reserve, currentness and multi-file cuts. State expected act/use/provider post-state and narrowing plant. Distinguish specified, executed, qualified and pending; list missing owner decisions explicitly. |

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
  Read point: [approved single-read amendment, original s/c and final m]
    T / f / epsilon: [finite qualified bounds or explicit pending gap]
    Predicates: m>=c>=s; f>0; m-s+f+epsilon<=T; m+f+epsilon<D
  Post-read mechanism: [enforced bound/deadline act, native evidence or closed]
  Uncertainty: [original interval/cap/floors/reserve and nested accounting]
  Act: [exact authoritative effect; private builders are not publication]
  Deadline endpoint:
    Commit model: [atomic act/use OR ordered recoverable multi-file protocol]
    Ordered durable components/readback/cleanup: [..]
    Authority/public visibility gate: [..]
    Later distinct release/visibility windows: [..]
  Versioned consumer use transition:
    Durable home/version and migration/capacity: [..]
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
