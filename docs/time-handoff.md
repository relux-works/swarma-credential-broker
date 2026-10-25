# Qualified-time local handoff

Status: **approved contract decisions; production admission remains inactive**.
This publication defines requirements and inactive interfaces. It supplies no
handoff codec, preparer, `VerifyWindow`, `ConsumeIfUnused`, consumer adapter or
new fixture. The unchanged eleven-fact `qualified-time/1` receipt and
[provider settlement API](qualified-time-api.md) remain separate contracts.

## Decisions and trust domain

1. The [approved final-window amendment](time-contract.md#final-issuance-enrollment-and-registration-windows)
   permits one fixed qualified suspend-aware monotonic read after all final-lock
   admission, outside the pure check. It does not qualify the remaining act.
2. Completion means durable local commit of the window's act together with its
   use state. Reservation, dispatch, page-cache visibility and acknowledgment
   are not that endpoint.
3. One-use applies per original logical operation and window in the owning
   consumer's versioned transition. Every H for a burned slot refuses. Existing
   closed wire formats remain unchanged; local storage changes need review.
4. Design (d), a protected retained-original anchor plus private commitment H,
   requires no new key inside a **trusted single process on a single host**.
   A different trust boundary needs a separately approved authenticated delivery
   profile. No existing signing/MAC key or purpose is borrowed.

A qualified preparer authenticates exact retained receipt, source, settlement
and ancestry bytes against protected enrollment and an independently current
rollback witness, before final locks. It retains bounded immutable owned copies
and a private anchor. H binds that preparation; requester-provided bytes and
their hash, `DecodeReceipt`, a sealed/duplicated descriptor, a nonce, a revision
string or an opaque private Go type alone cannot authenticate it. A signature
or MAC would not establish elapsed time, one-use or rollback safety either.

Original loading, witness/provider traffic, history traversal, validation and
bundle allocation finish before the window under the original deadline. No
lazy reader, helper, callback, provider or witness RPC runs under final locks.
Protected live custody must exclude or invalidate known holds, steps, lost
originals, provider/authority changes and competing writers through completion.
Copied bytes cannot detect an otherwise unobserved revocation/deletion. Until
that retention/currentness mechanism is qualified, admission stays closed.
Provider W, holds, in-flight markers and associations persist independently of
a consumer refusal, unused preparation, crash or abandoned window.

## Native operation and logical window

Every consumer publishes an approved [native window profile](time-window-profile.md).
Bind exact owning identity bytes, original caller/request/generation/arguments
or scheduled-operation identity, immutable candidate and base/checkpoint/snapshot,
authority generation and signing purpose, relevant local revisions, phase and
logical sequence. Hash the owning canonical codec; native UTF-8 or larger
identifiers must not be truncated into provider ASCII enrollment fields. Bind
the protected enrollment mapping. Journal, publication and use revisions are
distinct types, not interchangeable sequence numbers.

Derive expected identities from independently retained operation inputs and
protected current state under the final exclusions. Never copy them from H or
the receipt into "expected" inputs. The operation digest must not depend on H
or a post-state digest containing H. Retain original boot/start/deadline, UTC
deadline identity and conservative domain mapping in the enclosing adapter;
a lower-level receipt lacking those facts cannot supply them by inference.

**N3:** a live handoff entry/run is distinct from the logical window. Fresh H,
challenge, sample, run or writer epoch cannot allocate another slot. At most
one live candidate is admitted for a slot. Abandon and retire the private
candidate on a failed check, final-lock release, boot/run/epoch change, expiry
or invalidation. Never carry a checked candidate across lock release. Before
burn, new preparation is possible only for an independently authorized,
still-unused window with its original constraints intact. After burn, it is
not possible for that window, even if no act occurred.

## Timing admission and reserve

Each profile repeats the approved read placement, pure-check boundary and
same-boot checked inequalities. Use receipt observation s, optional retained
capture c (otherwise c=s), final read m, original qualified allowance T,
enforced remaining bound f and conservative error epsilon:

```
m >= c >= s
f > 0
m - s + f + epsilon <= T
m + f + epsilon < D
```

Some profiles call m `n` or `c`; names do not change these meanings. T is the
total original observation-to-endpoint allowance, not a fresh allowance starting
at entry. All bounds are finite nonnegative integer nanoseconds, f strictly
positive. Reject overflow, mixed domains/boots, and equality at D. Reserve
verification, atomic use admission, every act write/sync/rename, namespace
barrier, readback, completion and required cleanup before provider settlement.
An unknown bound returns activation refusal `handoff_unqualified`; a proved
expired deadline refuses `deadline`, and inadequate interval coverage refuses
`reserve`. These are future internal handoff reasons, not new public consumer
codes. The profile maps them to its existing refusals.

Preserve original [L,U], `L > max(prior_W,J)`, stricter locked consumer floors,
`U < A` and consumer expiry/release predicates. Keep effective uncertainty
separate from the operation budget: the shared cap is at most 1.5 seconds,
possibly stricter. Never advance O using an unqualified rate, shrink delta,
increase D/T/reserve, or charge/reuse the same reserve twice. Each distinct
window collects fresh bound evidence without extending its enclosing deadlines.
Coarse projections retain original nanoseconds and require both predicates:
floor L and exclusive A, ceil U and durable upper floors. An admitted consumer
watermark is `max(prior_admitted,floor(L))`, while durable upper floor J is
`ceil(U)`; provider W is neither a substitute nor a permitted admitted watermark.

The final read detects a pre-lock pause only. An arbitrary pause after it still
defeats ordinary check/write/rename. Qualification must enforce f through durable
act/use completion, or the act itself must honor the original deadline. A
post-write check cannot retract an already visible effect. Envelope size caps,
TryLock, cancellation, average storage latency and suppressed success replies
supply no hard bound. A five-second enclosing operation, where its native
profile specifies one, is not permission to exceed its uncertainty cap or
another applicable deadline. Emergency stop must remain reachable without
waiting for this provider, its journal or their retained lock holders.

## Durable one-use and crash behavior

`ConsumeIfUnused` is a future consumer-owned serialized transition, not a shipped
Go interface or provider store. Its contract takes a checked candidate plus
independently current logical key, exact predecessor revision, live ownership
and unused slot. Under final exclusion, compare them together and durably
serialize the burn with the owning act/intent. A pure check returns only a
candidate and may be computed twice; neither result grants dispatch authority.
Any H for a burned slot refuses. A digest-keyed cache is not one-use.

The key covers protected consumer/store/owner, original operation, phase and
logical window sequence/slot. Where native identity already includes those
components, do not duplicate or normalize them. H may be a stored commitment
value, but is never the uniqueness key. The approved logical burn does **not**
require every consumer to persist H. A profile must specify whether it retains
H and how exact private preparation binds its durable native operation/window.
Use state remains inside the consumer's reviewed next version of its owning
transaction, not an unapproved independently restored ledger.

A genuinely atomic act/use commit may burn and act together. A multi-file
recoverable transaction must durably burn its owning intent before any separable
authoritative act, then establish the complete act and use outcome endpoint.
Only the still-live admitted call may make its one attempt after that burn.
It remains subject to the deadline/fence; recovery cannot redispatch from a
burned intent. This is at-most-once authorization, not exactly-once delivery.
No act/use success is reported before all required durability and recovery
bindings are established strictly before D.

Pure snapshot/journal builders do not burn; the owning authoritative publication
does. Freshness commits exact history/outcome, admitted watermark, decision
floor and boot together with use state under the same predecessor comparison.
Post-resolution visibility is a separate window with a fresh handoff and durable
visibility transition. Exact stored-outcome replay is status/recovery, never a
new time grant, new append or new publication position.

Closed journal, checkpoint, revocation, freshness and witness-intent records
gain no new members here. Local schema/API, capacity, genesis/version migration
and recovery changes require owner review. H obtained after witness acknowledgment
cannot be inserted into a previously frozen candidate inventory or change its
digest. Approve a versioned binding from immutable witnessed content to later
atomic local completion/use, its independent rollback authority and exact bridge
recovery checks, or explicitly revise the owning protocol. Until then that
adapter is unavailable. An unbound sidecar, digest-only assertion or silent
candidate change is insufficient. A separate use ledger, if unavoidable, needs
an explicit owner decision on custody and restore protection.

| Crash cut | Required disposition |
| --- | --- |
| Before durable burn | No act; retire private preparation. Reconcile complete independently current history before treating a still-permitted slot as unused. Missing/torn/restored state is not unused. |
| Burn write/sync/acknowledgment ambiguous | No act; retain evidence and fence until exact resolution. Do not retry with a fresh H to bypass ambiguity. |
| Burn durable, act absent | Slot stays burned. Delivery may be lost; no refund or recovery dispatch. |
| Partial act, sync, rename or completion unknown | Keep burn, exact candidate and actual files; hold authority and reconcile. Never reconstruct unused from an older checkpoint. |
| Act visible without matching use/intent | Forbidden accepted state: fence. Do not fabricate a burn or treat readable bytes as a completed transaction. |
| Full durable act/use outcome, reply lost | Recover exact original outcome; no second act, publication or consume. |
| Known late disk outcome | Preserve burn and evidence; it cannot become automatic late publication. Withholding reply does not excuse an already late authoritative effect. |
| Restored history or two instances | Independent currentness and old/delegated-writer exclusion must reject stale state; otherwise admission remains closed. Provider W, a boot ID and a run nonce do not protect consumer use state. |

**N2:** also fence a process paused or restored *after burn and before act*, which
later resumes after replacement ownership or D. The effect must enforce current
epoch/deadline, or qualification must prove the old executor cannot resume.
Startup checks or fencing only at burn do not suffice.

## Original-reader and witness interfaces

The new Linux [interface file](../timeconf/original_linux.go) defines
`OriginalReader.ReadOriginals(context.Context, OriginalRequest) (OriginalBundle,error)`.
The request retains the original deadline, protected enrollment, independent
operation/challenge/current boot, exact receipt digest and independently current
witness checkpoint. The reader authenticates provenance, exact original bytes,
association, settled acknowledgment and full ancestry before returning owned
copies, checked descriptor/object identities and pinned validator/reader
qualification digests. These reported identities are audit data, not independent
authentication: the installed reader must retain a qualified live custody guard.
Public bundle fields grant no authority: only installation of a
qualified reader and its live custody/invalidation contract can authenticate
provenance. No constructor accepts a backend or enables production admission.

Closure limits remain 64 objects, 8 MiB aggregate, depth 16, no cycles, each
object at most 8 MiB, receipt at most 65536 bytes; all receipt/record/source and
backend witness material count, with no hidden unbounded ancestry. Preparation
must refuse an incomplete closure. Required pinned validators authenticate
original source and record semantics, not only their digest; unknown formats
and unavailable provenance refuse. Witness material has **no frozen handoff
wire format** until an independent backend is selected and reviewed.

The existing [RollbackWitness](../timeconf/settlement_linux.go) is unchanged:
`Read(ctx) (WitnessHead,error)` and
`CompareAndSwap(ctx,old,next WitnessHead) error`. No extension is needed to name
a current head and durably advance it; original-reader validation separately
checks ancestry. A qualified implementation supplies fresh authenticated reads,
exact predecessor CAS, durable acknowledgment, no generation reuse/wrap, no
cached/reset baseline, strict original-deadline completion and continuity
outside **all** relevant restore domains. The independently protected confirmed
head and old-instance exclusion must survive witness/provider/consumer restores;
separately held key material alone is insufficient. An off-node backend is not
selected or assumed equivalent to local CAS: its traffic and bootstrap/custody
costs must fit the original budget before final locks.

Only `ClosedOriginalReader` and `ClosedWitness` ship as production backends.
The reader always returns an empty bundle and
`ActivationRefusal{Reason:"originals_unavailable"}`; the witness returns
`ActivationRefusal{Reason:"witness_unavailable"}`. Both wrap `ErrUnavailable`.
A future qualified reader uses `ConsumptionRefusal` codes `originals`, `binding`,
`continuity` or `deadline` for failed validated inputs, never a partial bundle.
No errors expose original bytes, paths or identities. These Linux interface
shapes do not supply the [mandatory macOS implementation](time-handoff-macos.md).

## Named future controls

**Specified, not executed or implemented here.** Every row needs the nearby
valid control, intended refusal and exact provider/use/act post-state. Native
pause, storage, suspend and restore controls require isolated authorized targets;
arithmetic fixtures do not qualify them. An unapplied plant, skip or setup crash
is not a killed control. Existing reviewer tests retain their names.

| Future vector | Exact negative expectation | Positive control and narrowing plant |
| --- | --- | --- |
| `HandoffStaleCapture` | Same bytes with pre-entry capture 100 ms, D=250 ms, f=20 ms can enter at 110 ms or after a pause at 1500 ms. Pure input alone cannot distinguish them. Actual admitted read at 1500 refuses deadline with no burn/act. | Same qualified inputs at 110 ms may pass time predicates; remove/move the admitted read and the native stale-admission assertion must fail. |
| `HandoffDoubleCheck` | Two pure checks of unused revision v may both produce candidates; serialized consume accepts at most one, with one burn and at most one act. H2 for the burned logical key also refuses. | One candidate under exact matching current revision commits once; remove predecessor/use comparison or key by H and duplicate-act assertion must fail. |
| `HandoffTimelyRun` | Missing enforced f or native act qualification gives `handoff_unqualified`, even with favorable numbers. | Illustrative ms s=0,c=100,m=110,f=20,epsilon=1,T=2000,D=250: 131<=2000 and 131<250; native qualified act/use endpoint must also finish strictly before D. Remove qualification gate and the unqualified-path assertion must fail. |
| `HandoffLateRun` | With the same constants and m=1500, deadline refuses before burn. Also pause immediately after on-time m until past D: mechanism must prevent late authoritative act, not just suppress reply. Without it admission remains closed. | Same real act/use protocol completes before D with independently enforced f; remove effect fencing while retaining pure arithmetic and late-effect assertion must fail. |
| `HandoffN1BeforeBurn` | Start J=140; settle O=200,delta=1 so W=201, then crash before consumer burn. Fresh [170,172] refuses provider continuity; missing witness/history refuses even [210,212]. No W reset or act. | Complete independent history and still-unused authorized original window, fresh [210,212], matching authority and remaining original deadline permit reprepare/new-run use. Plant restoring W from J=140; continuity assertion must fail. |
| `HandoffN1AfterBurn` | Same provider sequence, but H1 burned the slot before failed act. [210,212] may pass provider time only; H2 still refuses that burned slot. W stays >=201, with no refund or second act. | Full consume only for an independently authorized distinct operation/window/attempt retaining all applicable original constraints; plant new-H/new-run key allocation and same-window replay assertion must fail. |
| `HandoffDeadlineEquality` | With s=0,c=100,m=229,f=20,epsilon=1,T=2000,D=250 ms, m+f+epsilon=D refuses `deadline`, no burn/act. U=A separately refuses authority. | m=228999999 ns gives endpoint bound 249999999 ns with the other constants converted exactly to ns; U<A and all other checks may pass. Plant inclusive D comparison; equality assertion must fail. |
| `HandoffLockedStateRace` | Prepare base/head A, find locked B: refuse binding with no burn/publication. Native sequence, owner bytes, reference size, phase or authority substitution also refuses. | Identical valid candidate under exact A/revision matches; plant copying expected state from H and binding assertion must fail. |
| `HandoffUseRecovery` | Lost acknowledgment returns exact outcome only; missing use metadata, independently restored use history beside intact W, post-intent H changing frozen inventory, or freshness retry minting another position fences/refuses. | Complete exact candidate/use/history recovers one outcome without redispatch; separately authorized freshness revalidation advances use/floor only. Plant omitted use/bridge validation and recovery assertion must fail. |
| `HandoffProvenanceAndPurity` | Missing/tampered original, another consumer/operation, changed boot/deadline/mapping, requester validator, accepting witness placeholder, or I/O/clock/provider inside pure check must refuse or fail structural gate. | Enrolled original-reader/witness and same exact bounded bytes match; remove one validation/dependency boundary and its named assertion must fail. |
| `HandoffEpochAfterBurn` | Resume old writer after burn and replacement ownership/deadline: forbid any authoritative effect. | Current live epoch plus timely qualified endpoint commits once; plant burn-only epoch check and stale-effect assertion must fail. |
| `HandoffMacParity` | Awake-only clock, mixed domain, conversion overflow, unsupported flush, unproved namespace recovery or sleep past D cannot qualify. | Same invariants on qualified native continuous-clock/boot/storage/fence target; substitute uptime or bypass parity gate and suspend/durability assertion must fail. |

N1 before-burn and after-burn branches are deliberately separate. A provider
time pass never overrides consumer burned state. No row is claimed green by
this documentation or by the shipped closed-reader unit test.
