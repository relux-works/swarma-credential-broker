# Inactive handoff API

The Linux codec and pure checker implement data checks for the
[handoff contract](time-handoff.md). **Production admission is inactive.** There
is no production preparer, original reader, witness backend, consumer adapter or
use-store implementation. Decoding or hashing does not authenticate an envelope.
Native elapsed-time, act, storage, retention and macOS qualification remain open.

## Closed encoding

`EncodeHandoff` and `DecodeHandoff` select `qualified-time/handoff/1`, separately
from `qualified-time/1`. UTF-8 JSON uses recursive ASCII member order, no whitespace
or terminal newline, and byte-identical re-encoding. Duplicate, missing, null,
unknown, malformed, noncanonical and trailing members/bytes refuse. Decimal
strings have canonical signed-int64 or unsigned-uint64 representations; elapsed
values/durations are nonnegative. The embedded receipt is unchanged.

The root has exactly `version`, `receipt`, `handoff`, `objects`. `handoff` has
exactly `profile`, `id`, `consumer_run`, `window`, `transition_version`, `deadline`,
`budget`, `receipt_ref`, `closure_digest`, `validator_digest`, `witness`.
`profile` is `retained-anchor/1`. IDs/runs are lowercase 128-bit hex. Profile and
native transition identifiers use enrolled provider IDs; native UTF-8 identities
and slash-bearing names need their protected native-codec mapping, never truncation.

`window` has `profile` and unsigned `sequence`. It names the originally authorized
phase/action/slot; it is independent of H, challenge and run. `deadline` retains
`boot`, `clock`, `start_ns`, `absolute_ns`, `original_utc_ns`, `original_budget_ns`,
`mapping_digest`. The only accepted clock here is Linux `CLOCK_BOOTTIME`.
`budget` retains `qualification_digest`, `total_delay_ns` (T),
`final_work_max_ns` (f), `error_ns` (epsilon) and `reserved_uncertainty_ns`.
The final capture m and optional pre-lock p are local inputs, not receipt claims.
The native transition version is a separately checked binding, never a new
logical use slot or permission to refund a burn. This uses the approved single-read amendment instead of the proposal's obsolete
pre-entry handoff-delay term. Neither deadlines nor reserve can be renewed.

References have `sha256` and decimal-string `size`; object descriptors additionally
have `role`. The ordered closure begins with exactly one `receipt`, `settlement`,
`evidence-manifest`, `witness`, then current `source` objects in original manifest
order. Complete ancestry uses the closed roles `history-settlement`,
`history-receipt`, `history-source`. Shared exact source bytes are retained once;
duplicate descriptors, missing ancestors, cycles and unrelated extras refuse.
These history roles make the proposal's full-ancestry obligation explicit instead
of silently omitting old originals. The manifest digest binds the entire order.

`witness` is exactly `{"version":"unavailable/1"}`. This is a closed placeholder,
**not a frozen backend proof format**. `ValidateHandoffWitness` always returns
`ActivationRefusal{Reason:"witness_unavailable"}` for every input. A structural
round trip or `CheckHandoffOriginals` success cannot replace that authentication.
A future backend needs its own reviewed closed validator and custody contract.

Limits: receipt 65536 bytes; metadata 16384; envelope 131072; JSON/ancestry depth
16; envelope plus closure at most 64 objects and 8 MiB, each object at most 8 MiB.
Excess refuses with no partial bundle or truncation. Fixture preparation also
counts exported copies and its private immutable copies before copying. Exact
settled receipt reconstruction, original manifest/source associations and the
entire generation chain are checked before private fixture preparation.

H is SHA-256 of `qualified-time/handoff-commitment/1`, a zero byte and exact
canonical envelope bytes. H is a commitment, never a one-use key or authenticator.

## Pure checking and consumer ownership

`VerifyWindow(PreparedHandoff, WindowExpected, LockedWindowState, FinalCapture)`
returns an opaque `WindowCandidate` or a typed refusal. `PreparedHandoff` has no
public constructor or mutable fields. Zero preparation returns
`handoff_unqualified`. Only tagged synthetic code constructs private immutable
anchors; byte decoding, arbitrary original-reader implementations and hashes
cannot do so. Independent expectations and locked intent are compared afresh;
owned exact originals remain retained. No cached pass grants use authority.

The checker performs bounded scalar comparisons and checked integer arithmetic:
operation/enrollment, boot/domain, original deadline, window/transition, run,
challenge, current unused revision, reserve/cap, unchanged interval, stricter
locked floor/expiry and `m>=p>=s`, `m-s+f+epsilon<=T`, `m+f+epsilon<D`.
The original budget bounds D; equality and overflow refuse. Reserve covers T
without adding already charged epsilon or reserve a second time. The fixture
uses the published 500 ms source plus 500 ms reserve under the 1500 ms cap.

`ConsumeIfUnused` and `ActProtocol` are consumer contract interfaces only. The
consumer admits all initial persistence/use exclusions and selects exact state
before m. It keeps serialization/live custody through consume and the full
endpoint. A candidate cannot survive lock release. A separable act follows a
durable burn; ambiguous burn means no act, and lost reply grants no redispatch.
Native transition versions and stricter native requirements remain authoritative.

## Tagged controls and limits

With `swarma_timeconf_fixture`, `timeconftest.NewHandoffProvider` collects real
synthetic provider settlements; `CollectHandoff` returns mutable test copies and
an isolated private preparation. `PrepareHandoff` accepts only the synthetic
fixture root. `NewUseStore(epoch, authorizedKeys...)` explicitly initializes
originally authorized slots, independently of H, before checking. Its reference
store is **volatile memory**, without native persistence or rollback protection.
Its `Admit` token retains the reference lock across the supplied synthetic read,
pure check and consume; `Release` retires it. No initial lock is reacquired after
that read in this reference path. It demonstrates exact revision/use comparison,
burn-before-act, ambiguous-burn
containment and no replay after lost reply. It cannot qualify a production act.

Run `go test -tags=swarma_timeconf_fixture ./timeconf -run '^TestHandoff'`.
Run `go test ./timeconf -run '^TestVerifyWindowCompiledPurity$'` for the actual
compiled checker graph. The structural check builds a symbol-bearing inspection
binary in test scratch, follows package/generated equality helpers and permits
only enumerated runtime language intrinsics; unresolved/indirect/foreign calls
fail closed. This proves no clock or I/O API dependency, not scheduler timing.
The fixture dependency and external compiler guards include the new symbols.

The published table has thirteen named rows after the admission-order addition.
Go controls cover codec/binding/arithmetic, N1 before/after burn, real interval
versus missing/restored continuity, duplicate/fresh-H use and reference crash cuts.
Stale pre-lock bytes and pauses after m remain documented infeasibility, not
simulated native runs. The epoch test proves only reference pre-dispatch rejection;
post-burn stale-executor fencing still needs the native effect primitive. The
macOS case refuses mixed domains; no native macOS storage/suspend run is claimed.
