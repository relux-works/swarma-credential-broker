# Lab contract C0, revision 1

Status: CONTRACT CANDIDATE FOR REVIEW. Inert construction only, not production
acceptance, a release, owner consent or permission to capture/use a key.
This is the closed byte inventory of [lab profile §5.2](../../docs/lab-profile-v0.md#52-c0s-closed-byte-inventory-and-consumer-joins).
The 24 entries in `surfaces.json` are authoritative together with this document;
`fixtures.json` pairs every own-format valid record with an unknown-field
negative. The acceptance allocations are construction obligations, not claims
that these fixtures implement A01–A12. B1–B5/G1/M1 must exercise their actual
readers and effects against these bytes. No runtime code or constructors ship here.

## Encoding and field grammar

Every record is CCJ-1, exactly as `internal/wire/canonical.go:15`: UTF-8, sorted
object keys, minimal escaping, integers only in the signed safe-integer range,
no duplicate members, null, missing or extra fields, no trailing newline. All
listed fields are required recursively. Arrays preserve order and have at most
256 members; identifiers are printable ASCII, 1..128 bytes. No unlisted extension
member or alternate format spelling exists. Nested structures are closed too.
The `format` member is the domain/version discriminator; a record digest is
`sha256:` followed by lowercase hex of **complete canonical bytes**, not a secret
fingerprint and not a hash with an added domain prefix. Do not hash material or
an enrollment input into a public operation input pin. For an embedded Approval's `approved_sha256`, the complete canonical target
image is `{"domain":"swarma-broker-lab-approval-target/1","record":R}`,
where R is the enclosing record with its single `approval` or `owner_approval`
member omitted. This image is a hash preimage only, never an acceptable record
or an authority source. The owner also approves the complete external receipt
and its timestamps through the authenticated off-VM channel. This avoids a
self-referential hash while binding every act/input/head field. A lab service
journal's own Head.sha256 similarly hashes the complete canonical image
`{"domain":"swarma-broker-lab-journal-head/1","record":J}` with only its
own top-level head omitted; Head.sequence equals entry count. Entries store a
sequence and previous committed head, never their own next hash. The explicitly
fresh empty journal's image gives its genesis digest. Later commits bind the
whole metadata snapshot and entries, including binding/lease/tombstone state.
Manager prefix heads retain the existing manager-owned hash algorithm rather
than being re-encoded as lab heads. Root/control and lease
frames use a 4-byte unsigned big-endian nonzero payload length then those bytes,
maximum 65536, as `internal/wire/frame.go:19`. Larger Q/release files (maximum
262144) are file records, never oversized socket frames. Activation is 16384 max.

In the machine-readable field grammar: `@Name` references a closed structure,
`[]T` is an array of T, `=text` is a string singleton, and `a|b` is a string enum.
`id` is the identifier above; `digest` is `sha256:` + 64 lowercase hex digits;
`operation` is 32 lowercase hex digits from a fresh 128-bit identifier;
`uuid` is lowercase 8-4-4-4-12 hex; `commit` is 40 lowercase hex. `bool` is a
JSON Boolean; `uint` is 0..9007199254740991; `positive` starts at 1; `time` is
canonical UTC RFC3339Nano, with a Z suffix and no redundant fractional zeros
(`time.Parse` followed by `UTC().Format(time.RFC3339Nano)` must reproduce it);
no subsecond precision is discarded from a bound or watermark; `root` is integer 0;
`lifetime` is 1..900; `alignment` is 0..2; `poll` is integer 250;
`capture-timeout` is integer 300; `exit` is 0..255. `material` is a nonempty
ASCII string up to 4096 bytes, carried **only in protected broker custody or the gateway lease
response**, erased from transient holder buffers on terminal paths and never
persisted in a fixture/evidence export with real contents. The published value is a public synthetic marker.
Lease requests use the existing service dialect; this record is its lab material
result, not a new worker route. Custody is the sole protected store object containing material. Account metadata
uses an opaque, never material-derived custody object ID and issued-version IDs;
it contains neither material nor its digest. No second secret store, key hash
or circular custody/account hash join is introduced. The 4096 bound reuses `internal/claude/account_linux.go:94`.

## Required semantic joins (beyond shape)

All consumers compare exact Context, expected heads and digest pins before any
effect, including account, installation, independently approved VM identity,
qualification revision/expiry. A matching local machine ID is insufficient.
A Head is a count plus digest of the exact append-only prefix; count zero has the
approved fresh-install genesis digest, never permission to initialize a missing
store. A nonzero head's digest binds its serialized chain prefix. Stores append
through existing fsync/CAS rules, not a new C0 journal engine. Journal bindings retain current gateway/caller tuples, epochs and revoked
tombstones; lease states retain their binding, issued version, exact deadlines
and issue/renew operation IDs. Entries retain canonical request digests and
results; none of these metadata records contains material. Exact manager
request bytes and returned receipt/request ID/head must agree; never synthesize a
manager receipt. Existing manager records retain their own formats. Principal
facts come from native protected manager evidence and kernel peers, not these
fixture assertions. Authority's gateway is `kind=service`, worker/caller is
`kind=worker`, generations and UIDs are disjoint; root control requires kernel
UID 0 separately. Lease material goes only to the exact gateway. Every duplicate
configuration lifetime equals activation's one selector; `authorized_until` is
the earliest issue+lifetime/authority/caller/time/qualification deadline. Equality
at a deadline closes use; hold/expiry/revocation invalidates replayed material.

Preparation cannot issue/renew. Enabled activation additionally joins current
preparation, authority, release, fence and all C/protection approvals. Disabled,
absent, stale, malformed, mismatched or expired records never widen authority.
Every manual start consumes a fresh off-home fence joined to off-VM final heads
and clock; later starts require acknowledged orderly-stop heads, not current
observed heads. Persist exact manager-prefix high-water before publication.
Time checkpoints retain watermark, incident and sticky holds across restart;
fresh NTS/settlement is necessary, not sufficient. Restore/clone/regression burns
the installation; no ordinary hold, good report or new revision resets history.
`amendment.txt`, `api-exception.txt` and `joins.txt` bind the exact lab §4.2–4.3
text (LF, quote markers removed for the two blockquotes, final LF retained).
Owners approve **all three file digests** and protected Context. The C1 text uses
retired bounds only as refusal floors, never imported authority or hold release.

`owner-decision` requires exactly repository/time-contract/user-manager roles,
each explicitly accepted; one human may cover roles only with recorded authority
for each. Off-VM authenticated owner approval precedes that exact invocation.
`decisions.json` records only the dated direction/residual act already in §4.1;
**C-OPEN-OWNERS is not recorded**, joins/native qualification and protection
inputs remain pending. Synthetic accepted-role fixtures are not owner decisions.
No production spec, API, consumer or acceptance set is amended by C0.

An access attestation covers all three surfaces: guest/external root/sudo/console/
hypervisor/snapshot access, every owner endpoint/root session through revocation,
and vendor workspace/cap/key administration. All effective privileged controllers
must be human; no agent-held admin key/session through a human principal. Owner
endpoint exclusions are all true; roster/audit coverage is complete/unchanged;
the hard cap and approved workspace/limit match. The owner verifies off-VM
observations and Infra's native complete guest/control-plane roster. Incomplete
visibility is closed. Read back before creation/enrollment, bind, activation,
every Q group, hold-lift and **both** prepare-next transitions; any change closes
admission. Creation occurs only after authenticated no-echo prompt and readback,
inside the window, with no interim holder; agent-exposed material is ineligible
and vendor-revoked. These are native/owner preconditions, not proven by JSON.

## Operation, failure and UNKNOWN contract

Operation envelopes are immutable, produced after predecessor commitment, from
actual current heads and exact nonsecret inputs; owner approval precedes their
own invocation. Enrollment binds preparation, never a public key hash. Same ID
and different content refuse with no effect; same ID and matching content
reconcile read-only, never recapture or silently rerun a root act. Enrollment
marks attempted durably **before** prompting, once per ID, for at most 300 s;
attempted/committed/UNKNOWN/conclusively aborted all spend that prompt ID.
A separate approved operation is required after conclusive recovery.

| State/result | Exit | Authority/effect |
| --- | ---: | --- |
| committed | 0 | Exact recorded act only; replay grants no new effect/material authority. |
| definitive refusal | 1 | None, except an independently admitted narrowing act. |
| not_committed:enrol_no_forward | 1 | Durable zero-forward fence spends the ID; no retry prompt. |
| unknown, attempted, incomplete or not_started | 2 | No success/absence assertion, no widening or re-prompt. |
| syntax | 64 | No request/effect. |
| authorization/closed admission | 69 | No widening/capture. |

Concrete reconciliation is `swarma-credential-broker-lab status --operation-from
FILE`, binding the same `operation_id` in that envelope. Never resubmit blindly.
Root-control `phase=request` carries state=not_started/exit=2 (not a result).
After authenticating both kernel peers and the approved operation, fresh enrol
marks attempted durably and returns one attempted/exit-2 readiness result **on
that same connection only**. It permits the single local prompt, not key use.
The first client receiving that readiness result prompts once, then sends a
4-byte big-endian length (1..4096) followed by exactly those ASCII capture bytes,
with no newline/JSON wrapper and no second frame. The 300-second deadline starts
before readiness; timeout, disconnect, malformed length, extra bytes or capture
abort spends the ID. If zero forwarding is conclusively fenced, record
not_committed:enrol_no_forward; otherwise UNKNOWN. Reconnection or status cannot
produce readiness or another prompt. Key bytes never enter an operation record,
result or log. B3 must prove this two-phase connection lifecycle and zero-forward
abort natively; this transport contract grants no live capture permission.
Result heads are authoritative only at committed; UNKNOWN heads grant nothing.
Hold uses leak_match/account/caller/operation ID, is durable before acknowledgment,
and an unknown result never reopens. Hold-lift binds the exact current hold in a
nonsecret input pin; it cannot revive a removed lease. Finite capacity reserves
narrowing before further widening. Current checks every 250 ms use a 100 ms RPC
timeout plus at most 500 ms closure; independent 500 ms watchdog plus 500 ms
closure bounds teardown to 1 s. These timing/effect obligations belong to G1/B4,
not to schema tests.

The root-only matcher accepts a protected collection ID and full issued-version
inventory, **never caller-supplied needle bytes or partial needles**. It emits
only clean/match/incomplete, no offsets/snippets/hashes of material. Nonzero
issued versions and complete encodings are required for clean: raw, JSON,
percent hex variants, standard/URL-safe base64 padded/unpadded at all three
alignments (0/1/2). A match durably holds before acknowledgment; an unknown hold
cannot report clean. Partial coverage, malformed inputs and inaccessible surfaces
are incomplete/exit 2. Q evidence includes real case exits, effect/completeness
and encoding bounds, all six Q groups and valid/negative/plant roles; complete
metadata is not a successful native Q. Export omits raw payloads and fingerprints.
Release assets bind signed tags, exact source commits, asset digests/modes and exact regular-file archive member paths/modes/digests
(relative paths, no dot-dot, absolute path, link or special member),
independent second-build equality and the closed contract-index digest. No lab
asset is acceptable to a production release reader.

## Fixture and reproduction boundary

`wire-fixtures.json` has the reconstructed plain API-key Messages body, exact
measured headers, credential-free GET, and adjacent OAuth/credential/beta/body/
path negatives. Request bodies were **not retained**; prompt/metadata strings
here are new public synthetic sentinels. The per-message effort value is also
reconstructed: the original projection retained its field path, not its value. `probe/observed.json` retains only the
original structural observation, without timings or paths. The observed model
is claude-opus-5-5 and max_tokens is 128000; these freeze an **inert observation**,
not a live output/spend approval. A live approved bounded invocation that changes
these bytes/fields requires a reviewed new profile revision and probe, never
silent fixture normalization. G1 forwards admitted body bytes unchanged and all
eleven measured non-OAuth flags; it rejects OAuth, unknown/missing/duplicate/
case-variant flags, duplicate beta fields, TTL 1h, system clear_at or tools outside
this frozen empty-tool invocation. It never strips body fields to fit API-key
mode. Policy GET receives no injected credential and preserves real errors.

`index.json` seals every contract, probe source and fixture with SHA-256, plus
the complete profile/wire/specification/time-contract/API source bytes; its own
hash is frozen in the test. No PR commit locator is used: unchanged bytes survive
signed rebases. Changing a frozen byte is a contract revision with a new index
and consumer review, not an automatic golden update. The existing production
sealed-index tests and source pins are untouched.

Run `go test -count=1 -v ./internal/labcontractv0 ./internal/assemblyv0` in an
isolated checkout with absolute task-owned HOME/caches/TMPDIR. Outputs go to
owned scratch, not installed broker paths. See [probe reproduction](probe/README.md)
for the exact executable pin, portable harness and bounded synthetic command.

## Source-backed C review

| Decision | Binding evidence / disposition |
| --- | --- |
| Lab conflict remains explicit | `docs/lab-profile-v0.md:5`, `spec/broker.md:880`, `spec/operator-and-activation-v0.md:1137`: manual-root lab only, never production. |
| Residual direction is not C opening | `docs/lab-profile-v0.md:457`, `spec/operator-and-activation-v0.md:1143`: the dated residual act supplies no other owner's consent. |
| Exact amendment/API bytes | `docs/lab-profile-v0.md:481`, `spec/operator-and-activation-v0.md:1285` and `:1349`: extracted text pins above; all three owner roles still required. |
| Every-start and prefix join | `docs/lab-profile-v0.md:543`, `timeconf/consume_linux.go:66`: joined off-VM fence/clock, persisted manager prefix and native NTS witness remain implementation/qualification gates. |
| Existing API-key intake is not assumed | `docs/lab-profile-v0.md:178`, `docs/lab-wire-profile-v0.md:34`, `docs/lab-wire-profile-v0.md:50`: frozen API-key header/body shapes, not the existing OAuth adapter. |

The table cites current file lines; the profile's B/G/M/D aliases resolve at its
immutable source pins. C0 neither edits production specifications nor imports
an accepting consumer. Future consumer implementation must compare this exact
index digest and provide both real lab/production cross-read directions with
own-format valid controls; C0's schema discriminator pairs are not that native
integration proof.

### Error fallback observation (not an admitted profile)

The exact-client HTTP-400 control exits 1 after three local model attempts.
`probe/error-observed.json` (relative to the contract root) retains only projected
headers/shape. The second/third attempts omit thinking-token-count-2026-05-13;
the third exceeds the recorder's reviewed enum projection and therefore has no
complete body shape. The published auditor validates the initial full profile,
fixed auth/path and genuine 400 replies, reports two **unqualified retries**, and
never treats those retries as admitted API-key requests. The corresponding
missing-thinking-beta fixture is a refusal. The lab gateway must reject such
profile drift, not silently broaden the eleven-token/body contract to make an
error fallback succeed. This observation qualifies neither a fallback body nor
vendor retry behavior; live Q1 must tolerate genuine errors under the closed
profile. The successful synthetic control remains exactly GET then POST.
