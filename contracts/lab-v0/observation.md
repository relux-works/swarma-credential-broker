# C0c: manager-owned lab observation, version 1

Status: CONTRACT CANDIDATE FOR REVIEW. Construction only. The owner-delegate
2026-11-20 decision selects a narrow manager-owned capability, not a root
broker, readable ledger copy, weakened DAC/ACL or production permission.
M1 implements the server; B1 implements its sole client. This addendum implements
neither. B5 installs the exact approved manager/daemon identities and store
binding. No fixture assertion is native authority or proof of installed locking.
The lab profile's section 14/operator conflict and C-opening gates remain intact.
Book dispositions remain **OS user per agent and network** and **Operator and
interfaces**, cited in `docs/assembly-v0-construction-contract.md:35` and
`spec/operator-and-activation-v0.md:18`: narrow privileged input, distinct
process identities, and observation never grants authority. This new tagged
lab capability refines that boundary; it is not a production API amendment.

## Native source and interpretation

Source references below are to the exact broker dependency
`swarma-user-manager` `v0.0.0-20261117085123-ebea7d32a89b`:

| Native source | Constraint reused, not replaced |
| --- | --- |
| `internal/launch/store_linux.go:39`, `:79`, `:194`, `:203` | Root-owned 0700 directory and 0600 ledgers/lock. Use the existing Store.Lock and its SAME effects.lock inode, currently LOCK_EX; “shared lock” means this common serialization boundary, not a new LOCK_SH or private mutex. |
| `internal/launch/receipt.go:5`, `:10` | Receipt is attempted start only; retain execution_id, epoch, pid, start_time, boot_id, session_id exactly. |
| `internal/launch/gate.go:68`, `:81`, `:107` | Debit proves committed start; invalidation closes use. Decode entire native ledgers strictly, including partial final lines; never treat unreadable/torn as empty. |
| `internal/launch/effects.go:27`, `:78` | Native launch effect binds request/start, owner, generation, epoch, UID, executor, plan/profile and phase. Native effects revision is distinct from observation sequence. |
| `internal/launch/store_linux.go:460` | Account(generation) obtains terminal successful create/bump evidence and manager journal floor. This alone does NOT establish that an old generation is still current. |
| `internal/launch/launcher_linux.go:221`, `:249`, `:357`, `:388` | Preserve current protected identity view, complete ledgers, exact root receipt and irreversible debit joins. |
| `internal/manager/request.go:18`, `:20`; `internal/launch/request.go:24` | Native request/start identifiers are 1..64 ASCII alphanumeric-first, then alphanumeric/period/underscore/hyphen; generation is 32 lowercase hex; executor/profile IDs are 1..32 lowercase alphanumeric-first, then lowercase alphanumeric/hyphen. |
| `internal/launch/process_linux.go:320` | Native clock is boot identity plus CLOCK_BOOTTIME milliseconds, not UTC or wall-clock time. |

The (operation_id,start_id) lookup must select exactly one native launch effect,
with the protected installed owner/generation binding. No match or ambiguous
match is UNKNOWN; neither guessed generation nor newest match is permitted.
The server must read the authoritative native journal/projection, launch effects,
receipts, debits and invalidations while holding that one native lock. Validate
all full ledgers and native store envelopes before selecting a start. Preserve
the native algorithms for prefix heads and raw protected-file digests; do not
re-encode native hashes as lab hashes. Read before and after collection and
confirm identical current store objects/heads under the lock. Replacement,
rollback, unreadability or a writer not honoring the native lock is UNKNOWN.
No detached copy or separately locked cache qualifies.

## Closed surfaces and canonical limits

`surfaces.json` defines every required member, recursively. Both formats are
CCJ-1 with the existing complete C0 operator catalogue; duplicate/missing/extra/
null/wrong-type/noncanonical data refuses before join checks. Numeric values
are safe nonnegative integers; positive fields start at one. Native UID is
1..4294967294, PID/session IDs 1..4194304; start_time and boot milliseconds use
0..9007199254740991. No default, truncation, clamping or implicit UNKNOWN value.
Arrays preserve native order, never silently truncate, and have <=256 members.
A complete projected response that exceeds its size/member limits is UNKNOWN,
not a partial response. On collection/transport failure the server closes
without a success frame; no additional error schema is introduced. The client
classifies that missing answer as UNKNOWN. A digest is not independent
authentication.

| Surface | Writer → reader | Maximum payload | Exact scope |
| --- | --- | --- | --- |
| `swarma-broker-lab-observation-request/1` | B1 → M1 | 4096 bytes | format, operation_id, start_id ONLY. Native launch request ID and execution ID; no selector path, UID, generation, caller facts, plan or ledger data. |
| `swarma-broker-lab-observation-response/1` | M1 → B1 | 65536 bytes | format, operation_id, start_id, manager, store, sequence, observed_monotonic_ms, complete, start, receipts, debits, invalidations. |

`manager` binds root UID, fixed service identity, approved executable digest,
instance_id and boot_id. `store` binds an owner-installed, immutable native store
generation, current native manager head, effects revision/digest, digest of ALL
receipts for the selected generation, full debit/invalidation prefix heads,
and generation_current. The generation is provisioned once in protected manager
state, not inferred from a path/inode or minted after a read failure. B5's
protected manifest pins it with manager/daemon identities and release digests.
Missing metadata after installation refuses; no lazy initialization or reset.

`start` is the exact native effect projection: operation_id=request_id,
start_id=execution_id, owner, generation, epoch, UID, executor, plan_sha256,
profile_id, profile_sha256, phase. No outcome normalization grants liveness.
The complete native effect remains bound by effects_sha256. `receipts`, `debits`
and `invalidations` contain ALL records for the selected (generation,start_id),
including every invalidation reason; no newest-only filtering. Full source
ledgers must first decode successfully. Exactly one receipt and exactly one
debit are required for B1's committed-use admission, with no invalidation.
Zero records is explicit observed absence, not committed authority; conflicting
or duplicate records, including duplicate invalidations, are UNKNOWN.
A shape-valid invalidation-bearing fixture is a refusal control, not approval.

Join request, response and start IDs exactly, then protected expected generation,
owner, epoch, UID, executor and plan/profile. Join receipt to debit on execution,
epoch, pid, start_time and boot_id, and to manager boot/current generation.
Join every invalidation's generation, execution and boot to that same start;
ANY invalidation prevents admission. Require committed_ms <= observed time.
Store.generation_current and complete must both be true, computed from the
actual native view. Historical Account evidence, a receipt without debit,
a bool supplied by a client, or a correct plan digest alone is insufficient.
All other native caller/current authority/liveness gates remain mandatory.

## Transport and sequence

Compile the capability only with `linux && manager_lab`; the daemon client is
`linux && broker_lab`. No untagged route, environment switch, generic file reader,
root-control proxy or fallback is introduced. Endpoint is the fixed installed
`/opt/swarma/run/lab-manager/observation.sock`, AF_UNIX SOCK_STREAM. The manager
owns the socket as root with mode 0660 and the dedicated daemon group; its
root-owned parent is 0710 with that group and root-protected ancestors. Native
launch directories/ledgers remain exactly 0700/0600, with no new ACL or caps.

Before reading a request, the server uses SO_PEERCRED and requires EXACTLY the
protected, dedicated nonzero lab daemon UID. Every other UID refuses, including
0, the gateway, worker, unrelated service and a previous daemon UID. Neither
same group nor root privileges authorize a client. The client validates the
protected socket/ancestors and manager owner, SO_PEERCRED UID 0, approved manager
identity/executable/instance and boot through the protected manager binding.
Server root identity is valid; a root caller is NOT a daemon. Never trust a JSON
UID, PID, header, transmitted descriptor or caller-supplied path as provenance.

Exactly one request frame and one complete response frame per connection.
Frames use 4-byte unsigned big-endian nonzero lengths and the limits above.
The client half-closes its write side after the request; the server requires EOF
without extra bytes before responding. Zero/two frames, trailing bytes, ancillary
FDs, truncated lengths/payloads, delayed EOF or persistent connections refuse.
A single nonextendable 250 ms CLOCK_BOOTTIME deadline covers connect, peer check,
request/EOF, native lock, collection, durable sequence reservation and response.
Equality closes the deadline. No progress/idle timeout resets or retry budget.
Client verifies response observed time lies within its local request/receipt
interval, same boot; final publication is also before that original deadline.

Sequence is a positive, durable manager observation counter scoped to installed
store generation. Under Store.Lock reserve and fsync a strictly higher sequence
BEFORE sending, even if sending later fails. Every successful observation takes
a new sequence, including an unchanged snapshot. Keep the counter in protected
manager state, never in the broker's copy or a second independent transaction.
B5 provisions its initial value 1 only with the explicit fresh-store install;
this is not a runtime default or launch approval. Restart retains it; missing,
exhausted, regressed or uncertain persistence gives
UNKNOWN. Instance/boot changes invalidate an in-flight pair. Store replacement
requires a separately approved new installation, never a counter reset.

## Fresh final-publication consumption

B1 initially validates an authenticated complete observation against protected
current factory/authority pins and a durable per-store high-water. It uses that
as a tentative candidate only. Immediately before publishing ANY result that
could enable use, B1 makes a NEW connection/request for the SAME native IDs.
Require a new, strictly greater sequence than the candidate and durable
high-water, identical manager identity/store proof/start/receipt/debit/
invalidation join, current generation and complete=true, fresh CLOCK_BOOTTIME
interval and deadline; the final request interval cannot precede the first
receipt interval. No intervening blocking I/O, effect or widening work is
allowed between the final check and publication; if delayed or retried, observe
again. Persist the new high-water in B1's atomic publication record; a failed or
uncertain persistence publishes nothing and yields UNKNOWN. Concurrent uses
serialize through that native B1 commit/CAS so no sequence is accepted twice.

Any mismatch (including an unrelated native prefix change), stale generation,
replayed/regressed sequence, timeout, missing/partial answer, reconnect failure,
restart or failed local CAS is UNKNOWN, with NO material/result publication and
no automatic resend of an effect. A known invalidation likewise permits no use;
containment may proceed through independently admitted narrowing paths. Retry
is a fresh observation only, never a retry of launch.start or a ledger reset.
No copied ledger is authoritative. A local high-water is a replay floor, not
current native evidence. The manager lock ends after observation: this does not
promise future liveness or atomicity with a later manager revocation. Native
per-use currentness, revocation polling and final publication checks still apply;
this is not a replacement for those authorities or a distributed transaction.
The existing no-restore/off-VM continuity gates and accepted whole-VM snapshot
residual remain unchanged; a local generation/counter is not rollback-proof.

## Construction evidence and remaining implementation

`observation-fixtures.json` provides one synthetic committed join, a separate
invalidation, protected expected pins and monotonic interval. Shared shape
fixtures cover every nested type. Catalogue tests apply recursively to all new
members, including the request's forbidden authority/path selectors. Reference
semantic/transport/publication tests pair each intended UNKNOWN/refusal with
an adjacent valid control and source-overlay witnesses in the coverage map.
These functions live ONLY in test files. M1 must prove real kernel peers, native
locking, fsync ordering, full native decoding and protected currentness; B1 must
prove real fresh observation, atomic high-water publication and no effects on
UNKNOWN. Those native obligations, installation, owner approval, live Q and
production acceptance remain unperformed and unclaimed.
