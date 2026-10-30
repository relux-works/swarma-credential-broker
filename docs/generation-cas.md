# Inactive generation selection fixture

`internal/generationcas` implements local generation comparison and outcome
fencing on Linux. One in-memory `Coordinator` owns the mutex, current token,
attempts, canonical records, and bounded observer mailboxes shared by all its
handles. It reads a dedicated, already-retained `freshstore` account; it never
writes content or a disk current pointer. Returned selections confer no
production currentness or complete-read authority.

`NewFixture(account, limits, initial)` requires a complete canonical initial
record and validated immutable registry. Missing or empty history refuses.
Constructing another coordinator creates another synthetic world. An observer
may reconnect to the same surviving coordinator; losing that coordinator loses
the experiment. This is not durable crash recovery or rollback exclusion.

## Tokens and operations

A token carries an unexported owner, generation number and domain-separated
record digest. `Bind` accepts genuine previously issued tokens, but only
`ComparePublish` compares the full token against the current root under the
shared lock. Candidate generation must be exactly the checked successor.
Immutable `Binding.Previous` remains the unit's birth ancestry, independently of
the generation token. Selecting retained A, then B, then A is permitted in this
fixture; the original A token remains stale. This grants no production rollback
permission.

`Bind` creates the stable nonce/payload-correlated request. `Submit` reserves
four full record slots before admitting the job: reservation R, prepared
generation G, outcome O and terminal fence F. Only one unresolved attempt may
hold the fence. Exact retries reuse the same admission; a changed payload or
nonce cannot reuse its identity. Different unresolved attempts refuse.

`ComparePublish` performs the actual selection. `RecordOutcome` records its
committed decision; `Deliver` writes a bounded mailbox reference and releases
the fence. Closing an observer does not cancel a job. Lost delivery after
selection preserves the true root, commit evidence, fence and charge.
`Reconcile` reads the exact admitted records and owned job state and recovers
the terminal outcome without selecting twice. It does not assert that an old
committed selection is still current or readable.

`CancelQueued` returns `ConfirmedNoCommit` only after recording O/F and revoking
the queued ticket under the same lock. Its delayed compare cannot commit.
Cancellation after publication returns `Unknown` with `ErrPending`, retaining
the fence. An old root, timeout, closed observer or missing response alone is
never a no-commit proof. A pre-admission capacity refusal has no ticket or
no-commit acknowledgement. Postpublication failures never roll back or refund
the possibly published attempt.

## Closed records and bounds

Schema is `freshcas/1`; embedded units retain `freshstore/1`. Records are ASCII
JSON with exact lexicographic field order, no whitespace, escapes, unknown or
duplicate fields, and positive canonical decimal integers. Hashes are 64 lower
hex characters. Identifiers follow the existing bounded immutable grammar.
The initial record contains epoch, generation 1, initial manifest, installation,
kind, pin, schema, scope and a nonempty manifest-sorted complete unit catalog.
Each unit contains its binding, complete name-sorted dependency inventory,
manifest and schema. Parsers enforce declared count bounds before growing
arrays. Hash domains are each exact record kind followed by LF and the complete
canonical bytes. Payload correlation additionally binds the expected token and
complete candidate. Attempt identity hashes `freshcas-attempt/1`, LF, raw
16-byte nonce and raw 32-byte payload digest. Digests are not provenance.

All fourteen `Limits` fields are explicit positive finite inputs. Scalars are
at most 2^40 and must fit `int`. Record size is inclusively at most 1 MiB;
objects at most 4096, units/attempts 64, handles 16, coordination records 257,
and dependencies 256. Unit/read/object and aggregate byte/count bounds apply
before copying, reading or admitting records. No eviction, truncation or
recycling is available. Pending files, abandoned attempts and closed handles
remain charged. Returned inventories are independent bounded copies; callers
must not mutate inputs during a method.

Coordination records reserve full `RecordBytes` capacity, including empty O/F.
Runtime entries reserve `4096 + 1024*(Attempts+Handles)` logical bytes.
Conservative checked memory/work formulae admit the whole peak, including
transient codec copies and underlying reads. Work includes
`W0 + (Units+1)*Ws`, where `Ws` bounds an unchanged `freshstore.ReadExact`.
Construction uses at most one underlying constructor and `Units` sequential
unit reads plus one separate census; later entrypoints use at most `Units+1`
underlying calls and one census, without retaining decoded variable metadata
between reads. These are logical accounting bounds, not measured RSS, timing,
physical storage or hostile same-UID filesystem qualification.

The public errors are exactly `ErrInvalid`, `ErrForeign`, `ErrCapacity`,
`ErrFenced`, `ErrRegistryChanged`, `ErrUnavailable`, `ErrDisconnected`,
`ErrPending`, `ErrTerminal`, and `ErrState`. Underlying storage errors never
escape this vocabulary. A changed protected census refuses publication;
canonical R/G/O/F remain coordinator-owned RAM records.

## Focused validation

Use an isolated synthetic `HOME`/`TMPDIR` and bounded execution environment:

```sh
GOTOOLCHAIN=local GOMAXPROCS=2 go test -p=2 -count=1 -timeout=90s ./internal/generationcas
GOTOOLCHAIN=local GOMAXPROCS=2 go vet -p=2 ./internal/generationcas
gofmt -l internal/generationcas/*.go
git diff --check
```

Tests exercise real owned transitions and existing immutable reads, including
finite competitor schedules, A-B-A, exact-attempt recovery, protected files,
closed codec, positive/negative capacity boundaries and delayed cancellation.
Private overlay controls and full command logs belong in isolated scratch,
outside Git. These focused checks establish no production, provider, physical
durability, process, clock, receipt-serving or nonrollback qualification.
