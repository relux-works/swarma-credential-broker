# Protected record size and refusal

`store.MaxRecordBytes` is the inclusive 1 MiB (1,048,576-byte) ceiling shared by
both protected readers and all record publication paths. It applies to the
exact bytes produced by `wire.Encode`, after JSON encoding, base64 expansion
and canonicalization. It is not a limit on an input string or byte slice.

`Account.Put`, `Account.Append` and the internal replacement writer refuse
oversized bytes before opening a temporary file, writing, syncing or renaming.
Put and Append serialize once and publish the same bytes used for validation;
a changing JSON marshaler cannot substitute a second encoding. Initial store
and account identity markers are encoded and checked before creating their
directories or locks. The installation policy watermark uses the same guarded
replacement path. The read ceiling and existing revision/protection checks
are unchanged. This is a stored-byte limit, not a serialization memory budget.

Oversize publication returns `store.ErrTooLarge`, identifiable with
`errors.Is(err, store.ErrTooLarge)`. It also wraps `store.ErrUnavailable`, so
`errors.Is(err, store.ErrUnavailable)` remains true for generic closed-state
handling. It is distinct from `store.ErrConflict`, which identifies revision or
immutable-name conflicts. Other validation failures retain their existing
error behavior. Already-oversized files remain unreadable; this change neither
repairs nor truncates them.

A refused oversized record leaves its previous bytes and directory entries
unchanged, with no temporary file or durability callback. In particular, a
failed append does not evict history to make room, and an oversized update is
not a reason to advance a revision or retry the same value automatically.

## Existing caller handling

The store refusal does not require a new wire error. Existing callers treat
publication failures as unavailable and preserve their current closed state.

| Writer and caller | Handling of a size refusal |
| --- | --- |
| Store/account identity initialization | Size preflight returns the refusal before directory/lock creation or synchronization. Callers receive an error, without a store/account result. |
| Policy watermark through `lease.New` | Constructor returns the error before publishing a manager or starting workers. |
| Policy watermark through `Manager.ReplacePolicy` | Marks policy authority failed, retains the previous policy and returns `lease_owner_unavailable`. |
| Put during `lease.New` recovery of expired records | Cancels construction and returns the error; no worker or manager is published. |
| Put through lease `Manager.persist` | Marks the account failed and returns `lease_owner_unavailable`; the in-memory record is published only after a successful store write. |
| Put through auth-owner `Engine.checkpoint` | Blocks the account and returns owner unavailable; the in-memory checkpoint advances only after success. |
| Append through auth-owner `appendIntent` / `appendEvidence` | Blocks the account and returns owner unavailable; does not publish the refused intent/evidence in memory. |
| Put/policy initialization in qualification `ownerSeed` | Propagates the error to the bounded synthetic fixture driver, which tears down its scratch state and grants no successful row credit. |
| Daemon store/manager construction | Returns unavailable and exits through its existing error path; it does not run with a partial constructor result. |

No inspected caller panics, ignores these writer errors or automatically retries
an oversized publication. Owner and lease account failures remain closed under
their existing recovery rules; callers do not gain authority to shorten or
discard durable history.

## Scoped checks

`internal/store/size_linux_test.go` covers base64 expansion beyond the ceiling,
exact-limit round trips, limit+1 refusal for all three record writers, unchanged
bytes/listings, zero filesystem write events and zero durability stages. It
also covers single-encoding publication, identity preflight and an oversized
watermark. Fixtures contain only synthetic metadata. Existing store durability,
revision, protection and immutable-append tests remain applicable.

Run the focused checks with `go test -race ./internal/store`; apply the host's
resource wrapper where required. Logs belong in private scratch, not protected
records or the repository. Caller recovery checks belong to the lease,
auth-owner and qualification packages; a passing store test alone does not
qualify a live owner or production release.
