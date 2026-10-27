# Connection request lifecycle

> **Proposed secret-free mode (inactive):** Broker material-publication fencing below is distinct from outbound use/effect fencing. Gateway and action service must retain both authorities, queued/in-flight/stream closure and effect identity/recovery; broker acknowledgment does not prove external completion.
> See [the separate contract](../spec/secret-free-mode.md#9-use-fences-effects-and-recovery).

This contract specializes profile sections 4.1, 4.2 and 7. Request IDs correlate
outstanding calls on one negotiated connection; they are not replay authority.
Lease IDs and durable terminal receipts retain their separate lifetime.

| Transition | Bookkeeping and synchronization |
|---|---|
| Received | The reader records arrival at the first header byte. Framing, method and typed parameters must validate before admission. Malformed requests close without an ID reservation, waiter, operation or response. Hello is synchronous and precedes asynchronous admission. |
| Received to admitted | Under the connection pending-map mutex, reserve the ID with a distinct call identity and charge one of 128 outstanding slots. IDs must be unique among outstanding calls only. A still-outstanding duplicate or full map closes the connection immediately; admission never waits behind a blocked response. The same mutex serializes admission with final nonblocking socket-write completion. Never hold it while polling for socket readiness, waiting for the writer, or performing blocking I/O. |
| Admitted to pending | Add a handler to the connection completion group. Account admission takes its cancellable state lock, checks the original deadline and charges the account pending operation and individual waiter. Joining a renewal reuses its operation and adds only a waiter. Status has no account operation or renewal waiter. |
| Pending to response-ready | The single account worker dequeues FIFO under the account lock, clears the consumed queue pointer and retains running occupancy. On completion it removes the operation and its waiters under that same lock while handing off buffered results. Later account admission cannot observe stale completion counts. No new owner refresh starts without live demand. |
| Response-ready to writing | Acquire the single connection writer token within the original arrival budget. Register final publication under the account/policy fences after owner I/O and final authorization checks, then release those state locks before writing. Generation-only responses use the policy publication registration. Writer admission, publication registration and account operation occupancy are distinct resources. |
| Frame fully written to retired | A complete frame ends the outstanding call. Retire its ID and outstanding slot in the same pending-map critical section as the final successful nonblocking socket write, while still holding the writer gate. A peer may immediately reuse the ID after consuming the frame. Admission cannot inspect the map between the kernel accepting the final byte and retirement. Readiness polling releases the map mutex, so an incomplete blocked frame cannot delay genuine duplicate or overflow refusal. Handler fallback retirement checks call identity, so an older handler cannot remove a successor using the same ID. |
| Retired to handler exit | Stop remaining cancellation callbacks and leave the handler completion group. The completion group protects connection shutdown; it is not the outstanding-ID limit. Identity-checked retirement is idempotent. No response or account work is admitted by handler cleanup. |
| Refusal before admission | Malformed envelopes, outstanding duplicates and connection overflow close without reserving a new slot or starting account work. Typed application refusals after admission use the same response/retirement path as successes. |
| Deadline or cancellation | Preserve the original arrival deadline through registry contention, account admission and writer admission. A disconnected or expired waiter is detached under the account lock. Its capacity remains charged until detachment. The final waiter of non-running work removes both the pending-map entry and physical FIFO pointer, preserving survivor order. Running work retains occupancy until reconciliation finishes; cancellation never authorizes another refresh. Failure before a response also retires only that handler's own ID. |
| Revocation or failed write | Release/replacement close new publication admission, revoke registered writes and wait outside state locks for callbacks to stop before durable acknowledgement. Expiry clamps the write deadline. Revocation expires only the active write deadline; a completed frame keeps the connection. Stop or join the interrupt before another response may install its deadline. An incomplete/failed frame closes the transport before releasing the writer gate, so no later frame appends bytes to it. Publication registrations remain until callback/interrupt cleanup is confirmed, independently of ID reuse. |

The account bounds are 256 active leases by default, 64 pending operations by
default, two response waiters per operation and 128 waiters per account. Active
capacity is checked with expired/released records excluded. Operation admission,
joining, dequeue, completion and detachment update their counters under the same
account lock; a running operation cannot lose its slot merely because its last
waiter leaves. Physical canceled queue entries are reclaimed with their map
entries. The wake channel holds at most one notification. The server separately
caps accepted connections at 256 under its connection mutex and retains each
connection slot until its handlers have stopped.

No account/policy state lock crosses socket, owner or filesystem I/O. The
connection pending-map mutex covers only a nonblocking socket syscall and its
completion bookkeeping; it never covers readiness polling or other blocking I/O.
Writer waits observe cancellation and the request's own deadline, and never
hold one of those state locks. Release and policy replacement preserve durable ordering and wait for
revocation outside state locks. Connection close cancels outstanding waiters;
accepted durable work still follows owner recovery rather than disappearing
with its response correlation.
