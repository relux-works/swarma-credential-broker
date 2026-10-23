# Codex refresher v0 profile

**Status: proposed, inactive; pending independent review and curator content review.**
This is a normative implementation target, not a supported-release claim. MUST,
MUST NOT and SHOULD bind an implementation that advertises this profile after
its rulings and qualification gates are accepted. No implementation ships here.

## 1. Scope and relationship to the broker

This profile extracts the slice-1 Codex auth owner and external-token delivery
from [the broker specification](broker.md#9-codex-auth-owner), ahead of the
slice-0 delivery order in [§16](broker.md#16-delivery-order). Its sole purpose is
N concurrent leases on one ChatGPT account with exactly one refresher on one
Linux machine. Multi-account structure is retained, but qualifying independent
accounts is not the v0 acceptance target. It does not deliver slice 0 or change its
acceptance criteria. The existing specification remains authoritative for the
full broker. The proposed exceptions below MUST NOT be advertised as full broker
compliance or admitted through its ordinary negotiation.

[§3.1](broker.md#31-first-consumer-and-execution-boundary) still selects
`curator-run` as the platform's first broker consumer. The temporary runner in
§6 is a standalone executor for this profile, not a replacement for that
platform boundary. CIP-0010 C2's `codex_cli` personal row defines the selected
channel: app-server external tokens, no launch credential file, ephemeral
credential storage. C1's file backend is retained. C3's conflict, effective-source
and child-inheritance qualification gates remain. This extraction does not
satisfy C7's cross-user slice-0 milestone.

| Deferred scope | Owning broker section / disposition |
|---|---|
| Signed grants, delegation, revocation and bindings | §§6–8; slice 0 |
| Dispatcher, user-manager admission ledger and platform executor integration | §§3.1, 4.2, 16; slice 0 |
| Phone/terminal operator command, observer commands and platform alert delivery | §§11, 14, 18.15, 18.22; slice 0 or later as specified there |
| Platform R-ALLSTOP, R-UNTRUSTED and fenced restoration integration | §§8.2, 15.4–15.5, 18; unavailable in this standalone extraction, required for platform activation |
| Network profiles, enforced egress and resolver isolation | §§5.5, 15.2, 16; slice 2 |
| macOS containment and platform qualification | §§9.6, 15; deferred here, still required for full slice 1 |
| Other providers, API keys and Business/Enterprise tokens | §§5.2, 10; outside this profile |

The static profile is for explicitly trusted local processes only. It MUST NOT
admit untrusted workloads or claim dispatcher admission, revocation, cross-user
store isolation in same-user mode, or node-wide containment. Accounts requiring
a network profile MUST refuse `lease_network_enforcement_unavailable` rather
than silently ignoring that requirement.

### 1.1 Decisions requiring curator disposition

- **R1 — pending curator ruling R1:** static operator-owned UID/account policy
  replaces grants, bindings and their generation checks for this extraction
  (§2), narrowing the deployment but differing from §§4.2, 7–8 and 13.2.
- **R2 — pending curator ruling R2:** same-user operation is permitted only with
  the explicitly weaker guarantees in §2.1; it differs from §§3, 12.1 and 15.1.
  The Linux user-manager containment proposed here is an interim realization,
  not qualification of the system-unit or macOS deployments in §15.2.
- **R3 — accepted curator ruling:** fresh-home device-code enrolment by the owner
  in §3 preserves §9.2; no adoption is allowed. Platform operator-command
  integration in §14 remains deferred. Enrolment is never a runner RPC.
- **Confirmed scope:** extraction ahead of slice 0 and the standalone headless
  app-server runner are included. This does not change the platform first-consumer
  boundary (§3.1). Linux user-manager containment, distinct profile negotiation,
  static lease ownership, queue/fairness limits and the exact qualification
  record below are implementation choices submitted for content review; no
  additional named curator ruling is invented for them.

No pending ruling authorizes real-account tests. Separate explicit curator
approval and an owner-controlled account are required for those tests. The
existing native login MUST remain intact during research and qualification
planning; only an explicitly approved maintenance cutover may retire it.

## 2. Interim authority and identities

**Pending curator ruling R1.** The daemon MUST load a protected static policy
containing a never-reused random installation ID, monotonic policy generation,
configured broker UID, approved executable absolute path and SHA-256 digest,
finite maximum lease duration (default 3600 seconds), and account entries. Each
entry contains its public account label, expected vendor account ID after
enrolment, exact allowed peer UIDs and profiles, inference endpoint, approved
release tuple, and enabled flag. No request-supplied UID grants authority.
Changing this policy is an operator action outside this socket subset.

The daemon MUST obtain `SO_PEERCRED` on every connection, fail
`peer_identity_unavailable` if unavailable, and authenticate the connecting UID.
A UID absent from every enabled entry receives `role_not_permitted`. A known
UID must first be admitted to the requested profile; otherwise refuse
`lease_not_authorised`. Only then check account existence
(`lease_account_unknown`) and its exact UID/account allowlist
(`lease_not_authorised`). This order bounds account enumeration to peers already
admitted to that profile; no unauthorized peer can probe account existence. Clients MUST verify the server UID before sending data
(`server_identity_mismatch`). Connections MUST be close-on-exec, never inherited
or passed, and closed before credential transitions ([§4.1](broker.md#41-peer-identity-and-connections)).

The policy generation, enabled flag, peer/account/profile allowlist, executable
and endpoint checks MUST be repeated immediately before every material release,
including after refresh. Policy replacement invalidates all old-generation
leases and connections; it cannot widen a lease. Reconnection by the owning UID
may renew only a persisted, active lease in the same installation and policy
generation. UID recycling MUST occur only after removing that UID from policy,
invalidating its leases, closing its connections and stopping its launches.
This manual operating constraint is weaker than generation-bound platform
principals; deployments that cannot enforce it MUST remain inactive.

Reads reveal only accounts allowlisted to that peer. `status` MUST contain no
material, token hashes, raw vendor errors or filesystem locations. No operator
or observer role is inferred from this interim read permission.

### 2.1 Interim run identity

**Pending curator ruling R2.** The daemon MAY initially run as the same OS user
as its launches. For cooperative approved processes, the account lock and
lifecycle gate establish a single writer; launch homes hold no `auth.json`;
access tokens travel only in private pipes and process memory, never argv,
credential files, diagnostics or logs. Refresh tokens remain only in the
broker-owned file store and its approved vendor writer's memory.

Mode 0700 directories and 0600 files do **not** isolate the store from a launch
with the same UID. Such a process can read or alter the store, contact the same
user manager, or violate the single-writer policy. No protection against a
malicious same-UID process, root, debugger or compromised daemon is claimed.
Dedicated service-user isolation remains the required platform target. Appendix
A prepares that transition; permission changes alone do not make same-UID
operation isolated.

## 3. Enrolment and existing logins

**Accepted curator ruling R3.** A person requests
`swarma-credential-broker enrol codex_cli --account <label>` outside any agent
session, with exact account confirmation. The operator authenticates through an
administrative path distinct from the lease socket; the complete §14 operator
command remains deferred. No `account.enrol` method is exposed by §7.

Before **every** vendor child, including enrolment and re-enrolment, the daemon
MUST acquire the account lock, resolve every previous writer and persist the
attempt intent in §5. It creates a fresh 0700 broker-owned Codex home, pins
`cli_auth_credentials_store = "file"`, and invokes the approved executable's
device-code flow. The executable path and digest MUST be checked immediately
before service-manager launch; a writable executable or ancestor is refused.
The child environment MUST be constructed from an allowlist with explicit HOME,
CODEX_HOME, locale, minimal PATH and approved routing settings. It MUST exclude
inherited credentials, helpers, endpoint overrides and user configuration.
Verification URL/code relay is restricted to the initiating person's private
administrative channel, never audit or status output.

After the vendor completes login, the daemon reads its own newly created store,
validates the vendor account ID and refuses `account_duplicate` if another
broker label maps to the same vendor account. The candidate MUST NOT become
active on refusal. Duplicate checking is serialized with account publication;
a provisional login is a writer subject to the same lifecycle gate. Before
starting a candidate whose vendor identity is not yet known, a daemon-wide
enrolment gate MUST close refresh admission and wait for all admitted writers
to resolve. Candidates are serialized; no account lock is held while waiting
for another account's writer. Reopen refresh admission only after candidate
identity, duplicate disposition and writer absence are resolved. Thus a new
label cannot hide a second writer for an already enrolled vendor account.
Existing
account labels refuse `account_exists`, except an explicit re-enrolment operation
that preserves the account label and invalidates every old lease.

The broker MUST NOT adopt an existing home, copy or strip an existing login,
export a keyring item, or infer identity from a label. A person already logged in
elsewhere on the machine MUST follow the maintenance cutover below and
re-enrol through this fresh-home ceremony. Old homes are not automatically read
or modified. Afterwards, **nothing else may refresh that vendor account on the
machine**, including interactive Codex, maintenance or another broker label
([§9.5](broker.md#95-other-consumers)). An unresolved external writer blocks
enrolment; vendor identity discovered to conflict after login holds the candidate
unavailable rather than publishing a second owner. Multi-machine ownership is
unsupported.

### 3.1 Cutover from a shared native login

The owner controls a maintenance window. The order is **new broker enrolment →
move launches to the runner → retire the old native login**. Preserving the old
login during preparation is not permission to leave its refreshers running.
The new enrolment is a distinct vendor login, not a copy of the native login;
the same vendor account still has only one admitted live refresher at a time.

1. **Prepare without touching the live login.** Inventory every old consumer,
   launcher, restart/watch path and native-login writer. Stage the reviewed
   daemon/runner, complete fake qualification and record the approved executable
   and routing. Verify R1/R2 disposition and live-test approval before proceeding.
   Do not inspect, copy, refresh or revoke the existing credential file as a
   qualification shortcut. If no maintenance window is authorized, stop here
   with a reviewed cutover plan and keep the current login unchanged.
2. **Quiesce old refreshers before enrolling.** Close old launch/restart
   admission; drain running launches only while the new broker owner is still
   inactive, then stop every old app-server/CLI and confirm its descendants
   absent. A running old launch that might refresh MUST be parked and stopped;
   it cannot bridge the cutover using its old login. Keep its transcript/task
   snapshot for a later fresh start. Record a complete inventory and confirmed
   absence. Unreadable inventory, an unreachable consumer or surviving writer
   aborts enrolment. The native login remains on disk, untouched and unused.
3. **Owner enrols the new broker login.** Perform accepted R3 device-code login
   into the fresh broker home, under intent/containment. Verify the expected
   vendor account ID, unique broker mapping and complete writer resolution.
   Run the approved live portions of §8 against this new login while ordinary
   leasing remains closed. Never permit the old native consumers to restart.
   If enrolment or qualification fails, remain closed or return to the old path
   only after stopping/confirming every new writer and explicitly abandoning
   broker admission. Never repair failure by copying either login.
4. **Move launches to the runner.** After the exact 0.163.0 tuple becomes
   qualified, enable the broker owner, switch every launcher to §6, verify no
   launch-home credential file and perform one canary followed by the specified
   N-caller acceptance. Resume parked work only through a new lease/external
   login, with qualified thread resume or a restart from the task snapshot. The old
   login remains inert; no native launch or independent maintenance refresh is
   allowed. An old-mode launcher discovered here is disabled and its launch
   stopped before any further admission. Unknown inventory closes admission.
5. **Retire the old shared login last.** The owner uses the vendor-supported
   retirement procedure after verifying every launcher and standing/restart path
   uses the runner and that no old consumer survives. Do not blindly run a
   vendor-wide logout/revoke operation: first establish whether it would also
   revoke the new broker login. If the vendor cannot retire only the old login,
   leave it inaccessible to disabled old consumers until the owner chooses a
   safe revocation/re-enrolment procedure; report retirement pending, never
   claim cutover accepted. Verify the new broker login still works and record
   sole-refresh ownership. No later rollback may reactivate the native path
   concurrently with the broker owner.

A cutover record contains phase, expected vendor account ID, old-consumer
inventory/absence verdict, launcher configuration digests, new enrolment and
qualification references, canary/load results, old-login retirement disposition
and owner acknowledgement, without tokens or credential-file contents. Each
phase is durable before its successor; interruption holds admission closed until
its evidence is reconciled. Real-account/vendor-specific retirement semantics
remain an owner-approved qualification step, not an assumed command.

## 4. Auth owner and renewal

The daemon MUST hold a singleton lifetime lock and a stable per-account lock
beside the vendor home. Lock files MUST NOT be replaced or unlinked during
operation. The account lock covers read, attempt admission, vendor execution,
confirmed absence, reload and outcome resolution. The vendor does not honor
this lock: §5 is mandatory even after a replacement daemon reacquires it.

An approved **managed-auth** app-server in the broker home refreshes via
`account/read { refreshToken: true }`, after `initialize` and `initialized`.
The broker MUST run the vendor executable; it MUST NOT implement the OAuth token
exchange itself. The access token MUST be reloaded from the durable vendor store
after writer resolution. In **external-auth** mode the same account/read flag
is ignored; that mode is exclusively the launch side in §6.

Default proactive window is 48 hours before known token expiry. The window is
configurable per qualified release and MUST NOT invent an expiry or create an
infinite refresh loop when vendor lifetimes are shorter. An unknown expiry
requires release-specific validity evidence; absent that evidence, issuance
refuses `lease_owner_unavailable`. Scheduling and lease limits MUST use trusted
time, durable watermarking and conservative expiry as in
[§15.1](broker.md#151-service-user-and-time); missing time/restore evidence
refuses material. Proactive work has the same intent and recovery gate as
reactive work. A refresh must replace a rejected token; unchanged material is
`renew_failed`, not successful renewal.

Renewal first checks `rejected_sha256` against **that lease's** bounded delivery
history, then against the current owner token, under account serialization.
Retain the most recently offered token digest and the client-observed digest
from its last admitted renewal. Updating an offered token MUST NOT erase the
client-observed digest until that client presents a newer offered digest. This
lets a reconnect retry a lost response without an unbounded history or token
copies; an arbitrary, never-offered digest is not admitted.

1. A malformed digest or one outside that lease's retained history refuses
   `renew_not_current`, without starting a writer or changing account state.
2. If the lease's rejected token is already superseded by a valid owner token,
   return the current token after final admission checks, without refreshing.
   This intentionally accepts an old, previously delivered digest; “non-current”
   does not mean that every concurrent caller after the first must fail.
3. If it equals the current owner token, join the existing attempt for that
   token or admit exactly one attempt. N distinct leases rejected with the same
   token MUST cause exactly one refresh, not N sequential rotations.

The daemon retains the current owner token digest and at most two history
digests per lease in protected state; they MUST NOT appear in status, audit or errors. Account
work is independent; no account lock waits for another account lock. The pending
queue is bounded to 64 pending lease operations per account by default; joining
an attempt also uses one slot per lease. A full queue returns `renew_timeout` without launching a child.

### 4.1 Many-launch bounds, fairness and bookkeeping

The default active-lease limit is 256 per account, an explicit static authority
limit; further lease requests refuse `lease_not_authorised` until a slot is
available. Each launch has its own never-reused lease ID and durable record,
bounded delivery history, finite authorization limit and terminal
state. Same-UID launches do not share a lease record, and release/timeout of one
lease MUST NOT end another. A peer owning the UID can intentionally act for any
of its leases; this is not isolation between same-UID sessions.

There is at most one pending renew operation per lease. Duplicate concurrent
renewal calls for that lease join that same operation and keep separate response
correlations/deadlines; they do not consume unbounded queue entries or start
another writer. The daemon caps response waiters at two per pending lease operation (128
response waiters total), refusing excess with `renew_timeout`. Disconnected/expired waiters are removed;
an abandoned lease retains its finite authorization limit, never an implicit
renewal. Expired/released records cease counting toward active capacity before
new admission, with tombstone retention as in §5.1.

Account work uses FIFO admission among lease requests and renewals, with at most
one queued operation per lease. Current-token renewals join the admitted
same-token refresh immediately within queue capacity; they do not queue new
rotations. Proactive refresh coalesces with that attempt and cannot jump ahead
of admitted demand or run repeatedly while demand waits. Deadline order is
checked on admission and dequeue; it does not let a late caller displace an
earlier one. Under finite arrivals and available capacity, an unexpired waiter
cannot be overtaken indefinitely. Bounds are not a guarantee of success under
unbounded load: overflow or deadline exhaustion refuses promptly and never
returns stale or late material.

Qualification targets **one account**, with N=8 and N=64 simultaneous launches,
plus N=65 to exercise queue overflow, maximum active-lease admission, late
waiter removal, duplicate-call caps, lost-response reconnect and FIFO progress. All rejected-current-token
callers admitted before the cutoff observe exactly one refresh. Per-request
arrival/dequeue/response monotonic timings, queue occupancy, writer concurrency,
lease IDs and token-generation counters are measured without material or token
hashes. Many-lease release/reconnect/expiry tests MUST show no cross-lease mutation.

### 4.2 Deadlines and state transitions

The renew deadline defaults to 8 seconds **from broker request arrival**,
including queueing, lock wait and I/O; it MUST be below the selected app-server's
10-second callback bound. The runner MUST reserve transport/error-reply time
within that bound and use an earlier local cutoff if needed. Deadline expiry
returns exactly one `renew_timeout`, and removes that waiter. A safely contained
attempt may still resolve its history and durable store, but MUST NOT deliver a
late success or trigger a retry merely because a waiter expired. Disconnection
and cancellation follow the same no-late-delivery rule.

| State | Admission and transitions |
|---|---|
| `active` | Usable, known-valid token and resolved writer. Refresh success durably publishes the new token generation and remains active. |
| `refresh_failed_transient` | Only conclusively safe non-rotation failure, with prior writer absent and durable store reconciled. A still-valid token may be leased; a rejected token is not returned as renewal success. Retry after 1, 2, 4, … seconds, capped at 60 seconds, only with the lifecycle gate. Success returns active; expiry blocks delivery. |
| `reauth_required` | Conclusive refresh-token rejection, or operator chooses fresh enrolment after ambiguous rotation and confirmed absence. Refuse `lease_reauth_required`; only explicit fresh-home re-enrolment can return active. |
| `owner_unavailable` | Stopped owner, unresolved child, missing/rolled-back store, unreadable evidence, or ambiguous rotation. Refuse `lease_owner_unavailable`; recovery may return active only with complete safe evidence, or move to reauth_required after confirmed absence. |

A client rejection alone changes no account state. Timeout, generic vendor
failure and child exit alone cannot prove that no rotation occurred. Unknown
outcomes enter `owner_unavailable`, never the transient retry loop. There is no
fallback to native login, another account, API key or direct OAuth exchange.

## 5. Linux writer containment and recovery

This profile proposes transient **services** under the daemon's systemd user
manager. It MUST NOT use a detached process, scope, shell background job or PID
probe as a substitute. Each account attempt has a never-reused unit name
`swarma-credential-broker-writer-<attempt-id>.service`. The daemon itself runs
in a named user service in the **same manager**. Each child unit MUST set:

```ini
Type=exec
KillMode=control-group
SendSIGKILL=yes
TimeoutStopSec=2s
RuntimeMaxSec=120s
RemainAfterExit=yes
Delegate=no
NoNewPrivileges=yes
ProtectControlGroups=yes
StandardInput=null
StandardOutput=null
StandardError=null
BindsTo=swarma-credential-broker.service
After=swarma-credential-broker.service
PartOf=swarma-credential-broker.service
```

The managed app-server's private pipes replace the null standard streams using
service-manager FD passing; the unit properties MUST NOT contain tokens or
serialized token-bearing RPCs. Device enrolment may use a separately qualified
finite runtime (default 15 minutes) and private administrative pipes. Numeric
limits are maximum containment bounds, not renewal deadlines. Expiry closes
waiters promptly while lifecycle resolution proceeds separately. Startup MUST
refuse readiness if required properties, private FD handling or manager
capabilities cannot be applied. All writers and descendants MUST remain in the
recorded cgroup; cgroup migration/delegation is forbidden for the approved child.
This is a trusted-vendor lifecycle boundary, not hostile same-UID containment.

The daemon durably records intent before asking `StartTransientUnit` to create
the unit. It uses the recorded name for lookup after an uncertain manager reply;
no second name or new attempt is allocated. A child cannot run before the
manager has attached it to its unit cgroup. The singleton replacement fence
closes all refresh admission before any recovery I/O. `BindsTo`/`PartOf` prompt
stop when the daemon becomes inactive or is stopped; replacement MUST also
reconcile units itself. Automatic dependency stop is not an absence certificate.

### 5.1 Protected records and ordering

All records are versioned canonical JSON, mode 0600, in 0700 account directories;
use temporary-file write, file fsync, same-directory rename and directory fsync.
No record contains an access/refresh token; material stays in the vendor home.
Each transition is monotonic, fenced by installation ID, daemon instance ID,
policy generation and expected prior record revision. A state lock MUST NOT be
held over service-manager or vendor I/O ([§13.1](broker.md#131-transport)).

| Record | Required members / meaning |
|---|---|
| `attempt-intent/1` | `installation_id`, `account`, `attempt_id` (random 128-bit), `revision`, `operation` (enrol/refresh/re-enrol), `daemon_instance_id`, `policy_generation`, `boot_id`, `manager_uid`, `manager_epoch`, `unit_name`, `executable_sha256`, `vendor_home_id`, `store_generation_before`, `token_generation_before`, trusted creation time, deadline, phase `intent`. Durable before child admission; never contains request material. |
| `attempt-evidence/1` | Same attempt binding and increasing revision; phase `submitted`, `running`, `stopping`, `absent` or `resolved`; manager `InvocationID`, cgroup path/identity, service `MainPID` plus process start time (diagnostic only), verified property digest, observation boot/manager epoch, complete read result, stop result, unit active/substate/result/exit status, recursive cgroup `populated`/membership observation, observation times, absence verdict `confirmed` or `unknown`, outcome `committed`, `safe_no_rotation`, `reauth_required` or `unknown`, store generation after if known. |
| `account-checkpoint/1` | Installation/account/vendor identity, account state, last resolved attempt, local store/token generations, policy generation and watermark; committed only after the vendor file is durably flushed and outcome is reconciled. |
| `lease-record/1` | Random lease ID, installation ID, peer UID, account, profile, policy generation, credential-binding digest, launch ID, authorized_until, last-offered token generation/digest, client-observed digest, state active/released/expired; no payload. |

Evidence is append-retained through resolution; replacing the current index
MUST NOT erase unresolved intent. Unit names are never reused. Completed units
are retained until their terminal evidence is durable, then stopped/unloaded;
unit collection is not permission to erase recovery evidence. Storage bounds
MUST close new attempt admission before discarding unresolved evidence.
Resolved attempt evidence remains until explicit account retirement while closed;
lease tombstones remain until their IDs are permanently inadmissible.

A complete manager observation MUST bind the original attempt, boot, manager
epoch and InvocationID, verify the unit cannot restart (`Restart=no`), stop it,
wait for stop completion, and establish no remaining processes in its entire
cgroup subtree. Prefer a readable recursive `cgroup.events populated=0` plus
empty membership; removal of a previously verified cgroup after a correlated
successful stop and complete manager readback is also admissible. `not-found`,
missing path, PID absence, timeout, permission error or partial enumeration
**alone** is `unknown`. After a boot/manager-epoch change, record loss or
contradictory identity, automatic recovery MUST stay unavailable until an
operator establishes a complete old-writer inventory and absence; this profile
does not equate a new manager's empty list with historical absence.

After absence, reload the durable vendor home and reconcile the outcome. A
successful vendor response, consistent replacement store and token/account
identity can resolve `committed` only if all required persistence completed.
`safe_no_rotation` needs positive evidence that the request never reached the
exchange, or an exact-release conclusive non-rotating response, together with
consistent store evidence. A changed file, exit zero, unchanged file, or token
expiry alone is insufficient. If external rotation could have succeeded before
persistence, hold `owner_unavailable`; do not retry. Fresh re-enrolment becomes
available only after writer absence is confirmed. Store absence or rollback
cannot be repaired by recreating an empty login and retrying refresh.

These records publish the v0 proposal for [§18.10](broker.md#18-open-questions).
They do not close it for the full broker: manager-epoch persistence, complete
FD-passing implementation, dependency-stop behavior, vendor outcome durability,
rollback reconciliation and every §9.6 scenario still require executable
qualification. No same-store counter can detect its own rollback. Supported
restore MUST close admission outside the restored store before replacement;
missing independent freshness/reconciliation evidence keeps the account
unavailable. Silent hostile rollback detection is not claimed.

## 6. External-token delivery and one-shot runner

Proposed public command (not yet implemented):

```text
swarma-credential-broker run-codex --account <label> --profile <profile> --launch-home <directory> (--prompt-stdin | --prompt-file <file>) --model <model> --reasoning-effort <effort> --output-last-message <file> [--cwd <directory>] [--timeout <seconds>] [--resume <thread-id>]
```

This live executor MUST verify the protected static tuple of peer UID, account,
profile, endpoint, executable digest and policy generation before requesting a
lease and again before starting the harness. A self-declared capability is not
authority. It starts no shell and uses no `codex exec`. Exactly one prompt source is required: `--prompt-stdin` reads UTF-8 to EOF;
`--prompt-file` reads one regular UTF-8 file without following a symlink.
Invalid UTF-8, a missing source, both sources, unknown options or nonpositive
timeout refuse with status 64 before lease/harness start. Prompt size is bounded
to 1 MiB. No credential CLI flags are defined.

`--model` and `--reasoning-effort` are required and forwarded as the selected
model and `turn/start.effort`; no silent model/provider or effort substitution
is allowed. The 0.163.0 schema represents effort as an advertised nonempty
string, so the runner validates it against the qualified model catalog rather
than inventing a fixed enum. Unsupported combinations refuse 64. `--cwd`
defaults to the caller's current directory; `--timeout` defaults to 300 seconds
and bounds initialization plus the turn (cleanup has its separate bound).

`--output-last-message` is required. On successful turn completion and cleanup,
write the concatenated final assistant-message text as UTF-8 by temporary-file
replacement in the destination directory, mode 0600. Refuse symlink destinations
or an unwritable directory before requesting a lease. On failure, leave an
existing destination unchanged and remove the temporary file; do not publish a
partial result as success. Output-file failure is status 75. Standard output is
reserved for assistant text deltas; diagnostics go to stderr as sanitized typed
metadata. Prompt/model/output options carry no credential. A launcher may rely
on exit 0 plus the output file; a turn-start response is not completion. Launch and working directory configuration
MUST NOT enable a native login, helper, alternate provider or arbitrary MCP/hook
that can obtain credentials. Product execution permissions remain the caller's
separate responsibility; credential admission grants none.

The runner MUST reserve `CODEX_ACCESS_TOKEN`, `CODEX_API_KEY`, `OPENAI_API_KEY`,
`OPENAI_API_BASE`, `OPENAI_BASE_URL`, `CODEX_AUTH`, credential-bearing provider
`env_key`/`http_headers`/`env_http_headers`, auth helpers and all login/refresh
endpoint overrides. Any configured or inherited competing source, including an
empty but explicitly supplied credential variable, refuses
`credential_source_conflict`; it is never silently cleared to make the launch
pass. A preexisting launch-home `auth.json`, including a symlink, refuses that
same code **without reading it**. Unreadable source/config inspection refuses
`credential_injection_unavailable`, never “absent”. Other selector overrides,
provider changes or executable drift refuse before lease/harness start.

Execution ordering:

1. Validate conflict-free launch home and approved configuration; open a fresh
   server-UID-verified broker connection; negotiate §7; obtain the lease.
2. Start a private per-execution `codex app-server --listen stdio://` using the
   pinned executable, private pipes, explicitly selected launch HOME/CODEX_HOME,
   `cli_auth_credentials_store = "ephemeral"` and a sanitized environment. No
   broker socket descriptor or token is inherited by this child.
3. Send `initialize` with clientInfo name/version and
   `capabilities: { experimentalApi: true }`; wait for success, then send
   `initialized`. Send `account/login/start` with `type: "chatgptAuthTokens"`,
   `accessToken`, `chatgptAccountId`, optional `chatgptPlanType`. Match the lease's
   account exactly. Any failure is `external_token_init_failed`.
4. Use `thread/start`, then one `turn/start` with the prompt. Stream permitted
   output, consume all protocol events, and wait for matching `turn/completed`.
   Only status `completed` means turn success; failed/interrupted is failure.
   Headless approval requests MUST receive a deterministic denial unless a
   separate explicit execution policy permits them; never wait for terminal input.
5. On `account/chatgptAuthTokens/refresh { reason: "unauthorized",
   previousAccountId? }`, verify any previousAccountId matches the current lease.
   Call `lease.renew` using the digest of the last token supplied to that server.
   Verify renewed account identity before replying once to the original server
   request ID with `accessToken`, `chatgptAccountId`, optional `chatgptPlanType`.
   On broker refusal, local cutoff or mismatch, reply with a sanitized JSON-RPC
   error, explicitly interrupt the turn and enter teardown immediately. The
   vendor may retry after an unanswered refresh; the runner MUST NOT wait for
   those retries or rely on the error reply alone to terminate execution. A
   timed-out server request receives no late answer.
6. On any terminal path, including initialization refusal, signal or runner
   failure, close turn admission, interrupt an active turn, stop the private
   app-server and confirm its descendants absent within a 5-second teardown
   budget. Release the lease idempotently, then erase in-memory material and
   close pipes. Unknown teardown prevents any claim of clean exit and is reported
   as failure. Release failure is reported; it cannot imply process absence.

If the runner is killed before cleanup, no exit callback is assumed. Its
qualified execution containment MUST stop the app-server; unresolved absence
keeps reuse of that launch home closed. The durable lease expires at its
original authorized_until; disconnect/restart does not renew or release it.
Startup expires overdue records before considering reconnects. Release stops
renewal; it cannot erase a token already delivered to a process.

Exit status: 0 completed turn **and** confirmed teardown and release; 1 failed
or interrupted vendor turn; 64 invalid command/input; 69 broker admission,
qualification, source or initialization refusal; 75 renewal/owner/cleanup
unavailability; 124 execution deadline; 130 handled interrupt after cleanup.
When several failures occur, cleanup/renewal failure (75) dominates vendor-turn
status; deadline/interrupt is retained only if cleanup succeeds. Diagnostics
contain typed codes, never raw RPC frames, vendor stderr or material.

`ephemeral` refers to credential persistence, not necessarily thread history.
The generated 0.163.0 schema exposes `thread/resume`. This profile MAY resume an
app-server thread in the same protected launch home using a **fresh lease and
external login first**, `thread/resume { threadId }`, then one new turn. It MUST
recheck account/profile/policy identity, configuration digest and all source
conflicts. It MUST NOT import native credentials, inherit an old lease or promise
mid-turn continuation. Resume remains disabled until exact-release fixture and
real-account qualification pass; otherwise restart from the task snapshot.
This refines the app-server possibility without treating CIP-0010 C3.5's
historical native-resume observation as current qualification.

## 7. Profile-specific `broker/1` subset

The transport is exactly [§13.1](broker.md#131-transport): Unix stream, four-byte
unsigned big-endian byte length, then one CCJ-1 canonical JSON object; maximum
payload 65536 bytes, rejected before allocation/read when larger
(`frame_too_large`). No newline is part of the payload. CCJ-1 rejects duplicate
keys, invalid UTF-8/lone surrogates, fractional/unsafe integers and negative zero;
recursively sort keys by Unicode scalar, emit minimal escapes and no insignificant
whitespace. No top-level `sig` member is allowed in these unsigned envelopes.
Unknown fields, noncanonical bytes and malformed members close the connection
without processing or reflecting input. No new malformed-frame refusal code is
assigned; Appendix A has none for this envelope.

Request envelope is `{method, params, request_id}`. `request_id` is a nonempty
ASCII string of at most 64 bytes, unique among outstanding calls on that
connection; it is correlation, not replay authority. Response is exactly
`{request_id, result}` or `{request_id, error: {code, message, details}}`.
`message` is fixed sanitized text; `details` is a closed metadata object (empty
unless explicitly specified). No raw request or secret is echoed. Unknown
methods close the connection without effects. Unanswered requests are canceled
on connection close; accepted durable attempts still follow §5 recovery.

The first request MUST be `hello` with `versions: [1]` and
`profile: "codex-refresher-v0"`. Success returns `version: 1`, that exact profile,
`principal: {uid}` (kernel identity) and current `policy_generation`. Unsupported
version/profile refuses `version_unsupported` and closes. A general broker client
MUST NOT negotiate this profile accidentally; no fallback between authority
models is allowed. Before successful hello, no other method is processed.

All object members below are required unless marked optional. Times are RFC 3339
UTC seconds with `Z`; hashes are 64 lowercase hex; lease/launch IDs are opaque,
nonempty ASCII strings, maximum 128 bytes. Binding digest is SHA-256 of canonical
`{uid, profile, harness, account, channel, endpoint, executable_sha256,
policy_generation}` from protected policy, not caller choice. UID is excluded
from the transmitted binding; it is supplied from kernel identity for hashing.

| Method | `params` | Successful `result` |
|---|---|---|
| `status` | `{}` | `{policy_generation, accounts: [{account, state, single_owner: true, token_expires_at: time or null, last_refusal: code or null}]}`; peer-scoped, no lease payload |
| `lease.request` | `{harness: "codex_cli", profile, account, channel: "external-token", credential_binding: {digest, harness, profile, account, channel, endpoint, executable_sha256, policy_generation}, network: null, launch_id, executor: {capabilities: ["credential-injection/1"], version}}` | `{lease_id, account, harness: "codex_cli", channel: "external-token", payload: {channel: "external-token", access_token, chatgpt_account_id, plan_type?}, token_expires_at, authorized_until, renewable: true}` |
| `lease.renew` | `{lease_id, rejected_sha256}` | Same shape as lease.request success, same lease ID, account and authorized_until; refreshed or already-current payload |
| `lease.release` | `{lease_id}` | `{lease_id, state: "released"}`; terminal receipt, idempotent for same owner |

A lease lasts at most the policy limit and known token/account authority limits;
renewal never extends authorized_until. Release of an active lease is durable
before acknowledgement. Released/expired leases refuse renewal
`lease_not_active`; ownership mismatch is `lease_not_owner`. Unknown lease IDs
also return `lease_not_owner`, avoiding another peer's lease discovery. A released
lease's duplicate release succeeds for its owner until its authorization limit;
after retained evidence is unavailable, refuse rather than invent a receipt.

Limits: status/hello 2 seconds, renewal 8 seconds, lease request 30 seconds,
release 2 seconds. Queue overflow/renew deadline is `renew_timeout`; other request
deadlines use `request_deadline_exceeded`. Lease-request timeout cannot start a
second attempt or cause late material delivery. The runner conflict gates run
locally before the request; these are executor refusals, not trusted client
claims enforced from request fields by the daemon.

Refusals reuse [Appendix A](broker.md#appendix-a-refusal-codes):
`peer_identity_unavailable`, `server_identity_mismatch`, `role_not_permitted`,
`frame_too_large`, `version_unsupported`, `request_deadline_exceeded`,
`account_exists`, `account_unknown`, `account_duplicate`,
`account_store_keyring_refused`, `enrol_material_invalid`,
`lease_not_authorised`, `lease_account_unknown`, `lease_harness_mismatch`,
`lease_account_revoked`, `lease_reauth_required`, `lease_owner_unavailable`,
`lease_channel_unsupported`, `lease_harness_unqualified`,
`lease_binding_mismatch`, `lease_network_enforcement_unavailable`,
`lease_not_owner`, `lease_not_active`, `renew_not_current`, `renew_timeout`,
`renew_failed`, `external_token_init_failed`, `credential_source_conflict`,
`credential_injection_unavailable`. No new refusal code is introduced.
Administrative enrolment reuses account codes; it is not added to this transport.
Deferred grant/binding/platform refusal codes are not remapped to fake success.

## 8. Release qualification

Unqualified executable/configuration/platform tuples MUST refuse
`lease_harness_unqualified`. The mandatory v0 target is 0.163.0: its exact tuple
becomes usable through the procedure below, not a permanent unqualified state.
Every other release remains refused by this profile until a later explicit
profile revision qualifies it. Version text alone is not a tuple:
qualification pins executable digest, generated schema digest, runner version,
OS/kernel/systemd version, applied unit properties and sanitized configuration.
Observed 0.163.0 schema support is experimental and explicitly marked unstable;
its presence is not a compatibility commitment.

Fresh-home probes establish capability rejection/acceptance and external-token
shape. The [exact-release bridge source](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/app-server/src/external_auth.rs)
specifies a 10-second refresh wait. A bounded fake inference-401 probe observed timeout diagnostics at 10.007 and 10.008
seconds after separate unanswered callbacks; the vendor retried afterwards.
The probe stopped before terminal turn completion, so it does not prove the
runner's failure/teardown path. Qualification MUST also measure it with a fake
inference 401, unanswered callback and late reply, with positive in-budget renewal. This profile does not
infer the callback behavior from `account/rateLimits/read` 401.

Qualification of 0.163.0 MUST include the full §9.6 table mapped below, real
device login, application-network-policy fetch, approved endpoint routing,
one successful headless inference turn, proactive managed refresh, concurrent
owner/rejected-token contention, successful 401 replacement, renewal rejection,
8-second broker timeout, measured 10-second vendor timeout and no late answer.
It MUST establish effective source, ephemeral/no-file behavior, absence of token
material from argv/logs/uncontrolled MCP/hooks/tools, complete parent/descendant
containment, daemon replacement and same-home resume if offered. Fixture-only
success does not establish vendor scopes, billing, rotation or policy behavior.
All real-account rows remain **pending curator approval and execution**.

Test-only overrides supported by the selected binary/source include
`CODEX_REFRESH_TOKEN_URL_OVERRIDE` (managed refresh),
`CODEX_APP_SERVER_LOGIN_ISSUER` (app-server login issuer),
`CODEX_AUTHAPI_BASE_URL` (auth API), `chatgpt_base_url` (backend), and a custom
provider `base_url` (inference). Fake-only qualification MUST route every network request
to local fakes with deny-by-default outbound access and synthetic credentials;
setting only the refresh URL is insufficient. Production MUST refuse inherited
overrides and pin approved routing. No real login is needed for protocol,
recovery or negative-source fixtures. Endpoint availability does not prove a
complete fake policy response or a safe real-account test.

### 8.1 Mandatory 0.163.0 qualification procedure

The v0 implementation MUST provide an owner-only qualification entry point:

```text
swarma-credential-broker qualify-codex --executable <approved-path> --evidence-dir <directory> --fixtures
swarma-credential-broker qualify-codex --executable <approved-path> --evidence-dir <directory> --live --approval-ref <reference> --account <label>
```

These are administrative procedures, not extra lease methods or a general
`--allow-unqualified` switch. Exit 0 means every selected row ran green; exit 1
means a failed row; exit 64 means bad inputs; exit 69 means missing approval or
unavailable qualification environment. Neither command can itself retire the
existing login. During qualification ordinary lease admission stays closed.
A narrowly scoped test client may exercise the candidate's admission and runner
paths only on a private qualification socket, with fixed test peer/account,
bounded lifetime and the candidate digest. This authority is removed at teardown;
it cannot enable ordinary clients, unrelated releases/accounts or fallback.

1. **Identify candidate.** Record version 0.163.0, executable digest, experimental
   schema digest, runner build digest, OS/kernel/systemd identity and applied
   configuration/property digests. Reject a different version or changed input.
   Verify tool readiness, scratch ownership and absence of inherited credentials.
2. **Run fake-only rows.** Route all candidate traffic to deny-by-default local
   fakes; test external login with/without capability, synthetic account identity,
   managed refresh through the approved executable, inference 401 success and
   renewed-account mismatch, renewal failure, queue/fairness/N-caller contention,
   slow response and late suppression. The managed-refresh fixture uses its own
   synthetic vendor login in an isolated test store, never the live native home.
   Run every §9.6 replacement/rotation row, source/child-inheritance fixtures,
   framing, limits and lease bookkeeping. Record the real command/exit and
   positive/negative control for each row. Fixture code must establish that its
   network and persistence fault controls actually trigger the intended faults.
3. **Obtain live approval, then use the cutover gate.** The curator approves the
   exact live cases and maintenance scope before the owner enrols the new broker
   login in §3.1. Preserve the existing native login; no live test may refresh,
   copy, revoke or overwrite it. If old consumers cannot be quiesced, defer the
   live rows with an explicit pending result. Missing approval never becomes a
   skipped pass, and an ordinary qualification command cannot stop live sessions.
4. **Run approved live rows on the new login only.** Owner device-code login,
   real account identity, application-network-policy fetch, successful inference,
   effective source/scopes, approved-executable proactive refresh, controlled 401
   renewal and failure, one-account contention and slow-renewal behavior require
   the real vendor where fixture equivalence is insufficient. Use bounded prompt
   and request budgets and the approved fault method; do not corrupt or revoke a
   live login just to produce a rejection. If no safe method exists for a row,
   record it unrun and keep qualification pending. Resume is optional and tested
   separately; its failure may disable resume without qualifying it accidentally.
5. **Publish qualified status last.** A protected `qualification/1` record contains
   candidate version/digests above, suite revision and case IDs, mode fake/live,
   per-case positive/negative verdict, exact command, real exit code, evidence
   artifact digests, monotonic duration/bound, live approval reference, account
   identity check, operator acceptance, completion time and disposition. It
   contains no tokens, hashes of material, raw frames or private diagnostics.
   All required rows MUST be present, executed and green on the exact tuple.
   Persist/flush the evidence record before atomically adding only that tuple
   to the daemon's qualified list. Re-read it before opening ordinary leasing.
   Interrupted publication or mismatched/missing evidence keeps the tuple
   unqualified. A digest/config/platform change invalidates the entry and reruns
   the affected identity's qualification; old evidence cannot bless a new binary.

A fixture-only report is useful progress, not a production qualified entry. This
spec task runs research probes and artifact validation only; execution of the
mandatory implementation qualification and approved live rows belongs to v0
implementation/cutover. The procedure makes 0.163.0 deliverable without weakening
`lease_harness_unqualified` for an untested candidate or another release.

## 9. Negative cases and adjacent positive controls

Each case describes a required future executable test, not a passed result.
`F` means fixtures/local fake endpoint in v0 tests; `L` means a real test account,
separately approved and pending. The [vectors](../vectors/v0/README.md) give the
machine-readable subset. Preconditions include a qualified fake tuple unless
the case changes that premise. Every refusal requires zero material delivery.

| Test / inputs (negative first) | Expected refusal or invariant; observable post-state | Nearby positive control | Mode |
|---|---|---|---|
| `peer-denied`: kernel UID absent from policy, forged UID in data | `role_not_permitted`; no lease/attempt, no material | `peer-allowed`: configured kernel UID negotiates and leases | F |
| `account-denied`: admitted peer requests another known account | `lease_not_authorised`; neither account starts a writer | `account-allowed`: exact peer/account/profile tuple leases | F |
| `account-unknown`: profile-admitted peer requests nonexistent label | `lease_account_unknown`; no account is created or fallback used | `account-known`: existing allowlisted label leases | F |
| `release-unqualified`: 0.163.0 digest lacks qualification | `lease_harness_unqualified`; no vendor child | `release-qualified`: fake approved tuple leases | F; real tuple L |
| `source-conflict`: reserved variable/helper/provider source present | Local `credential_source_conflict`; no lease or app-server | `source-clean`: approved effective source only, no child token inheritance | F; effective vendor source L |
| `home-auth-present`: auth.json path or link in launch home | Local `credential_source_conflict`, without reading file; home untouched | `home-auth-absent`: clean home, external login, path stays absent | F |
| `renew-unknown-digest`: digest not last delivered to this lease | `renew_not_current`; token generation and writer count unchanged | `renew-superseded`: old delivered token, newer owner token; current payload, zero refresh | F |
| `renew-contention`: eight active leases reject same current token | Exactly one refresh and one token-generation advance; all admitted waiters get same account/current token | `renew-single`: one rejection causes one refresh | F; vendor contention L |
| `renew-late`: fake writer result after 8-second renew deadline | `renew_timeout` once, no late success/callback; history may resolve separately | `renew-in-budget`: result before cutoff, one correlated answer | F; vendor callback L |
| `queue-full`: 64 queued lease operations, another lease renewal | `renew_timeout`, queue never exceeds bound, no extra writer | `queue-slot`: one free slot admits waiter to same attempt | F |
| `daemon-death`: kill daemon during refresh; child/descendant initially survives | Replacement owner_unavailable, no second writer; kill and confirm subtree absence before outcome resolution | `normal-stop`: complete stop/evidence + committed store permits safe next attempt | F; vendor child behavior L |
| `replacement-contention`: replacement plus rejected-token callers | One durable attempt identity, at most one live writer across all contenders | `resolved-replacement`: exact resolved prior attempt permits one successor | F |
| `rotation-crash`: fake endpoint rotates, crash before store/checkpoint persistence | owner_unavailable; absence alone causes zero retries; no stale-token success | `rotation-committed`: durable vendor store and correlated successful result publish active once | F; actual vendor durability L |
| `cleanup-interrupted`: crash after kill, before absence record | Admission stays closed until full same-attempt observations and store reconciliation | `cleanup-confirmed`: complete observations and safe outcome reopen | F |
| `absence-unreadable`: denied/partial/conflicting unit or cgroup read; missing unit alone | owner_unavailable; absence unknown, no new writer or re-enrolment | `absence-complete`: bound invocation, successful stop and complete empty subtree evidence | F |
| `store-missing`: missing/unreadable vendor home or prior intent/checkpoint | owner_unavailable; no empty-store reconstruction or stale delivery | `store-current`: complete matching checkpoint and safe durable reload admit | F |
| `store-rollback`: old valid store/checkpoint under external restore fence, or unknown freshness | owner_unavailable; fence not cleared by parse success, zero retries | `store-reconciled`: independent freshness and explicit reconciliation while closed | F |
| `transient-ambiguous`: timeout/vendor error could follow rotation | owner_unavailable, no transient backoff retry | `transient-safe`: proven non-rotation + absence + reload; bounded backoff may retry | F; vendor error classification L |
| `reenrol-unresolved`: person requests new login while prior writer unknown | owner_unavailable; no enrolment child, old evidence retained | `reenrol-resolved`: confirmed absence then explicit fresh-home ceremony | F; device ceremony L |
| `duplicate-account`: new label resolves to already enrolled vendor ID | `account_duplicate`, no second active mapping or lease | `distinct-account`: different vendor ID activates independently | F; live ID provenance L |
| `owner-mismatch`: another UID renews/releases lease | `lease_not_owner`; lease unchanged | `owner-match`: same UID/generation context renews or releases | F |
| `lease-ended`: renew after release or authorization limit | `lease_not_active`; no writer/material, no limit extension | `lease-live`: same owner before limit renews; duplicate release idempotent | F |
| `time-untrusted`: clock/freshness evidence missing after restart | `lease_owner_unavailable`; no watermark advance/material | `time-trusted`: trusted time and current evidence permit bounded lease | F |
| `init-without-capability`: login without experimentalApi | `external_token_init_failed`, child stopped and lease released | `init-with-capability`: initialize/initialized then external login succeeds | F |
| `resume-conflict`: account/config drift or native-file path at resume | Refuse before inference; no old lease reused | `resume-fresh`: qualified same-account thread resume after new lease/login | F; resume qualification L |
| `frame-oversized`: length 65537 before payload | `frame_too_large`; body unread, no effects | `frame-valid`: canonical hello framed with exact length succeeds | F |
| `profile-unsupported`: ordinary/unknown profile or version | `version_unsupported`, close, no authority-model fallback | `profile-v0`: exact profile plus versions [1] succeeds | F |

### 9.1 Mapping every broker §9.6 row

| Broker qualification row | Tests above; required evidence |
|---|---|
| Daemon death during refresh; child survives | daemon-death / normal-stop; dependency stop plus correlated subtree absence |
| Concurrent replacement and rejected-token callers | replacement-contention, renew-contention / resolved-replacement; one writer and attempt identity |
| External rotation before persistence; daemon crashes | rotation-crash / rotation-committed; ambiguity blocks retry |
| Interrupted cleanup or restart between kill and confirmation | cleanup-interrupted / cleanup-confirmed; absence publication and store resolution ordering |
| Failed, partial or contradictory process/absence read | absence-unreadable / absence-complete; unknown never becomes absent |
| Missing, unreadable or rolled-back vendor-home/outcome evidence | store-missing, store-rollback / store-current, store-reconciled; no stale-token success |
| Safe transient failure and durable reload | transient-ambiguous / transient-safe; positive non-rotation evidence before backoff |

## Appendix A. Owner action for dedicated-user isolation

**Preparation only; pending R2. These commands are not executed by this work.**
A root administrator performs them in a maintenance window, outside a harness.
The normal platform installer MUST instead use the service-account provisioning
contract in [§15.1](broker.md#151-service-user-and-time). The manual Linux bootstrap
below is for this interim deployment only; it MUST NOT create a second account
if the platform installer already provisioned one.

First close admission, disable automatic restart, stop the old daemon, and
resolve every retained writer through §5. Confirm full process absence and
store/outcome reconciliation before moving anything. Stop is not proof of safe
rotation. If any outcome is unresolved, keep it unavailable after migration;
never enrol or refresh during the move. The operator supplies `OLD_USER` and the
absolute `SOURCE_STORE` path privately; neither is a shipped default. All old
paths/configurations that could auto-start the daemon must remain disabled.

```sh
# Run as root; supply these values privately, without logging their contents.
read -r OLD_USER
read -r SOURCE_STORE
case "$SOURCE_STORE" in /*) ;; *) exit 64 ;; esac
OLD_UID=$(id -u "$OLD_USER")
runuser -u "$OLD_USER" -- env XDG_RUNTIME_DIR="/run/user/$OLD_UID" \
  systemctl --user disable --now swarma-credential-broker.service
# STOP HERE until the operator has confirmed the §5 absence/outcome gates.
# The following commands do not establish those gates.
useradd --system --user-group --home-dir /opt/swarma/services/swarma-credential-broker \
  --shell /usr/sbin/nologin swarma-credential-broker
install -d -o root -g root -m 0755 /opt/swarma/services
install -d -o swarma-credential-broker -g swarma-credential-broker -m 0700 \
  /opt/swarma/services/swarma-credential-broker
DEST_STORE=/opt/swarma/services/swarma-credential-broker/store
test -d "$SOURCE_STORE" && test ! -L "$SOURCE_STORE" && test ! -e "$DEST_STORE" || exit 1
# Store migration must stay on one filesystem for an atomic rename.
test "$(stat -c %d "$SOURCE_STORE")" = \
  "$(stat -c %d /opt/swarma/services/swarma-credential-broker)" || exit 1
mv -T -- "$SOURCE_STORE" "$DEST_STORE"
chown -R --no-dereference swarma-credential-broker:swarma-credential-broker "$DEST_STORE"
find -P "$DEST_STORE" -type d -exec chmod 0700 {} +
find -P "$DEST_STORE" -type f -exec chmod 0600 {} +
loginctl enable-linger swarma-credential-broker
BROKER_UID=$(id -u swarma-credential-broker)
systemctl start "user@$BROKER_UID.service"
```

The administrator MUST inspect the store structure before migration and refuse
links, unexpected mount points or untrusted parent ownership; the commands do
not sanitize a hostile tree. Cross-filesystem migration needs an explicitly
reviewed offline procedure, never a silent copy-and-delete fallback.

Before starting the new daemon, install the reviewed user service and executable
under protected ownership, set its store path to DEST_STORE, update clients'
pinned broker UID/socket and static policy, invalidate all old leases, and
verify the new manager's writer containment while admission is closed. Reconcile
all retained attempt identities against the old manager; a new manager's empty
inventory is not absence evidence. Enable only the new service after readiness
checks. The old service MUST remain disabled. Account outcome ambiguity survives
the user change. No command here reads, prints or imports credential values.
