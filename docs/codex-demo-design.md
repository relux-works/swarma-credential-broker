# Codex demo: owner, service broker and one-shot consumer

Status: design for review; no activation or implementation approval. This note
is based on broker main `90338be1dacfee9f2a4e6c51cb1fa75da953a93b`.
The source claim map is in [codex-demo-sources.md](codex-demo-sources.md).
The designated source custodian reviews this note before any code. Subsequent
privileged code requires two fresh independent reviewers of the exact candidate.

## 1. Demo boundary

Demonstrate one explicitly enrolled Codex personal-plan account on a disposable
Linux VM: an owner supplies usable access material, a broker running as its own
service user authorizes a worker, and `curator-run` takes a lease immediately
before one harness launch. Authority is protected static policy plus kernel
identity and the frozen operator roster. There is no signed-grant verification.
The operator uses an ordinary terminal and the reviewed sudo path. Stopping is
manual through the dispatcher; this adds no automatic all-stop controller.
Existing expiry, failure cleanup and fail-closed admission still apply.

This is a small integration demo, not full broker compliance, slice-0 acceptance,
release qualification or a secret-free service. Real access material reaches the
trusted worker process. Secret-free mode is later work and does not gate this
demo. No general model proxy, authentication bypass, alternate billing fallback,
new trust root or wider provider support is proposed. No deployment, root action,
account change or network-policy change is authorized by this document.

## 2. What exists, and what does not

| Area | Source fact at the base | Proposed demo work |
| --- | --- | --- |
| Owner boundary | `owner.Owner` has `Snapshot` and generation-checked `Refresh`; the daemon constructs `owner.Stopped{}` | Explicitly wire a real admitted owner after lifecycle and qualification prerequisites exist |
| Codex refresh | `authowner.Engine` contains managed refresh, durable intent/recovery and protected material reload; it is a library | Supply genuine account admission, containment, independent confidence and exact-release evidence; do not mark fixture evidence qualified |
| Initial issuance | Codex supports person-driven managed login and managed token refresh; the broker enrolment ceremony is specified but not shipped as a command | The owner must provide an admitted bootstrap route for one fresh account home; no invented `issue-token` or working `enrol` command |
| Worker transport | `brokerclient.DialWorker`, server peer verification, hello, request, renew, release, erase exist | Embed the worker in the one-shot execution lane; preserve all existing fences |
| Dedicated service | Daemon static config is broker-owned 0600; current runner reads that same file | Publish a minimal protected worker authority projection; do not make the private config world-readable |
| Principal generation | Current static policy allowlists UIDs; it does not consume the demo roster | Add a read-only roster admission adapter, scoped to this demo and reviewed before code |
| One-shot intake | Launcher source labels agent-account one-shot exec a target amendment, with publication questions | Coordinate its exact immutable-plan intake with that lane; no assertion that a suggested CLI already works |

A policy label, UID allowlist entry, successful RPC, version string or token
expiry claim alone proves neither provider admission nor safe issuance. The
shipped qualified release set is empty. This note does not activate it.

## 3. Piece A: Codex owner that actually supplies material

The provider issues or rotates the access token. The broker issues a local lease
over that material; it does not mint a new provider credential per launch.
For the selected existing path, the adapter implements the real `owner.Owner`:

1. An operator-mediated fresh managed login creates a new owner-private home,
   explicitly using Codex file storage. Never import an existing login, scan a
   host home, export a keyring item or read a worker's auth state. The operator
   confirms the single account and the approved executable tuple privately.
2. The admitted owner validates account identity, private-home identity, durable
   retained history, writer absence, independent freshness/time and the exact
   executable/release qualification before `Snapshot` returns usable material.
3. When refresh is required, the existing contained vendor path starts the
   pinned Codex app-server with a clean allowlisted environment and the owner
   home. It sends `initialize`, `initialized`, then
   `account/read {"refreshToken":true}` on private pipes. In managed ChatGPT
   mode this invokes Codex's refresh authority, which performs the provider
   exchange and persists replacement tokens. This is an actual vendor path,
   not a fake response assembled by a test owner.
4. `account/read` returns account information, not a transferable access token.
   Only after correlated writer absence, durable outcome reconciliation and
   protected reload may `authowner` expose the new material in `Snapshot`.
   Unknown rotation, partial persistence, changed manager epoch or lost evidence
   leaves the account unavailable. Cancellation alone never proves absence.
5. The owner retains the refresh token in its protected native file store and
   approved writer memory. The lease response contains only access material,
   account identity and bounded authority. Refresh credentials never reach the
   dispatcher, plan, launcher, worker lease file, report or logs.

The pinned upstream source is Codex `rust-v0.163.0`, commit
`83086188ae0614bd882818ff1aa23f3194962012`. Its app-server supports managed
login/refresh and experimental external token input. Its external token schema
also warns that the interface is unstable and for internal use. Current official
OpenAI documentation describes experimental host-managed token input; that is
context, not a replacement for qualification of this exact release and account.
`account/login/start` with `chatgptAuthTokens` consumes an already-issued token;
`account/chatgptAuthTokens/refresh` asks the host for a replacement. Neither is
an upstream credential minting API. `account/read` ignores its refresh flag in
external mode. Do not use that consumer session as the refresh owner.

### Missing owner input and minimal admission seam

The current daemon has no activated owner, shipped enrolment implementation,
complete native qualification or always-fresh confidence provider. These are
real gaps, not commands to infer. The proposed typed bootstrap seam is a local
reviewed operation `AdmitCodexAccount`, not a new public CLI or wire method:

| Input / result | Required meaning |
| --- | --- |
| `AccountAdmission` | One account label and confirmed vendor identity; fresh owner-home identity; approved executable path/digest/release; policy generation; retained enrolment/writer outcome evidence; independent confidence reference; qualification reference |
| `AdmitCodexAccount(context, AccountAdmission)` | Validate those independently supplied facts, serialize against every account writer and durably publish initial owner state; it never accepts raw token JSON from a worker |
| Result | `admitted` with immutable evidence reference, or closed `unavailable`, `reauth_required`, `qualification_missing`, `confidence_missing`, `outcome_unknown`; these are proposed local outcomes, not new wire codes |

The owner must name the existing admitted provider/owner API and the operator
ceremony that supplies these inputs. The route above is supported in source but
not currently admitted end to end. If a separately admitted owner already exists,
reuse its typed `Snapshot`/`Refresh` and evidence contract instead of building a
second refresher. Do not fabricate an endpoint, use a production issuance probe,
or replace independent confidence with `Trusted=true`/`Fresh=true` constants.
A direct OAuth client, different token-sharing product or API-key billing path
would be a separate reviewed design, not an implicit substitute here.

## 4. Piece B: service broker and authoritative caller identity

Use a dedicated unprivileged broker service account, distinct from every worker,
the dispatcher and the terminal operator. Its numeric UID/GID must be selected
and recorded by the operator outside worker range 30000–30019; this note assigns
no new numeric service identity. Protected service state and native owner home
are 0700, private files 0600. Root-owned non-writable ancestors and installed
binary/configuration identity must be verified. The service owns no sudo launch
path. Do not run the broker as root or reuse a worker's native store.

Use an existing separate broker-owned socket directory, exactly 0755, outside
the private state tree, with root-owned non-writable ancestors. The existing
0666 Unix socket only permits connection: kernel credentials and policy decide
admission. Qualify cross-UID reachability and verify the server peer UID before
clients send bytes. Keep all connections close-on-exec, never pass them through
the launcher or across credential transitions, and open the worker connection
after privilege drop. No inherited dispatcher socket may confer its identity.

The frozen roster is `/etc/swarma-demo/roster.json`, root:root 0644. It binds
account name, UID, GID, generation and owning dispatcher account. The worker
range is **inclusive 30000–30019**, UID equals GID, private primary group, no
supplementary groups and no UID reuse. The three precreated demo accounts are
`swarma-demo-01` through `swarma-demo-03`.
The root-owned roster, not the caller's JSON or requested account label, is the
authority for these bindings. The P1 lane owns its schema and provisioning;
this lane must consume that published schema without inventing another roster.

For each new worker connection, lease request, renewal and final material
publication, the proposed roster adapter must:

- Obtain the peer UID from `SO_PEERCRED`; reject unavailable identity, UID
  outside the range or no unique active roster match.
- Read the protected roster without following links, reject unsafe ownership,
  mode, duplicate entries, missing/invalid generation or ambiguous dispatcher
  ownership, and resolve the named dispatcher using operator-owned identity
  data. A caller cannot choose another dispatcher by sending JSON.
- Match `(uid, generation, owning dispatcher)` to the protected admitted launch
  and static policy. A plan digest or `launch_id` is correlation, not authority.
  The launch/plan must be bound by the dispatcher/P1 lane to that roster entry.
- Recheck the protected roster snapshot and policy generation after blocking
  owner work and before publication. Change, retirement or unreadability closes
  admission and invalidates affected connections/leases; no silent adoption of
  a new generation. The immutable demo roster needs a no-change maintenance
  fence across admission/publication; future online replacement requires an
  explicit synchronized generation contract, not a final stat-only race claim.

The existing v0 wire has no worker-generation or dispatcher-ownership field.
Do not add an unreviewed caller authority field. Proposed internal
`ResolveDemoPrincipal(peerUID, protectedRoster, admittedLaunch)` returns a pinned
principal or refusal. This joins existing launch custody to broker admission;
it must not recreate the dispatcher's launch ledger, helper or privileged
launcher. Static `allowlist.check` remains an observer-only advisory check;
the dispatcher never acquires, renews, releases or serializes worker tokens.
The broker performs actual worker admission independently.

### Private configuration versus worker authority

The current runner's `ProtectedDependencies` cannot read a different service
UID's 0600 daemon config. Keep that refusal. The proposed local
`DemoWorkerAuthority` contains only socket location, expected broker UID,
account/profile/harness/channel/endpoint, executable digest, static policy
generation and roster/launch binding. It contains no native-store path, token,
refresh credential or capability to edit policy. An operator-installed,
root-owned non-writable projection or a protected launch binding supplies it.
Its exact closed schema and identity checks must be agreed with the one-shot
lane before code; this note introduces no new supported config flag. The broker
checks the same tuple against its private policy. A projection cannot grant
lease authority, qualify a release or waive a roster check.

## 5. Piece C: curator-run consumes at launch

Caller-side Curator composes once. The dispatcher admits the launch, and the
existing P1 privileged launcher passes a bounded immutable plan on FD3, records
its start receipt and drops to the frozen worker UID/GID with no supplementary
groups. `curator-run` verifies the plan and destination-local protected binding;
it does not compose or resolve profiles under that worker. P1 and the dispatcher
own those implementations. This note adds only the broker consumer seam.

At launch, after all plan/source/authority checks and immediately before starting
the approved harness, the worker opens its own broker connection, verifies the
service UID, negotiates hello and requests exactly one bounded lease using
`brokerclient`. No preissued token travels in the plan or dispatcher receipt.
It checks the returned account, lease bounds and policy binding again, then
supplies access material to a private per-session Codex app-server through the
qualified external-token RPC channel. No `codex exec`, native-login fallback,
credential in argv/environment or shared auth home. The harness uses fresh
0700 HOME/CODEX_HOME and ephemeral credential storage. It can see its own access
token; this demo makes no secret-free isolation claim.

### Private lease file: proposed metadata-only lifecycle

The current Codex contract explicitly forbids launch credential files. Therefore
the proposed private lease file contains **metadata only**: local launch
correlation, lease ID, worker generation, policy generation and terminal state,
never access/refresh tokens or token digests. It is not an auth cache or bearer
authority. If the requested handoff requires a token-bearing lease file, that
is an explicit unresolved contract exception; do not implement it silently.

The worker creates its own fresh 0700 launch-private directory and a new 0600
regular single-link file with exclusive, no-follow creation. The exact basename
is derived from a protected launch identity, never an arbitrary caller path.
There is no file supplied by another UID to chown or adopt. A worker-owned
exclusive launch lock covers create/claim/consume/terminal cleanup. Read and
validate at most 4 KiB of closed-schema metadata once at launch, atomically
claim the record in that directory, and refuse duplicate/replayed or changed
binding. The actual lease is acquired over the fresh peer-authenticated socket;
file bytes cannot supply authority. Record the actual outcome privately, then
remove only this launch's file and directory on normal completion or failure.
Do not publish the file, dump it in diagnostics, or confuse it with Curator's
separate environment/home leases.

After a crash, do not infer broker release from file removal, missing process or
an empty directory. The operator reconciles the recorded launch/lease against
the dispatcher and broker; expiry bounds remain effective. Retain an unresolved
metadata record privately until reconciliation and never replay a payload.
Same-UID malicious processes and root are outside this private-file guarantee.

During the turn, a qualified unauthorized-token callback uses the same lease's
bounded `Renew`, with the rejected access-token digest only inside the private
broker protocol. It never logs the digest or starts a second owner. One-shot
completion, error or manual stop closes the child transport, confirms owned
process cleanup, releases the lease with a validated receipt, erases owned
buffers and removes launch-private artifacts. Cleanup failure is unknown/failure,
not success. Unlinking a file or erasing a Go slice is not physical memory wipe
or provider-side revocation of an already extracted access token.

## 6. Bounds, manual stop and evidence

Preserve the frozen P1/P2 limits: decoded plan at most 48 KiB; start receipt
within 10 s or unknown; stop grace 10 s default and 30 s maximum, then KILL;
2 s quiet window; final scan within 5 s of KILL; whole stop at most 45 s;
stdout/stderr at most 1 MiB each, still drained past the cap. Durations use a
monotonic clock and evidence timestamps use UTC. The executor records its own
UID, GID and groups in its workspace for operator readback; a launcher receipt
alone does not prove successful worker execution or leasing.

Retain existing broker ceilings: hello 2 s, request 30 s, daemon renewal 8 s,
client renewal 8.5 s and release 2 s, all shortened by the caller context.
These are nested phase bounds, not permission to extend the whole stop bound.
No speculative new retry or deadline relaxation is proposed.

The terminal operator requests manual stop through the admitted dispatcher.
Only the dispatcher calls the existing frozen helper's `exec.stop`; this lane
adds no sudoers entry, root helper operation or alternate signal route. Record
stop request, grace expiry, KILL if needed, final process scan, lease release
receipt or uncertainty and owned-file cleanup. Successful broker release closes
local authority; it cannot revoke a provider token already copied by a trusted
worker. Manual stop must not be advertised as global revocation or all-stop.

Evidence contains fixed codes, exact source/executable digests, UTC phase times,
monotonic elapsed bounds, actual exit/signal, peer identity witness, roster and
policy generation and cleanup result. Keep operational identities and private
paths in protected run evidence, not product documentation. Never capture raw
RPC, vendor stderr, authorization URLs/codes, environment dumps or lease payloads.
No production token issuance or paid inference is needed to review this note.

## 7. Known CI lifecycle risk: instrumentation plan only

A previously tracked owner-close scheduling/race risk remains open. This note
neither reproduces it nor identifies its cause. Existing owner-close diagnostics
freeze closed phase/exit observations before cancellation and report them after
cleanup; those observations can become stale and do not qualify absence.

Proposed follow-up CI instrumentation records bounded fixed-label events with
monotonic offsets for child start, origin entry, close entry, timeout snapshot,
cancel issued, supervisor terminal observation, wait consumed, join complete
and diagnostic delivered. Bind events to a synthetic per-case correlation and
the exact source/test/toolchain; include the test deadline, actual exit/signal,
missing phases and cleanup outcome. Capture into a bounded in-memory ring and
emit after cleanup, preserving the original failed log and timeout instead of
replacing it with a passing retry. A paired ordinary completion/cancellation
control and bounded repeated scheduled runs can distinguish ordering from
missing evidence. Do not log PIDs, paths, arguments, tokens or arbitrary errors.

This is a plan, not instrumentation code or a fix. It adds no pre-cancel wait,
blocking callback, sleep, timeout increase, skip or relaxed qualification gate.
The current hosted workflow's ordinary 20-minute test bound and three-minute
bounded race subset remain unchanged. Comprehensive fresh code reviews retain
the required broader race/privileged-path coverage.

## 8. Acceptance and questions before code

| Acceptance criterion | Required review or later evidence |
| --- | --- |
| Design before implementation | Source custodian reviews this exact note; docs-only diff; no runtime changes |
| Real issue path | Named admitted owner route and bootstrap inputs; no test fake or invented CLI; exact Codex tuple and release qualification |
| Dedicated service | Separate measured service identity, protected owner state/config and genuine allowed/denied cross-UID peer tests |
| Frozen principal | Allowed worker; out-of-range UID; forged JSON identity; wrong/missing generation or dispatcher; duplicate/unsafe roster; changed roster during owner I/O all refuse as appropriate |
| Static policy | Exactly one account; account/profile/endpoint/binary/policy tuple matches; stale or unknown projection refuses; observer cannot lease |
| Launch consumption | Worker acquires at launch; immutable FD3 plan and UID/GID/groups witness; no broker/secret FD inherited from privileged path |
| Secret custody | Only owner holds refresh state; worker access material stays in private RPC/memory; metadata lease file has no payload; no alternate source or native fallback |
| Cleanup and stop | Success, refusal, lost reply, crash and manual stop retain actual bounds, release/unknown state and owned-file cleanup; no false revocation claim |
| Known race | Risk retained with timeline plan; no claim of reproduction, cause or fix |
| Code gates | Subsequent privileged code has two fresh independent exact-candidate reviews; no deployment or merge by this note's producer |

Four decisions are needed from the source custodian and adjoining lane owners:

1. Which admitted owner API and operator bootstrap supply enrolment, native
   qualification and independent confidence for this one account?
2. Is a metadata-only private lease file acceptable? If a token-bearing file is
   required, what explicit amendment replaces the current no-file contract?
3. Which published one-shot plan/binding schema and protected worker authority
   projection join roster generation and dispatcher ownership without exposing
   the daemon's 0600 configuration?
4. Which exact Codex build/account/channel is admitted despite the upstream
   experimental/internal-use warning, and what evidence qualifies its delivery?

These gaps bound the current demo integration. They do not reinstate the
separate future secret-free project as a prerequisite.
