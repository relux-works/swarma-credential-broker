# Fixed demo executor, not curator-run

This source candidate adds the protected intake and broker gates for one fixed
Codex demonstration. It does not enrol an account, qualify a binary, provision a
VM, change the dispatcher, write P1 records, or activate a managed owner.
The consumer release is exactly Codex `rust-v0.163.0`, source commit
`83086188ae0614bd882818ff1aa23f3194962012`. Its external-token interface is an
explicitly accepted demonstration risk; there is no credential-file,
environment-token, `codex exec`, provider or release fallback.

## Intake and protected authority

The installed entrypoint is
`/usr/local/libexec/swarma/swarma-demo-codex-executor`. Its ordinary invocation
accepts no arguments. It requires real/effective UID and GID to agree, UID=GID
in 30000..30019, and no supplementary groups. It reads FD3 once, only after that
check. FD3 must be a read-only, fully sealed regular memfd positioned at zero,
containing at most 49152 decoded bytes. Its SHA-256 covers those exact bytes,
including JSON whitespace. No base64 decode or canonical re-encoding changes the
preimage in the executor.

The fixed demo plan is a closed JSON object with exactly `execution_id`,
`prompt`, `model`, and `reasoning_effort`. It selects no account, executable,
credential source, environment, home or work directory. This is the P4-owned
fixed executor's intake, not the general Curator one-shot plan contract. The
model and effort must also occur in the protected qualified catalog. The single
prompt is submitted to one thread and one turn.

`execution_id` preserves P1's grammar exactly:
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Its first character must be alphanumeric;
slashes, backslashes, NUL, parent components and alternative path spellings
cannot select another record. The only lookup is
`/run/swarma-demo/launch-records/<execution_id>.json`.
That root:root 0444, single-link regular record has exactly:

- `execution_id`
- `uid`
- `generation`
- `plan_sha256`
- `boot_id`

Both the executor and broker consume it. The executor compares its independently
protected digest with the exact FD3 digest. The broker resolves the existing
wire `launch_id` (that digest) to exactly one protected record for the kernel
peer UID, without adding a caller-controlled authority field to broker/1.
Launch directories and every ancestor must be root-owned and non-writable by
group or others; every component is opened without following links.
P1 owns production of these records in a successor change. Source tests create
only synthetic records in a disposable user namespace.

The broker consumes the exact P1 roster schema from `validate_roster` at source
`09daa07220a207ae0f4eceb9169b2c30bf62c529`. Its `source_revision` remains the
frozen private-copy baseline `7d705966aa92acaebea2d55060dcb84ddf7e5031`.
There is no transformed roster, second roster or permissive union parser.
The row's `owning_dispatcher` must match `dispatcher.principal`, and that service
must be the canonical dispatcher at UID/GID 1101. The launch UID, generation and
boot must match the roster, and the boot must be current. Runtime admission and
all three P1 qualification flags must be present and true before leasing.

The public root:root 0644 projection
`/etc/swarma-demo/broker-authority.json` is closed, with exactly `socket_path`,
`broker_uid`, `binding`, and `roster_path`. `binding` uses the existing
`wire.Binding` member names unchanged. Broker UID is 1102 and roster path is
`/etc/swarma-demo/roster.json`. The worker recomputes the existing binding digest
including its UID. Neither a private owner-store path nor a qualification boolean
belongs in the projection. `brokerclient.DialWorker` sends no bytes; the runner
verifies kernel server UID 1102 before sending Hello or any lease request.

The separate public root:root 0644 record
`/etc/swarma-demo/codex-qualification.json` is closed, with exactly
`chatgpt_account_id`, `account_reference`, `executable`, `release`,
`schema_sha256`, `config_sha256`, `catalog`, and `evidence`. `evidence` is the
existing `qualification/1` record, not a third evidence format. It must be live,
accepted, operator accepted, account matched, and have all required positive
and negative controls passed. The catalog digest, executable and schema must
match that testimony. Root installs this record only after VM qualification and
the account holder's fresh login. Absence, fake/pending evidence, wrong mode,
links, extra members or mismatches refuse. The source does not create or publish
this record and does not treat synthetic test testimony as real qualification.

`config_sha256` is the existing runner's per-launch source fingerprint. It
includes the exact home and work paths, separately from qualification's static
configuration identity. To make that fingerprint knowable before execution,
the fresh home is the exclusive path
`<roster-home>/.codex-demo-<execution_id>`; an existing path refuses. The operator
must bind the actual admitted launch's fingerprint. Reusing a record whose
fingerprint describes another launch refuses. HOME and CODEX_HOME both point to
this fresh 0700 directory. The work directory comes only from the roster.
The runner retains effective-source inspection, executable digest opening,
exact version probing, containment, external-token RPC and model catalog checks.

## Broker lifetime and renewal

The dedicated UID 1102 daemon installs `demo.BrokerOptions`. Its manager also
retains the existing static-policy and qualification observers. Local embedders
must install the same options and an independently admitted contained owner.
The demo adapter's `ManagedAccountReference` configures the existing auth owner
to re-read the protected account reference for each managed refresh and compare
it with the managed `account/read` email. The vendor account ID is independently
checked by the existing protected material reload. An error, missing identity or
changed reference gives no successful demo refresh. No independent time/freshness
provider is replaced with a true constant.

The initial lease is at most 300 seconds, clamped by provider expiry and owner
authority. Its deadline never extends. At most two logical renewal admissions
are permitted. The existing `lease-record/1` gains one optional member,
`renewal_admissions`; its absence is zero for old ordinary records. A demo
renewal increments and atomically persists it before owner Snapshot or Refresh.
Failed and unknown admitted operations consume it; concurrent deduplicated
waiters consume one operation. Stale rejected-token checks remain in place.
A third admission refuses before owner work. If a current provider/confidence
bound moves earlier than the original deadline, renewal and publication refuse
rather than issue a result beyond that bound.

Initial acquisition reserves the launch in the same existing lease record as
an expired tombstone before any owner I/O, then uses its next revision for the
active lease. Cross-account reservations are serialized. Released, failed and
expired launch records prevent another lease for that launch. Unknown writes
close the account. On daemon restart every recovered demo active lease becomes
expired; no ambiguous lease can renew, and its launch remains consumed. There
is no new store, counter inferred from revision, reconnect reset or restart reset.

Roster and launch records require an operator no-change maintenance fence for
the broker lifetime. Observed roster replacement latches refusal, and evidence
is rechecked after owner I/O and inside the local publication gate. The local
mutex orders local publication; it cannot synchronize a root process replacing
files. Online root maintenance is not supported or claimed qualified. Stop the
broker before root changes this authority, retaining its durable tombstones.

The existing phase bounds remain unchanged: peer negotiation 2 seconds, lease
request 30 seconds, daemon renewal 8 seconds, client callback cutoff 8.5 seconds,
callback reply before 9 seconds of the upstream 10-second bound, and local lease
release 2 seconds. Runner cleanup retains one total five-second budget. P1's
10-second launch, shared 45-second stop and first-KILL-plus-five-second final
scan remain in P1 and are untouched by this change.

A private uid/gid/groups witness is written before acquisition. After child
absence, a private metadata-only outcome records launch digest, lease ID,
worker generation, policy generation and turn state before local release.
Each record is exclusive, no-follow, 0600, fsynced, and at most 4096 bytes.
The runner's unresolved marker remains conservative on failure. Neither record
contains a token or token digest. Model output uses the runner's existing
redacted output path; app-server stderr and diagnostic material are not exported
by the fixed executor. Local release does not revoke an extracted provider
token: broker or worker crash may leave it valid until its own expiry.

## Current integration boundaries

The exact canonical P1 validator currently approves only
`swarma-demo-executor` at its witness path. The fixed Codex executor requires
its own approved ID/path/digest. This candidate preserves both restrictions and
therefore both broker and consumer refuse the witness-only roster. P1 must
explicitly publish its successor approval, and the broker's pinned canonical
validator must follow that exact successor. This candidate does not quietly
reinterpret the current roster or admit a union of executor values.
The launch-record writer likewise remains a P1 successor, and dispatcher roster
adoption remains with the dispatcher. No P1 or dispatcher file is edited here.

The ordinary daemon's owner remains `owner.Stopped`. The existing owner package
requires protected enrolment/checkpoint state, a contained manager, independent
confidence and native qualification. This candidate supplies a managed-reference
adapter, not a fabricated account enrolment or an always-fresh provider.
The live owner bootstrap and operator ceremony must supply these missing
prerequisites; this source candidate cannot demonstrate real issuance yet.

Two fresh independent whole-head reviews at the requested model/effort, source
checks and custodian landing are still required. Synthetic source tests establish
local behavior only, not cross-UID VM, provider, account or model qualification.
