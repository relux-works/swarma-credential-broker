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
P1 owns production of these records. Source tests create
only synthetic records in a disposable user namespace.

The broker pins canonical P1 validator source
`bf72a78a2c02ca30d1238e218df2f3318a63b92b` (landed PR75). The closed schema has
one `executor` object with exactly `id`, `path`, and `sha256`. It admits only
`swarma-demo-executor` at `/usr/local/libexec/swarma/swarma-demo-executor` or
`swarma-demo-codex-executor` at
`/usr/local/libexec/swarma/swarma-demo-codex-executor`, with a lowercase SHA-256
digest. A third executor, mixed ID/path pair, list or extra member refuses.
Only the Codex row authorizes Codex leasing and running; a witness row grants
no Codex lease. There is no transformed roster or second roster.

The wire `source_revision` in both the roster and P1 attempt is the frozen
user-manager copy-source revision
`7d705966aa92acaebea2d55060dcb84ddf7e5031`. The broker requires exactly this
value in the roster; any other value, including the P1 program pin, refuses.
P1 owns the attempt record; the broker consumes the protected launch projection
above, which has no `source_revision` member.

The separate out-of-band program qualification pin is
`bf72a78a2c02ca30d1238e218df2f3318a63b92b`. It is recorded here and in
`internal/demo/testdata/p1/manifest.json`, with byte-exact roster and attempt
fixtures emitted by that unmodified program's validator, encoder and attempt
constructor. It is never compared against a roster field. The PR76 receipt
route (`e11b565c`) leaves the roster, `EXECUTORS` and `source_revision` unchanged,
so that receipt-only successor preserves this qualification pin. Refusal of an
old roster is by its content: an executor outside the two exact pairs, a third
executor, a mixed pair, an unknown member, wrong format or wrong copy-source
revision. A valid witness roster is schema-admitted but grants no Codex lease.

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

Publication captures one absolute delivery deadline before entering the local
admission gate. Gate contention uses that same deadline. Immediately before the
material callback, the manager checks expiry and caller/release/replacement
cancellation again; time spent waiting cannot extend the delivery interval.

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

The canonical P1 validator approves the two exact executor pairs above. The
fixed Codex executor still requires its own approved ID/path/digest, and both
broker and consumer refuse Codex use of the witness-only roster. The unmodified
canonical P1 fixture is admitted for each exact executor pair;
only the Codex pair permits the Codex lease and runner authority paths.
The launch-record writer belongs to P1, and dispatcher roster adoption remains
with the dispatcher. No P1 or dispatcher file is edited here.

The ordinary daemon's owner remains `owner.Stopped`. The existing owner package
requires protected enrolment/checkpoint state, a contained manager, independent
confidence and native qualification. This candidate supplies a managed-reference
adapter, not a fabricated account enrolment or an always-fresh provider.
The live owner bootstrap and operator ceremony must supply these missing
prerequisites; this source candidate cannot demonstrate real issuance yet.

Two fresh independent whole-head reviews at the requested model/effort, source
checks and custodian landing are still required. Synthetic source tests establish
local behavior only, not cross-UID VM, provider, account or model qualification.
