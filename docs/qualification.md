# Qualification records and command frame

`qualify-codex` implements the protected record, publication and pending-row
frame for the mandatory 0.163.0 procedure in profile §8.2. It measures the
candidate's version, experimental schema and model catalog under the egress
boundary. Six transport row bodies can run with explicit fixture configuration; other
rows remain pending, so it grants no production
release qualification. The shipped owner also remains stopped.

```sh
swarma-credential-broker qualify-codex --executable "$CANDIDATE" --evidence-dir "$EVIDENCE" --fixtures
swarma-credential-broker qualify-codex --executable "$CANDIDATE" --evidence-dir "$EVIDENCE" --live --approval-ref "$APPROVAL" --account "$ACCOUNT"
```

The command uses the same fixed operator configuration as `run-codex`.
Arguments cannot select an observer or qualification provider. The executable
must match protected policy, and the existing evidence directory must be owned
by the effective broker user with mode 0700. Inherited credential variables and
inheritable extra descriptors are unavailable inputs; their contents are never
read. The command never inspects an existing native login or executes a
candidate outside an isolated launcher.

| Exit | Meaning |
|---|---|
| 0 | Every selected row executed and passed; unreachable with the pending bodies shipped here |
| 1 | An executed row failed with all other required inputs available |
| 64 | Invalid, duplicate, conflicting or missing arguments |
| 69 | Missing approval, unsupported candidate, unsafe/unavailable environment or pending required bodies |

Every live invocation currently returns 69, including one carrying an approval
reference. A fixture invocation writes a protected `run.json` when its policy,
scratch and inherited-input checks permit collection. It lists all required
rows with actual executed verdicts or pending state and unavailable observers,
then returns 69. Pending rows have
`executed: false`, empty command/artifact arrays, zero elapsed duration and
`exit_code: -1`, meaning no process ran. It never fabricates a process exit or
publishes a qualified entry. An existing report is not overwritten.

A private, owner-only socket reservation is bound to the measured candidate
digest and the run's two-minute context. This reservation has no lease handler; individual transport
workers create separate private listeners as described below. Cancellation closes it, teardown removes only the same
socket object, and a replacement endpoint is preserved. It cannot authorize an
ordinary client. Transport row authority is limited separately below.

## Current identity observers

`IdentityObserver` has one method for version, executable, schema, runner,
platform, configuration, applied properties and model catalog. A current
measurement returns a digest and a closed observer name, or the typed
`qualification_unavailable` result. Record and publication re-reads use the same
contract; a stored historical digest is never a measurement of current state.

| Input | Current production implementation |
|---|---|
| Executable | SHA-256 through a retained no-follow open of every path component; regular single-link executable, broker/root-owned, no group/world write |
| Runner | SHA-256 of `/proc/self/exe`, combined with `debug.ReadBuildInfo` main version and VCS revision |
| Platform | Kernel release/version, OS ID/VERSION_ID, architecture and bounded `systemctl --version` first line, canonically hashed; no machine name |
| Configuration | Canonical static daemon configuration plus harness/channel/profile, ephemeral-source policy and supervisor containment revision |
| Version | Exact `codex-cli 0.163.0` line from the isolated candidate; version string and its SHA-256 |
| Experimental schema | Two fresh isolated generator runs; digest of the identical canonical schema bundle |
| Applied properties | Unavailable until the contained owner's unit template and current-property observer are available |
| Model catalog | Account-free stdio app-server model/effort pairs, sorted and canonically hashed |

### Candidate execution and measurements

Every observer run opens and hashes the protected approved executable, matching
the configured SHA-256 before execution and again afterwards. The retained
candidate is descriptor 4; descriptor 5 retains the trusted broker launcher.
The private `--internal-qualification-candidate` bootstrap installs
`internal/egress` before executing descriptor 4. The explicit flag makes an
embedding executable without that entry point reject the invocation promptly.
It has no policy, account or lease authority. No pathname reopen selects the
candidate between hashing and execution.

Each run gets a newly created, empty, owned mode-0700 directory for both `HOME`
and `CODEX_HOME`; teardown removes it. The environment contains only those
homes, fixed `PATH`/`LANG` and the boundary's proxy variables. The proxy points
to a reserved, non-listening loopback socket; network allowlists are empty.
Runs have a 15-second deadline, bounded stdout/stderr and process-group cleanup.
Any non-loopback refusal, unknown addressed network operation, incomplete
boundary evidence, timeout or output overflow makes the measurement unavailable.
No digest is returned after failed isolation, even if stdout looks valid.

The commands and byte contracts are:

- `--version`: stdout must equal `codex-cli 0.163.0\n` exactly, within 256 bytes.
  The recorded version digest hashes the UTF-8 bytes `0.163.0` without a newline.
- `app-server --help`, then `app-server generate-json-schema --help`: bounded
  help must advertise the generator and its `--experimental`/`--out` flags.
  `app-server generate-json-schema --experimental --out <schema-directory>`
  runs twice in distinct fresh homes. Each output directory must contain only
  regular owned single-link JSON files, with no symlinks. Files are limited to
  8 MiB each, 32 MiB total and 2,048 files. Directory enumeration reads at most
  64 entries per batch, rejects more than 8,192 entries or depth 32, and checks
  cancellation between batches/entries. JSON object keys and relative file
  names are sorted, whitespace is removed, array order and number lexemes are
  preserved, and duplicate keys, invalid UTF-8, trailing values and nesting
  beyond 128 levels are rejected. The digest covers a JSON object mapping
  relative filenames to canonical JSON values. Different canonical bundles
  return unavailable with `schema_comparison: "different"`.
- `app-server --listen stdio:// -c 'cli_auth_credentials_store="ephemeral"'`:
  send `initialize` with experimental API capability, `initialized`, then
  bounded paginated `model/list` requests. There is no login or account request.
  Reject missing/empty/duplicate model or effort names and malformed responses.
  Sort model names and each effort list; hash the canonical `Catalog` object
  encoded by `internal/wire`. Frames are limited to 4 MiB, total output to
  8 MiB, responses/notifications to 128, pages to 16 and models to 1,024.

The catalog remains required: [profile §6](../spec/v0-codex-refresher.md#6-external-token-delivery-and-one-shot-runner)
requires model/effort validation against the qualified catalog; §8.2 step 1
requires version/schema identity. An account-free advertised catalog supplies
identity evidence, not proof that any model is available to a particular account.

`run.json` includes `candidate_observers`: the version measurement, bounded
per-run command and egress summaries, and the schema comparison result.
Commands use a fixed schema-directory placeholder. Raw candidate output,
environment and temporary paths are excluded. This diagnostic evidence grants
no publication authority. Applied properties remain unavailable, unimplemented rows remain
unexecuted, and `--fixtures` still returns 69 without a qualified
entry.

The static configuration identity covers socket/store/executable policy,
account/vendor/profile allowlists, endpoints, generation, release references,
network requirement and lease limit. It excludes launch home, cwd, output,
prompt and temporary paths. It is separate from the runner's existing
per-launch `ConfigSHA256`, which still fingerprints the allowed source files
and their launch-specific paths. That source policy remains enforced before a
lease. Any unavailable input refuses publication and ordinary admission.

## Record and evidence schema

`qualification/1` is a closed typed object decoded with `internal/wire`.
Unknown, missing, duplicate and null members are refused, including nested
members. It contains:

- `identity`: version and the executable/schema/runner/platform/configuration/
  properties/catalog digests, each with its observer name;
- `suite_revision`, `mode` and the fixed ordered case registry;
- each case's positive and negative verdict, execution flag, exact argv, actual
  exit code, typed artifact digests, monotonic elapsed nanoseconds and bound;
- a digest reference to protected live approval, the account identity check,
  operator acceptance, completion time and disposition.

There are no raw-output, diagnostic, token, token-hash or RPC fields. Command
argv must equal the registry's reserved descriptor-bound row command, not shell
text. The dispatcher uses the retained broker worker at descriptor 4; each
case/control selects its fixed argv, with candidate identity separately at FD6.
Elapsed bounds and verdicts cannot convert pending, unrun or skipped rows into
passes. Fake reports can never publish a production entry.

Artifacts are closed `qualification-case/1` metadata, bound to the entire
identity, case/control, argv, real exit and timing. Approval is closed
`qualification-approval/1`, bound to the same identity and matched-account/
operator acceptance. Their content-addressed files are verified on every
publication/read. Digest syntax alone is insufficient: substituting a hash of
material for an observer, artifact or approval digest fails its source binding.
No claim is made that an arbitrary hex string can be classified as secret by
syntax. The writer accepts these typed objects, never arbitrary logs or frames.

## Protected publication and re-read

The qualification directory is the fixed `qualification` child beside static
configuration. It is broker-owned 0700; files are regular, single-link,
broker-owned 0600, with no final symlink. Relative operations remain bound to an
opened directory descriptor. This follows the static policy's protection model
and retains the interim same-user deployment's trust boundary.

Only a confirmed `ENOENT` proves a missing file. Lookup errors such as EIO or
EACCES refuse admission; permission checks and protected opens also fail closed.
All listed records must pass protection, digest, closed-schema, approval and
artifact verification before any matching tuple can be selected. One corrupt or
missing unrelated record refuses the entire list, regardless of entry order.

Publication holds the exclusive lock. Readers hold a nonblocking shared lock.
The following state table describes failures and crash recovery; a marker being
visible never substitutes for validated evidence. The final activation rename can
be visible before its directory entry is durable; a filesystem crash can turn a
successful admission into refusal. This availability rollback is accepted: no
surviving activation admits a tuple without all of its verified evidence.

| Step | State after an error or crash | `Read` verdict |
|---|---|---|
| Open/protect root and acquire lock | No new authority was created; an earlier committed list is unchanged | No new tuple; existing authority still needs every normal check |
| Create/fsync `in-progress`, fsync directory | Fence exists, or publication has not created a new list | Refuse new tuple |
| Remove prior `activation.json`, fsync directory | Fence retained; old activation cannot commit this attempt | Refuse |
| Write/fsync evidence and directory | Evidence may exist; fence retained | Refuse |
| Write/fsync pending list, replace list once, fsync directory | List may be visible; fence retained | Refuse |
| Re-read every listed record/source and current measurements | Any mismatch leaves fence retained | Refuse |
| Write/fsync `pending-activation`, fsync directory | Prepared activation bytes bind the list digest; fence retained | Refuse |
| Unlink fence, fsync directory | On failure, activation is absent and prepared activation remains | Refuse, including immediately after a returned flush error |
| Rename prepared activation to `activation.json` | Last fallible operation, performed only after all durability operations succeed | Admit only after the entire list and current measurements verify |

Activation is a closed `qualification-activation/1` object binding the exact
qualified-list digest. Its inode and preparation directory entry were flushed
before fence removal. No fsync follows its final rename: that would introduce
another possible durability failure after admission had become visible. A crash
may lose this final namespace change and restore `pending-activation`; that is a
conservative refusal requiring reconciliation. If the activation name survives,
all authority data and the fence-removal flush preceded it. Readers require both
fence and pending activation to be confirmed absent and the protected activation
to match the entire list. An old publication without activation is unqualified.

Fault hooks retain the earlier evidence/list stages and add the completed
fence-removal flush. Test-only syscall shims exercise every reached storage I/O
boundary, including the final flush after unlink; production cannot select the
shim. Every injected failure is required to fire, with an adjacent successful
control. The tests simulate individual call failures and stopped publication
stages; they do not emulate filesystem power-loss recovery.

Pending command runs leave admission closed. Fence or activation recovery
requires an operator to reconcile the interrupted evidence while closed; there
is no automatic recovery or override command here.

The daemon and runner use `policy.Config.Qualified` and the same protected list
and evidence reader. The daemon checks before requests/refresh and before
material publication, without holding its state locks over observer I/O.
Release remains available for cleanup. The runner re-reads on each authority
resolution. Binary, configuration, platform or other measured input drift,
missing evidence, tampered provenance or an unavailable observer refuses the
entry. Production applied properties and required row bodies remain unavailable, so
ordinary admission stays `lease_harness_unqualified` (69 at the runner).

## Validation

```sh
GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/qualification ./internal/qualify ./internal/runner -count=1
CANDIDATE_EXECUTABLE="$CANDIDATE" CANDIDATE_EVIDENCE_DIR="$EVIDENCE" GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race -tags=realcandidate ./internal/qualification -run '^Test(RealCandidateObservers|CandidateTraceControls)$' -count=1 -v
GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./... -count=1
"$CURATOR_GO" build -o "$ARTIFACT" ./cmd/swarma-credential-broker
"$CURATOR_GO" tool nm "$ARTIFACT"
```

Run through the installation's shared heavy slot with an owned short TMPDIR.
Tests inject observers only through test-compiled constructors. The synthetic
published positive control exercises the production reader, real daemon,
runner, refresh and durable release with the fake app-server. Its live-shaped
metadata is fixture data, never real row or account qualification evidence.
Check that fixture observer/constructor symbols are absent from the production
binary. Keep test logs, binaries and narrowing overlays in private scratch.
The tagged observer test requires a protected executable, an explicit private
evidence directory and `strace`. It executes only account-free observers through
the boundary, compares two schema measurements, requires zero external grants
and independently rejects external or undecodable connect trace records.

## Fixture row dispatch and limits

`--fixtures --fixture-config "$FIXTURE_CONFIG"` selects a protected, owned 0600
JSON file with exactly `broker`, `allowed_peer`, `foreign_peer`, `account` and
`same_user_r2`. The first three fields are OS account names; `account` is an
explicit enabled policy label. This transport slice resolves broker and allowed
peer through the OS database and requires both to be the current broker user,
with `same_user_r2: true`. No default account or UID is inferred. The foreign
role is reserved but not resolved or executed here: `peer-denied` stays pending
until its genuine foreign-UID helper is supplied. Missing configuration leaves
all rows pending. This format is separate from the existing multi-UID test
helper configuration, which also needs a helper executable and shared socket
directory; it does not claim that helper's evidence.

Each implemented control executes the retained broker descriptor as
`/proc/self/fd/4 qualification-case <id> <positive|negative>`. FD5 is a bounded
private input pipe; FD6 retains the measured approved Codex executable. These
transport rows do not execute Codex. Every worker executes under `internal/egress`
with an empty fresh HOME/CODEX_HOME, closed proxy port and only its private Unix
socket allowlisted. The trusted parent creates the listener outside the client
boundary; candidate listener creation remains forbidden. Use an owned short TMPDIR because Unix socket paths have a
platform length limit. Each worker and its server share a 30-second parent
context. Only the supervised client kernel PID and configured UID can negotiate; an
ordinary same-UID process is refused before reading input. The manager is
issuance-closed, restricted to one configured account and digest, and never
calls an owner. Joined shutdown closes the socket; parent teardown removes the
home and isolated store. No test authority can qualify ordinary leasing.

The report records actual argv, exit, monotonic duration and bound for both
controls. Owned 0600 `row-<id>-<side>.json` files contain closed
`qualification-row-control/1` diagnostic evidence with the exact control,
candidate digest, bounded observation and aggregate egress counts. Their hashes
are verified before crediting the report. They contain no raw frames, private
role mapping or material. They are deliberately distinct from publishable
`qualification-case/1` artifacts: the full current identity, including applied
properties, is unavailable. Missing, mismatched or partial evidence gains no
pass; a refused network destination fails the control even with successful
stdout and exit zero. Pending rows are never launched. Live rows and applied
properties keep fixture reports at exit 69 and prevent publication.

The six implemented rows below have real adjacent hello controls. Malformed
first frames cover both invalid JSON with an apparent ID and a valid non-hello
first request. Unsupported profile covers both an unknown profile and an
unsupported version. The injected peer-probe fault is explicitly model-only;
it is not foreign-UID evidence. No implemented row launches Codex, so tagged
real-candidate row execution is inapplicable to this slice; the existing tagged
observer checks remain the separate candidate measurement procedure.

## Required row classification

The registry below has all 46 required IDs. “Next slice” means unexecuted,
never a skipped pass. The size boundary stops this implementation after the
harness, framing and peer-probe rows; other admission bodies also remain pending.
P9 means [profile §9](../spec/v0-codex-refresher.md#9-negative-cases-and-adjacent-positive-controls);
P9.1 means its broker mapping; B9.6 means [broker §9.6](../spec/broker.md#96-qualification);
P8.2 means [profile §8.2](../spec/v0-codex-refresher.md#82-mandatory-01630-qualification-procedure).
P8.2 step 2 requires synthetic login, account identity, managed refresh,
inference 401, queues, slow/late responses, source/child inheritance and framing.
The step 4 sentence beginning “Owner device-code login” requires real vendor
coverage where fixture equivalence is insufficient for login, real identity,
network-policy fetch, successful inference, effective source/scopes, proactive
refresh, controlled 401 renewal/failure, contention and slow renewal. Only rows
without an equivalent fixture claim are classified live-required below; a
fixture result cannot satisfy the live part of a combined row.

| Required ID | Class; reference | Positive control | Negative control | Current row body |
|---|---|---|---|---|
| peer-denied | fake-only; P9, P8.2 step 2 | Genuine configured allowed process negotiates and leases | Genuine foreign UID gets null-ID role_not_permitted before input, no effects | Pending genuine helper |
| account-denied | fake-only; P9 | Exact allowed peer/account/profile leases | Known disallowed account gets lease_not_authorised, no writer | Next slice |
| account-unknown | fake-only; P9 | Existing allowed label leases | Missing label gets lease_account_unknown, no creation/fallback | Next slice |
| release-unqualified | fake-now + live-later; P9, P8.2 steps 2/4 | Exact approved fake tuple leases; later real tuple | Unqualified digest gets lease_harness_unqualified, no child | Next slice |
| source-conflict | fake-now + live-later; P9, P8.2 steps 2/4 | Clean effective external source; later real scopes | Reserved variable/helper/provider refuses before lease/child | Next slice |
| home-auth-present | fake-only; P9 | Absent native file stays absent | Existing path/link refuses without reading or altering it | Next slice |
| renew-unknown-digest | fake-only; P9 | Superseded delivered token returns current payload without refresh | Unknown digest gets renew_not_current, generation unchanged | Next slice |
| renew-contention | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | One rejection causes one refresh | Eight same-token rejecters share exactly one refresh/generation | Next slice |
| renew-late | fake-now + live-later; P9, P8.2 steps 2/4 | In-budget result answers once | After-eight-second result gets renew_timeout, no late callback | Next slice |
| queue-full | fake-only; P9 | Free slot admits same-attempt waiter | Sixty-four queued operations refuse excess, no extra writer | Next slice |
| daemon-death | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Complete stop and committed outcome permit successor | Surviving child prevents second writer until subtree absence proven | Next slice |
| replacement-contention | fake-only; P9, P9.1, B9.6 | Resolved attempt permits one successor | Replacement and rejecters retain one attempt and writer | Next slice |
| rotation-crash | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Durable store and correlated success activate once | Crash after rotation before checkpoint closes admission, zero retry | Next slice |
| cleanup-interrupted | fake-only; P9, P9.1, B9.6 | Complete correlated absence and reconciliation reopen | Crash before absence record keeps admission closed | Next slice |
| absence-unreadable | fake-only; P9, P9.1, B9.6 | Complete invocation/subtree evidence establishes absence | Partial/denied/conflicting observations permit no writer/enrolment | Next slice |
| store-missing | fake-only; P9, P9.1, B9.6 | Matching durable checkpoint reloads | Missing/unreadable home or intent never reconstructs empty store | Next slice |
| store-rollback | fake-only; P9, P9.1, B9.6 | Independent freshness and explicit reconciliation | Restored old store/fence never retries or clears by parsing | Next slice |
| transient-ambiguous | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Proven non-rotation, absence and reload permit bounded retry | Ambiguous vendor error permits no retry | Next slice |
| reenrol-unresolved | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Confirmed absence then fresh-home enrolment | Unknown prior writer prevents enrolment child | Next slice |
| duplicate-account | fake-now + live-later; P9, P8.2 steps 2/4 | Distinct vendor ID activates independently | Repeated vendor ID gets account_duplicate, no second mapping | Next slice |
| owner-mismatch | fake-only; P9 | Same UID/context renews/releases | Other UID gets lease_not_owner, lease unchanged | Next slice |
| lease-ended | fake-only; P9 | Before-limit renewal and idempotent release | Released/expired renewal gets lease_not_active, no extension/writer | Next slice |
| time-untrusted | fake-only; P9 | Trusted current evidence permits bounded lease | Missing freshness after restart gets lease_owner_unavailable, no advance | Next slice |
| init-without-capability | fake-only; P9, P8.2 step 2 | Experimental initialize then external login | Missing capability gets external_token_init_failed, stop/release | Next slice |
| resume-conflict | fake-now + live-later; P9, P8.2 step 4 optional resume | Fresh lease/login for qualified same-account resume | Drift/native file refuses before inference, no old lease reuse | Next slice; live resume optional |
| frame-oversized | fake-only; P9 | Canonical hello echoes validated ID | Header 65537 gets null-ID frame_too_large then EOF; no records/owner calls | Implemented; no Codex launch |
| frame-zero-length | fake-only; P9 | Canonical hello echoes validated ID | Zero header closes without response/effects | Implemented; no Codex launch |
| frame-truncated-header | fake-only; P9 | Canonical hello echoes validated ID | Two-byte header then half-close yields EOF, no response/effects | Implemented; no Codex launch |
| frame-malformed-first | fake-only; P9 | Canonical hello echoes validated ID | Invalid JSON/non-hello first request closes, no apparent-ID echo/effects | Implemented; no Codex launch |
| peer-identity-unavailable | fake-only; P9 | Genuine own-PID SO_PEERCRED completes hello | Fired injected probe failure gets null-ID peer_identity_unavailable before input | Implemented model-only fault; no Codex launch |
| profile-unsupported | fake-only; P9 | Exact profile and versions [1] negotiate | Unknown profile/version gets version_unsupported then EOF, no effects | Implemented; no Codex launch |
| external-login | fake-now + live-later; P8.2 steps 2/4 | Synthetic login; later approved real device-code login | Missing capability/rejected login leaves no active child/lease | Next slice |
| account-identity | fake-now + live-later; P8.2 steps 2/4 | Matching synthetic ID; later verified real account | Mismatched ID refuses without replacing active mapping | Next slice |
| managed-refresh | fake-now + live-later; P8.2 steps 2/4 | Approved executable refreshes synthetic store; later vendor | Failed/ambiguous rotation never publishes stale material or retries blindly | Next slice |
| inference-401 | fake-now + live-later; P8.2 steps 2/4 | Controlled 401 renews once and inference succeeds | Failed renewal answers error once, no stale replay | Next slice |
| renew-account-mismatch | fake-now + live-later; P8.2 steps 2/4 | Renewed account matches lease | Changed account suppresses delivery/inference | Next slice |
| renew-failure | fake-now + live-later; P8.2 steps 2/4 | Approved safe renewal completes | Rejected renewal gives bounded error, no stale success | Next slice |
| queue-fairness | fake-now + live-later; P8.2 steps 2/4 | Bounded N callers progress on one account | Slow writer causes no starvation, duplicate writer or late delivery | Next slice |
| callback-unanswered | fake-only; P8.2 step 2 | One correlated callback answer | Missing answer times out once, no retained lease/child | Next slice |
| callback-late | fake-now + live-later; P8.2 steps 2/4 | Before-cutoff callback accepted once | Late callback cannot deliver success after timeout | Next slice |
| child-inheritance | fake-only; P8.2 step 2 | Ephemeral source works without child material | Spawned descendant never inherits material/files/descriptors | Next slice |
| network-policy | live-required; P8.2 step 4 network-policy fetch sentence | Real approved application policy fetched/applied | Unavailable/incompatible policy refuses inference | Pending approved live slice |
| approved-routing | fake-only; P8.2 step 2 | Each candidate endpoint reaches only its selected local fake | Unlisted/external connect refuses and fails isolation | Next slice |
| headless-inference | live-required; P8.2 step 4 successful-inference sentence | Bounded approved real headless inference succeeds | Authentication failure gives no false success/fallback | Pending approved live slice |
| effective-source | fake-now + live-later; P8.2 steps 2/4 | Ephemeral external source; later vendor scopes/source verified | Native/helper/provider source cannot override or persist | Next slice |
| vendor-callback-timeout | fake-now + live-later; P8.2 steps 2/4 | Bounded callback answers before cutoff | Eight-second broker/ten-second vendor timeout has no late success | Next slice |
