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

## Qualification authority containment

Both the single-lease and bounded multi-lease synthetic authorities are shipped
with the qualification command. They are constructible only through its explicit
`--fixtures` mode, protected `--fixture-config` roles, protected policy and owned
evidence directory. Neither authority is selectable through daemon/serve,
default `Run`, manager defaults, daemon configuration, flags or environment.
`serve` is currently an unsupported command. Synthetic material and stores remain
inside the private fixture; no real account, token endpoint or store is used.

`TestQualificationAuthorityContainment` derives its first-party source set from
`go list -deps -compiled` for the production Linux/amd64 build with default tags.
It scans every compiled dependency regardless of directory name; unavailable or
invalid dependency sources fail the check. Constructor aliases in dependencies
shared with the daemon are refused; qualification-only dependencies may hold
aliases but cannot call authority during package initialization.
`TestQualificationContainmentImportedWrapper` checks both directions with compiled
source fixtures, including imported `testdata` and underscore-prefixed trees.
The guard also checks server-local wrappers and the command dispatch gates;
`TestQualificationAuthorityCLIContainment` checks shipped entry refusals.
`TestQualificationAuthorityProtectedInputs` pairs those refusals
with protected command-driver execution of both authorities and rejects missing
or unprotected fixture inputs. These checks establish a source/entry boundary,
not exclusion from the shipped binary.

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
JSON file with required `broker`, `allowed_peer`, `foreign_peer`, `account` and
`same_user_r2` fields. Broker and allowed roles resolve to the current broker
user in declared same-user R2 mode. Optional `runner_fixture`, `socket_group`
and `peer_helper` enable the synthetic runner and genuine peer bodies. They are
protected configuration, not CLI or environment bypasses. The runner fixture is
built from `internal/runner/testdata/appserver`; the peer helper from
`internal/qualify/testdata/peerhelper` (use `go build -o <private-output> <package>`).
No account or UID is inferred. Missing inputs leave affected rows pending.
The older tagged multi-UID configuration remains a separate format.

Each diagnostic fixture invocation attempts to execute the retained broker descriptor as
`/proc/self/fd/4 qualification-case <id> <positive|negative>`. FD5 is a bounded
private input pipe; FD6 retains the measured approved Codex executable. These
rows do not execute Codex. Transport and direct admission workers execute under `internal/egress`
with an empty fresh HOME/CODEX_HOME, closed proxy port and only its private Unix
socket allowlisted. The trusted parent creates the listener outside the client
boundary; candidate listener creation remains forbidden. Use an owned short TMPDIR because Unix socket paths have a
platform length limit. Each worker and its server share a 30-second parent
context. Only the supervised client kernel PID and configured UID can negotiate; an
ordinary same-UID process is refused before reading input. The manager is
issuance-closed for transport rows, restricted to one configured account and
digest, and never calls an owner on those rows. Joined shutdown closes the
socket; parent teardown removes the home and isolated store. No test authority can qualify ordinary leasing.

Admission fixtures use a separate constructor with the same private socket and
kernel PID/UID checks. The protected selected account authorizes a synthetic
subject, endpoint and vendor identity; a separate nonissuable anchor keeps
peer/profile admission available when the subject is disabled. Production
policy, lease, publication revalidation and wire encoding remain in use. An
in-memory qualified set contains only that exact fixture policy tuple, or is
empty for `release-unqualified`; it never opens the production qualification
repository. The list and both activation names remain byte-unchanged in the
publication-fence test. No new flag, environment selector or custom build tag
selects this authority.

Each control can make at most one initial lease request, with `MaxActive=1`,
`MaxPending=1`, a five-second lease ceiling and eight total lease methods.
Unknown methods and additional requests close the fixture connection. Material
is generated in parent memory; Snapshot only serves the synthetic subject.
Refresh always refuses and is counted. Early account and qualification refusals
require zero Snapshot calls and zero records. Valid grants require exactly one
record and two Snapshot calls, including production publication revalidation.
The ended-lease script first gets a real grant. Its negative releases the grant,
then compares records and counters against that ended baseline; its positive
renews from an already-newer snapshot without Refresh and releases twice.
An independent unit variant advances the decision clock exactly to the grant's
authorization limit and checks the unchanged active-record baseline. There is
no hand-seeded ended lease. A private pipe acknowledges the parent's snapshot
change only after the grant/release reply. Joined teardown checks the exact
record state, authorization limit, counters and empty unchanged home, then
removes the entire scratch store and home.

The genuine `peer-denied` pair shares a separate listener in an owned 0750
root/directory with a 0660 socket, all in the configured group. Both entries
must retain that exact ownership and mode; the transport listener stays
0700/0600. The foreign role must differ from broker/allowed and belong to the
configured group. Each helper starts as its real configured account through
noninteractive sudo; the same-user allowed helper selects the configured group.
A private handshake checks effective UID/GID and binds the supervised child PID.
The server independently obtains PID/UID/GID through SO_PEERCRED. After the
identity transition, the helper's own egress boundary supervises its fixed
client. The foreign client sends no bytes, checks the broker UID, validates the
closed null-ID terminal and EOF; the parent checks the unchanged store and zero
Snapshot/Refresh calls before the allowed client negotiates and leases on that
same listener. Only role-verification booleans leave the private handshake.

### Execution evidence origin

This section is normative. With protected fixtures on Linux/amd64, six transport,
four single-lease admission and three bounded lease-protocol rows have execution
credit. Peer and runner remain **UNRUN**;
all unavailable paths emit `executed=false`, `exit_code=-1`, no artifact, and
suppress the neighbouring control. No approved candidate runs in these cases.

The proposed [trusted peer supervisor contract](peer-supervisor.md) defines the
foreign-case waiter and its installation/attestation gates. It is inactive; the
peer row above remains UNRUN until an independent supervisor origin is approved
and qualified. The accepted [runner testimony contract](runner-testimony.md)
permits credit for the two runner pairs after implementation and qualification;
it does not change the current executable or confer credit in this docs-only step.

Here P is the trusted qualification parent and K the kernel. A CaseOrigin is
optional in the egress supervisor: ordinary Run retains its existing contract.
It accepts only a parent-created typed endpoint, never generic socket ExtraFiles.

| Path and tests | Launch and identity | Canonical entry | Completion and actual status | Artifact authority |
| --- | --- | --- | --- | --- |
| Transport — `TestOriginExecIdentity`, `TestRowsHarness` | P observes Start, retains the worker image and pidfd. At K's exec stop P compares `/proc` image device/inode and exact bounded initial argv. | P sends a fresh challenge only after verified exec; the measured dispatcher answers on FD9 after input, candidate and empty-home checks. K's SO_PASSCRED supplies the same PID/UID/GID. P acknowledges before exchange. | The locked Start thread owns trace stops and the sole consuming `cmd.Wait`. It retains actual case status, including genuine 0/17 (`TestCaseCompletionStatus`). | P alone writes artifacts after verified entry and join. A passing pair additionally requires exact envelopes and unchanged fixture effects. |
| Admission — same origin tests, `TestRowRefusalEnvelope` | Same retained-image, initial-argv and pidfd proof. | Same post-exec challenge; server checks live origin together with SO_PEERCRED. | Same exact-process wait authority; no helper-supplied status. | P checks grant bounds, store state and Snapshot/Refresh counts before accepting both artifacts. |
| Peer — `TestExecutionOrigin/peer` | P observes sudo Start and kernel connection credentials, but lacks independent measured inner-case identity. | Helper metadata or its receipt can precede entry. UNRUN. | P waits for sudo; no trusted exact-inner-case waiter. Only launcher diagnostics. | Missing origin prevents artifacts and neighbour launch. |
| Runner — `TestExecutionOrigin/runner`; accepted contract, implementation pending | P must measure the image/digest and exact argv at its own direct-child exec stop. | After real Command returns, audited code signals readiness, then answers P's fresh nonce with the actual outcome; SO_PASSCRED binds PID/UID to the traced child. This is `measured-code-testimony`, not a kernel-observed call. | P must own the exact-child wait and validate effects. Missing origin is UNRUN; a valid case with actual nonzero exit is FAIL. Expected local Command refusal 69 is separate from case exit. | P must bind the evidence class and outcome to exact artifacts and its own effect observations. Current executable stays UNRUN until the [contract](runner-testimony.md) is implemented and qualified. |

The origin exchange uses a fresh SOCK_SEQPACKET pair with SO_PASSCRED; FD9 is
marked CLOEXEC on dispatcher entry and closed after acknowledgement. Pre-exec,
wrong-sender, missing-credential, malformed and duplicate replies fail closed.
An additional exec invalidates the origin. This attests the measured dispatcher
and its defined entry boundary, not an arbitrary function call inside the image.

The fixture pathname is selected early, but its listening socket is created only
inside the verified-exec callback while the tracee is stopped
(`TestOriginListenerEpoch`). The server admits only the verified, entered, live
case PID and its real kernel credentials. No pre-exec connection can be queued
on that socket object. Seccomp filters and policy decisions are unchanged.
Unsupported tracing, pidfd, exec metadata or notification facilities fail closed.

Trace handling follows runtime non-leader exec and consumes only stop events
with `waitid(WSTOPPED)`. Terminal state for the case stays waitable until the sole
final `cmd.Wait`; cancellation kills the pinned case and drains trace stops on
that same owner. `TestOriginWaitOwnership` covers cancellation and 0/17 status.

`TestRowArtifactPair` rejects either missing artifact, substituted identity or
hash, invalid duration, lifecycle metadata, closed envelope fields/variants,
parent counters and grant bounds. Serialized lifecycle claims cannot replace
the private parent proof bound to these exact artifact bytes. Failed genuine cases retain their actual nonzero
status, but cannot pass qualification. `row_executions` retains bounded typed
launcher diagnostics for unavailable origins; helper text never becomes authority.
Peer still requires its independent supervisor-origin decision. The runner
contract is accepted; its implementation and qualification remain pending.
The any-peer control remains a declared survivor for that boundary.

Runner source rows execute the real runner Command and SocketClient. The
protected fake app-server descriptor is measured separately; its exact digest
binds both the synthetic broker policy and runner policy. The approved candidate
remains separately measured diagnostic identity and is never run. The parent
creates a fresh launch home/project, an empty reserved source for
`source-conflict`, or an unreadable synthetic native-path file for
`home-auth-present`. The real preflight produces the typed local refusal;
there is no invented wire error. For the negatives, parent checks require zero
connections, requests, records, Snapshot/Refresh calls and child/login events.
The authority-resolution counter and exact local diagnostic are measured-code
testimony, not independent parent observations; see the
[accepted runner contract](runner-testimony.md).
Lstat metadata and inotify verify the fixture path was unchanged and never
opened. The clean neighbor performs one synthetic external login and releases
its bounded lease. Only its expected scenario, event and runner bookkeeping
files are used; the native path stays absent.

The trusted runner establishes its normal session/supervisor before starting
the fake app-server. The fake's qualification scenario confines its version and
protocol children under the existing egress boundary, with no network allowlist.
This placement preserves the boundary's refusal of setsid inside untrusted code
and the runner's real containment setup. Parent validation requires exactly two
complete boundary reports and rejects refused traffic. Negatives start no child
and have no boundary report. These are synthetic runner fixture operations.
The current implementation receives no qualification credit. The accepted
testimony contract permits synthetic pair credit only after implementation and
qualification; no real Codex login, inference or release qualification is established.

`time-untrusted` remains unrun. The snapshot-only fixture has no retained owner
watermark, so a provider Boolean or a fake checkpoint would not prove profile
§9's no-watermark-advance invariant. The real owner's successful Snapshot loads
protected synthetic native material and reconciles durable owner history;
that requires a separate bounded durable-owner enrollment/restart fixture with
the real time provider and adapter. The test-only confidence constructor is not
linked into the release worker. No time-row pass credit is granted here.

For the thirteen attested transport, admission and lease-protocol rows, the
artifact schema records
argv, exit, monotonic duration and bound for each credited control in a pair.
Peer and runner remain UNRUN pending their documented owner decisions in
[Execution evidence origin](#execution-evidence-origin). Owned 0600 `row-<id>-<side>.json` files contain closed
`qualification-row-control/1` diagnostic evidence with the exact control,
candidate digest, bounded observation and aggregate egress counts. Their hashes
are verified before crediting the report. Each exchange retains its validated
closed envelope kind, request ID, payload byte count and hello or refusal fields.
Admission results retain only lease ID and expiry/authorization timestamps,
never material or a material hash. Parent-attested counters are checked again
when validating row evidence.
The validator rechecks these facts against the configured generation and the
exact response shapes in profile §7: errors have no result, empty details, fixed
sanitized text, the expected code and null or validated ID, and at most 512
payload bytes; hello responses have no error member, even when null. Both
unsupported negotiation variants and both malformed-first variants need facts.
They contain no raw frames, private
role mapping or material. They are deliberately distinct from publishable
`qualification-case/1` artifacts: the full current identity, including applied
properties, is unavailable. Missing, mismatched or partial evidence gains no
pass; a refused network destination fails the control even with successful
stdout and exit zero. UNRUN rows may launch one diagnostic fixture but receive no execution credit. Live rows and applied
properties keep fixture reports at exit 69 and prevent publication.

The six transport fixture implementations below have real hello exchanges. The four
admission rows and the genuine peer row have bounded synthetic lease controls;
two runner source rows have synthetic external-login controls. Malformed
first frames cover both invalid JSON with an apparent ID and a valid non-hello
first request. Unsupported profile covers both an unknown profile and an
unsupported version. The injected peer-probe fault is explicitly model-only;
it is not foreign-UID evidence. No implemented row launches Codex, so tagged
real-candidate row execution is inapplicable to this slice; the existing tagged
observer checks remain the separate candidate measurement procedure.

### Bounded lease-protocol authority

Three additional rows use a separate `NewQualificationLeaseRow` constructor.
It has no CLI, environment or build-tag selector. It leaves the original
single-lease constructor, owner, listener and exchange script unchanged. The
production manager/server defaults and the egress boundary are unchanged.
Only a protected fixture policy can reach these scripts; the parent generates
all synthetic material in memory. There is no network endpoint, token socket,
OAuth exchange, vendor store or approved candidate execution.

| Row/control | Leases and initial requests | Total lease methods ceiling | Pending operations | Wall deadline |
| --- | ---: | ---: | ---: | ---: |
| renew-unknown-digest, either side | 1 | 3 | 1 | 30 seconds |
| renew-contention, positive / negative | 1 / 8 (ceiling 8) | 24 | 1 / 8 | 30 seconds |
| queue-full, either side | 65 | 195 | 64 plus one attempted excess | 30 seconds |

The queue positive uses 194 methods: 65 grants, 64 renewals and 65 releases.
The negative uses 195, including the refused 65th renewal. Contention uses
3 or 24 methods; history uses 3. The row listener counts accepted requests,
accepted lease methods and refused excess/unknown methods across connections;
ceiling violations close the connection. Hello negotiation is separate from
lease methods. The manager instance uses existing options: MaxWaiters=1,
MaxActive equal to the row's actual lease count, and MaxPending 1, 8 or 64.
No production limit is raised. Leases have a fixed 30-second authorization
ceiling and cannot be extended by renewal. All rows run serially and once per
control in each test; this is bounded functional queue construction.

Each worker follows the canonical descriptor dispatch under the same attested
transport/admission origin. One Unix connection correlates at most 65 pending
calls. Parent-only phase gates hold Refresh until actual Manager.Stats counts
establish 1/8 pending contention operations, or 63 then 64 queue operations.
The full-queue negative observes the excess operation's manager completion
while the first refresh remains held. Before releasing that gate, the parent
compares the unchanged protected synthetic records/tree and owner generation.
It also detects an admitted 65th operation and drains that violation so the
queue assertion fails without relying on a timeout.

The history positive advances the parent snapshot after a real grant, then
renews using that lease's superseded delivered digest. The negative uses a
never-delivered digest and checks the exact unchanged tree, records, generation
and Snapshot/Refresh counters before release. The parent owns refresh count,
maximum simultaneous writers and generation. The pending peak records only
observations at the held phase gates; history has no held-refresh phase.
No worker-supplied counter is
accepted. Final checks require all real leases released, exact record revisions,
unchanged authorization bounds, one refresh/generation for contention/queue,
and no refresh for history. The live contention half remains pending.

Each pair retains every validated, correlated hello/grant/renew/refusal/release
shape with sanitized lease IDs and timestamps, never material or its digest.
The new scripts alone have a 128 KiB observation limit. Parent counters are
attached after join and bound to the exact artifact bytes by the private
completion proof. `TestLeaseProtocolRows` exercises each pair and rejects
hash-consistent envelope/counter changes or missing private proof;
`TestLeaseRowAuthorityBudget` exercises request/method ceilings and rejection
counts. Existing credited rows retain their original limits and artifact shape.

## Required row classification

The registry below has all 46 required IDs. “Next slice” means unexecuted,
never a skipped pass. This implementation covers the harness, framing,
peer-probe, genuine peer denial, account, release qualification, runner source
and ended-lease fixture implementations. Thirteen transport/admission/lease rows and seven fake owner-core rows execute with attested origin and paired artifacts.
The peer row and two runner rows remain UNRUN even with usable fixtures; the
accepted runner testimony contract awaits implementation and qualification.
Other bodies remain pending; the time row
requires the durable owner integration described above.
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
| peer-denied | fake-only; P9, P8.2 step 2 | Genuine configured allowed process negotiates and leases | Genuine foreign UID gets null-ID role_not_permitted before input, no effects | UNRUN: execution origin unavailable; real configured fixture; P8.1:695–724, P9:800 |
| account-denied | fake-only; P9 | Exact allowed peer/account/profile leases | Known disallowed account gets lease_not_authorised, no writer | Executed with attested paired artifacts; disabled subject, zero Snapshot; P7:582–598, P9:801 |
| account-unknown | fake-only; P9 | Existing allowed label leases | Missing label gets lease_account_unknown, no creation/fallback | Executed with attested paired artifacts; missing label, zero Snapshot; P7:582–598, P9:802 |
| release-unqualified | fake-now + live-later; P9, P8.2 steps 2/4 | Exact approved fake tuple leases; later real tuple | Unqualified digest gets lease_harness_unqualified, no child | Executed with attested paired artifacts; fake tuple; no production publication; P8.2:749–788, P9:803, B9.6:575–587 |
| source-conflict | fake-now + live-later; P9, P8.2 steps 2/4 | Clean effective external source; later real scopes | Reserved variable/helper/provider refuses before lease/child | UNRUN: accepted measured-code-testimony contract, implementation pending; empty reserved-variable pair; P6:493–507, P9:804 |
| home-auth-present | fake-only; P9 | Absent native file stays absent | Existing path/link refuses without reading or altering it | UNRUN: accepted measured-code-testimony contract, implementation pending; synthetic-file pair; retained runner link regression; P6:499–502, P9:805 |
| renew-unknown-digest | fake-only; P9 | Superseded delivered token returns current payload without refresh | Unknown digest gets renew_not_current, generation unchanged | Attested synthetic pair; parent verifies history refusal and unchanged state |
| renew-contention | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | One rejection causes one refresh | Eight same-token rejecters share exactly one refresh/generation | Attested fake pair only; live half pending |
| renew-late | fake-now + live-later; P9, P8.2 steps 2/4 | In-budget result answers once | After-eight-second result gets renew_timeout, no late callback | Next slice |
| queue-full | fake-only; P9 | Free slot admits same-attempt waiter | Sixty-four queued operations refuse excess, no extra writer | Attested synthetic pair; parent holds and verifies the full queue |
| daemon-death | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Complete stop and committed outcome permit successor | Live singleton or Unknown RPC prevents successor | Attested fake owner-core pair; live vendor half pending |
| replacement-contention | fake-only; P9, P9.1, B9.6 | Resolved attempt permits one successor | Replacement and rejecters retain one attempt and writer | Fake owner-core pair |
| rotation-crash | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Durable store and correlated success activate once | Missing durable RPC proof refuses after complete singleton Stop, zero retry | Attested fake owner-core pair; actual owner SIGKILL, independent synthetic writer; live vendor half pending |
| cleanup-interrupted | fake-only; P9, P9.1, B9.6 | Complete correlated absence and reconciliation reopen | Crash before absence record plus partial constructor input keeps admission closed | Attested fake owner-core pair; complete independent constructor reconciles the same attempt |
| absence-unreadable | fake-only owner-core; P9, P9.1, B9.6 | Complete correlated model input resolves the retained attempt | Eight partial/denied/conflicting inputs refuse admission; separate constructor recovery | Attested core pair; model premises only, no platform absence or enrolment credit |
| store-missing | fake-only owner-core; P9, P9.1, B9.6 | Matching durable checkpoint reloads | Eleven home/native/intent/checkpoint/root faults refuse without reconstruction | Attested core pair; continuous bounded filesystem audit |
| store-rollback | fake-only; P9, P9.1, B9.6 | Independent freshness and explicit reconciliation | Restored old store/fence never retries or clears by parsing | Next slice |
| transient-ambiguous | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Proven non-rotation, absence and reload permit bounded retry | Ambiguous synthetic error permits no retry, with old or changed native bytes | Attested fake owner-core pair; Safe 1s/2s backoff and restart control; live vendor classification pending |
| reenrol-unresolved | fake-now + live-later; P9, P9.1, B9.6, P8.2 step 4 | Confirmed absence then fresh-home enrolment | Unknown prior writer prevents enrolment child | Next slice |
| duplicate-account | fake-now + live-later; P9, P8.2 steps 2/4 | Distinct vendor ID activates independently | Repeated vendor ID gets account_duplicate, no second mapping | Next slice |
| owner-mismatch | fake-only; P9 | Same UID/context renews/releases | Other UID gets lease_not_owner, lease unchanged | Pending: foreign-UID admission and independently observed peer origin require an owner decision |
| lease-ended | fake-only; P9 | Before-limit renewal and idempotent release | Released/expired renewal gets lease_not_active, no extension/writer | Executed with attested paired artifacts; release pair + independent expiry unit; P7:624–630, P9:821 |
| time-untrusted | fake-only; P9 | Trusted current evidence permits bounded lease | Missing freshness after restart gets lease_owner_unavailable, no advance | Unrun; needs real retained-watermark integration; P9:822 |
| init-without-capability | fake-only; P9, P8.2 step 2 | Experimental initialize then external login | Missing capability gets external_token_init_failed, stop/release | Pending: independent runner initialization and teardown origin requires an owner decision |
| resume-conflict | fake-now + live-later; P9, P8.2 step 4 optional resume | Fresh lease/login for qualified same-account resume | Drift/native file refuses before inference, no old lease reuse | Next slice; live resume optional |
| frame-oversized | fake-only; P9 | Canonical hello echoes validated ID | Header 65537 gets null-ID frame_too_large then EOF; no records/owner calls | Executed with attested paired artifacts; no Codex launch |
| frame-zero-length | fake-only; P9 | Canonical hello echoes validated ID | Zero header closes without response/effects | Executed with attested paired artifacts; no Codex launch |
| frame-truncated-header | fake-only; P9 | Canonical hello echoes validated ID | Two-byte header then half-close yields EOF, no response/effects | Executed with attested paired artifacts; no Codex launch |
| frame-malformed-first | fake-only; P9 | Canonical hello echoes validated ID | Invalid JSON/non-hello first request closes, no apparent-ID echo/effects | Executed with attested paired artifacts; no Codex launch |
| peer-identity-unavailable | fake-only; P9 | Genuine own-PID SO_PEERCRED completes hello | Fired injected probe failure gets null-ID peer_identity_unavailable before input | Executed with attested paired artifacts; model-only fault; no Codex launch |
| profile-unsupported | fake-only; P9 | Exact profile and versions [1] negotiate | Unknown profile/version gets version_unsupported then EOF, no effects | Executed with attested paired artifacts; no Codex launch |
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


## Synthetic durable owner pairs

These two pairs run real `authowner.Engine`, protected `store`, and
`lease.Manager.Call`/`Publish` in at most two sequential, independently attested
owner processes. The parent generates a fresh initial checkpoint and synthetic
native material once, then owns the manager/native-RPC model, frozen time
premise, requests, observations and verdict. Every recovery constructor opens
with initialization disabled. The approved candidate descriptor is measured
and never executed. Ordinary daemon ownership remains stopped.

This is **fake-only owner-core evidence**: no public socket, physical vendor
subtree absence, real manager, contracted time or production activation credit.
It does not complete platform P9.1/B9.6. The complete/empty model flags are inputs,
not observations of physical absence. Zero vendor children follows from the
closed traced topology; every attempted model Start is counted before its reply.

The owner role uses exact measured-image argv `/proc/self/fd/4
qualification-owner <context-digest>`, with a separate post-exec challenge domain
and kernel sender credentials. `Control.Command` retains the registry's logical
`qualification-case <id> <side>` selector; these rows aggregate the separately
attested owner-role epochs, rather than executing an additional case worker.
Each epoch records its actual full argv, owner-image digest and actual terminal status.
The context binds scenario, epoch, parent and
fixed descriptor roles. No composition/model authority is admitted before entry.
Source containment fixes the private dispatcher and synthetic factory closure;
positive durable effects also have to occur. Image entry or exit zero alone
cannot earn credit. Runtime threads must belong to the actual owner thread group;
additional processes, second exec and incomplete trace/join fail. Each epoch has
one parent-owned consuming terminal wait.

### Store fault matrix

All live faults follow a valid request and release. Two fresh requests must each
return exact `lease_owner_unavailable` with no payload, before reopening the same
faulted state. Unsafe-mode cases exercise protected-mode rejection, not EACCES.

| Fault | Parent mutation | O2 observation |
| --- | --- | --- |
| home-absent | Remove generated home | Owner startup refusal |
| home-mode | Home mode 0750 | Owner startup refusal |
| native-absent | Remove generated native file | Typed owner-unavailable |
| native-mode | Native file mode 0644 | Typed owner-unavailable |
| intent-absent-committed | Remove intent after real committed refresh | Typed owner-unavailable |
| intent-mode-committed | Intent mode 0644 after committed refresh | Lease startup refusal |
| intent-absent-pending | Remove intent after real incomplete-stop prefix | Typed owner-unavailable |
| intent-mode-pending | Intent mode 0644 after pending prefix | Lease startup refusal |
| checkpoint-absent | Remove checkpoint | Typed owner-unavailable |
| checkpoint-mode | Checkpoint mode 0644 | Lease startup refusal |
| metadata-absent | Remove metadata root | Store startup refusal |

Startup refusal records its actual failed construction stage; it is never a
served typed lease reply. The independent intact-store control publishes the
same generation in both epochs. Individual outcome-record loss and metadata
identity/account-directory variants are outside this eleven-case matrix.

The parent arms inotify over existing generated objects and their enclosing
root before faulting. It accounts for the exact parent mutation, retains missing
objects as tombstones, drains through both joins and compares inventories.
A removed open file's expected watch retirement can arrive at O1 close; only
that exact retired watch's self-delete/ignored events are allowed. Any creation,
write, unexpected watch loss, overflow or incomplete inventory fails evidence.
Create-then-delete is detected even when the final tree is unchanged. This is a
bounded cooperative fixture claim, not monitoring of arbitrary external paths.

### Absence inputs and constructor recovery

The real refresh persists its intent and successful native-RPC outcome before
the parent replies to Stop. Complete correlated input permits absent/resolved
records, generation 2 and replacement publication. The following single-input
changes must retain the attempt unavailable and deliver no replacement:

| Input | Exact model error or changed field |
| --- | --- |
| stop-denied | `synthetic_stop_denied` |
| unit-missing | `synthetic_unit_missing` |
| partial | `complete_read=false` |
| invocation | `invocation_id` conflicts with before |
| cgroup | `cgroup_path` empty |
| pid-only | PID zero, but `subtree_empty=false`, `populated_zero=false` |
| boot | `manager.boot_id` contradicts retained binding |
| epoch | `manager.manager_epoch` contradicts retained binding |

Repeated renewal, fresh request after release, and the fresh-home prerequisite
probe refuse without another Start. The probe earns no enrolment credit.
Scenario A keeps incomplete evidence at O2's first constructor and stays refused.
Independent scenario B supplies complete input at O2's first constructor and
resolves the same retained attempt. A blocked O2 is never reconstructed or
recovered again. Boot/epoch contradictions remain negative. Timed-out reads are
not covered by this matrix.

### Enforced budgets (setup included)

Counts are per scenario, in the order request / renewal / release / prerequisite.
Every scenario has one account, at most two owner epochs and at most one Start.

| Script | O1 calls | O2 calls | Total Starts |
| --- | --- | --- | --- |
| Intact store reload | 1 / 0 / 1 / 0 | 1 / 0 / 1 / 0 | 0 |
| Store fault without retained attempt | 3 / 0 / 1 / 0 | 1 / 0 / 0 / 0, or all zero on startup refusal | 0 |
| Store fault with committed/pending intent | 3 / 2 / 1 / 0 | 1 / 0 / 0 / 0, or all zero on startup refusal | 1 setup refresh |
| Complete absence | 1 / 2 / 1 / 0 | 1 / 0 / 1 / 0 | 1 |
| Incomplete O1, incomplete O2 | 2 / 2 / 1 / 1 | 1 / 0 / 0 / 0 | 1 |
| Independent partial O1, complete O2 construction | 2 / 2 / 1 / 1 | 1 / 0 / 1 / 0 | 1 |

Each epoch permits at most three requests, three renewals, two releases, eight
lease calls, two prerequisite probes and 256 messages total. Frames and
context are at most 4 KiB, metadata at most sixteen 16 KiB records, trace/network
and filesystem events at most 4096 and 1024 respectively. Budget exhaustion,
unknown observation and the 30-second scenario/row deadline are evidence
failures. Initial refresh is counted separately from zero additional Starts.

`TestOwnerStoreMissingPair`, `TestOwnerAbsenceUnreadablePair`, the reconstruction,
PID-only resolution, hidden-Start, no-op dispatcher and filesystem audit controls
run in default Linux/amd64 tests. Capability skips follow actual pidfd, ptrace
or seccomp listener probe failures and earn no executed-row credit. No systemd,
chrony, root, additional UID, real login or real endpoint is needed.

The `time-untrusted`, peer and runner rows remain pending.
`reenrol-unresolved` and `duplicate-account`
need the administrative fresh-home enrolment and publication mechanism (separate
decision). `store-rollback` needs independent CAS witness and broker restore
reconciliation. The frozen fake time premise supplies none of those authorities.
## Synthetic writer lifecycle pairs

`transient-ambiguous`, `rotation-crash` and `cleanup-interrupted` add a parent-owned
singleton synthetic writer, independently attested under `qualification-writer`.
Its measured image is the trusted broker fixture, distinct from the measured,
never-executed approved candidate. It receives only generated replacement bytes,
can persist them through write/fsync/rename/directory-fsync and answer fresh
challenges, and cannot fork or exec another image. Actual PID/start identity,
post-owner-join challenge, terminal SIGKILL, complete trace and sole wait support
only **no second synthetic writer** and **complete singleton absence**. Manager,
endpoint rotation and confidence remain explicit parent models. Real vendor
subtrees/cgroups, vendor durability, public transport and platform P9.1/B9.6
qualification remain pending.

The parent holds synchronous Confidence calls at canonical running prefixes with
old/new native bytes and no stopping proof, or holds Stop after Committed stopping
proof and the writer's joined termination but before absence. It rechecks the
prefix, seals a nonce/context digest and requests SIGKILL through that session's
supervisor-owned pidfd. A separate planned-termination certificate records that
authorization, verified role entry, actual signal 9, exit -1, nonzero wait error,
trace closure and one joined wait. Ordinary origin facts, error and credit rules
still reject the signaled run. Cleanup cannot create a missing certificate. Every
crash epoch remains mandatory even though O2 later closes normally; aggregate
artifacts also require the private parent's exact-byte completion binding.

Ambiguous code 1002 remains Unknown after complete Stop, restart and a +61s fake
step, for either old or changed native bytes. Safe code 1001 proves nonrotation
only in this qualified synthetic composition. Its unchanged-token renewal returns
`renew_failed`; resolution sets persisted 1s then 2s backoff, and a due successor
publishes A1 with owner `TokenGeneration=2` and lease `OfferedGeneration=2`.
A superseded A0 rejection returns A1 without a new Start. Outcome generation is
policy generation. The full backoff schedule retains its existing pure owner
tests; these integrated scripts exercise only 1s and 2s. A durable Committed
stopping prefix with A1 can recover at O2's first complete constructor; partial
input cannot append confirmed absence or resolve. A separate terminal reload
control needs no new Stop.

Each row side retains its unchanged absolute 30s bound, including all independent
variants and joined cleanup. Work stops at the row deadline minus 5s to reserve
cleanup. An earlier lifecycle row deadline failure remains unexplained; test-only
diagnostics retain its scenario, last phase, pending wait and bounded error chain on recurrence.
A timeout, overflow, extra attempted Start or incomplete observation
fails evidence. New private caps are Q/R/L=3/5/2, eight lease calls, three clock
steps and 512 combined 4KiB frames per owner; two sequential owner epochs; three
writer launches and one live singleton per scenario; 64 non-Confidence model calls;
32 records of at most 16KiB, 64 filesystem objects, 2048 filesystem events and
4096 trace/network events per process. Existing pairs retain their limits.
Directory observers admit fixed owner-record paths during owner activity and
native replacements only during the explicit writer permit, pin stable identities
and reject revision rollback, unknown paths, watch loss and overflow. This is a
cooperative measured-code observation, not hostile same-UID byte monitoring.

Pure classifier, pending-state, clock, certificate and observer checks run in
default CI. Integrated pairs require only generated fixtures and actual minimal
seccomp/pidfd/ptrace capability; missing capability follows `hosttest.Require`,
never an assertion-based skip. Process-overlap and no-op-persist controls test
actual launches and file effects. Store rollback, reenrolment, duplicate
publication, contracted time, peer/runner origin
and real manager/vendor qualification remain deferred.

### Daemon death and competing replacements

`daemon-death` holds the real owner at durable submitted/running evidence before
any native exchange. A planned SIGKILL joins that owner; its independent writer
must answer a fresh challenge afterward. Independent replacement constructors
receive either partial Stop while that writer remains live, or complete Stop
with actual joined singleton termination. Both retain Unknown, generation 1 and
one pending intent without a successor. Later forced cleanup is recorded
separately and supplies no absence authority. The independent normal-stop
positive first commits A1, then permits one successor committing A2.

`replacement-contention` runs both A-first and B-first schedules. Two measured
replacement candidates enter before either opens the real store. The winner
holds the store lock before its first Ready; a non-consuming lock probe on the
pinned generated lock inode confirms it. The loser must fail at store startup,
join and serve zero calls. Each process has immutable context and correlated
bounded messages; a held callback does not block another caller's arrival.

In the unresolved script, two retained valid A0 leases reject A0. L1 is held at
its actual dequeue before Snapshot; L2's actual arrival is observed before L1
resumes. Both renewals, a repeat and two fresh requests after both releases give
exact `lease_owner_unavailable`. In the resolved script, two fresh A1 leases
renew through overlapping Calls and publish A2; both repeated superseded A1
rejections publish A2 without another Start. An existing response callback holds
one caller until its neighbor has called and published, preventing publication
from racing the neighbor's nonblocking owner Snapshot. This schedule establishes
Call overlap, not concurrent publication or a count of already queued waiters.

For each admitted renewal the parent reads checkpoint `TokenGeneration=3` and
that lease's `OfferedGeneration=3`. `Outcome.Generation=1` is policy generation;
`ObservedGeneration=2` correctly identifies the rejected A1. Retained prior
attempt records must remain byte-identical, and actual complete Stop plus the
old committed history precede successor Start.

| Script | O1 Q/R/L | Serving replacement Q/R/L | Starts |
| --- | --- | --- | --- |
| Death, each live-partial / complete-Unknown variant | 1/1 interrupted/0 | 2/1/1 | 1 |
| Normal stop and successor | 1/1/1 | 1/2/1 | 2 |
| Contention unresolved, each lock order | 2/1 interrupted/0 | 2/3/2 | 1 |
| Contention resolved, each lock order | 1/1/1 | 2/4/2 | 2 |

The loser has zero calls. Clock steps are zero. Engine MaxAttempts is 4;
MaxActive, MaxPending and MaxWaiters are each 2, with at most two concurrent
Calls, three simultaneous parent children and one live writer. All variants and
joined cleanup share the unchanged 30s row-side bound. These scripts keep the
512-frame, 64 model/gate-entry and existing observation limits; the distinct
bounded Call callback ledger has at most 64 entries. Tests and controls run via
`go test ./internal/qualify -run 'TestOwner(DaemonDeathPair|ReplacementContentionPair|Parallel)'`;
normal test logs are caller-selected and protected qualification artifacts use
the evidence directory. Real manager/vendor and descendant-tree qualification
remain outside this synthetic singleton evidence.
