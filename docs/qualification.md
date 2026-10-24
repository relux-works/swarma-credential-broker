# Qualification records and command frame

`qualify-codex` implements the protected record, publication and pending-row
frame for the mandatory 0.163.0 procedure in profile §8.2. It measures the
candidate's version, experimental schema and model catalog under the egress
boundary. Qualification row bodies remain pending, so it grants no production
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
| 1 | An executed row failed; also reserved until bodies are supplied |
| 64 | Invalid, duplicate, conflicting or missing arguments |
| 69 | Missing approval, unsupported candidate, unsafe/unavailable environment or pending required bodies |

Every live invocation currently returns 69, including one carrying an approval
reference. A fixture invocation writes a protected `run.json` when its policy,
scratch and inherited-input checks permit collection. It lists all required
pending rows and unavailable observer names, then returns 69. Pending rows have
`executed: false`, empty command/artifact arrays, zero elapsed duration and
`exit_code: -1`, meaning no process ran. It never fabricates a process exit or
publishes a qualified entry. An existing report is not overwritten.

A private, owner-only socket reservation is bound to the measured candidate
digest and the run's two-minute context. It has no row dispatcher or lease
handler in this slice. Cancellation closes it, teardown removes only the same
socket object, and a replacement endpoint is preserved. It cannot authorize an
ordinary client. The real private candidate harness arrives with the row bodies.

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
no publication authority. Applied properties remain unavailable, all required
rows remain unexecuted, and `--fixtures` still returns 69 without a qualified
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
text. The future dispatcher uses the measured runner at descriptor 4; each
case/control selects its fixed argv. No such dispatcher is exposed yet.
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
