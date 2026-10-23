# Qualification records and command frame

`qualify-codex` implements the protected record, publication and pending-row
frame for the mandatory 0.163.0 procedure in profile §8.2. This slice executes no
candidate, fake qualification body or live row. It grants no production release
qualification. The shipped owner also remains stopped.

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
| Executable | SHA-256 through a retained no-follow open of every path component; regular executable, broker/root-owned, no group/world write |
| Runner | SHA-256 of `/proc/self/exe`, combined with `debug.ReadBuildInfo` main version and VCS revision |
| Platform | Kernel release/version, OS ID/VERSION_ID, architecture and bounded `systemctl --version` first line, canonically hashed; no machine name |
| Configuration | Canonical static daemon configuration plus harness/channel/profile, ephemeral-source policy and supervisor containment revision |
| Version | Unavailable until the network-isolated launcher in the next qualification slice |
| Experimental schema | Unavailable until candidate schema generation under that launcher |
| Applied properties | Unavailable until the contained owner's unit template and current-property observer are available |
| Model catalog | Unavailable until the candidate app-server observer is available |

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

1. Acquire the exclusive directory lock and create/fsync the `in-progress`
   admission fence; fsync the directory. Readers take a nonblocking shared lock
   and refuse a running or interrupted transaction.
2. Measure current inputs and verify all required executed green rows, typed
   artifacts and live approval. Persist/fsync the content-addressed record,
   then fsync the directory. Existing bytes at that name must be identical.
3. Write/fsync the pending list and atomically rename it to `qualified.json`.
   The list adds only the exact measured identity; no wildcard version exists.
4. Fsync the directory. Re-read the list, record, approval/artifacts and current
   measurements before removing the fence and flushing that removal.

Fault hooks cover before evidence flush, after evidence flush, after list
replace and after list-directory flush. Every interrupted path preserves the
fence, so a visible renamed list is insufficient for admission. Pending command
runs also leave admission closed. Fence recovery requires an operator to
reconcile the interrupted evidence while closed; there is no automatic recovery
or override command here.

The daemon and runner use `policy.Config.Qualified` and the same protected list
and evidence reader. The daemon checks before requests/refresh and before
material publication, without holding its state locks over observer I/O.
Release remains available for cleanup. The runner re-reads on each authority
resolution. Binary, configuration, platform or other measured input drift,
missing evidence, tampered provenance or an unavailable observer refuses the
entry. Production version/schema/properties/catalog are unavailable today, so
ordinary admission stays `lease_harness_unqualified` (69 at the runner).

## Validation

```sh
GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/qualification ./internal/qualify ./internal/runner -count=1
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
