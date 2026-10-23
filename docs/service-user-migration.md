# Offline service-user migration

`scripts/migrate-service-user` implements the ordered orchestration in
[profile Appendix A](../spec/v0-codex-refresher.md#appendix-a-owner-action-for-dedicated-user-isolation).
It is a Bash script for a root administrator in a reviewed maintenance window.
It never enrolls an account, refreshes credentials, reconstructs a missing store,
or resolves an ambiguous rotation. Interim mode retains
[§2.1's limits](../spec/v0-codex-refresher.md#21-interim-run-identity).

**This script requires review before owner use.** Fixture success qualifies
its orchestration only. The repository does not supply a production site driver,
activation inventory, writer-evidence verifier, service deployment or readiness
qualification. Missing dependencies refuse migration. A driver that merely
prints the strings below does not implement the contract. Do not install the
fixture commands as an administrator.

## Preparation and configuration

Use Bash 5 or newer, GNU find/stat/coreutils (including `mv --no-copy`),
util-linux `flock` and `mountpoint`, and the account-management tools. Run with
a trusted PATH and a clean environment; never enable shell tracing. Every
external command goes through `command_layer`. No shell configuration is
sourced, no command is evaluated from a string, and command output/errors are
suppressed except for fixed sanitized status messages.

The administrator prepares the service parent required by A.1, its trusted
ancestors, a separate root-owned mode-0700 run directory, and an empty
root-owned mode-0600 `lock` file inside it. The script does not create the service
parent or adopt a pre-existing service identity. Configure these exact keys in
a root-owned mode-0600 regular file with a single link:

```text
old_user=<former account name>
old_uid=<former positive numeric UID>
old_gid=<former positive numeric GID>
user=<new service account name>
uid=<unused positive numeric UID>
group=<new service group name>
gid=<unused positive numeric GID>
home=<absolute new home>
parent=<absolute prepared service parent>
source=<absolute existing store directory>
destination=<absolute destination directly inside the new home>
state=<absolute prepared run directory>
driver=<absolute protected site-driver executable>
shell=<absolute nologin executable supplied by the installation>
```

Placeholders must be replaced privately. Do not put credentials in this file.
Names use lowercase ASCII, digits, underscore and hyphen; paths use ASCII
letters, digits, slash, dot, underscore and hyphen, without empty, `.` or `..`
components. The home is a direct child of the prepared parent; the destination
is a direct child of that absent home. Configuration, state, driver and service
parent ancestors must be root owned and not group/other writable. Source
ancestors may also belong to the specified old UID. Links are refused; only `/`
may be a mount point in the ancestor chains. Installations with additional
trusted mounts need an explicitly reviewed extension.

The service parent must be mode 0755. The existing store must be owned by the
specified old UID/GID, contain only mode-0700 directories and mode-0600 regular
files, and contain no links, mounted children or multiply linked files. Names
outside the supported path alphabet are refused. All store observations are
metadata operations; neither file bodies nor token values are read or hashed.
Retained attempt/outcome files move with the directory.

`flock` serializes invocations using the same run directory. It does not lock
other administrators or writers. The site driver must independently hold the
complete account-database, filesystem and activation maintenance fence across
both invocations. This is a prerequisite for path-based identity guards, not a
claim of protection against concurrent root or malicious same-UID processes.

## Operator procedure mapped to A.1

Invoke with a sanitized environment using the installation's trusted tool PATH:

```sh
env -i PATH=<trusted-tool-path> /bin/bash scripts/migrate-service-user close-admission <absolute-config>
```

| A.1 step | Tool action and operator gate |
|---|---|
| 1. Close old admission | Complete read-only preflight first, including absent user/group by both name and numeric ID, absent home and therefore destination, same filesystem, full metadata snapshot, protected paths and serialized inventory. Persist preflight; record intent, then ask the site driver to close both admissions, disable all old activations/restarts and stop the old daemon. Independently verify closure and write `closed`. |
| 2. Reconcile | After the first invocation exits zero, the operator reconciles every retained original-manager attempt and durable outcome under §5/§5.1. The site's independent evidence verifier must succeed on current observations. Obtain its evidence digest and the preflight fingerprint (last colon-separated field of `closed`). Write the exact confirmation line below to root-owned mode-0600 `confirmation` in the run directory and durably flush it. Do not copy an earlier confirmation. |
| 3. Provision | A separate `migrate` invocation repeats the entire preflight, checks it against the persisted transcript, rechecks closure, serialization and independent writer evidence, and checks confirmation. Create exactly the requested group, account without an automatic home, and protected home. Capture each identity. |
| 4. Move | Recheck closed admission, serialization and the captured source/tree identities. Use `mv -T --no-copy --no-clobber` on the same filesystem. Verify absent source and identical destination device/inode. |
| 5. Normalize | Set and verify each captured directory/file owner and 0700/0600 mode individually; reject links/mounts/hard links. Set and verify the protected home owner. Recheck old-writer evidence. |
| 6. Re-pin | Invoke the reviewed site deployment, then independently verify the executable/service/configuration, client UID/socket/static-policy pins and invalidation of all old leases. |
| 7. Readiness/start | While admission stays closed, require containment, store/outcome, policy and qualification gates. Start the new manager/daemon, verify readiness, recheck store identities/permissions, then enable only new admission and verify the final state. Old activation paths remain disabled. |

Confirmation is exactly one line, with the two lowercase hexadecimal digests
obtained during the operator's reconciliation:

```text
I_HAVE_RECONCILED_ALL_WRITERS_AND_DURABLE_OUTCOMES:<preflight-fingerprint>:<current-evidence-digest>
```

Then invoke separately:

```sh
env -i PATH=<trusted-tool-path> /bin/bash scripts/migrate-service-user migrate <absolute-config>
```

A missing, stale or altered transcript/confirmation, changed store metadata,
changed inventory/serialization, or unknown writer evidence refuses migration.
The confirmation does not establish writer absence. Neither a stop result nor
a new manager's empty inventory is accepted as old-writer evidence.
If step 1 itself changed store metadata while stopping the daemon, prepare a
fresh run directory and repeat step 1 while keeping admission closed; never
edit the recorded transcript to bypass the mismatch.

## Required site-driver contract

The protected root-owned executable receives `ACTION CONFIG`. Successful reads
must return **exactly** the following single-line values, followed by one LF,
and exit zero. The complete record must fit in 1024 bytes. NUL, CR, nonprintable
or non-ASCII bytes, missing LF, extra lines and oversized output are unknown.
Any nonzero status is unknown even with expected-looking output. All digests are
64 lowercase hexadecimal characters. Observation output never includes secret
material. The root administrator reviews and installs the driver together with
the deployment; it must validate the supplied configuration and its own inputs.
Every action uses exit 0 for success; every nonzero exit, signal, missing result,
partial observation or unexpected value is unknown. Mutation stdout is ignored;
an exit 0 never replaces the independent readback. A mutation can take effect
before failing, so recovery records intent and reconciles actual state.
The following table maps each operation to the ordered gate and status,
evidence or recovery requirements in A.2.

| Action | Result or required effect | Gate served |
|---|---|---|
| `inventory` | `inventory:I:serialized:S`. I commits to approved maintenance scope and the complete old/new lease, launch, socket, timer, dependency and restart inventory. S identifies the still-held exclusive account/filesystem/activation maintenance fence. Refuse if incomplete, changed or not held. | A.1 preflight/steps 1–7; A.2 serialized preflight and status validation |
| `close` | Mutation: durably close both old/new lease and launch admission, disable all automatic activation/restart paths and stop the old and any new daemon. Idempotent, safe during recovery; never enroll/refresh. Failure after a partial effect is allowed but remains unknown until readback. | A.1 step 1/recovery; A.2 intent and closed admission on failure |
| `closed` | `closed:I:old-inactive:old-disabled:new-disabled`. Independently verify the entire inventory and both admission gates, including any new daemon activation. This is not writer-absence evidence. | A.1 steps 1–7/recovery; A.2 independent status/readback before success |
| `evidence` | `reconciled:E:original-manager:complete-absence:durable-outcomes`. Inspect retained §5/§5.1 intent, evidence and checkpoints, current original-attempt/boot/manager-epoch/InvocationID bindings, stop/readback/recursive cgroup absence, durable outcome reconciliation and independent freshness. E commits to that complete retained inventory and current resolution. Unknown, lost, contradictory or ambiguous records refuse. Inspect metadata records only, never credential files. Works before and after store rename, retaining the same evidence binding. | A.1 steps 2/5/6; A.2 confirmation is not writer evidence |
| `install-and-repin` | Mutation: install the reviewed executable/service/configuration, replace client broker UID/socket/static-policy pins and invalidate old leases, with both admissions closed. | A.1 step 6; A.2 intent and preserve uncertain deployment |
| `installed` | `installed:I:uid=U:leases-invalidated:clients-repinned`, independently verified for configured new UID U and exact reviewed deployment. | A.1 step 6; A.2 status before value and independent verification |
| `prestart` | `ready:I:containment:store-outcomes:policy:qualification:admission-closed`. Independent positive results for every required gate, still bound to retained old attempts; absent qualification refuses. | A.1 step 7 before start; A.2 failed/unknown observations refuse progress |
| `start-new` | Mutation: start the new manager/daemon with admission closed; old paths stay disabled. | A.1 step 7 while closed; A.2 intent and failure reconciliation |
| `readiness` | `ready:I:new-active:old-disabled:admission-closed`. Verify actual new readiness and both closed admission gates before opening. | A.1 step 7 before admission; A.2 status before value |
| `open-new` | Mutation: enable only the new lease/launch admission. Must retain disabled old activation. | A.1 step 7 after readiness; A.2 partial effects reconciled and re-closed on failure |
| `final` | `active:I:new-open:old-disabled`. Independently verify final state. | A.1 step 7 completion; A.2 final post-state before success |

No implementation for these platform-specific operations is supplied here.
The tool cannot be used against a real installation until its driver meets this
contract and real provisioning, writer lifecycle, FD passing and required
release/readiness checks have been qualified. Fixtures do not provide those
proofs.

## Intent, recovery and exits

`preflight` preserves all original store device/inode/owner/mode/type/link-count,
size and modification/change-time observations plus the original account record,
configuration digest, parent/state identities and inventory/serialization.
`journal` is append-only during a run. Before each target mutation it records
intent and flushes the file and run directory. Identity captures and phase
records are also flushed. Journal writes are the persistence mechanism, not
recursively journaled target changes. They contain private paths and account
metadata, so keep the run directory protected and do not publish its contents.
Before the first target effect in either phase, the tool also durably records a
conditional `recovery-close` intent. That authorizes the idempotent safety close
throughout the phase, even if subsequent journal writes or flushes fail. Recovery
closes and verifies admission before attempting another journal append; failed
persistence still yields exit 75 and incomplete/unknown recovery.

The first phase requires `journal`, `preflight`, `closed`, `confirmation`,
`migration-started` and `result` to be absent. It rechecks still-unused records
before closing admission. Migration rechecks `migration-started` and `result`
before its first mutation, and each forward mutation rechecks `result`.
Unexpected records are preserved, never adopted or overwritten. The maintenance
fence remains necessary to exclude concurrent changes between checks and effects.

All command observations use a bounded raw Bash read and a separate child-status
wait before comparison. Identity, stat and digest outputs require one LF;
`getent` absence requires exit 2 and empty output; `mountpoint -q` non-mount
requires exit 32 and empty output; `flock` success requires empty output.
Configuration, retained phase records and tree listings preserve internal LFs
and require a final LF; find's absence/count formats retain their no-LF framing.
All observations reject NUL and bytes outside printable ASCII/LF. Non-driver
single records are limited to 4096 bytes; configuration, phase records and
enumerations to 1 MiB. Exceeding a limit refuses rather than truncating.

A record already known to be invalid never waits for the producer's normal
exit. The command execs as the captured direct child PID. Bash 5.3 or later is
required: `wait -n -p` races this child against an owned 50 ms timer. Only a
positive completion naming that exact child establishes `absent` (the original
child has been reaped), regardless of its exit code. No failed filesystem
lookup establishes absence or authorizes a subsequent producer wait. If the
timer completes first, a successful `/proc/<pid>/stat` read with matching direct
parent and a valid start time establishes `present`. Read failures, including
ENOENT, EACCES and EIO, malformed metadata, foreign parentage, and unavailable
wait evidence remain `unknown`. This uses positive child completion rather
than interpreting a filesystem not-found result as process completion.

The tool closes the read end and attempts TERM, then KILL, only when direct
parentage and the same observed start time are freshly confirmed. Each phase
has at most ten 50 ms probes, followed by one final bounded confirmation:
nominally 1.05 seconds plus command/scheduling overhead, not a real-time
scheduling guarantee. Unknown probes retain the identity and consume this
bounded budget without blocking on the producer. Valid records keep an
unbounded wait for their producer's actual exit status.

If termination cannot be confirmed, the tool retains and reports the numeric
PID, returns incomplete/unknown (75 even during preflight), and never reports
verified cleanup. During migration it still attempts the pre-armed safety close
and closed-state readback before halting. An unavailable process table also
means termination is unconfirmed. No process group is signaled. Parentage and
start time are checked again before KILL, reducing the PID reuse window. Bash
still supplies a numeric PID to `kill`: the original child could exit and Bash
could reap it between the metadata read and the signal syscall, permitting PID
reuse in that interval. These checks do not close that race or guarantee that a
reused foreign PID can never be signaled. Closing it requires a separately
reviewed process-handle implementation such as Linux pidfds. These bounds
concern the captured command itself; the site driver must own and reconcile any
subprocesses it creates.

Errors and INT/TERM/HUP enter reconciliation based on current observations and
the preflight identities. Recovery first re-closes admission and verifies the
maintenance fence. A store with its original identity is restored only if the
source is proven absent, with no-clobber rename after restoring original
owner/modes. A reappearing source is never overwritten. Created resources are
removed only with their captured identities; unknown partial creations remain
in place. Guard/readback failures preserve resources and report
`incomplete/unknown`. Cleanup success requires complete final resource and
closed-admission readback. Deployment or start having begun requires site
recovery; the generic script preserves deployed resources and re-closes
admission instead of guessing how to undo them.

Never rerun a started migration as an automatic recovery action. The durable
`migration-started` marker refuses that. After SIGKILL, power loss or unknown
recovery, an administrator must inspect the protected transcript, reconcile
actual resources and §5 evidence, and arrange reviewed recovery with both
admissions closed. There is no automatic resume or removal of unknown records.
Failure to close admission requires operator resolution before any migration.

| Exit | Meaning |
|---|---|
| 0 | Requested phase verified; `close-admission` still requires step 2 and a separate invocation. |
| 64 | Invalid invocation or config-path syntax. |
| 69 | Read-only preflight/evidence/confirmation refused; no migration mutations. |
| 75 | Persistence, mutation, verification or recovery failure; fixed diagnostic distinguishes verified target cleanup from incomplete/unknown recovery. |
| 130 | INT handled through reconciliation. |
| 143 | TERM/HUP handled through reconciliation. |

## Fixture checks and their limits

Run only this tool's tests, using a fresh scratch directory outside the checkout:

```sh
bash -n scripts/migrate-service-user
bash -n tests/migration/run
bash tests/migration/run <absolute-fresh-scratch-directory>
```

The shell runner executes the **shipped script unmodified**. Python 3 standard
library command doubles provide structured failure injection and call records.
The process-lookup regressions also require `strace` syscall injection on Linux;
they trace the main Bash process and verify EACCES/EIO at the exact owned-child
`openat` call. Each includes an ordinary shutdown control. A test-only Linux
subreaper, accessed through Python's standard-library `ctypes`, collects any
fixture producer abandoned by the narrowing mutant. Real fixture inodes,
renames and credential-canary
atimes are checked; account database, ownership, root authority, mount inventory,
manager and durability effects are simulated. No real account or service-manager
operation runs. The doubles reject credential reads via `cat`/`sha256sum`; every
assertion checks no forbidden read, no canary in output/state records, unchanged
payload atimes and unchanged unrelated-directory identity. Atime observations
supplement call records; they do not establish a kernel-level no-open proof on
all filesystems. The bounded process-metadata traces do not establish a general
no-open proof. No real mount operations, root provisioning or real credential
tests are claimed.

| Requirement | Implementation | Named tests (with adjacent controls) |
|---|---|---|
| Observation status before value | `observe`, `lookup`, `stat_path`, `not_mount`, `absent`; explicit status handling, no errexit/negated command checks | `ObservationRejectsFailed-*`, `GetentExit1IsUnknown`, `GetentExit3IsUnknown`, `Rollback*FailureIsUnknown` |
| Raw framing before value | Bounded NUL-delimited read, exact LF validation, independent child status; no lossy command substitution | `ReworkRawDriverRejects-*`, `ReworkRawDriverExactFormatControl`, `ReworkRawObservationRejectsNul-*`, `ReworkRawMetadataHashRejectsNul`, `ReworkRawFlockRejectsOutput`, `ReworkRawMountpointRejectsOutput` |
| Invalid live producer cannot postpone refusal/recovery | Bounded child-completion probes, parent/start-time guards before TERM/KILL; unknown PID retained | `LiveProducerNul-*`, `LiveProducerOversize-*`, `LiveProducerTermCooperative`, `LiveProducerClosedInvalid`, `LiveProducerUnconfirmedRefusal`, `LiveProducerUnconfirmedRecovery`, `LiveProducerWaitOrderingControl` |
| Failed process lookup remains unknown | Actual EACCES/EIO at the shipped script's process metadata lookup cannot authorize blocking wait or discard a live child | `ProcessLookupEACCES`, `ProcessLookupEIO` (each with ordinary shutdown control), `ProcessLookupUnknownAbsenceNarrowingControl` (same EACCES regression fails on discarded live child; trace confirms fault and fixture cleanup) |
| Reader evidence remains valid after stop | Invalid-child absence needs no fd read; valid incomplete output retains the pipe reader until release | `ReaderWaitEvidenceOversize`, `ReaderWaitEvidenceNul`, `ReaderWaitEvidenceValidControl` |
| Valid producer status still awaited | No valid-observation deadline, including fragmented output and valid EOF | `LiveProducerFragmentedControl-*`, `LiveProducerNonzeroControl-*`, `LiveProducerValidEofControl` |
| Absence before mutation, retained preflight | Read-only preflight then `write_record` | `PreflightRejects-*`, `ConfirmationRejects-stale-store` |
| Fresh phase/result artifacts before dependent effects | Initial absence checks, phase-boundary rechecks and per-mutation result guard | `ReworkExisting-*-RefusesBeforeClose`, `ReworkExisting-*-RefusesBeforeMigration`, `ReworkLateResultBlocksDependentMutation`, `ReworkFreshArtifactsControl` |
| Intent before mutation, effects reconciled on error/signal | `mutate`, traps, `recover`, durable transcript | `RenameErrorAfterEffectRestores`, `TermBetweenRenameAndBookkeepingRestores`, `PartialGroupCreationPreserved`, `TermAfterGroupCreationPreserved` |
| Late persistence loss still permits the safety close | Durably armed conditional close, verified before further journal writes; unknown cleanup preserved | `ReworkPersistentJournalFailureAfterOpenRecloses`, `ReworkPersistentJournalControl` |
| Separate close/confirmation/migrate and actual evidence | Phase dispatch, transcript comparison, independent `evidence` | `ConfirmationRejects-*`, `ConfirmationControl-*` |
| Identity-guarded rollback, final readback, no reopen | `restore_metadata`, `cleanup_resources`, `recover` | `ReappearingSourceNeverOverwritten`, `Rollback*FailureIsUnknown`, `PartialChownRestoresMetadata`, `PartialChmodRestoresMetadata` |
| Offline rename and metadata-only normalization | `mv --no-copy --no-clobber`, tree snapshot/guards | `PreflightRejects-device`, `PreflightRejects-symlink`, `PreflightRejects-mount`, `PreflightRejects-hardlink`, `RenameErrorControl` |
| Gates for deployment/start/open | Required site-driver observations | `DeploymentFailureStaysClosed-*`, `DeploymentControl-*` |
| Sanitized output, credential bodies unread | Fixed diagnostics, metadata-only command set | Every fixture assertion, including successful migration controls |
| Narrowing control | Scratch copy removes only the marked generic status-validation block; all value comparisons remain | `ObservationStatusNarrowingControl` runs the identical root-observation regression and requires its exit 1 plus an actual unsafe admission mutation. `mutant-observation.log` and `mutant-result.txt` capture expected-red evidence. This narrows generic observation handling only; dedicated getent/mountpoint status handling remains. |

The brief supplies no attack-surface table. This requirement map does not claim
real platform qualification, complete §5 verification, power-loss durability,
or adversarial root/concurrent-writer isolation.
