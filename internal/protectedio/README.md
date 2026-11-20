# Inactive protected reads (U02 / I02)

This Linux-only library implements construction stage C1, using the unchanged
`assemblyv0.ProtectedFilePolicy`, `FileIdentity`, `ProtectedRead` and `ConfigGate`
ports. `Reader` always walks descriptor-relatively from `/`; it has no root,
environment or installed fixture selector. Tests use real files under their
private temporary root and explicit expected ownership, except the read-only
public `/etc/passwd` owner-comparison control and the task-owned process's
kernel-generated `/proc/<pid>/stat` byte-count refusal described below. No files are created
by the library, no daemon imports it, and default behavior is unchanged.

`Reader.Read` accepts clean absolute paths and a regular, single-link file
policy bounded to 1 MiB. Owner, group, complete permission/special bits and
size must match. Every ancestor must be a real directory, owned by root or
the expected file owner, without special bits or group/world write access.
All descriptors and their names remain joined across the one checked read;
in-place leaf changes and ancestor replacement refuse without partial bytes.
Only a missing final leaf after safe ancestor checks reports `fs.ErrNotExist`.
Missing ancestors, symlinks, FIFOs, unsafe metadata and unavailable facts refuse.

`CheckDirectory` additionally checks an exact directory owner/group/mode and
the permitted root/ancestor-owner set. The authority consumer uses it to
enforce root configuration 0750, broker data/store 0700 and their distinct
root versus broker ancestor boundaries.

`TestRootZeroBoundary` passes literal root UID/GID/ancestor zero into the
real reader and lock factory beside valid non-root controls. It isolates
directory UID/GID, regular-file GID and ancestor-zero enforcement. Its file
and lock UID-zero refusals also encounter the root-only ancestor rule;
`TestReviewerLeafOwnerComparison` separately admits the root-owned public
`/etc/passwd` source at its literal production policy, then refuses the same
leaf for the non-root broker UID without returning bytes or identity. It
fails, rather than skips, if the host source is not root:root 0644, regular,
single-link and bounded. It never changes or logs the source's contents.
The narrower P1 zero-owner and process-EUID wildcard variants still require
privileged provisioning; ordinary leaf-owner equality does not.
`TestProductionPolicyComparisons` exercises 0640/0644 file modes, 0750/0700
directory modes, single links and exact zero/one-MiB bounds, with accepted
boundary controls and one-step violations. `TestPolicyShapeComparisons`
uses a missing leaf to distinguish early policy validation from later file
metadata checks. `TestConfigGatePolicyComparisons` distinguishes the gate's
0640/zero-bound requirements from otherwise valid ordinary reads. Directory
link and size fields are unused, not additional enforced directory policy.

`TestReviewerAncestorModeBits` independently checks world-write, group-write,
setuid, setgid and sticky ancestors beside safe reads.
`TestReviewerDirectorySpecialBits` checks all three special bits at both
0750 and 0700 beside accepted directory controls. The AST mutation driver
enumerates the complete two target files, not a manually selected comparison
list. Its result table distinguishes named assertion kills, syntactic
identities, surviving changes and execution errors; a survivor is not a
completeness proof or automatically an equivalent mutation.
`TestMechanicalReadByteCount` rejects nonempty task-owned proc metadata when
the kernel reports size zero, without logging the process contents. Direct
descriptor-pin tests independently exercise mode, mtime and ctime equality;
gate tests cover construction-time parent/leaf refusal and nil inputs. The
driver exits nonzero while any raw survivor or execution error remains.

`NewConfigGate` opens an existing 0640, single-link, zero-byte lock and pins
its device/inode and metadata; it never creates or replaces it. Its immediate
directory must match root/broker 0750 policy. `WithRead` reacquires that same
inode with real shared nonblocking `flock`, verifies the named descriptors
before and after the callback, refuses contention/replacement/reentry, and
clamps the callback context to the existing 250 ms identity window. Writers
must honor the specified exclusive lock protocol. This does not claim to stop
a malicious privileged writer or roll back effects of a callback that ignores
its deadline. Initial lock-validation/contention failures never invoke the
callback. A final recheck failure is a refusal, not rollback of arbitrary
callback side effects.

## Tools and evidence

Use the assigned private Go environment, absolute `GO`, private mode-0700
temporary directories and `GOFLAGS=-p=2` before invoking these commands:

Both U02 packages use the shared `internal/testutil/protectedfixture` preflight
and the real reader to check their fixture root before exercising a control.
An unsafe ancestor fails with `protected_fixture_temp_ancestry` and its path;
it never skips a witness. Linux CI creates and checks a mode-0700 directory
under `RUNNER_TEMP`, then exports `TMPDIR` and `GOTMPDIR` before Go steps.
The helper checks the actual returned tree's ancestors before chmodding its
fresh leaf to 0700; the real reader then checks that leaf without relaxation.
`TestTempDirUmask022` and `TestTempDirUmask002` each pair an accepted normalized
leaf with a refused widened leaf. `TestTempDirUsesGoTempRoot` covers differing
temporary variables; `TestTempAncestry` retains unsafe-ancestor refusals.

| Tool | Exact entrypoint | Output |
| --- | --- | --- |
| Formatter | `gofmt -w internal/protectedio/*.go` | Updated source; private formatter log. |
| Race tests | `go test -race ./internal/protectedio` | Real synthetic read/ancestor/lock controls and paired refusals. |
| Vet and repository tests | `go vet ./...`; `go test -race ./...` | Separate commands and real exit codes in task scratch. |
| Narrowing plants | Apply each `testdata/PL-*.patch` independently in an isolated checkout with `git apply --unidiff-zero --check` and `git apply --unidiff-zero`, then run its mapped test. | Exact failing assertion and adjacent unchanged control in task scratch; never runtime switches. |
| Mechanical mutation | `go run ./internal/protectedio/testdata/mutation -root . -scratch "$PWD/.temp/mutation-work" -output "$PWD/.temp/mutation.jsonl"`; use `-list` to inspect the inventory without executing it. | New task-owned scratch copy, one standalone two-package test per mutant under 022, per-mutant logs and JSONL real exits; checked-in `testdata/mutation/results.tsv` records the audited run. |

Book-first sources and the still-open acceptance points are recorded in C1
and the applicability register. This unit establishes protected equality and
local synchronization only, not deployment, native qualification, account
creation/history provenance, credential custody or activation.
