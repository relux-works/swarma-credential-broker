# Inactive protected reads (U02 / I02)

This Linux-only library implements construction stage C1, using the unchanged
`assemblyv0.ProtectedFilePolicy`, `FileIdentity`, `ProtectedRead` and `ConfigGate`
ports. `Reader` always walks descriptor-relatively from `/`; it has no root,
environment or installed fixture selector. Tests use real files under their
private temporary root and explicit expected ownership. No files are created
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

| Tool | Exact entrypoint | Output |
| --- | --- | --- |
| Formatter | `gofmt -w internal/protectedio/*.go` | Updated source; private formatter log. |
| Race tests | `go test -race ./internal/protectedio` | Real synthetic read/ancestor/lock controls and paired refusals. |
| Vet and repository tests | `go vet ./...`; `go test -race ./...` | Separate commands and real exit codes in task scratch. |
| Narrowing plants | Apply each `testdata/PL-*.patch` independently in an isolated checkout with `git apply --unidiff-zero --check` and `git apply --unidiff-zero`, then run its mapped test. | Exact failing assertion and adjacent unchanged control in task scratch; never runtime switches. |

Book-first sources and the still-open acceptance points are recorded in C1
and the applicability register. This unit establishes protected equality and
local synchronization only, not deployment, native qualification, account
creation/history provenance, credential custody or activation.
