# Mechanical decision mutations

This test-only Go program parses both complete production files with the Go
AST: `internal/protectedio/read_linux.go` and
`internal/authorityv0/reader_linux.go`. It enumerates if/for decision negations,
each comparison negation, each side of every Boolean conjunction/disjunction,
mode-mask complements, zero constants, unions and mask-test true/false constants,
each bit removed from literal mode masks, and each policy owner/group/mode/
link/size/ancestor read or initializer replaced by zero and the actual broker
UID/GID. Five additional narrow mutations reproduce all four review findings,
including both directory-special-bit spellings.

Boolean operands are neutralized in an unreachable expression rather than
textually erased, preserving lexical variable/import uses without executing
the dropped operand. The program first creates a new scratch snapshot; each
mutation independently starts from the original source. Only the two target files are rewritten in
that snapshot, and each is restored before the next mutation. The original
checkout is never mutated. The process uses umask 022 and launches only below
one-minute load 10, with inherited private Go HOME/cache/temp settings.

From the repository root, in its private Go environment:

```sh
go run ./internal/protectedio/testdata/mutation -list > .temp/inventory.jsonl
go run ./internal/protectedio/testdata/mutation -root . \
  -scratch "$PWD/.temp/mutation-work" -output "$PWD/.temp/mutations.jsonl"
```

The scratch directory must not already exist. Each primary command is exactly
`go test -count=1 ./internal/protectedio ./internal/authorityv0`, with standalone
log, PID, exit and launch load. JSONL includes all Go-source hashes. A valid
unmodified control must exit zero. A crash alone, timeout, build failure or
unapplied mutation never counts as a kill. If a broad mutant also crashes an
older test after a new mechanical assertion has failed, the driver reruns that
named mechanical test alone and requires exit 1, its named failure and no
unhandled panic before counting the assertion kill. Both exits/logs are kept.

`-only M0001,M0002` selects IDs after running the unchanged control. IDs are
deterministic for these exact source bytes and broker IDs; rerun `-list` when
source changes. An identical textual substitution is explicitly syntactic
equivalence. The driver exits 2 while any raw survivor/error remains (the
`go run` wrapper returns 1); it never converts those results to green.

`results.tsv` contains the audited result for every generated mutant, including
the exact byte span, primary exit, named assertion or individually stated
equivalence/remaining bound. Semantic equivalence is a separate human audit,
not inferred from a passing mutant run. Unproved survivors remain survivors
and block the whole-class claim. The private handoff retains every full log,
the original receipts and source/environment binding.

## Privileged residual replay

The separate `privileged-protectedio` PR job uses the runner's root capability
through `sudo -- unshare --mount --propagation private`. It uses the same pinned
Go toolchain as ordinary CI. No credentials, system users or host fixture
provisioning are needed. Every fixture child gets another private mount
namespace and chroots into a newly mounted, task-owned tmpfs. Only that tmpfs
root inode and its inert numeric-owner files are changed, never the runner's
root inode. Loss of root, mount, chroot or tracing capability fails the job.
The ordinary job has no `privileged` tag and cannot compile these fixtures.
The syscall instrument is intentionally Linux/amd64; the hosted job asserts
that architecture before running. It is not a portable-kernel qualification.

Run in a root private mount namespace, with an absolute isolated Go HOME,
cache, temp and populated source checkout as in `.github/workflows/linux-ci.yml`:

```sh
go test -count=1 ./internal/protectedio/testdata/mutation
go vet -tags privileged ./...
go run ./internal/protectedio/testdata/mutation -root . -privileged \
  -scratch "$PWD/.temp/privileged-work" \
  -output "$PWD/.temp/privileged.jsonl" \
  -audit-output "$PWD/.temp/results.tsv"
```

`-privileged` forbids `-only`, binds all 18 original row identities to the audit
table, runs their clean tagged controls, then runs each exact substitution with
its designated named assertion. Historical `policy-*-broker` replacements come
from the audited table, not the current root process's UID/GID: running as root
must not silently turn the original mutations into different ones. Root mode
never executes the ordinary tests that require a non-root process. The fixture
child helper is invoked only through the named parent tests, not as a standalone
control. A timeout, setup failure, missing fault application, panic, build error,
wrong test or absent assertion marker is not a kill.

The two fault rows are **M0204 (negative stat size)** and **M0240 (non-EOF read
error)**. M0204 is not an ownership substitution. A tracer entirely in the
build-tagged `_test.go` file observes only its owned child thread. It keeps the
same inert leaf's `fstat`/`newfstatat` sizes consistently negative for M0204,
calling `openFile` directly so a later read-length check cannot mask the guard.
For M0240 it replaces the EOF syscall result with EIO only after exactly the
saved size was actually read. Both exercise the real reader without modifying
production Go files, adding a production seam, substituting `io.ReadAll`, or
claiming semantic equivalence. Uninjected valid controls accompany both. The
tracer verifies actual applications and byte counts before any refusal assertion
can qualify; no applied fault means infrastructure failure, not a kill.

The exported `results.tsv` is written atomically **only after all 18 rows have
named assertion kills**. CI uploads it, the source hash manifest, exact command
exit codes, control logs and per-row receipts as `protectedio-privileged-residual`.
Nonselected table rows are preserved. The checked-in table deliberately retains
its original survivors until real hosted evidence exists; do not pre-mark local
unrun fixtures as kills. Review the hosted artifact and use its exported table
for the subsequent evidence-only source-table update. There is no CI write token,
automatic commit or pull-request-secret dependency.
