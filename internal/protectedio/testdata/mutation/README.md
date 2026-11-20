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
