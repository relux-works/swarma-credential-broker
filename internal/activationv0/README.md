# Inactive activation selection (U03)

`Loader.Load(context.Context, policy.Config)` implements construction contract
C0 seam I04, using `assemblyv0.ActivationDocument` and `ProtectedRead`.
The source is the proposed operator contract sections 5 and 9, pinned by
`docs/assembly-v0-construction-contract.md`; the book-first disposition there
remains controlling. No daemon import, runtime selector, installation or
activation is added. All existing default behavior remains unchanged.

The injected reader owns safe ancestor traversal and protected absence/error
classification (I02/U02). It must report `fs.ErrNotExist` only for safe absence,
with no bytes or identity. All other read errors refuse. The loader requests
the fixed root-owned/root-group 0644 regular, single-link, 16 KiB policy and
checks the returned leaf metadata and size. Synthetic reader tests do not
prove filesystem protection or qualify a concrete U02 implementation.

The zero selection is Refused; safe absence is Absent. Both have zero lifetime
and no document or digest. Every present document, including `enabled:false`,
is fully structurally validated and joined to the operational installation ID.
Valid false is Inactive; valid true is only structurally Enabled. Neither
state opens authority/custody, constructs services, authorizes material use or
satisfies the independent enabled-startup joins. Exact source bytes, identity
and digest are retained for later consumers; returned bytes and the optional
document lifetime are defensive copies. Runtime rereads/drift closure remain
U11/U23 work, not this loader's claim.

Only the optional activation lifetime member selects a ceiling: missing means
900 seconds, integral 1..900 is accepted, and explicit null, other types,
nonpositive values, larger values and unknown/conflicting members refuse.
The unrelated `policy.max_lease_seconds` is never consulted. Environment and
CLI inputs are not loader inputs. A `test-c` selector returns `STOP:O-21`;
O-01/O-19 specification/engineering acceptance and every other applicability
point remain open. No signing, identity, time, continuity or custody backend
is selected here.

The owner's 2026-11-19 authorization admits this inactive I04 consumer through
the predecessor import guard's explicit consumer/import table. No runtime
package gains an import grant, and shared declarations cannot import this
consumer. Grants name exact package directories, not recursive prefixes;
undeclared subpackages under an inactive directory and imports of those
subpackages refuse. Non-test Go files, including fixture directories, are
scanned outside Git metadata and task scratch, so an indirect runtime path
must contain a refused edge into an exact inactive package or
one of its undeclared subpackages. Test-only imports remain outside this
production-file guard. The parallel service construction unit is not added
here. See
[the remaining acceptance boundaries](UNRESOLVED_QUESTIONS.md). Passing local
gates is not owner acceptance, native qualification or runtime activation.

## Tools and evidence

Use the assignment's private Go environment and scratch settings before every
Go command. From the task checkout:

| Tool | Command | Evidence |
| --- | --- | --- |
| Go formatter | `gofmt -w internal/activationv0/*.go` | Task scratch formatting log |
| Go tests | `go test -race ./internal/activationv0` | ACTIVATE controls and refusals |
| Import boundary tests | `go test -race ./internal/assemblyv0 -run 'Test.*Import'` | Explicit I04 grant, runtime and reverse-edge controls |
| Go vet | `go vet ./...` | Task scratch vet log |
| Go race suite | `go test -race ./...` | Task scratch full-suite log |

The landed vectors in `internal/assemblyv0/testdata/construction-v0/` are read
unchanged. `testdata/PL-*.patch` contains bounded source plants, never enabled
product switches. Apply each separately to an isolated source copy and run its
named negative test; the intended assertion failure, not a setup error, kills
the plant. These are zero-context unified patches: use
`git apply --unidiff-zero --check <patch>` before
`git apply --unidiff-zero <patch>`. The delivery handoff maps each acceptance
row to named tests and records real command exit codes. No native qualification
is inferred.

| Source plant | Named detecting test |
| --- | --- |
| `PL-ACTIVATE-ABSENCE` | `TestACTIVATEAbsentStaysStopped`, `TestACTIVATESoleLifetimeSelector` |
| `PL-LIFETIME-CLAMP` | `TestACTIVATELifetimeRefusals/above-900` |
| `PL-I04-CONSUMER` | `TestInactiveImportGraph`, `TestImportBoundaryControls/activation-consumer` |
| `PL-I04-CONSUMER-PREFIX` | `TestImportBoundaryControls/consumer-prefix` |
| `PL-I04-REVERSE` | `TestImportBoundaryControls/reverse-dependency` |
| `PL-I04-RUNTIME-ACTIVATION` | `TestRuntimeImportBoundaryControls/internal/server/activationv0` |
| `PL-I04-RUNTIME-ASSEMBLY` | `TestRuntimeImportBoundaryControls/internal/server/assemblyv0` |
| `PL-I04-NESTED-FORWARDER` | `TestInactiveImportGraph` |
| `PL-I04-NESTED-BYPASS` | `TestInactiveImportGraphForwardingControls/activation-subpackage` |

`PL-I04-NESTED-FORWARDER` adds a production subpackage that carries a shared
declaration into a runtime importer. Pair it with the unchanged valid wire
control. `TestInactiveImportGraphForwardingControls` also exercises similarly
named sibling directories, multi-hop, fixture-directory and public runtime
forwarders, undeclared inactive subpackages, and an allowed test-only import beside the production
refusals. `PL-I04-NESTED-BYPASS` restores recursive admission and hides nested
targets to check that the regression detects that original failure class.
