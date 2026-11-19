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
undeclared production subpackages under an inactive directory and imports of
those subpackages refuse. One reusable check obtains the compiler-selected graph
with `go list -deps -test -json ./...`, rather than walking the source tree.
Every production package in that graph, including dependencies discovered
only through tests, is checked against its full dependency set. An inactive
dependency requires an exact package-path, directory and table grant.
Resolved physical directories also identify inactive aliases, including an
alias of the shared package with no inactive imports of its own. Imported
hidden, fixture and vendor directories have no scan exemption; harmless
symlinks and harmless multi-hop and vendored forwarders remain allowed.

Internal/external test variants and their generated drivers may import the
inactive declarations for testing; their production dependencies receive no
such exemption. If `-test` reports a recompiled production dependency without
its original package, the same check obtains that original production graph
with `go list -deps -json <missing-originals>` before applying the boundary.
This separates injected test imports from production dependencies without
silently exempting every `ForTest` record. Discovery includes cgo-only
production sources when cgo is selected. A directory containing only tests
does not itself add a selected production package. The real-tree check lists
the inherited toolchain/GOOS/GOARCH configuration and inherited `GOFLAGS`;
compiled test-binary metadata supplies explicit `-tags` and enabled
race/memory-sanitizer modes for that inherited invocation. It also lists all
four shipped release profiles: Linux amd64 and arm64, each with `CGO_ENABLED=0`
from `.scripts/release-build.sh` and `CGO_ENABLED=1` from the conditional native
cgo matrix in `.github/workflows/release.yml` and `.scripts/release-profile.py`.
Those invocations override the nested command's environment with the release
settings (`GOAMD64=v1`, `GOARM64=v8.0`, empty `GOEXPERIMENT`, workspace/Go env
files disabled, and `GOFLAGS='-mod=readonly -p=2'`), without inherited explicit
tags or instrumentation. Cross-listing establishes Go dependency selection,
not a native cgo build, C compiler/profile qualification or release execution.

For every listed production package, each non-test `IgnoredGoFiles` entry is
also parsed with `ImportsOnly` and checked against the exact direct-edge rule,
regardless of build constraints. Ignored test files remain exempt. This
backstop does not discover an unlisted forwarder's own ignored dependencies.
The remaining bound is a transitive path selected only by a custom tag, race
or sanitizer mode, another GOOS, or a non-release `GOEXPERIMENT`, `GOAMD64` or
`GOARM64` variant not selected by the inherited invocation. It is not an
all-configurations reachability claim. Failed listings, malformed/incomplete
metadata and empty output refuse rather than becoming a successful graph.
The parallel construction units in #74 and #75 must each extend the same
exact-path table with their own authorized row, not install another guard;
fixture packages are generated from that table, so no second fixture edit is
needed. No additional production grant is added here. See
[the remaining acceptance boundaries](UNRESOLVED_QUESTIONS.md). Passing local
gates is not owner acceptance, native qualification or runtime activation.

## Tools and evidence

Use the assignment's private Go environment and scratch settings before every
Go command. From the task checkout:

| Tool | Command | Evidence |
| --- | --- | --- |
| Go formatter | `gofmt -w internal/activationv0/*.go internal/assemblyv0/*_test.go` | Task scratch formatting log |
| Go tests | `go test -race ./internal/activationv0` | ACTIVATE controls and refusals |
| Import boundary tests | `go test -race ./internal/assemblyv0 -run 'Test.*Import'` | Explicit I04 grant, runtime and reverse-edge controls |
| Go package graph | `go list -deps -test -json ./...` | Inherited and four release configurations; ignored non-test direct imports also checked |
| Tagged import boundary | `GOFLAGS="${GOFLAGS} -tags=swarma_inactive_probe" go test ./internal/assemblyv0 -run '^TestInactiveImportGraph$'` | Selected-tag graph; inactive tags are a different configuration |
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
| `PL-I04-NESTED-BYPASS` | `TestImportBoundaryControls/undeclared-internal/activationv0` |
| `PL-I04-SYMLINK-ALIAS` | `TestInactiveImportGraph` |
| `PL-I04-HIDDEN-FORWARDER` | `TestInactiveImportGraph` |
| `PL-I04-TAGGED-FORWARDER` | `TestInactiveImportGraph` with `GOFLAGS` selecting `swarma_inactive_probe` |
| `PL-I04-SYMLINK-IDENTITY` | `TestInactiveImportGraphToolchainControls/symlink-assembly` |
| `PL-I04-GRAPH-DEPENDENCIES` | `TestInactiveImportGraphToolchainControls/hidden-forwarder` |
| `PL-I04-TEST-VARIANT-COVERAGE` | `TestInactiveImportGraphRecompiledDependencyControls` |
| `PL-I04-CGO-VARIANT-COVERAGE` | `TestInactiveImportGraphRecompiledDependencyControls/cgo` when cgo is selected |
| `PL-I04-NOCGO-FORWARDER`, `PL-I04-ARM64-FORWARDER` | `TestInactiveImportGraph` beside the unchanged valid graph |
| `PL-I04-RELEASE-CONFIGURATIONS` | `TestInactiveImportGraphReleaseConfigurationControls/arm64-pure-forwarder` and `/arm64-cgo-forwarder` |
| `PL-I04-IGNORED-FILES` | `TestInactiveImportGraphIgnoredFileControls/nocgo`, `/arm64` and `/custom-tag` |
| `PL-I04-EMPTY-LISTING` | `TestInactiveImportGraphListingFailureControls/empty` |

`PL-I04-NESTED-FORWARDER` adds a production subpackage that carries a shared
declaration into a runtime importer. Pair it with the unchanged valid wire
control. `TestInactiveImportGraphForwardingControls` also exercises similarly
named sibling directories, multi-hop, fixture-directory and public runtime
forwarders, undeclared inactive subpackages, and an allowed test-only import beside the production
refusals. `TestImportBoundaryControls/undeclared-*` isolates the undeclared
package refusal using only `time`, beside valid exact-directory controls.
`PL-I04-NESTED-BYPASS` removes that refusal and restores recursive admission;
the isolated rows kill it without relying on a forbidden incoming edge.

The symlink, hidden-forwarder and tagged-forwarder source plants reproduce
compiler-buildable runtime paths. Each is paired with the unchanged valid
graph. The tagged plant is a valid inactive-tag control before selecting
its tag through `GOFLAGS` or an outer `go test -tags`. The narrowing mutants
separately remove physical package identity, dependency-set enforcement,
original-package recovery, cgo-only discovery, release-matrix traversal,
ignored-file parsing or empty-output refusal. The toolchain
controls kill them beside harmless symlink, multi-hop and vendor controls;
test-variant, recompiled-dependency and listing-failure controls bound the respective exemptions
and fail-closed behavior. No source plant activates a daemon in these tests.
