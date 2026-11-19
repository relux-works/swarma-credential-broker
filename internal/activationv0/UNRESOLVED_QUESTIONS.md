# U03 unresolved construction boundary

## STOP:O-19 — predecessor import guard versus I04

The construction contract's I04 row and U03 brief require
`internal/activationv0` to consume `assemblyv0.ActivationDocument` and
`assemblyv0.ProtectedRead`. However,
`internal/assemblyv0/invariants_test.go:150` rejects every non-test import of
`internal/assemblyv0` or `internal/statev0` except from `internal/statev0`.
The unchanged `TestInactiveImportGraph` therefore rejects this required U03
consumer even though no daemon/runtime package imports it.

The failed assumption was that the landed inactive-construction boundary
already admitted its specified downstream construction leaves. The unchanged
baseline gate passes; the candidate gate fails its actual import assertion.
U03's focused race tests and both required narrowing plants are independent
evidence, not overrides of that failure. Full command results are retained in
task scratch and the requested handoff.

The clean implementation reuses the exact landed types/vectors and leaves
daemon/default behavior untouched. It does not duplicate shared types, hide
implementation in test files, skip the inherited test, introduce a build tag,
or use an alias/indirection to evade its import scan.

The owner's precise scope decision is required: authorize a predecessor guard
amendment that explicitly admits this inactive construction consumer while
retaining daemon/runtime import negatives, or supply a reviewed predecessor
revision with that amendment. The first option changes a file outside U03's
write scope and needs fresh guard controls and complete validation; the second
preserves the current unit scope but waits for that dependency. Neither option
is applied or treated as accepted here. O-01/O-19 and all other registered
O-points remain open; C still refuses with `STOP:O-21`.
