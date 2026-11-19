# U03 unresolved construction boundary

## Authorized predecessor guard amendment

The construction contract's I04 row and U03 brief require
`internal/activationv0` to consume `assemblyv0.ActivationDocument` and
`assemblyv0.ProtectedRead`. The predecessor guard initially rejected this
inactive consumer. The owner authorized the precise scope amendment on
2026-11-19: change only the guard file outside this package, admit I04 beside
the state consumer, and retain runtime and reverse-dependency refusals.

The failed assumption was that the landed inactive-construction boundary
already admitted its specified downstream construction leaves. The unchanged
baseline gate passes; the original U03 candidate failed its actual import
assertion. The authorized amendment replaces the implicit exception with an
explicit inactive consumer/import table. New controls distinguish the grant
from runtime imports and the reverse edge. Pre-amendment failures and amended
gate/plant results remain in task scratch and the requested handoff.

The clean implementation reuses the exact landed types/vectors and leaves
daemon/default behavior untouched. It does not duplicate shared types, hide
implementation in test files, skip the inherited test, introduce a build tag,
or use an alias/indirection to evade its import scan.

## Remaining open acceptance points

The authorization resolves the guard edit's scope, not broad O-01/O-19
specification/engineering acceptance or any other registered O-point. Those
remain open. C still refuses with `STOP:O-21`; no backend, publication gate,
owner identity, filesystem traversal or service-wiring decision is made here.
The parallel service construction allowance belongs to its own unit and is
not preemptively granted by this amendment.

## PR #73 non-blocking carryover

- N2: I04 has no outward import allowlist in the construction contract. An
  additional activation-to-runtime restriction needs a contract decision;
  this fix does not invent one.
- N3: the intermediate loader commit predates its guard amendment and is red.
  This fix preserves the existing signed history; reordering or combining
  published commits is a separate delivery decision, not a source-boundary fix.
- N4: safe absence remains the injected reader contract. Joined errors with
  an unsafe cause and `fs.ErrNotExist` are outside that contract; an exact
  absence sentinel and future consumer state/error handling remain
  integration work, not a new guarantee here.
- N7: native ancestor, symlink, regular-file and permission enforcement still
  belongs to I02/U02. Synthetic metadata checks do not qualify that reader.
