# Assembly v0 fix round 1 evidence

This is producer evidence for PR #71 on input head
`3c47e51fc22ca06e8e4af41b41470257174fbb29`, not review acceptance,
hosted-CI success or a landing claim. The foundation remains inactive.
The publishing owner should include the plant table below in the PR body;
it is checked in here so it does not depend on a private handoff.

## Findings and controls

| Finding | Change | Named evidence |
| --- | --- | --- |
| Both reviews B1: invented socket path | Session vectors use `/opt/swarma/run/credential-broker/broker.sock`, exactly S:1591 and `spec/broker.md:900`; their index cites S:1589–1591 and the baseline line. The fixture checker pins the literal, not merely an absolute path. | `TestConstructionVectors`, `TestConstructionRefusals/session-installed-socket`, `TestConstructionRefusals/session-arbitrary-socket`, P01 |
| Review of record B2 / second review N1: empty-only sum controls | The declared inactive receipt and revocation-state records have closed JSON sum adapters. UTC and BOOTTIME receipts (the latter with `at:null`) and a signed grant/key revocation state round-trip through `wire.Decode`, the same instrument as their negatives. | `TestJournalSchemaControls`, `TestJournalNonEmptyVectors`, `TestJournalNestedSchemaControls`, `TestJournalSumDecoding`, `TestJournalSumRefusals`, `TestJournalSumFailurePreservesReceiver`, P02–P04/P11 |
| Domains and invented optional fields | Independent literal prefixes/framing and spec-quoted struct tags, including the only optional lifetime and reason tags. Regeneration does not bless a changed contract. | `TestDomainSeparation`, `TestConstructionSpecMemberSets`, `TestJournalSpecMemberSets`, P05–P09 |
| Missing widening and size controls | UTC widening session with non-null protected policy/continuity; activation and candidate exactly 16 KiB valid controls beside 16 KiB+1 refusals. | `TestConstructionVectors/session-widening.json`, `TestConstructionRefusals/widening-session-needs-policy`, `TestConstructionRefusals/widening-session-needs-continuity`, `TestConstructionSizeBounds`, P10 |
| Seam and loader notes | I01 adds O-04/O-05 and `ConfigGate`; I02 aliases it; I13 adds O-13; I18 adds O-16. C0 records the activation raw presence/null check, raw sealed-sum decode limitation, U05/U08 loader ownership, zero-sized token identity trap and leaf-grant checker limitation. | Construction contract C0; no O-point is resolved. |
| DISPLAY and unresolved-name limits | A non-ASCII act body/preimage pins original UTF-8 hashing, not escaped display bytes. The name blocklist explicitly does not detect renamed incomplete schemas. | `TestUnicodeActBytes`, `TestUnresolvedDeclarationsAbsent`, P12/P13 |

S references mean the unchanged revision-4
`spec/operator-and-activation-v0.md` pinned in C0. Socket line 1591 is a
construction-profile source, not evidence that a socket is installed.

## Validation identity and results

Linux amd64, Go 1.26.8, `GOTOOLCHAIN=local`, `GOFLAGS=-modcacherw`,
`GOMAXPROCS=2`, task-private absolute HOME/config/cache/Go paths and task-owned
temporary directories. Heavy commands start only below one-minute load 10.
This is local validation, not an emulation of hosted Go 1.26.10 CI.
The sorted source/test/vector manifest for both inactive packages has SHA-256
`5ccfde14e58f1f3b98e29a016497b9955ff104434f0b7c93d90c415d4c1f19de`.
The manifest and complete command logs are retained in task-owned scratch.

| Command | Actual exit | Scope |
| --- | --- | --- |
| `go test -count=1 -v ./internal/assemblyv0 ./internal/statev0` | 0 | All construction, schema, non-empty sum, port and inactive-import tests |
| `go test -race -p 1 -count=1 ./internal/assemblyv0 ./internal/statev0 ./internal/wire` | 0 | Both inactive packages and unchanged transport package |
| `go build -p 1 ./...` | 0 | Whole module compiles |
| `go vet -p 1 ./...` | 0 | Whole-module static checks |
| `go test -count=1 -coverprofile=.temp/fix-u01f1/state-coverage-01.out -covermode=atomic ./internal/statev0` | 0 | 98.2% statement coverage of the new inactive record adapters; not semantic admission coverage |
| `go tool cover -func=.temp/fix-u01f1/state-coverage-01.out` | 0 | Coverage report, not an additional behavior gate |
| `gofmt -l internal/assemblyv0/*.go internal/statev0/*.go` | 0 | Empty output |

## Plant table for the PR body

Each plant is applied to a fresh task-owned source copy. The unplanted copy
passes first. All rows run **G**:
`go test -count=1 -v ./internal/assemblyv0 ./internal/statev0`.
Rows marked **R** first run
`go test ./internal/assemblyv0 -run '^TestConstructionVectors$' -update-assembly-vectors`.
R is a regeneration experiment, not permission to accept changed bytes.

| Plant | Mutation and property narrowed | Command | Named failing test | Actual exit / result |
| --- | --- | --- | --- | --- |
| Control | No mutation; valid controls must work | G | None | 0 / control |
| P01 | Fixture socket reverted to the old `/run/swarma/credential-broker/broker.sock`; detects spec-path drift even during regeneration | R then G | `TestConstructionVectors` | R=1, G=1 / killed |
| P02 | Rename `OperationReceipt.UnmarshalJSON` so JSON does not call it; non-null receipt decoding must be exercised | G | `TestJournalSchemaControls` | 1 / killed |
| P03 | Rename `BaselineRevocationState.UnmarshalJSON`; non-empty signed revocation records must be exercised | G | `TestJournalSchemaControls` | 1 / killed |
| P04 | Both freshness variants use permissive `json.Unmarshal` instead of closed `wire.Decode`; nested shape closure, not just happy paths | G | `TestJournalNestedSchemaControls` | 1 / killed |
| P05 | Arguments domain `operator-arguments/1` becomes `operator-argument/1`; independent domain anchor | R then G | `TestDomainSeparation` | R=0, G=1 / killed |
| P06 | Enrollment domain `enrollment-token/1` becomes `enrolment-token/1`; independent domain anchor | R then G | `TestDomainSeparation` | R=0, G=1 / killed |
| P07 | Drop LF after method in the arguments preimage; exact method framing | R then G | `TestDomainSeparation` | R=0, G=1 / killed |
| P08 | Add optional `witness` to `TerminalReceipt`; independently frozen member sets even when vectors do not change | R then G | `TestConstructionSpecMemberSets` | R=0, G=1 / killed |
| P09 | Add `omitempty` to `/2` receipt; required nullable member cannot become absent | G | `TestServiceJournalVersionContract` | 1 / killed |
| P10 | Raise fixture size guard to 32 KiB; both exact 16 KiB bounds must be exercised | G | `TestConstructionSizeBounds` | 1 / killed |
| P11 | Disable explicit-null revocation reason refusal; omitted optional string is not nullable | G | `TestJournalSumRefusals/reason-null` | 1 / killed |
| P12 | Add forbidden `OperatorOutcome` declaration; named unresolved-type guard works | G | `TestUnresolvedDeclarationsAbsent` | 1 / killed |
| P13 | Add renamed `EnrolmentOutcomeRecord` partial schema | G | None | 0 / **survived**: the guard is a name blocklist, not semantic detection of arbitrary renamed schemas; code review and accepted-contract ownership remain necessary |
| P14 | Add a production `cmd` import of inactive `assemblyv0`; daemon wiring must remain absent | G | `TestInactiveImportGraph` | 1 / killed |

Thirteen plants are killed by named tests; one intentional limitation plant
survives. No crash, unapplied patch or unrelated setup failure counts as a kill.

## Coverage limits and remaining gates

The assignment has no attack-surface table; that remains a brief gap, not a
waiver of later qualification. Existing committed test names are retained.
The delta stays in the two inactive packages and their construction documents.

Out of contract here: storage, runtime authority/provenance, live time/boot
checks, crypto admission, complete canonical journal loading and durable
publication belong to U05/U08 and the later leaves (C0 I05–I09 and its byte
boundary). Method arguments/results remain the existing service-owned raw
unions, not a new validator (C0 excluded incomplete schemas). Actual display,
TTY/confirmation safety and the activation raw-null loader check remain
U13/U15 and U03 respectively. No native or live broker qualification ran.
The whole-module runtime test suite and hosted checks are not claimed here;
the owner still publishes the signed head and obtains exact-head review/CI.
