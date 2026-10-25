# Provider API and settlement format

`timeconf.Consumer` supplies the provider-side settlement implementation for the
[qualified-time contract](time-contract.md). **Production consumption is inactive.**
`NewConsumer` installs only `ClosedWitness` and has no qualified collector path.
Every call returns a typed `*ActivationRefusal`, also matching `ErrUnavailable`.
There is no configuration, environment variable, flag, enrollment reset or public
fixture constructor in default builds that activates it. The ordinary
`Provider.Sample` and `StartSample` APIs retain their existing behavior and do
not establish durable consumption.

The tests construct an independent fixture witness and qualified fixture path
in `_test.go` files and the explicit test-tag implementation described below.
These fixtures exercise settlement and canonical receipts; they do not qualify
a production backend, chronyc/chronyd graph, storage device, reboot transition or
platform fence. The production build-graph
containment check rejects fixture implementations and time-path construction or
assignment in compiled sources. Its compiled plant demonstrates detection.

## Public API

On Linux, construct a consumer with:

```go
consumer, err := timeconf.NewConsumer(enrollment, policy, protectedStoreRoot)
raw, err := consumer.ConsumeBeforePin(ctx, timeconf.ConsumptionRequest{
    Deadline: originalDeadline,
    Expected: enrollment,
    OperationDigest: independentlyDerivedDigest,
    Challenge: newChallenge,
    JournalFloor: importedUpperBoundNS,
})
```

`Enrollment` binds authority, adapter, policy, machine/consumer/purpose/continuity
scope and the public store identifier. Its `Scope.OperationDigest` must be empty;
the request supplies the operation binding without selecting another history.
The store root is an explicitly supplied protected persistent directory from the
contract's storage plan; no location, provisioning mechanism or production
configuration is selected here. Construction never creates or resets it.

`EffectivePolicyDigest` hashes the canonical manifest
`{effective,service_digest,shared_digest,version}` with version
`qualified-time/policy/1`. `effective` is the exact applied `Policy` JSON,
including all its bounds and source inventory; absent service bytes use `none`.
The supplied enrollment must match this manifest. Protect and independently
validate the original policy bytes and enrollment before using this API.

`ExecutorOperationDigest` applies the published domain-separated SHA-256 recipe
to already validated owning-codec CCJ-1 bytes. `NativeOperationDigest` applies
the native profile/length/public-identity recipe. They are pure hash helpers;
they neither validate an executor Scope nor choose or authenticate a native
profile. Those adapters belong to their consumers. Only public identity bytes
belong in these helpers.

`EncodeReceipt` and `DecodeReceipt` publish the closed `qualified-time/1` codec.
The eleven facts use decimal-string `Nanoseconds` and `Generation` types.
Decoding rejects unknown, missing, duplicate or null members, noncanonical
ordering/escaping/integers, excessive bytes/depth and invalid internal bounds.
It verifies exact nanosecond interval predicates, exclusive authority and
representation limits. **Decoding does not authenticate a provider or its
original evidence.** An independently installed enrolled owner validator and
protected retained descriptors remain required; supplied hashes and flags grant
no authority. No consumer journal codec or frozen object changes here.

## Durable records

All opens are descriptor-relative after checking the protected service-owned
mode-0700 root and ancestors. Objects are no-follow, mode-0600 regular files
owned by the service with exactly one link. A nonblocking directory flock and
witness CAS serialize instances; contention returns refusal.

`current` is canonical JSON `{generation,record_digest}`. The generation is an
unsigned decimal string. `record-<hex digest>` contains a complete immutable
canonical `qualified-time/settlement/1` record with these required members:

- `binding`, the digest of canonical protected `Enrollment`;
- `generation`, `previous` (the previous record digest, or `none` for genesis),
  `high_water`, `held`, `hold` and `last`;
- `in_flight`, `operation`, `challenge`, `facts` and `originals`;
- `version`.

`last` and `hold` each contain `{boot,elapsed,reference,wall}`. Numeric values use
the receipt's exact decimal-string nanoseconds. A clear initial hold has empty
boot and zero bounds. `facts` is null for begins/refused settlements, or the
successful eleven facts with sample/continuity generations and record/witness
digests initially empty. The record digest is computed over these stored bytes;
the receipt fills those four derived fields afterward, avoiding self-reference.
`originals` is null or an ordered array of `{digest,size}` for retained original
evidence. `size` is an unsigned decimal string. `evidence.digest` hashes that
canonical array. Original bytes live in immutable `evidence-<hex digest>` files;
exact reply bytes live in `receipt-<hex digest>` files.

The current witness acknowledgment is the canonical head above; its digest is
`continuity.witness_digest`. For fixtures, trust comes from the independent
in-memory witness and its retained head, not this hash. A production backend
must supply independently qualified authority and durable acknowledgment; the
hash is not a substitute for that decision or its proof.

The original-evidence closure is flat, at most 60 original objects and
8 MiB minus 256 KiB of original bytes, reserving four objects/256 KiB for bounded
receipt/record/manifest/witness material. No original object exceeds 8 MiB.
Its record and receipt nesting stays below 16 and has no self-cycle. Settlement
ancestry is separately retained for durable operation/challenge history; it is
checked against the authoritative current witness within the request deadline,
never pruned or reconstructed from consumer floors. Long histories may refuse
when verification no longer fits; no archival/compaction authority is introduced.

## Write order and recovery

Each begin and final settlement uses the same ordering:

1. Exclusively create the complete immutable record; fsync the file, then root.
2. Durably CAS the independent witness from the exact old head to the next
   generation/digest. Generation wrap or a stale head refuses.
3. Exclusively write `pointer-<generation>`; fsync that file and root; rename it
   over `current`; fsync root again. Only then acknowledge that checkpoint.

The begin is durable before either clock observation or collection. Final
settlement retains originals first, advances W only for a qualified interval
with `L > max(W,J)` and `U < A`, and retains the complete operation/challenge/
sample association and clock pair. Exact canonical receipt bytes are fsynced
with their directory before reply. A later consumer refusal or lost reply
cannot undo committed W. A consistent completed failed query can settle with
unchanged W; detected steps persist a sticky hold and incident/reference bounds.

Startup requires matching protected record, current pointer and independent
witness, plus intact retained history/evidence. A single already prepared,
matching successor may finish pointer publication after ancestry validation.
Unused prepared records before witness advancement confer no authority. An
unfinished begin is held; missing, unreadable, corrupt, stale or conflicting
history refuses without reset. Reboot retains W and holds. No hold recovery or
production genesis/provisioning path is shipped.

## Deadline, completion and limits

The consumer leaf has no incident callback, shared consumer lock or application
RPC. Admission never waits. One absolute deadline, capped by the caller/context,
policy timeout and qualified budget (never over ten seconds), covers collection,
store/witness operations, retention, drain and teardown. The fixture reservation
adds its entire qualified storage/return/handoff allowance to conservative source
uncertainty before W is committed. Missing or excessive allowance refuses.

A deadline always returns refusal, even if a storage operation or fixture child
remains blocked. The instance remains fenced until resolution; an unresolved
begin prevents collection after restart. No worker sends a later success or
reuses a previous verdict. Stop dispatch has no provider entry or dependency;
each consumer must separately prove that its own exclusions keep emergency stop
reachable.

Accepting fixture collection requires both subtree terminal and drain evidence.
Tests also exercise the actual `CollectorEntry` descriptor execution/fixed argv
path with a known synthetic executable, and refuse a forked child retaining its
pipe. The existing `SystemRunner` does not establish native whole-subtree fencing.
No accepting fixture qualifies that missing guarantee. Production activation
still requires the independent witness backend and full reviewed installed
CallContract, dependency closure, boot transition, remaining-delay qualification,
terminal/fence authority, retained-original validator and consumer adapter review.

Run the bounded fixture package with `go test ./timeconf -count=1 -v` and the
containment checks with
`go test ./cmd/swarma-credential-broker -run '^TestQualification(AuthorityContainment|Containment|TimeFixture)' -count=1 -v`.
Use the selected toolchain and the host's resource limits. Tests use only isolated
synthetic files, clock points and child processes; no real account or time service
is accessed. Build/test outputs belong in private scratch outside the repository.

## Consumer test fixtures

On Linux, import `github.com/relux-works/swarma-credential-broker/timeconftest`
only from `_test.go` files with `//go:build timeconf_fixture`. Run these tests
with `go test -tags=timeconf_fixture ./...`; keep approved application builds
on default tags. The default import is a refusing stub, not an activation path.
The standalone `timeconf` and broker default compiled graphs exclude the tagged
implementation and fixture package. The compiled graph guard has a planted
fixture-symbol control.

```go
//go:build timeconf_fixture

package example_test

import (
    "context"
    "os"
    "testing"
    "time"
    "github.com/relux-works/swarma-credential-broker/timeconf"
    "github.com/relux-works/swarma-credential-broker/timeconftest"
)

func TestAdapterPositive(t *testing.T) {
    root := t.TempDir()
    if err := os.Chmod(root, 0700); err != nil { t.Fatal(err) }
    fixture, err := timeconftest.New(root)
    if err != nil { t.Fatal(err) }
    digest, err := timeconf.NativeOperationDigest("operation", []byte("public identity"))
    if err != nil { t.Fatal(err) }
    raw, err := fixture.ConsumeBeforePin(context.Background(), timeconf.ConsumptionRequest{
        Deadline: time.Now().Add(400*time.Millisecond), Expected: fixture.Enrollment(),
        OperationDigest: digest, Challenge: "11111111111111111111111111111111",
        JournalFloor: 140000000000,
    })
    if err != nil { t.Fatal(err) }
    if _, err = timeconf.DecodeReceipt(raw); err != nil { t.Fatal(err) }
    // Feed raw to the consumer's real adapter and assert its expected acceptance.
}
```

`New` requires an empty protected mode-0700 test-owned directory and never
resets existing history. `FixtureConsumer` uses the unchanged consumption and
settlement engine, a fixed synthetic clock initially at Unix second 211,
one-second reserved uncertainty, W initially 140 seconds, and an in-memory
witness. `Advance(d)` moves its wall/elapsed observation together (0 < d ≤ 1h).
`LoseNextReply` suppresses a successful reply after settlement; `HighWater`
reads the settled bound. `Policy` and `Enrollment` return the fixture bindings.
The dedicated `timeconf-fixture-only` authority and root are synthetic, public
identities, not credentials or production trust anchors.

`VerifyReceipt(raw, expected)` combines the real codec with exact **fixture**
enrollment/domain matching. It rejects a production enrollment; ordinary
`Consumer` and `ClosedWitness` remain closed even in tagged tests. Structural
`DecodeReceipt` alone intentionally accepts valid fixture bytes. This helper
provides no authentication, original-evidence verification, final-lock safety
or one-use handoff. Independently bind the operation/challenge in the real
consumer adapter; never install the fixture root as production authority.

Every consuming repository must have an executable dependency check: run
`go list -deps -compiled -f '{{.ImportPath}}' -tags= ./...` and again with
`-tags=timeconf_fixture`, without `-test`, and fail if either graph includes
`github.com/relux-works/swarma-credential-broker/timeconftest`. Pair the check
with a temporary non-test `.go` import of that package and require the intended
fixture-dependency violation; the identical import in `_test.go` must pass.
`TestFixtureConsumerDependencyBoundary` demonstrates both real compiled graphs,
the failing application-import control, and an external-module positive receipt.
Do not count a Go setup/compilation error as detection of the forbidden import.

Mirror `TestFixtureReceiptCodecPositive`, `TestFixtureReplayRefused`,
`TestFixtureDeadlineRefused` and `TestFixtureLostReplyBurnsUpperBound` when testing
consumer adapters. The published contract vectors complement these controls;
they do not replace durable settlement, reboot, receipt authentication or
bounded handoff/integration testing. Native collector qualification stays closed.
