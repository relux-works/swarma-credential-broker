# Lab B2 time and continuity producer

This is the fixture-tested B2 slice of [lab profile v0](lab-profile-v0.md),
sections 4.2–4.3, 5.1–5.2 and 7, at broker baseline `7a730950`.
It is not live construction, native qualification, enrollment or production
activation. **C-OPEN-OWNERS is not recorded.** No credential, vendor request,
root operation, VM restore or installed service is exercised by these tests.

Fix round 2 rebases this slice onto `eef0f9f3`, preserving all C0b bounded
invocation and C0c manager observation addenda, their sealed index and coverage
map. Those other-unit surfaces are construction contracts, not new B2 writers
or runtime authority. The five B2 byte surfaces remain unchanged.

## Contract disposition

Same: reuse the book chapters **OS user and network**
(`book/ru/05-polzovatel-i-set.md`, OS-user boundary and trusted root) and
**Credentials** (`book/ru/09-uchetnye-dannye.md`, separate custody and authority),
at the design pin `bc1132c9d9be60864ef7195efa83215357ad3011`. Reuse
`docs/time-contract.md` durable continuity, `docs/qualified-time-api.md`,
`docs/time-policy.md`, and the exact C0 amendment and joins. No local substitute
for those contracts is introduced. The design already identifies manual-root C
as a scoped conflict with **Operator’s phone** and
`spec/operator-and-activation-v0.md`; only the named owners can accept it.

The five consumed frozen formats are owner-decision, off-vm-approval,
start-fence, consumer-high-water and time-checkpoint, all with their exact
`swarma-broker-lab-…/1` domains. `internal/labtimev0` uses CCJ-1, closed nested
shapes, scalar/label/array grammar and the 65536-byte limit from
`contracts/lab-v0`. Text digests and approval-target preimages are unchanged.
Tests drive the actual readers from the C0 operator catalogue, including
wrong kinds, labels, scalars and array boundaries. C0 files are not edited.

## Integration seam

All new Go files require `linux && broker_lab`. Ordinary `NewConsumer`,
`ClosedWitness`, production record readers and production command sources are
unchanged. No public fixture clock, arbitrary witness or injected runner is
accepted by the lab factory.

Lab composition and its public `PrepareLabTime` / `NewLabConsumer` entry points
live in `internal/labtimev0`, not in the production `timeconf` package.
`timeconf/lab_engine_linux.go` exposes tagged engine/store/collector hooks only;
it imports no lab package. The real-tree graph instrument checks both tagged
and untagged configurations, in addition to its retained forwarding plants.
There is no approved forwarding exception. Tests replace a private lab runtime
factory, not the exported constructors, and use synthetic expected ownership
for the root fence logic. The installed binding remains `SystemClock`, the
concrete NTS collector and root ownership; none is qualified by that substitution.

- `LabInventoryDigest` pins applied NTS-authdata/operator policy and complete
  protected explicit source-file bytes. Source expansion is conservatively
  refused: `confdir`/`sourcedir` cannot hide unenumerated inputs. The concrete
  collector reuses `SystemCollector`/`SystemRunner`, checks inventory before
  collection and unchanged source files afterward, and retains original reports.
- `PrepareLabTime` is a future owner-bootstrap library operation, **not a CLI**.
  It checks exact owner consent/context and dedicated lab enrollment, requires
  two separate existing empty protected directories, and establishes a fresh
  local witness and settlement using authenticated NTS before returning heads.
  Consent is checked before genesis writes and again against both settled
  interval bounds before the first lab floor is published.
  It never adopts existing storage. Partial provisioning refuses subsequent
  provisioning; it is not an automatic reset path.
- `ConsumeStartFence` requires effective root and a protected off-home regular
  root:root 0644 fence, exact independent pins and a valid owner/off-VM seal.
  It spends the fence using exclusive staging, file sync, rename and directory
  sync. Uncertain staging remains refusal evidence. `LoadStart` constructs an
  opaque consumed-start capability, not a new approval. A non-root fixture
  exercises the same descriptor reader with synthetic expected ownership;
  that is not evidence of native root qualification.
- `NewLabConsumer` requires that opaque start, the dedicated authority and the
  exact time/floor/manager heads. It verifies complete underlying settlement
  ancestry and consumes a durable per-generation process marker. It never
  provisions or reconstructs missing state. The dedicated authority identifier
  is `swarma-broker-lab-C-1`; production authority policy is not widened.
- `ConsumeWithManager` requires an independently pinned previous manager head.
  It verifies the entire owning `genjournal` history against that prefix,
  imports retained W and refusal floors, and delegates to the existing
  settlement engine. That engine retains in-flight state, clock/boot tests,
  receipt associations and originals. New C0 checkpoint/floor bytes and their
  publication head are durable **before a receipt returns**. A failed second
  pointer update leaves a mismatch, not an inferred baseline. `Heads` returns
  only the three B2-owned heads; B1/B5 must join authority/service/revocation
  heads independently, not treat their zero values as enrolled heads.
- `Deadline` provides only B2’s 1..900 and exclusive qualification/authority
  deadline predicate. It is not a second issue/renew engine. B1/G1 own actual
  lease bounds, idempotency, UNKNOWN reconciliation and gateway enforcement.
  `Start.Deadline()` exposes the earliest owner-decision, off-VM approval and
  qualification expiry for those callers. Every public use checks its fresh
  settled upper/W against that exclusive deadline before returning a receipt.
  An expired use returns no receipt or advanced lab floor and closes that
  consumer; `Heads` refuses failed/burned consumers.

The protected B5 caller must authenticate owner-terminal provenance and obtain
expected digests/VM identity/invocation, off-VM clock and final heads from
independent current authority. A content seal alone is not authentication.
Never derive those expected values from the restored home, or reuse an old
invocation approval as a fresh start. Later starts require acknowledged consumed
orderly-stop heads and exactly the next generation; missing/crash/unknown
evidence refuses. Qualification revision and expiry remain fixed.

The lab timing path currently demands a one-second reserve, 500-ms bounded
collection and one-ms handoff bound, and declares the reboot predicate as a
native qualification obligation. These constants are requirements to measure,
not measurements or a live qualification result. B4/Q must prove the actual
load, timeout, cancellation, boot, storage, adapter/release and platform closure
before the owners authorize construction/use. No fixture authorizes them.

## Holds, burn and C1

The local witness uses locked exact-head CAS and fsync publication. Missing,
corrupt, linked, skipped-generation or stale-CAS heads refuse. Existing
settlement holds survive reopen; C0 incident metadata retains sticky holds and
W. Only verified regression writes a durable burned checkpoint; reconstructed
consumers refuse a burned marker even if matching history is later supplied.
First the entire nonempty manager journal must verify from genesis, including
capacity. Only then can its owning verifier report a fork/rollback at the
persisted prefix as burn evidence. Missing, partial, malformed, oversized or
capacity-refused history never burns. A failed burn write returns explicit
`lab_burn_persistence_unknown` alongside the ordinary refusal.

Stricter reading of unknown state: lock contention, cancellation, unreadable,
missing or undecodable metadata refuses this start without burning or spending
its process marker. No absence is promoted to regression evidence. Once the
transient fault is removed the exact matching start may be retried. Complete
decoded state differing from independent off-VM pins does burn. An inconsistent
two-pointer floor publication remains closed/unknown, not a burn inferred from
an ordinary crash. No code automatically restores or resets that state.
Physical crash persistence and root/VM rollback exclusion remain native obligations.

Public construction rejects every authority/enrollment/start field mismatch
before selecting the runtime or opening its store. The regression suite varies
authority ID/version, amendment, decision digest and all four scope fields
independently. Its D1/D2 case keeps the provisioned enrollment naming D1 while
presenting a freshly sealed, later-expiring D2 start. Construction must refuse
without burning or spending that start; a restored D1 control constructs and
releases a receipt naming D1 inside its own approval window. Test-only runtime
selection counters distinguish the early joins from redundant downstream
store-binding refusals; their kills do not claim every deletion admits use.
Replaced/removed fences are also varied between Start loading and construction.
Policy source/resync, overlapping roots and inventory grammar have separate
public-path negatives. Nil Start refuses, with the currentness guard as its
shared structural protection.

A caller-supplied, syntactically valid inventory mismatch is not independent
off-VM burn evidence: it refuses without burn or a spent marker. Supplying the
original pinned inventory afterward can admit that same start. Replaying a
spent start is checked before the stale-head join, so replay after a valid use
also refuses without burning the original consumer. The later exclusive marker
write remains mandatory; the early read is not a replacement for it.

Unverified manager history at PrepareLabTime now refuses before genesis writes,
leaving fresh roots empty for a corrected complete-history attempt. Settled
approval checks necessarily follow collection/provisioning: their refusal can
still leave nonempty roots, which must not be retried, reset or silently adopted.
An expired approval during use advances the time settlement before failing
closed; Heads then refuses. B5 must seal an orderly stop BEFORE the earliest
Start.Deadline(), or treat expiry as an unsealed stop and use the independently
approved C1/reprovisioning procedure, never guess a stop seal from stale heads.

The tagged timeconf seam remains broad, including the durability fault hook.
No production entry calls it, but the import graph alone is not a symbol-use
gate. RB/assembly must forbid timeconf.Lab* calls at production admission in
addition to rejecting the lab tag. Implementing that cross-unit symbol scanner
or changing the already-sanctioned seam is deferred, not claimed by B2 fixtures.

`CheckRecovery` is a metadata predicate, not a restore command or a hold-release
API. C1 requires distinct never-reused installation and time scope, empty new
history, pinned VM/account/revision and fixed expiry, separately authenticated retirement,
revocation/replacement and recovery evidence, no other consumers, and fresh NTS
lower bound strictly above every retired refusal floor. A source incident needs
its separately accepted recovery policy. Old W/holds are comparison floors only;
they never seed the new history. Ordinary holds are not a C1 reason. B5/Infra
must authenticate those acts and perform reprovisioning; these fixture tests do
not vendor-revoke a key or establish that an installation has never existed.

Whole-VM live rollback can rewind the local witness and outside-home fence
together. This implementation does not claim to detect it; the accepted lab
residual and owner vendor revocation boundary in section 4.3 remain explicit.

## Tools and reproduction

Use the repository Go toolchain and standard-library Python 3 only. Python is
already used by C0; here it orchestrates Go overlays and receipts, not product
behavior or an alternative test framework. No installation is required.

Create a protected short physical scratch parent (Unix socket paths in existing
tests must fit the platform limit), containing `.temp/work`, `.temp/home`,
`.temp/config`, `.temp/cache`, `.temp/go-build`, `.temp/go-mod`, `.temp/go-path`
and `.temp/tmp`. Copy the checkout into `work` excluding `.git` and `.temp`;
populate `go-mod` from the approved existing module cache without network use.
Resolve every path physically before exporting it. With `B2_SCRATCH` naming
that absolute `.temp`, export:

```sh
export HOME="$B2_SCRATCH/home" USERPROFILE="$B2_SCRATCH/home"
export XDG_CONFIG_HOME="$B2_SCRATCH/config" XDG_CACHE_HOME="$B2_SCRATCH/cache"
export XDG_DATA_HOME="$B2_SCRATCH/data" XDG_STATE_HOME="$B2_SCRATCH/state"
export GOCACHE="$B2_SCRATCH/go-build" GOMODCACHE="$B2_SCRATCH/go-mod"
export GOPATH="$B2_SCRATCH/go-path" TMPDIR="$B2_SCRATCH/tmp"
export TMP="$TMPDIR" TEMP="$TMPDIR" GOTMPDIR="$TMPDIR" GOTOOLCHAIN=local GOWORK=off GOENV=off
export GOPROXY=off GOSUMDB=off GOTELEMETRY=off GOFLAGS=-trimpath
unset GOTELEMETRYDIR
export GO="$(command -v go)"
export GOROOT="$("$GO" env GOROOT)"
cd "$B2_SCRATCH/work"
go test -count=1 ./...
go build ./...
go test -count=1 -tags broker_lab ./...
go build -tags broker_lab ./...
go test -race -count=1 -tags broker_lab ./timeconf ./internal/labtimev0
python3 tests/lab-b2/mutants.py --out "$B2_SCRATCH/mutants"
```

Run each command as a standalone gate; retain stdout/stderr and its real exit
separately, without a status-losing pipeline. The overlay driver refuses output
reuse and nonisolated HOME/caches. Each row records source/overlay hashes,
command, PID, exit and the **named failing test and intended assertion**.
Compilation/setup failure, panic or an unrelated deadline refusal is not a
killed mutant. `results.json` and `results.md` are generated
under the selected task scratch. Scope and limits are in the
[coverage map](lab-b2-coverage-map.md); the producer handoff records actual
tool versions, exits, signed source head and native gates.

## Review fix round 1

Both independent reads required revision. The public lifecycle now drives fresh
provisioning, fence consume/load, construction, use, advanced heads, an
acknowledged second generation, per-start replay and fence substitution/removal.
Adjacent negatives cover consent before writes and at settled expiry, C1 floors,
both approval expiries (including trusted upper equality), start lock/read
uncertainty, verified mismatch burn, complete versus torn/forked journals and
sticky holds through restart. The restart predicate has separate negatives for
generation, acknowledged heads/state, approval generation/invocation, both clock
orderings and the decision digest pin. Each gate has a narrowing overlay.

The acknowledged-stop fixture is canonical C0 metadata supplied by a trusted
caller; it is not proof of B5 provenance. C0 has no stop-record digest member in
the off-VM approval. That existing contract gap is recorded in
`UNRESOLVED_QUESTIONS.md`; no frozen field or unauthenticated live stop writer is
invented here. Native reboot/load/root and whole-VM exclusions remain unrun.
