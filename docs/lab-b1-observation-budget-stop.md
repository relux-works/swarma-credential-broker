# Historical B1 C0c observation/current-check budget diagnostic

Status: **RESOLVED by PR #82, main 9f1f90fa (C0d)**. The requirements and
decision request below are historical, not current gates. Fresh pairs now
serve admission/publication only; recurring checks use receipt-anchored single
observations and independent freshness fences. See the current construction
coverage map and protected installation binding gap. The native evidence access decision is
resolved by PR #81, broker main `eef0f9f3388c3b35ce562f126540fc333370ec43`.
This stop concerns composition of the newly frozen observation protocol with
the unchanged current-RPC and watchdog requirements, not native read access.
The OPTION 2 private recovery contract remains intact as the first B1 commit.

## Requirements read together

- `contracts/lab-v0/observation.md`, **Fresh final-publication consumption**,
  requires an initial authenticated observation above the durable high-water,
  then a NEW connection and a strictly greater sequence immediately before
  ANY result that could enable use. The whole native snapshot must agree.
  Successful publication advances the durable floor; a sequence cannot be
  accepted twice. A previous published final observation is therefore not a
  new initial candidate above that floor.
- The same contract, **Transport and sequence**, requires a global
  cooldown of at least 250 ms CLOCK_BOOTTIME from native lock release to the
  next acquisition, with no bursts, queue or extra concurrency. Initial and
  final observations must respect it; waiting occurs before the final request.
  Each connection separately has a nonextendable 250 ms window. That window
  does not waive the cooldown or the caller's shorter timeout.
- `docs/lab-profile-v0.md`, section 3's **Revocation** requirement, retains
  250 ms poll cadence, a 200 ms current-RPC timeout, an independent 500 ms
  watchdog from the last successful current check, and another at most 500 ms
  to close affected use/connections. Section 8's Q4 valid
  `fixture-slow-current-check` requires a successful 190 ms response under the
  200 ms timeout and no watchdog closure of that valid stream.
- `internal/service/broker.go` sends `service.revocation.check` through
  `Authority.WithCurrent`; `not_revoked` permits continued use. The strict
  reading is that it is a result that could enable use, not an exemption from
  C0c final-publication consumption. No exemption has been specified.

The conservative consumption reading used here validates each new enabling
operation's initial candidate against its then-current durable floor. It does
not bank a previous published final as the next operation's initial candidate,
or prevalidate an overlapping operation against an older floor and carry that
validation across another publication. C0c does not specify cross-use candidate
reuse, how such prevalidation binds a subsequently changed durable floor, or a
pipelined admission/publication schedule. Permission and invariants for that
optimization are a possible owner clarification, not something this client or
the tests silently assume. The recurring bound below is conditional on this
strict non-reusing reading; it is not a proof against every conceivable revised
or explicitly clarified pipelined protocol.

## Bound and executable witnesses

An on-demand initial/final pair cannot fit a 200 ms RPC: even with zero I/O and
zero collection time, the mandatory interval before the final acquisition is
at least 250 ms. This is not a slow fake server or an inherited Go timeout.
Moving the first observation before a particular RPC could shorten that RPC,
but under that strict reading does not solve recurring use: every new
publication needs two sequences above the previous committed floor. Two global cooldowns, plus native work,
are required per recurring publication. The sustainable rate is below two
successful publications per second, without the strict sub-500 ms margin the
watchdog requires. Reusing a published final as the next initial, sharing a
sequence among successful uses, cached permits or silently ignoring current
polls would change the frozen contract.

The tagged tests use a real Unix stream and actual SO_PEERCRED/CLOCK_BOOTTIME
against a contract-exact, material-free fake server. The server enforces its
global cooldown and changes sequence on each successful observation. It is
not a native ledger or privileged-server qualification.

| Test | Valid diagnostic control | Adjacent required refusal |
| --- | --- | --- |
| `TestLabObservationCurrentRPCBudget` | Complete pair under a one-second caller budget | 200 ms budget expires in cooldown, only one request, UNKNOWN |
| `TestLabObservationComposedCurrentBudget` | Actual existing-engine `service.revocation.check` returns `not_revoked` with the pair under one second | Same account/lease and 200 ms budget return `request_deadline_exceeded`, no result and byte-identical journal |
| `TestLabObservationRecurringWatchdogBudget` | Two pairs respecting all three intervening cooldowns succeed with a 750 ms second diagnostic window | A 500 ms window anchored at the preceding final receipt expires before the next final observation; UNKNOWN |

The one-second and 750 ms controls deliberately are NOT compliant A09 timing
controls. They establish that the client, framing and existing-engine join can
work when given sufficient time; they do not amend the profile. The recurring
witness anchors its deadline to receipt time and is a bounded fixture witness,
not an installed callback/stream shutdown measurement. No full A09 or full B1
acceptance is claimed.

## Decision needed

Publish one coherent owner-approved contract decision covering current checks,
observation sequence/floor consumption, cooldown/load bounds and the watchdog.
Clean options are:

1. Specify or explicitly clarify a per-current-check consumption rule that can
   meet the existing cadence/timeout/watchdog, including exactly how tentative
   candidates, possible cross-use reuse/pipelining, final observations and
   updated durable floors compose. Keep freshness,
   pending-stop projection, no-publication-on-UNKNOWN and native currentness.
2. Revise the observation rate/pair protocol with M1 and qualify the resulting
   native lock/read/fsync load while preserving the existing revocation bound.
3. Revise the RPC, watchdog and end-to-end revocation requirements together,
   with explicit new valid/negative timing controls and G1/B4 agreement.

These are product/protocol decisions, not implementation flags. B1 does not
pick one, bypass the cooldown, extend G1 timeouts, exempt `not_revoked`, invent
an authoritative ledger cache or claim a failed valid timing gate as green.

## Bounded construction retained

The tagged observation client validates kernel peer/path protection, full C0c
shape and incarnation/currentness joins, initial/final sequence and snapshot
agreement, bounded framing/EOF and deadline failures. Adversarial modes include
wrong UID binding, stale generation, partial/incomplete answers, timeout,
pending stop and mismatch at final revalidation. The C0 operator catalogue also
exercises the actual tagged C0b/C0c shape reader, including integer/micro-USD
ceilings and native identifiers. This reader is not a bounded-invocation
approval/execution authority.

The client returns tentative metadata only. It is NOT connected to an accepting
daemon or installed authority factory, and does NOT yet implement B1's atomic
observation high-water/publication transaction. The composed diagnostic uses a
test-only authority wrapper, not a permissive installed authority. Daemon/API
mapping, real managed authority, worker/legacy refusal, root controls, complete
finite-plan admission and qualified shutdown remain unimplemented. All seven
B1 acceptance rows remain open. No material, vendor call, live activation or
production behavior is added by this construction.
