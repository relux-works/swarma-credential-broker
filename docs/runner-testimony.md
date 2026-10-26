# Runner measured-code testimony contract

This accepted contract covers only the synthetic `home-auth-present` and
`source-conflict` pairs. Implementation and qualification are pending; the
current executable still reports both rows **UNRUN**. Once implemented and
qualified, this contract permits execution credit for these pairs. It grants no
live vendor, peer, arbitrary runner or production release qualification credit.
Kernel tracing of function calls, including uprobes, is separate future work.

The isolated Linux/amd64 `egress.NewRunnerOrigin` / `TraceRunner` API supplies
only the direct-child trace and consuming wait. It checks retained bytes and
initial argv, follows runtime threads, rejects a later case exec and detaches
process children at their initial stop so the runner owns its nested tracer.
Its result preserves the real exit status separately from origin errors.
Other platforms return `ErrRunnerOriginUnavailable`. It installs no outer
network policy and proves no post-Command exchange or complete absence of
process effects. The two runner pairs now use this origin, but remain UNRUN
until the evidence-class and private artifact proof gate is implemented and
qualified.

The separate `qualify.RunnerTestimonyCommand` dispatcher calls
`runner.CommandWithOutcome` synchronously before sending readiness. The typed
outcome retains the final status and a bounded success/source-conflict/failure
classification from the same deferred classifier used by `Command`. A private
address pipe at FD4 is closed before Command; the case's seqpacket endpoint is
close-on-exec. `RunnerTestimony.Exchange` checks both case messages against the
live traced PID and configured UID, uses a fresh one-time nonce and requires
ACK followed by endpoint closure. Both pairs now join this exchange with the
trace and bounded parent effect observations. They still supply no artifact
binding or qualification-row credit.

The parent creates the runner broker listener only at verified exec. Its live
origin check remains mandatory at admission. Parent counters record accepted
connections, including refused peers, and parsed post-hello request, release and
other method attempts, including refused attempts. A pending listener queue or
failed listener/server join makes observation unavailable. The existing fixture
checks zero owner/store effects on negatives and the bounded released lease on
positives. Child counters remain testimony and must agree with parent counts.

After parent fixture setup, inotify watches the fixture root, home and project.
The bounded drain rejects overflow, lost watches, malformed/unknown events and
out-of-set mutations; negative controls permit no mutations or native-path open.
Positive controls permit only the existing output staging/publication, runner
lock/intent and fake app-server files, and still require login, release and both
complete isolated child-boundary reports. Native-path metadata is compared
without reading credential contents. Fixture diagnostic files use protected
bounded reads and a 64 KiB acceptance bound. Process-creation counters include
fork events before parent resumption as well as newborn stops; negative controls
require zero. These checks do not establish absence of effects outside their
declared observers or complete descendant absence for arbitrary runner code.

Both report controls retain `executed=false`, status -1 and no row artifacts.
Actual joined case waits remain diagnostics, separate from Command testimony.
An unavailable positive observation prevents launching its negative neighbour;
even valid preparatory observations grant no credit before the next proof gate.

P is the trusted qualification parent; C is its direct case child; K is the
kernel. The evidence class is **`measured-code-testimony`**. It combines
kernel-observed process identity and completion with testimony from audited
code. It is not a kernel-observed `runner.Command` call.

## Credited facts and ordering

1. P retains the case executable and checks its digest against the independently
   accepted digest of the audited dispatcher. At the exec stop from P's own
   trace of its direct child, P verifies the executed image against that retained
   descriptor and checks the exact bounded initial argv. The case image digest
   is distinct from the synthetic app-server digest and approved candidate
   digest. The latter candidate is measured but never executed by these rows.
   Missing trace support, missing exec stop or a digest/image/argv mismatch
   prevents credit. A later exec by C invalidates this origin.
2. P creates a private, single-use SOCK_SEQPACKET channel with SO_PASSCRED.
   C marks its endpoint close-on-exec before launching any child. An entry
   receipt, ordinary stdout, helper report or broker silence supplies no
   testimony credit. The existing transport/admission entry challenge cannot
   serve as this post-return exchange.
3. The audited dispatcher invokes the real `runner.Command`, retains its actual
   returned status and bounded typed local outcome, and only then sends a
   return-ready message. P checks the message's kernel credentials against C's
   traced PID and configured UID before issuing a fresh unpredictable nonce.
   Readiness is itself code testimony: it is not independent proof of a return.
   Under this protocol, the challenge is sent only after Command returns;
   that ordering relies on the audited dispatcher.
4. C answers that nonce once, with its actual Command outcome. P requires the
   response's K-supplied PID and UID to equal the traced child and expected UID,
   and binds the response to this invocation, row, side, measured image and
   validated fixture context. Neither a claimed PID nor possession of the
   endpoint substitutes for SO_PASSCRED. Readiness and response from different
   senders are refused. No nonce is reused across controls or retries.
5. P acknowledges the accepted response and closes the exchange. One trace/wait
   owner joins the exact child and preserves its actual terminal status. P
   joins the fixture server and validates effects before assigning credit or
   writing an artifact. A reply without a joined case cannot pass. All phases,
   output collection and teardown share the existing bounded row deadline;
   cancellation closes the channel and accounts for the pinned child.

The post-return effect point in steps 3–4 is the return of the real Command,
including its deferred status classification and cleanup. A response before
that point violates the contract. The protocol rejects replies before an
outstanding challenge, reordered phases and known early-return paths. It cannot
independently detect a compromised dispatcher that fabricates readiness and
then answers a valid fresh challenge without calling Command.

## Required outcomes and effects

For each **negative** control, the local result must be the actual Command
return value 69 and exact typed outcome `credential_source_conflict`. This is a
local runner refusal, not an invented broker wire error. P validates this
testimony together with its own fixture observations:

- Zero broker connections/requests, lease records, Snapshot/Refresh calls and
  material delivery; no lease or writer operation is allowed.
- No app-server/version/login child or output effect. P's case trace must
  account for forbidden process creation; ordinary runtime threads are not
  writer children. Child-reported counters do not replace that observation.
- The synthetic native-path fixture is neither opened nor changed, or stays
  absent for the source-conflict case. P uses bounded filesystem observation
  and metadata checks without reading native credential contents. Loss of
  observation, including event overflow, cannot establish absence of effects.

Authority-resolution counters and the exact local diagnostic originate inside
C; they remain testimony even when P compares them with zero broker work.
Filesystem absence and broker counters do not independently prove a function
call or the diagnostic's origin. Fixture setup may create synthetic material
in P; the zero-effect claim concerns delivery/use during the negative case.

Each pair also needs its adjacent **positive** control: the same clean fixture
calls Command successfully, completes one synthetic external login and releases
its bounded lease. P verifies the existing exact broker counts, lease/store
state, allowed fixture effects and child-boundary reports. Its native path stays
absent. The positive side uses its own measured origin, post-return exchange and
nonce. It cannot borrow the negative's origin or replace a missing negative.

## Verdicts and fail-closed rules

UNRUN uses `executed=false`, `exit_code=-1`, no credited artifact and no launch
of a still-unattempted neighbouring control. Actual waits remain bounded
diagnostics; a missing origin must not acquire a synthetic canonical status.

| Condition | Required result |
| --- | --- |
| Missing exec stop, unsupported tracing, wrong retained image/digest or argv, or later case exec | UNRUN; no receipt fallback. |
| Missing credentials, wrong PID or UID, sender change, helper-only report or inherited receipt | UNRUN. |
| Replayed, duplicate, malformed, truncated, oversized or late nonce response; response without a challenge; return phase before the defined effect point | UNRUN. |
| Child exits without the required response, wait ownership is unavailable, or the deadline expires before joined completion | UNRUN, retaining only independently observed launcher/wait diagnostics. |
| Unexpected material, broker, lease, writer or filesystem effects, or incomplete effect observation | UNRUN, never PASS, even if the child claims the expected refusal. |
| Origin, testimony and effect observations are valid, but the actual case process exits nonzero | FAIL with the real case exit status, never rewritten to UNRUN or zero. |
| Valid origin and effects, but Command's reported outcome differs from the side's required result | FAIL; retain the actual Command return separately from the case process exit. |
| Negative Command returns 69 with the exact local refusal; case process exits zero; all negative effect checks hold | Eligible for PASS with the adjacent positive control, under this evidence class. |
| Positive Command returns zero; case process exits zero; all positive effect checks hold | Eligible for PASS with the adjacent negative control, under this evidence class. |

An expected Command return of 69 is therefore distinct from a case process
exiting 69. The dispatcher normally exits zero after recording an expected
negative result. A verified case exiting 17 after a valid response is FAIL with
17; exiting 17 without a response is UNRUN with 17 retained only as a diagnostic.
If an origin/effect gate is unavailable or contradicted, its UNRUN rule applies
even when a real nonzero wait is also available. No failure may become PASS.

## Trust limit and reports

This is testimony of audited code at the measured digest. It is **not proof of
an unmodified binary** beyond the digest check, runtime memory integrity, or
proof that the function was really called. Digest equality identifies measured
bytes; it does not establish correct control flow, exclude runtime compromise,
or certify the source-to-binary build. Trust in the audited measured program is
an explicit premise of this contract.

A compromised measured C could skip Command, announce a fabricated return,
answer its fresh nonce as the correct PID/UID, invent status 69 and the local
conflict diagnostic, and report zero internal counters. By producing no visible
effects it could satisfy P's negative effect checks too. It could also lie about
which internal path caused observed effects. It cannot thereby change P's own
exec measurement, K-supplied sender credentials, consuming wait status or
independently retained broker/effect observations, assuming P and K are trusted.
Effects outside the declared observers are not proven absent by this contract.

Reports and protected row artifacts must label these two rows
`measured-code-testimony`, including the measured case-image digest and actual
Command outcome separately from the parent's actual case wait. The class must
remain bound to the invocation and exact artifact bytes by private parent
evidence. Missing, forged, unknown or substituted classes cannot earn credit.
Serialized testimony or a self-declared digest never supplies private authority.
Reports must distinguish these rows from kernel-observed process/entry evidence
on transport/admission rows and from any future kernel-observed call evidence.
They must never describe this exchange as a kernel-observed Command call.
