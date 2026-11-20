# B1 protected installation binding gap

Status: **STOP:C0C_PROTECTED_INSTALLATION_BINDING**. Source construction only.
Base: broker main `9f1f90fa` (PR #82). No accepting daemon, root control,
installed authority factory, real credential, vendor request or native
qualification is supplied by this partial construction.

## Resolved decisions, not reopened

The private recovery decision supplies the B1-only, material-free, atomic
existing-engine adapter. C0c supplies the manager-owned native observation
socket rather than root ledger access. C0d supplies fresh publication pairs,
receipt-anchored periodic singles, independent freshness fences and separate
durable S/F. C0e makes the gateway the sole per-attempt gate. These decisions
are accepted. Historical pre-C0d budget witnesses are not current acceptance
requirements. No cooldown, deadline, replay or hold-boundary check is weakened.

## Exact remaining input

`contracts/lab-v0/observation.md`, “Closed surfaces and canonical limits”,
requires B5's protected manifest to independently pin the immutable installed
native store generation together with approved manager/daemon identities and
release digests. “Socket, framing and peer authentication” independently
requires the protected manager identity/executable/instance and boot binding.
Missing installed metadata refuses; neither a first successful observation nor
a restarted counter is an installation pin. Lab profile section 5.2 freezes
shared fields and writers before parallel implementation.

At this base the thirty external closed formats contain no B5-to-B1
installation binding with the manager instance and native store generation:

| Existing surface | Available information | Missing independent pin |
| --- | --- | --- |
| Authority / activation | Context, gateway/worker tuples, manager journal head, enablement and content digests | Native store generation, manager instance and daemon identity binding |
| Install / launch plan | Approved context, predecessor heads, manager receipt and named input **digests** | A typed payload/source for the protected native binding; a digest does not define its preimage |
| Release set | Approved executable/source/member digests | Native store generation and manager instance |
| C0c response | The complete observed manager/store/start join | This is **M1-to-B1 observed evidence**, not a B5-approved expected binding |
| Private recovery | B1-only replay/hold/state and S/F | B5 cannot write it and no other component may consume it |

`ObservationManager.instance_id` and `ObservationStore.generation` are the
only typed external definitions for those native pins; their enclosing
surface is written by M1, not B5. The generic `InputPin{name,sha256}` cannot
silently define an additional shared payload. The book dispositions remain
“OS user per agent and network” and “Operator and interfaces”, as cited by
`docs/assembly-v0-construction-contract.md` and
`spec/operator-and-activation-v0.md`: narrow privileged inputs, distinct
identities and no authority from observation. This is a missing refinement
of that installation boundary, not a production permission change.

## Clean approaches considered

1. An existing accepted protected B5/native binding is sufficient **if its
   exact bytes, source, ownership, approval/content join and fixtures are
   identified**. No such closed record or reference is present at this base.
2. A dedicated C0 addendum can define that B5/M1-to-B1 installation binding,
   with exact fields, lifecycle/currentness, protection and shared fixtures.
   It must not alter the frozen observation response or private recovery's
   writer/readers.
3. Reusing a response as a B5-written static manifest changes its frozen
   writer/meaning and requires a committed native start before installation.
   Taking the first response as expected pins is TOFU. Reading root-only
   native metadata or widening its permissions reopens the rejected access
   model. These are rejected, not implemented fallbacks.

Decision/input needed: identify the accepted protected binding record and
exact field projections, or authorize its narrowly scoped C0 addendum before
B1 builds an accepting factory. The tentative response-shaped configuration
was removed rather than delivered as an invented shared surface. The internal
client still requires independently supplied pins; test fixtures are not an
installation authority. No failure initializes pins, resets S/F or enables use.

## Bounded construction retained

The tagged existing-engine adapter retains committed account bootstrap,
lossless replay, exact hold/release times, CAS/UNKNOWN, finite-plan narrowing
reserve and external/private atomic recovery. C0d construction adds durable
S/F, final-pair revalidation, singles that never publish, sticky fencing and
an independent native-age closer. Observation I/O/cooldowns hold no account
lock; a concurrent existing-engine hold wins and the pair publishes nothing.
Protected native managed projection/journal controls validate the gateway and
native `agent` account used as the lab worker; synthetic caller facts are not
installed authority. No B1 attempt counter or vendor client is introduced.

These library controls are not the composed accepting daemon. In particular,
the publication callback is not an installed deadline-bound socket writer;
transport closure, B2 time/facts assembly, authenticated root commands and
genuine worker service/legacy refusals remain open. Every B1 acceptance row
remains incomplete in `docs/lab-b1-construction-coverage.md`. No claim is made
that this new input alone completes those implementation obligations.
