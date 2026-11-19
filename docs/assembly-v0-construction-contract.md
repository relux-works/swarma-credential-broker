# Assembly v0 construction contract C0

This stage retains its U00/U01 scope and source pin. The repository owner's
[construction stage C1](assembly-v0-construction-contract-c1.md) separately
extends inactive construction to U02 only against the published DN-05 text;
it does not accept an O-point or authorize activation.

## Authority, acceptance and scope

This is a **CONTRACT for inactive U00/U01 construction**, not an activation
contract or a second implementation plan. The assignment authorizes these
declarations, closed record sum codecs and synthetic vectors. Exact-head
engineering acceptance remains the review gate; this document does **not** assert the specification acceptor's
verdict. O-01 and O-19 remain open. Consumers must not call a proposed seam
accepted merely because a Go declaration compiles.

The source pin is `e295b4c7c0dc397ecdaa89e73c057d53d2e3f533`,
`spec/operator-and-activation-v0.md` revision 4, SHA-256
`d242db6d897ffe7a6fc662df9c47f9d67a035ddcbaffbcc245b87b13ad9d7c79`.
References below use that file's line numbers, abbreviated **S**. The supplied
implementation plan section 2 supplies engineering names, not additional wire
authority. This task covers I01–I21 only; I22–I24 and all later implementations
are outside its scope.

Section 9 controls applicability: DN-01–DN-08 select A with conditions;
DN-09 selects A for production; nothing in C is in force (S:1727–1751).
The rest of S remains PROPOSED. DN-05 is a declared **conflict**, not a
precedence rule. C0 did not publish the outstanding broker/service/Claude/book
amendments (O-01). The DN-05 broker/service subset is now published at
[section 4.4's clause links](../spec/operator-and-activation-v0.md#44-required-ownership-amendments-dn-05-conflict),
still PROPOSED pending acceptor review; other O-01 publications remain open.

Book-first sources, read at `swarma-docs` commit
`b57a9be633c245373b448c3786bcbd49d636fe8a`:

- Same: **Operator and interfaces**, `book/ru/16-interfeysy.md:49–72`:
  password fallback confirms the same narrow content; observation is not authority.
- Same: **OS user per agent and network**, `book/ru/04-polzovatel-i-set.md:27–35`:
  separate installer/launcher duties, absolute no-argv entry, bounded closed input.
- Refines/new: S sections 2–6 still require their owners' specification/book
  publications; this contract neither copies nor amends those upstream chapters.
- Conflicts: S section 4.4's DN-05 amendments are now published, not accepted;
  C's time-contract exceptions are unaccepted, excluded here, and may not be
  silently borrowed for A.

## Seam sheet

Every row is **PROPOSED** at least for engineering acceptance O-19. An additional
O-point on a row is a substantive unresolved choice, not a default. The
invariants below are construction constraints, not evidence that any named
implementation exists. Paths are module-relative. A later accepted amendment
must revise this contract and its dependent vectors together.

| Seam | Status / open points | Exact boundary and ownership |
| --- | --- | --- |
| I01 | PROPOSED: O-01, O-04, O-05, O-07, O-09, O-19 | U01 `internal/assemblyv0`: `Digest`, `OperationID`, `Nonce`, `PrincipalPin`, `BrokerPin`, `Freshness`, `Continuity`, `AccountPolicy`, `AuthorityDocument`, `ActivationDocument`, `TerminalAuth`, `LoginPath`, `LoginSession`, `TTYDevice`, `TerminalSession`, `TerminalReceipt`, `OperatorCandidate`, `OperatorBody`, `OperatorEnvelope`, `OperatorRequest`, `EnrolArguments`, `Event`; narrow `ProtectedRead` and `ConfigGate` ports and policy/identity values. No admission methods, wire registration or proof constructors. Unresolved complete schemas are omitted, not replaced by raw JSON. |
| I02 | PROPOSED: O-01, O-03, O-19 | U02 `internal/protectedio`: `FilePolicy`, `Identity` and `ConfigGate` alias I01 declarations; `Reader.Read(context.Context,string,FilePolicy) (Identity,[]byte,error)`; `ConfigGate.WithRead(context.Context,func(context.Context) error) error`. Exact checked descriptor-relative read from fixed production root `/`, inode/owner/group/mode/link/size checks and configuration-lock continuity. No accepting filesystem stub. |
| I03 | PROPOSED: O-01, O-03, O-19 | U02 `internal/authorityv0`: `StartupPins`; `Reader.Load(context.Context) (assemblyv0.AuthorityDocument,StartupPins,error)`; `Reader.WithPinned(context.Context,StartupPins,func(context.Context,assemblyv0.AuthorityDocument) error) error`. A separate current `WithIdentity` leg must not require authority history, managed evidence, activation or trusted UTC for unmanaged operator unbind. |
| I04 | PROPOSED: O-01, O-19, O-21 excluded | U03 `internal/activationv0`: `Selection`; `Loader.Load(context.Context,policy.Config) (Selection,error)`; `Selection.ServiceLifetime() time.Duration`. Distinguish absent, valid inactive, structurally enabled and refused; invalid false is not absent. No custody read on inactive startup; no C selector. |
| I05 | PROPOSED: O-01, O-07, O-09, O-19 | U01 declarations in `internal/statev0`: `Gate`, `Tx`, independent nonce/revocation and `/2` service record/port types. U04/U05/U06/U08 implement storage later. Complete `AuthorityState`, `OperatorOutcome`, `CallerState`, `BindingRecord` and `ReceiverEffect` remain undeclared where O-07/O-09 prevent exact types. `Gate.With(context.Context,func(*Tx) error) error` is one shared nonrecursive serialization boundary. |
| I06 | PROPOSED: O-01, O-07, O-09, O-19 | U04 `AuthorityJournal.ReadLocked(*Tx) (AuthorityState,error)`, `CommitLocked(*Tx,uint64,AuthorityState) error` await the complete state schema. `NonceStore.ConsumeLocked(*Tx,assemblyv0.TerminalReceipt) error` is declared. CAS/outcome and nonce publications are independent, not cross-file atomicity. Missing state is unavailable except explicit fresh installer initialization. |
| I07 | PROPOSED: O-01, O-19 | U05 `ServiceJournal.LoadLocked(*Tx,string) (ServiceStateV2,error)`, `CommitLocked(*Tx,string,uint64,ServiceStateV2) error`, `ReserveLocked(*Tx,string,ServiceStateV2) error`. `internal/servicev0.JournalAccount` later bridges existing `service.Account`; `/1` never accepts `/2`. Reserve every active binding's removal/receipt plus hold headroom within 1 MiB. |
| I08 | PROPOSED: O-01, O-09, O-18, O-19 | U06/U08 `CallerJournal.ReadLocked`, `CommitLocked`, `ReserveLocked` await O-09 types; `RevocationStore.ReadLocked(*Tx) (RevocationState,error)` and `PutLocked(*Tx,RevocationState) error` are declared. Caller storage is independent; revocation has the sole `{seq,records}`. No acknowledgement before durability/reconciliation. |
| I09 | PROPOSED: O-01, O-19 | U07 `internal/grantv0`: named aliases of I01 `GrantEnvelope`, `RevocationEnvelope`, `Chain`; `VerifiedChain`, `Evaluation`; `Verify(Chain,Evaluation) (VerifiedChain,error)`. Baseline broker §§6.1–6.4 unchanged, both independent chains and all narrowing/time/revocation checks. Evaluation is captured protected evidence, never request-supplied roots/time. |
| I10 | PROPOSED: O-03, O-09, O-19 | U09 `internal/managedfacts`: `Reader.WithVerified(context.Context,func(context.Context,Verified) error) error`; `Verified.Service(uint32) (ServiceRecord,error)`; `Verified.Agent(uint32,string) (AgentRecord,error)`; `Head`. Reuse verified projection/journal with existing bounds. Service-only lookup never accepts operator/observer; values cannot escape the callback. |
| I11 | PROPOSED: O-10, O-11, O-12, O-13, O-19 | U10 `internal/readinessv0`: `Source.Prepare(context.Context) (Prepared,error)`; `Prepared.WithCurrent(context.Context,func(context.Context,Window) error) error`; `GenerationFloor.AdvanceLocked(*statev0.Tx,managedfacts.Head) error`. Existing owners supply accepted qualified evidence. Collection outside state locks, bounded final settlement recheck; missing inputs refuse before authority callback. No C3 high-water borrowing. |
| I12 | PROPOSED: O-01, O-03, O-09, O-10, O-11, O-12, O-13, O-19 | U11 `internal/protectedfacts.Reader` implements existing `service.Authority`; `View` implements `service.View`. `Reader.ForAct(operatoract.VerifiedAct) service.Authority` is call-scoped, never a global authenticated flag. Preserve `WithIdentity`, `WithCurrent`, `Principal`, `Service`, `Caller`, `Owner`, `OperatorAct`, `Event`, `Sequence`; recheck live peer/receipt at mutation. |
| I13 | PROPOSED: O-09, O-13, O-19 | U12 `internal/callerv0`: `Receiver`, `BindArguments`, `UnbindArguments`, `EffectQuery`; `Receiver.Call(context.Context,Peer,wire.Request,func(any) error) error`. Baseline §13.2 only; peer kernel-derived. No invented R-UNTRUSTED/rebind/effect/principal fields. |
| I14 | PROPOSED: O-01, O-04, O-06, O-19 | U13 `internal/operatoract`: `Canonical.Body(assemblyv0.OperatorBody) ([]byte,error)`, `Preimage(assemblyv0.OperatorBody) ([]byte,error)`, `ArgumentCommitment(string,json.RawMessage) (assemblyv0.Digest,error)`; `Verifier.Verify(context.Context,Peer,assemblyv0.OperatorRequest) (VerifiedAct,error)`. No unchecked proof constructor. Act and argument domains differ; proof binds one live connection/invocation, with rechecks. Nonce burn is separate. |
| I15 | PROPOSED: O-01, O-07, O-19 | U14 `internal/operatorv0`: `Receiver.Call(context.Context,operatoract.Peer,wire.Request,func(any) error) error`; `Enroller.Enrol(context.Context,operatoract.VerifiedAct,[]byte,func(any) error) error`; `ServiceCalls.CallAct(context.Context,operatoract.VerifiedAct,func(any) error) error`. U19/U20 supply implementations. Exactly four inner methods; enrollment reply bytes remain absent pending O-07. |
| I16 | PROPOSED: O-03, O-04, O-06, O-16, O-19 | U15/U18 `internal/operatorentry` and separate operator command: `Composer.Compose(context.Context) (assemblyv0.OperatorCandidate,error)`; `CandidateFD.Seal(assemblyv0.OperatorCandidate) (*os.File,error)`; `Display.Confirm(context.Context,assemblyv0.OperatorEnvelope,assemblyv0.TerminalSession) error`; `Signer.Sign(context.Context,[]byte) ([]byte,error)`; `Terminal.Capture(context.Context) ([]byte,error)`; `Client.Run(context.Context) error`. Protected supervisor retry facts, no candidate filename/argv/token-source selector. No signing-key path is chosen here. |
| I17 | PROPOSED: O-02, O-03, O-04, O-19 | U16/U28 `internal/ceremonyv0`: `Supervisor`, `LoginGate`, `Invocation`, `TTYGate`, `Launcher`; separate ceremony command. Selected SSH/login evidence, continuously held task/FD gate, single-launcher thaw/refreeze, relay and root cleanup await owners. No arbitrary-session freeze or whole-cgroup thaw. |
| I18 | PROPOSED: O-04, O-05, O-16, O-19 | U17/U29 `internal/witnessv0`: `Server`, `Session`, `ReceiptWriter`, `AuditSession`, native audit bridge. Exactly `Begin(method,account)` → `Issue(act,confirmation)` → `Retire(nonce)`, S:349–392; receipt unlink and directory sync before definite result. No FD3 assumption/I/O plugin; native ABI/build language not selected. |
| I19 | PROPOSED: O-01, O-07, O-16, O-19 | U19 `internal/enrolv0.Coordinator.Enrol(...)` implements I15. Existing Claude custody only, sole-writer admitted-intent/material/metadata/initial-`/2` reconciliation. No invented success projection or duplicate custody backend. |
| I20 | PROPOSED: O-01, O-17, O-19 | U20/U21 `internal/servicev0`: `Calls.CallAct(context.Context,operatoract.VerifiedAct,func(any) error) error`; `BindingIndex.ResolveLocked(*statev0.Tx,string) (AccountTarget,error)`; `Runtime`. Reuse `*service.Broker`, `NewWithLifetime`/`NewWithCatalog`, `Call`. Protected scan never reads material or authority history; exhausted budget is unavailable, not unknown binding. |
| I21 | PROPOSED: O-01, O-08, O-18, O-19 | U22 `internal/baselinev0`: `SelectionPolicy.AccountModeLocked(*statev0.Tx,string,string) (string,error)`; `BaselineGate.CheckLocked(context.Context,*statev0.Tx,uint32,string) error`; `Adapter`. One state boundary for both baseline interlocks and final release. Known secret-free refuses `secret_free_lease_required`; unknown authority closes use; observer/static allowlist never grants service authority. |

## Shared gate and import contract

S:1065–1094 and baseline `spec/broker.md:429` require configuration →
user-manager gate/data → shared broker state ordering, only for sources the
particular operation needs. I05 freezes the proposed Go signature, **not an
implementation**. U05 must enforce all of the following:

1. One runtime gate serializes publication/revocation/narrowing and final
   material release; private per-unit mutexes are not equivalent.
2. `*Tx` is issued only inside `With` and cannot escape, be copied into
   authority, reused after return, used with a different gate, or authorize
   through its zero value. Callback/context cancellation fails closed.
3. Every `Locked` method consumes the live token, never reacquires the gate,
   and does no network/PAM RPC or human wait. Re-entry is forbidden.
4. Durability precedes acknowledgement. Independent files are not a single
   transaction. CAS mismatch/capacity/uncertain publication never fabricates success.
5. Operator unbind needs only its current identity, receipt and target journal;
   no widening nonce/authority/grant/time dependency may be introduced.

U01 supplies opaque `Tx` and interfaces only: no constructor, token issuer,
mutex or store, and **no runtime token-enforcement claim**. Its structural
signature tests are not U05 concurrency/cancellation/durability qualification.
`transactionScope` is zero-sized: Go does not guarantee distinct addresses for
zero-sized allocations. U05 must not use its pointer identity as a live token
without adding non-zero-sized runtime identity state.

Imports: `assemblyv0` → standard library; `statev0` → `assemblyv0`, existing
`wire`, standard library. Existing `wire` imports neither new package. Future
`grantv0` aliases shared envelope values; storage cannot import its verifier,
`service`, `protectedfacts` or `servicev0`. The `JournalAccount` bridge belongs
in `servicev0`. Do not use casts between `/1` and `/2`; preserve existing
wire record values while explicitly projecting their required receipt/time
differences. Required null/empty-array members never use `omitempty`.

## Byte contract and validation boundary

- S:75–85: CCJ-1 UTF-8, sorted keys, no insignificant space/LF; reject duplicate
  keys, invalid Unicode, unknown/missing members, floats, negative zero and unsafe
  integers. Pin IDs are data, never proof of protected origin.
- S:409–450: body contains all ten required members; exact act domain + one LF
  + CCJ-1 body. ID is SHA-256 of that preimage; Ed25519 signs exactly those bytes.
  Arguments have their own domain + LF + method + LF + canonical arguments.
- S:424–433: widening uses only UTC, unbind only current-boot BOOTTIME;
  positive interval ≤300 s / 300,000 ms, no mixed forms. Actual time/current-boot
  authority is a later leaf, not a fixture assertion.
- S:454–488: four method argument forms, equal inner/body operation IDs;
  enrollment expiry required nullable, exact nonzero whole-second UTC when set.
  Prefix is first 16 SHA-256 bytes of the separate installation/operation/token
  preimage (S:469–474). Candidates omit that prefix (S:108–113).
- S:785–824: complete authority bytes define installation-policy digest;
  all arrays explicit; root keys distinct and include operator key; principal
  role UIDs disjoint; account owner is operator, not terminal caller.
- S:1405–1427,1506–1515: activation ≤16 KiB, one optional integral 1..900
  lifetime (missing means 900; explicit null/zero/float/>900 refuses, never clamps).
  Only production continuity is in this construction slice. A false document
  is still structurally validated; no reader/startup implementation is supplied.

Admission validators, canonical verifier methods and filesystem readers remain
with their format-owning leaves. U01's assembly decoder, semantic vector checks,
deterministic synthetic signing and fixture generation live only in `_test.go`.
They are not callable production APIs or a permissive factory.
The unchanged unsigned `wire.Parse` refuses top-level `sig`; tests validate
signed fixture envelopes as a nested value using that parser, without weakening it.

Plain `wire.Decode` cannot populate the sealed `assemblyv0.Freshness` and
`assemblyv0.RevocationTarget` interfaces. The inactive `statev0` record types
therefore provide closed `UnmarshalJSON` adapters for `OperationReceipt` and
`BaselineRevocationState`: both freshness forms and both revocation targets
decode without pre-seeding an interface, and unknown/missing/forbidden-null
members refuse. These are schema adapters only, not stores, signature verifiers,
time admission or authority constructors. U05 and U08 own the actual journal
loaders and must use sum-aware decoding, validate complete canonical bytes and
all semantic/provenance invariants, and never infer those guarantees from a
successful `wire.Decode`. Non-empty UTC and BOOTTIME `/2` controls (the latter
with `at:null`) and signed grant/key revocation controls are checked in under
`internal/statev0/testdata/construction-v0/` (S:774–776,892–895).

U03 must check activation lifetime member presence/null on the raw object:
plain decoding into `*uint32` cannot distinguish absent from explicit null.
`TestConstructionRefusals/lifetime-null` is a mandatory U03 negative, not
permission to default an explicit null to 900 (S:1509).

The leaf-grant fixture checker accepts only `credential.lease`; it must not be
reused as a baseline grant validator. The unresolved-declaration test is a name
blocklist, not a proof that differently named partial schemas cannot exist.
The non-ASCII act vector freezes original UTF-8 hashing bytes, not a display
implementation: complete reversible escaping, confirmation and terminal safety
remain U13/U15 responsibilities (S:499–503,1632).

## Excluded incomplete schemas

O-07: no enrollment success/result type, wrapper success framing or complete
`OperatorOutcome`/`AuthorityState` containing that result. O-09: no producer
class/provenance/replacement payload, baseline principal/effect encoding,
`BindingRecord`, `ReceiverEffect`, `CallerState` or dependent journal interface.
Partial structs would pretend to be complete closed objects, so none is supplied.
Existing service operation `json.RawMessage` argument/result slots are inherited
published service-method unions, **not** substitutes for these missing schemas.

O-21: no `test-c` wire members/types, fence, high-water file or selecting backend.
All other unresolved points and applicability are in
[the applicability register](assembly-v0-applicability.md). No synthetic fixture
or checked-in pin selects an installed SSH stack, private key, identity backend
or custody. [The vector index](../internal/assemblyv0/testdata/construction-v0/index.json)
binds each exact file/preimage to source lines and a byte digest.
