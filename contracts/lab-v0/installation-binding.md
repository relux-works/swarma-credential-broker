# C0f: protected installation binding, version 1

Status: CONTRACT CANDIDATE FOR REVIEW. Lab construction only; no runtime reader,
installer, owner approval, live budget or production acceptance is supplied.
The owner-delegated decision of 2026-11-20 selects one B5-written protected
installation record. The revision separates installation authorization from
C0b's expiring per-start authority. Observed C0c evidence is never an expected
manifest. The profile's production conflict and time/native gates are unchanged.
Same book dispositions: **Operator and interfaces** (observation is not authority)
and **OS user per agent and network** (installer/launcher separation), cited in
`docs/assembly-v0-construction-contract.md:35` and
`spec/operator-and-activation-v0.md:20`. No production ownership rule is amended.

## Closed record and installation approval

`surfaces.json` freezes `swarma-broker-lab-installation-binding/1`, B5 (root) ->
B1 and M1, maximum 16384 canonical bytes. All fields are required; CCJ-1 and the
complete recursive C0 catalogue apply, including the nested Approval. Duplicate,
missing, extra, alias, null, wrong kind, noncanonical integer, unknown literal
and oversized data refuse at shape/preflight, before seals or state changes.

| Member | Grammar / exact meaning |
| --- | --- |
| format | Exact discriminator above |
| context | Existing Context; equals the installation release and each admitted P/A/R Context in every field |
| manager | Existing ObservationManager: root UID, exact service identity, approved executable digest, expected instance ID and boot ID |
| store_generation | Existing operation grammar, 32 lowercase hexadecimal bytes; installed native STORE generation, not start/account generation |
| daemon_uid / daemon_gid | Canonical uint; native range 1..4294967294 each, never root, all-ones sentinel or overflow |
| daemon_executable_sha256 | Full approved daemon executable digest, not a process name |
| daemon_socket_path | Exactly /opt/swarma/run/lab-broker/broker.sock |
| observation_socket_path | Exactly /opt/swarma/run/lab-manager/observation.sock |
| installation_approval | Existing closed Approval, authenticated through the existing owner-terminal procedure; approves TI below, not a start or budget |
| approval_record_sha256 | Digest of ALL canonical installation_approval bytes; NEVER digest of per-start C0b A |
| release_set_sha256 | Digest of ALL canonical installation release R0 bytes selected at the section 6 gate, not the changing per-start R |
| install_epoch | Existing positive grammar, 1..9007199254740991; fresh installation 1, rotation exactly previous+1, overflow refuses |

I is the complete record. TI is CCJ-1
`{"domain":"swarma-broker-lab-installation-binding-target/1","record":T}`,
where T is I with ONLY installation_approval and approval_record_sha256 omitted.
TI INCLUDES release_set_sha256 and every runtime identity, socket and epoch.
It is an approval preimage, not an external executable record or archive member.
The embedded installation_approval.approved_sha256 equals digest(ALL TI).
B5 authenticates that approval and R0's owner approval, checks their seals and
unexpired windows at installation publication, and refuses revoked/unknown
provenance. R0 is the existing closed swarma-lab-release-set/1, with unchanged
signed-source, second-build, archive-member and contract-index requirements.
B5 retains its exact nonsecret bytes at
`/etc/swarma/lab/installation-release-set.json` with I's file/parent protections.
This is a retained release record, not a second installation-binding authority.
Readers rehash R0 against I, verify its seal and authenticated provenance and
current installation revocation status. The protected B5 publication attests
consumption inside the installation approval windows; readers do not reinterpret
their expiry as a running-installation lease. Unknown/revoked installation
approval closes use. The approval remains historical authorization, not live use.

For EACH later start/group, C0b still requires its own fresh sealed R -> A -> P
-> L, current heads, access/clock/qualification checks and full bounded gates.
Compare current R.assets, R.contract_index_sha256 and R.context EXACTLY with R0;
R.invocation_sha256 and owner_approval may differ for a newly approved group.
Never require digest(current A) or digest(current R) to equal I's install pins.
Changing only that valid per-start chain needs no I rewrite, new epoch or manager
instance. A stale/foreign/revoked start approval still refuses at C0b. Neither
installation approval nor R0 authorizes another invocation or extends a bound.
Changed installed release inventory/index/Context requires approved rotation.

The chain is acyclic: verified R0 -> runtime TI -> installation approval -> I
-> complete-I InputPin in install/launch plans; separately each current R/A/P
approves the start. No I/TI is inserted into a tagged build archive, no tag,
source commit or second-build digest is rewritten to represent runtime values.
B1/M1 reconstruct TI from I, not a C0c response. Manager executable_sha256 names
an approved product=manager member (0755); daemon_executable_sha256 an approved
product=broker member (0755). The approved TI chooses the exact digest, not an
arbitrary member; membership alone does not attest a root peer's running image.

Exactly one InputPin named `installation-binding` supplies digest(ALL I) in the
FINAL install plan and each launch L; duplicate names refuse. B5 validates
its install plan's own approval/head joins separately; its off_vm_approval pin
is not I's installation approval digest. The install plan has its existing
published readers; B1 never needs B5's root-only installer envelope or receipts.
The early release-copy/identity-setup plan cannot yet pin I: it is non-enabling
setup only, not a successful C0f install or launch plan. After actual UID/GID
readback and installation approval, B5 computes complete I and regenerates the
FINAL install plan with its exact pin and current heads; its existing owner/
operation authorization must cover that final plan before binding publication
or broker prepare. No guessed digest or preliminary plan may pass the final
checker. A pin without this protected typed preimage supplies no identities.

## Runtime source, placement and protection

B5's install-set first verifies and places the reproducible release, disabled
units and setup plan. It does NOT yet emit I from prospective UID guesses.
After M1 create-identities/verify-identities, B5 reads actual native NSS UID/GID,
current kernel boot and approved executable members; assigns a fresh manager
instance and, on store creation, a fresh native store generation. A retained
store keeps its immutable generation and entire history. The owner approves TI's
exact nonsecret values through the existing terminal gate, then B5 generates I
at install time. This step is repeated on boot-bound rotation, not by rebuilding
an archive. If R0's owner approval has expired, the owner renews that
approval on the unchanged released inventory before rotation; no archive/source/
second-build claim changes. M1 root setup consumes I read-only to provision exact native pins
under the SAME Store.Lock/effects.lock (currently LOCK_EX; `observation.md:23`).
B5 verifies that setup readback before install success or daemon start. Unknown,
partial setup leaves use closed; no reader lazily creates or repairs native pins.

The ONE installed binding is `/etc/swarma/lab/installation-binding.json`, beside
B5's root placements, not B1-private state: regular, single-link, non-symlink,
root:daemon_gid, exact 0640, at most 16384 bytes. `/etc/swarma/lab` is
root:daemon_gid 0750; all ancestors root-owned non-symlink directories without
nonroot write access. No extended/default ACL or alternate group grants access.
The dedicated daemon group has no agent/gateway/worker member; M1 reads as root,
B1 as the nonroot daemon. Native launch store remains root 0700/0600 unchanged.
B5 uses a same-directory protected temporary inode, rehash/fsync, atomic rename
and parent fsync. Failure/uncertain publication is UNKNOWN. Readers securely
open the fixed protected paths, verify opened-inode ownership/mode/type/links/
ancestors/ACL and current path-to-complete-inode/digest after reading. Absence,
unreadable metadata, bad protection, stale descriptor, swap or partial bytes
refuses/UNKNOWN. No repair, privileged fallback, TOFU or root broker is allowed.

## Reader checks and epoch adoption

Before admission, each C0d publication pair and every existing periodic single,
B1/M1 re-read I/R0 and compare their full digests, epoch, installation authority
and current per-start authority independently. No extra native pair or deadline
allowance is added. Actual daemon UID/GID/executable/sockets must equal I; M1's
SO_PEERCRED allowlist is exactly I.daemon_uid. Every C0c response.manager member
must equal I.manager. response.store.generation must equal I.store_generation,
not response.sequence_generation, a copied C0c Expected object or start.generation.
C0c's sequence_generation equality is a SEPARATE consistency check. I is the sole
expected source even if another expected object is internally coherent and stale.
All native start/stop/currentness/sequence and C0d floor/freshness checks remain.

In-flight ANY I full-digest/epoch/path change, installation revocation, failed
current per-start approval or tuple mismatch closes that group and publication.
UNKNOWN is sticky for that group; later good data cannot reopen it. Binding reads
fit existing C0d budgets. Fenced diagnostics-only startup and identity-only
unbind/hold remain permitted as in the profile; they cannot admit live use or
publish an enabling result when either authority is invalid.

Only owner-approved B5 root installation/rotation may replace I. First close old
admission, quiesce affected broker/gateway use and prove no in-flight old-epoch
use. Unknown quiescence forbids replacement. Authenticate the new runtime TI
and release; next epoch is exactly prior+1 and manager instance must be fresh.
A new boot, manager/daemon tuple, store replacement or release inventory requires
rotation. Never edit in place, reset native history/sequence or publication floors.

B1 and M1 independently own their durable private installation latches. Adoption
is a separate idle transition, never the recurring read's mismatch path:
- M1's root setup adopts from approved protected I/R0 and native pin readback
  under the existing store lock BEFORE serving observations. No start or C0c
  pair is required for this installation-only step, and it enables no live use.
  Routine observation requests never initialize/advance that installation latch.
- B1 adopts only for a NEW group after a fresh approved start and the existing
  C0d native admission pair; no additional pair or publication floor reset.
- Each first bootstrap requires an independently verified fresh T2 baseline AND
  fresh private recovery with no prior latch; accept ONLY approved epoch 1.
  Missing recovery on an existing installation is loss, not fresh bootstrap.
- Each rotation requires persisted (epoch, full I digest, manager instance) at e;
  accept ONLY e+1 with a fresh instance, complete new installation provenance and
  old use quiescent. Same-epoch restart accepts only the SAME full digest/instance.
  Each reader commits its own latch durably BEFORE reporting readiness. Partial/
  unknown commit enables nothing. M1 installation readiness precedes the native
  start; B1 group readiness follows its admission pair. Admission requires both
  readers on the same I. Reconcile each reader's own durable state after failure;
  never reset it, accept arbitrary higher epochs or reopen a closed old group.
- Lower/skipped/same-epoch-different records, missing nonfresh latch, reused
  instance, missing installation authority/readback/quiescence or failed durable
  commit refuse without advancing. B1 additionally refuses absent fresh start/
  pair. B1 preserves replay/floors; M1 preserves native history. An in-flight
  change first closes; only the separate transition above may later adopt it.

B5 NEVER reads/writes/repairs/exports B1-private recovery; B1/M1 never write I.
B1 stays nonroot; M1 retains its own root-owned installation latch. Whole-VM
rollback protection/accepted lab residual is unchanged, not solved by this file.

## Construction controls and remaining gates

Synthetic installation-binding-fixtures.json publishes I, retained R0, target,
protection facts and current start joins. Existing C0b-only launch fixtures are
not composed C0f admissions. Generic recursive operators cover the new nested
Approval; lifecycle/adoption and coherent foreign-manager/store witnesses have
adjacent valid controls and narrowing overlays. Metadata proofs are not native
stat/SO_PEERCRED/fsync, authentic owner acts or executable implementations.
B5/B1/M1 still owe native protection/race/crash, revocation, adoption, quiescence
and timing qualification. No production constructor, native DAC or B1-private
recovery format is added here.
