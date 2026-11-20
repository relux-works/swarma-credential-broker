# C0f: protected installation binding, version 1

Status: CONTRACT CANDIDATE FOR REVIEW. Lab construction only; no runtime reader,
installer, owner approval, live budget or production acceptance is supplied.
The owner-delegated decision of 2026-11-20 selects one B5-written protected
installation record. Observed C0c evidence is never its expected manifest.
This refines the lab installation boundary; the profile's declared production
conflict and all time/approval/native qualification gates remain unchanged.
Same book dispositions: **Operator and interfaces** (observation is not authority)
and **OS user per agent and network** (separate installer/launcher duties), as
cited in `docs/assembly-v0-construction-contract.md:35` and
`spec/operator-and-activation-v0.md:20`. No production ownership rule is amended.

## Closed record and typed approval preimage

`surfaces.json` freezes `swarma-broker-lab-installation-binding/1`, B5 (root) ->
B1 and M1, maximum 16384 canonical bytes. All fields are required; CCJ-1 and the
complete C0 recursive catalogue apply. Duplicate/missing/extra/alias/null, wrong
kind, noncanonical integer, unknown discriminator and oversized data refuse at
shape/preflight, before any seal/join or state change. There is no default record.

| Member | Grammar / exact meaning |
| --- | --- |
| format | Exact discriminator above |
| context | Existing Context; equals approved P/A/R Context in every field |
| manager | Existing ObservationManager: root UID, exact service identity, approved executable digest, expected instance ID and boot ID |
| store_generation | Existing operation grammar, 32 lowercase hexadecimal bytes; independently assigned installed native STORE generation, not start/account generation |
| daemon_uid / daemon_gid | Canonical uint representation; semantic native range 1..4294967294 each, never root, the invalid all-ones sentinel or overflow |
| daemon_executable_sha256 | Full approved daemon executable digest, not a process name |
| daemon_socket_path | Exactly /opt/swarma/run/lab-broker/broker.sock; not a selectable read path |
| observation_socket_path | Exactly /opt/swarma/run/lab-manager/observation.sock; existing C0c endpoint |
| approval_record_sha256 | Digest of ALL canonical C0b off-VM approval A bytes |
| release_set_sha256 | Digest of ALL canonical section 6 release R bytes; equals A.release_set_sha256 |
| install_epoch | Existing positive grammar, 1..9007199254740991; first explicitly fresh installation is 1, rotation is previous+1, overflow refuses |

Define I as the complete record. Its typed target TI is CCJ-1
`{"domain":"swarma-broker-lab-installation-binding-target/1","record":T}`,
where T is I with ONLY approval_record_sha256 and release_set_sha256 omitted.
TI is a hash preimage/approved configuration artifact, never an executable
installation record or permission to omit those members from I. No new external
RPC/authority format is implied. All identity, socket, epoch and Context fields
are in TI. In R require exactly one product=broker member at
`contracts/lab-v0/installation-binding-target.json`, mode 0644, digest(ALL TI).
Duplicate matching paths across assets, wrong product/mode/digest refuse. B5
reproduces the configuration artifact from the prospective installation values;
the aggregate retains its existing source/second-build/member/provenance gates.
The owner approves these exact nonsecret values at the existing section 6 gate.

This is acyclic: prospective TI -> sealed R -> sealed A -> bounded P -> launch L;
I contains A/R digests but TI does not. C0b's invocation target, R/A seals,
authenticated approval/freshness, protected expected P/R digests and qualified
clock/access checks remain mandatory, not replaced by a hash. B1/M1 reconstruct
TI from I and verify the exact member. Manager executable_sha256 must name an
approved product=manager executable member (0755); daemon_executable_sha256 an
approved product=broker executable member (0755). Executable membership does not
independently attest a root peer's running executable; C0c socket trust remains.

The existing install/launch InputPin named `installation-binding` supplies
digest(ALL I). This addendum supplies its previously missing typed preimage.
Exactly one such pin is required in the protected install plan (checked by
B5 as root) and each launch L using I (checked by B1/M1); duplicate InputPin
names refuse. B1 does NOT read B5's root-only install envelope or receipts: I
and its approved launch/approval inputs are the daemon-readable boundary. The
InputPin follows I, never gets hashed back into TI, R or A. Existing plan authentication/head joins still apply. Neither
InputPin nor a C0c response alone supplies an expected identity manifest.

## Source, placement and protection

B5 constructs I from the owner-approved prospective TI, approved executable
members, trusted native identity/NSS readback and current kernel boot identity.
It assigns a fresh nonsecret manager instance ID and, on native-store creation,
a fresh native store generation BEFORE approval, not from the first observation.
M1's root installation setup consumes I read-only to provision those exact pins
once in its existing protected native state, under the SAME Store.Lock /
effects.lock serialization (currently LOCK_EX, not a new LOCK_SH or mutex;
`observation.md:23`). B5's root installer verifies that readback before reporting install success;
only then may B1 start. No arbitrary source path or response-shaped config is
accepted. Failure/partial setup leaves all use closed; no reader provisions,
repairs, lazily creates or resets missing native metadata. An unchanged native
store retains its immutable generation and complete sequence/prefix history.

The ONE installed record is `/etc/swarma/lab/installation-binding.json`, beside
B5's other root placements, not in the broker's private state. It is a regular,
single-link, non-symlink root:daemon_gid file, exact mode 0640, maximum 16384
bytes. `/etc/swarma/lab` is root:daemon_gid, exact 0750. All ancestors are
root-owned, non-symlink directories without nonroot write access. No extended
file ACL, inherited/default ACL or alternate group grants access to I. The
selected group is the dedicated daemon group, with no agent/gateway/worker
member; M1 reads as root, B1 as the nonroot daemon. The existing native launch
store stays root 0700/0600 with NO new ACL, capability or widened DAC.

B5 writes a protected same-directory temporary inode, rehashes its own bytes,
fsyncs file, atomically renames and fsyncs parent; a failure/uncertain commit is
UNKNOWN. Readers securely open the fixed path without links, verify all owner,
group/mode/type/link/ancestor/ACL facts on the opened inode and verify that the
current protected path still names that complete inode/digest after the read.
Absence, unreadable metadata, wrong owner/group/mode, stale descriptor/path swap,
partial bytes or uncertain read refuses/UNKNOWN, never a first-response TOFU.
No ownership/mode repair, privileged fallback or broker-as-root is allowed.

## Reader and rotation rules

B1 and M1 are read-only consumers of I. Before start admission, every fresh C0d
pair/publication and every existing periodic SINGLE check, independently read
and compare the current I digest/epoch and authenticated unexpired approval
chain. Do not add native observation pairs or change C0d's lock/cadence budgets.
Check the actual daemon kernel UID/GID, approved executable and fixed socket
against I; M1 uses I.daemon_uid for its exact SO_PEERCRED client allowlist.
The C0c response.manager must equal I.manager in EVERY member; installed
store.generation must equal I.store_generation, not start.generation. All C0c
start/currentness/stop/lock/sequence, C0d pair/floor and C0b approval checks remain
independent. A shape-valid I is not itself native admission or liveness.

No first-response TOFU, root broker, alternate socket, widened native DAC,
transmitted UID or copied observation can initialize expected pins. In a running
group, ANY change to I's epoch OR full digest, current path, approval or expected
native/daemon tuple closes use and prohibits final publication. Missing/late/
partial/changed input is UNKNOWN; later good data cannot reopen that group.
This local check is inside the existing C0d deadlines/closure ceilings; a slow
binding read does not extend an RPC, pair, watchdog or approved wall bound.

Before reinstall/rotation B5 authenticates the new owner-approved TI/R/A and
checks the protected prior I (or the independently verified fresh T2 baseline
for epoch 1). It closes old admission, quiesces affected broker/gateway use and
proves no active/in-flight old-epoch use before replacing I. Failed/unknown
quiescence means NO replacement or new use. New epoch is exactly previous+1,
new manager instance never reuses the old ID, and all old bindings/connections
are invalid. Changed daemon UID/GID/executable, manager executable/instance/boot,
or native store replacement requires this rotation, not editing in place.
Do not reset a retained store's sequence/history or any publication floor.
A new boot is not permission to adopt an old boot-bound I.

B1 retains its own epoch/digest and replay/floor state in B1-private recovery;
M1 retains its own installation latch in existing native protected state.
A lower epoch, same-epoch different digest, missing prior record at a nonfresh
installation or counter overflow refuses. Restart obtains a fresh approved
binding and native admission pair, never cached liveness. Fresh use after
rotation needs a new approved plan and native start; no in-flight migration.
B5 NEVER reads, writes, repairs or exports B1's private recovery. Its privileged
write set here is I plus its existing installer receipts/native setup boundary,
not the broker recovery store. Root's theoretical power is not an authorized
B5 API. B1 remains a dedicated nonroot daemon. Whole-VM rollback protection and
accepted lab residual are unchanged, not claimed solved by an epoch file.

## Construction controls and remaining gates

`installation-binding-fixtures.json` publishes explicitly synthetic I, protection
facts and full approval/launch joins, with intended refusal reasons. Generic
closure/grammar/byte fixtures and paired rule tests apply every C0 operator.
Independent source-overlay tests remove each added gate. Reference metadata
proofs are NOT stat/SO_PEERCRED/fsync or native provisioning qualification.
B5 implements placement/approval/quiescence; B1/M1 implement actual protected
readers, epoch invalidation and native joins. Native load/DAC/path-race, crash/
atomicity, group membership and timing evidence remain their release gates.
No native-store permission, B1-private format, observation wire or production
constructor/default is modified by this contract-only addendum.
