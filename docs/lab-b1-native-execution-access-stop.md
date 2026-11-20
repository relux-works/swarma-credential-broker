# B1 native execution-evidence access stop

Status: **RESOLVED**, historical evidence only. The owner selected the
manager-owned observation capability in PR #81, broker main
`eef0f9f3388c3b35ce562f126540fc333370ec43`. Native store permissions stay
unchanged; M1 owns the server and B1 the client. The recovery-surface decision
also remains resolved by OPTION 2. Neither decision is reopened. The remaining
composition stop is [C0c current-check timing](lab-b1-observation-budget-stop.md).
The original access analysis below records why a privileged capability was
needed, not a current request to change native permissions or daemon identity.

## Conflicting requirements

- Lab profile section 2 assigns the daemon to the dedicated nonlogin
  `swarma-lab-broker` system user, not root.
- Section 3.2 requires current protected manager projection/journal evidence
  **and** actual launch receipt/debit and root-approved execution before
  `Caller` can succeed. It forbids using permissive fixture facts in the lab
  factory. The separate UID-0 control client does not change the daemon EUID.
- The pinned manager dependency is
  `v0.0.0-20261117085123-ebea7d32a89b` (broker `go.mod`). Its production
  `internal/launch/store_linux.go:39` opens with owner 0 and anchor `/`;
  lines 40–65 require the launch directory to remain exactly root-owned 0700.
  Its `Debits` reader (line 194) uses `manager.ReadProtected`; the protected
  ledger is owner-only 0600. `effects.lock` is also 0600 and shares the
  helper serialization boundary. Receipt files are 0644, but a receipt alone
  is expressly an attempted start, not a committed-start debit or liveness.
  `ProvisionStore` writes `effects.json`, `debits`, `invalidations` at 0600.
- A named-user/group read ACL for another UID requires a nonzero effective ACL
  mask reflected in group mode bits. Changing the launch directory to allow
  that traversal, or changing ledger group mode to permit reads, violates the
  native exact-mode contract. An ACL with zero effective mask grants no access.
  Keeping the manager correct and merely changing the B1 reader cannot bypass
  Linux DAC. The lab profile section 7 worker socket traversal ACL is unrelated.

No live protected state, real credential, privileged process or vendor endpoint
was accessed to establish this conflict. The manager source is the exact pinned
module copy retained under the task-owned isolated scratch.

## Executable witness and limits

`TestLabB1NativeLaunchAccessBoundary` is a source-overlay test in that native
manager package. Its valid control opens the real native fixture with a 0700
launch directory and reads its 0600 debit ledger. Its adjacent negatives change
only the directory to 0750 or the debit to 0640 and require the actual native
readers to refuse. Both changes are confined to disposable fixtures, with the
directory restored for the second valid control. This proves native reader
permission requirements, not a live installed ACL or a running broker denial.
The POSIX DAC consequence for a different nonroot UID is independent of those
fixtures. Test source, source overlay, full log and real exit are listed in the
requested handoff. No native manager source or acceptance rule is changed.

## Clean paths requiring an explicit decision

1. **Root-mediated native evidence reader:** publish a narrow lab-only reader
   boundary, with exact peer authentication, no material, current shared lock
   order, complete receipt/debit/invalidation joins, bounded per-use validity and
   final-publication revalidation. Preserve the dedicated material holder and
   native permissions. Specify which unit owns this privileged boundary and its
   B5 installation before implementation. An inherited read-FD variant likewise
   needs an explicit descriptor/provenance/replacement/revalidation contract;
   a directory FD alone does not bypass search permission checks.
2. **Manager-owned lab observation capability:** M1 publishes an authenticated,
   material-free current-execution observation under the native manager lock,
   readable by the dedicated broker without widening the protected store.
   This must report real native facts, not another broker-generated receipt.
3. **Revise the daemon privilege split:** an owner-approved design may choose a
   different process privilege arrangement, with corresponding threat model,
   installation and native tests. B1 will not silently run the material holder
   as root or grant it broad DAC capabilities.

Changing native 0700/0600 checks, reading only public receipt/projection data,
accepting a root JSON assertion as a committed debit, polling a stale copied
ledger, claiming a second mutex as the native lock, or accepting fixture
`OperatorAct=true` / arbitrary `time.Now` in an installed factory are not paths.

## Delivered construction versus remaining B1

The private recovery contract is signed separately. Tagged construction now
contains a strict C0 reader, disjoint protected-store domains, explicit fresh
committed enrollment bootstrap, the lossless one-record recovery adapter,
bounded narrowing reserve and the narrowly parameterized existing service
engine. Tests use only `ssh-placeholder` as new credential material. The tagged
engine constructor is an internal construction seam, not an installed lab
factory or a statement of native authority. Its synthetic test authority never
enters a daemon. No accepting lab daemon/factory, managed caller authority or
root-control bridge is installed or claimed. No partial construction is
advertised as A01/A02/A03/A05/A07/A08/A09 acceptance. Continue those paths only
after the exact native evidence access decision, without weakening any control.
