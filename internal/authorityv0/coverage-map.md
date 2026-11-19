# U02 acceptance and narrowing controls

Authority: construction C1, the I02/I03 seam sheet and implementation-plan
section 4 U02. C1 permits only inactive current equality. The brief supplies
no attack-surface-catalog table; that is a declared brief gap, not a waiver or
a claim that the full service View is implemented. The named rows below are
the U02 acceptance slice, not acceptance of other units.

Every negative has an unchanged valid real-filesystem control. In particular,
the authority helper exercises both pinned-use and current-identity callbacks
before changing a fact. No accepting filesystem, directory or lock stub is
used. Numeric fixture ownership is the unprivileged test user; paths and
expected fixture ownership are private test substitutions, not production
configuration options. The landed authority vector payload is unchanged.
The shared fixture preflight names unsafe temporary ancestry before a control
can run; both CI temp variables use the checked private root. Ownership-table
tests use distinct synthetic paths and root/broker IDs, not privileged host
provisioning. The separate composed recorder maps IDs only when delegating
to the real filesystem reader and real configuration gate; its exact trace
assertion remains in the synthetic identity domain.

| Acceptance row | Named executable witnesses | Killed narrowing plant | Bound |
| --- | --- | --- | --- |
| ACTIVATE-DRIFT: U02 authority bytes | `TestACTIVATEDriftCurrentBytes`, especially `/same-revision-bytes`; `TestIdenticalReplacementAndDefensivePins` | PL-AUTHORITY-CACHE | Exact current authority bytes and immutable startup pins; no activation-loader or connection-closing claim. |
| AUTHORITY-LOCUS | `TestAUTHORITYLOCUSEquality` | PL-AUTHORITY-LOCUS | Installation, broker, exact observer/account sets, selected legacy allowlists and installed socket/store joins; no precedence. |
| AUTH-ROLE: U02 local directory slice | `TestAUTHROLEDirectoryPins` | PL-DIRECTORY-PIN | Current protected UID/name/home, distinct roles and present broker primary/explicit group membership; no dedicated-human creation/history provenance. |
| VIEW/SINGLE-SEQ: U02 protected-facts slice | `TestVIEWProtectedFactsAndLockContinuity`; `TestVIEWFinalRecheckAndConcurrentReaders` | PL-FINAL-RECHECK | Protected sources and bounded final local rechecks, callback errors, cancellation and concurrent readers; no sequence, journal, publication or integrated View claim. |
| File protection | `TestProtectedFileAndAncestorProtection`; `TestProtectedAbsenceCancellationAndRecheck`; `TestDescriptorNameReplacement/leaf` | PL-PROTECTED-MODE | Real regular/single-link/owner/group/exact-mode/special-bit/size and descriptor/name checks, safe absence and no partial result. |
| Ancestor and installed-directory protection | `TestProtectedFileAndAncestorProtection/ancestor-mode`; `/ancestor-symlink`; `TestDescriptorNameReplacement/ancestor`; `TestVIEWProtectedFactsAndLockContinuity` | PL-ANCESTOR-MODE | Descriptor-relative no-symlink walk, safe owners/modes and root-config/data/store joins; deterministic replacement witnesses, not exhaustive scheduling proof. |
| Configuration-lock continuity | `TestConfigurationLockContinuity`; `TestDirectorySiblingDoesNotReplaceLock`; `TestVIEWProtectedFactsAndLockContinuity` | PL-LOCK-INODE | Existing zero-byte exact-policy inode, real shared nonblocking flock, contention, replacement, exact parent mode, deadline and final recheck. Sibling changes and identical authority replacement remain valid. |
| Identity-only independence | `TestIdentityOnlyIndependence` | PL-IDENTITY-USE-GATE | Current unmanaged identity survives startup/use-policy drift without activation, history, managed projection or UTC; malformed/unavailable current identity still refuses. |
| File/ancestor owner boundary | `TestDirectoryAncestorOwnerBoundary` | PL-ANCESTOR-OWNER | Same real directory and leaf policy, distinct ancestor UID; the test does not chown or change privileged host ancestors. |
| Protected source ownership table | `TestSourceOwnershipPolicies` | PL-AUTHORITY-OWNER, PL-LOCK-OWNER, PL-PASSWD-GROUP, PL-GROUP-GROUP, PL-CONFIGURATION-OWNER, PL-DATA-ANCESTOR, PL-STORE-ANCESTOR | Exact path/policy pairs with distinct root/broker UIDs/GIDs; group extends the spec 4.1 passwd rule by analogy. |
| Composed ownership-policy binding | `TestSourcePolicyCallSites/Load`; `/WithPinned`; `/WithIdentity` | PL-DATA-ROW-SWAP, PL-STORE-ROW-SWAP, PL-LOCK-CALL-POLICY, PL-AUTHORITY-CALL-POLICY, PL-CONFIGURATION-CALL-OWNER, PL-CONFIGURATION-CALL-ANCESTOR, PL-PASSWD-CALL-POLICY, PL-GROUP-CALL-POLICY | Exact ordered lock/directory/read calls and final rechecks; each source refusal yields no startup result or callback. Synthetic IDs are mapped only for real filesystem delegation, not asserted as privileged owner provisioning. |
| Fixture root under canonical umask | `TestTempDirUmask022`; `TestTempDirUsesGoTempRoot` | PL-FIXTURE-UMASK, PL-FIXTURE-TEMP-ROOT | Actual tree preflight, deterministic 0700 leaf and unchanged reader; widened leaf still refuses, without a skip. |
| Directory uniqueness | `TestDirectoryUniquenessWitnesses` | PL-PASSWD-UID-UNIQUENESS, PL-GROUP-GID-UNIQUENESS | Prepended pinned-UID alias and unrelated repeated GID isolate uniqueness instead of incidental name mismatch. |
| Root keys and non-root broker | `TestRootKeyUniquenessWitness`; `TestNonRootBrokerWitness` | PL-ROOT-KEY-UNIQUENESS, PL-BROKER-UID-ZERO, PL-BROKER-GID-ZERO | Duplicate roots refuse startup; UID zero and GID zero independently refuse identity. No key custody or enrollment claim. |
| Process identity binding | `TestBrokerProcessBinding/uid`; `/gid` | PL-BROKER-PROCESS-BINDING | Document/config/passwd/group agreement cannot replace captured process EUID/EGID; neither mismatch invokes the identity callback. |
| Inactive runtime-import boundary | `TestInactiveImportGraph`; `TestU02ImportBoundaryControls` | PL-RUNTIME-PROTECTEDIO, PL-RUNTIME-AUTHORITYV0 | Real runtime-import plants fail the toolchain guard; paired synthetic import plants refuse inherited and all four checked Linux architecture/cgo configurations. |

## Plants and intended failures

The patches are inert test data, never runtime flags or alternative readers.
Apply each independently to an unmodified isolated source copy. From that
copy, run `git apply --unidiff-zero --check <patch>`, then
`git apply --unidiff-zero <patch>` and the mapped test. All mapped tests
must first pass without their patch. A plant is killed only by its named
assertion with test exit 1, not by compilation/setup failure or a skip.
Private task evidence records the source hashes, both apply exits, test PID,
exact test command, complete log and actual exit. No surviving plant is
claimed as a kill.

| Mutant | Narrows the gate to | Named failing test | Intended assertion |
| --- | --- | --- | --- |
| `testdata/PL-AUTHORITY-CACHE.patch` | Revision equality instead of exact startup authority bytes | `TestACTIVATEDriftCurrentBytes/same-revision-bytes` | `changed exact authority bytes/pins admitted` |
| `testdata/PL-AUTHORITY-LOCUS.patch` | Root document without operational duplicate equality | `TestAUTHORITYLOCUSEquality/installation` | `mismatched configuration/authority leaked a result` |
| `testdata/PL-DIRECTORY-PIN.patch` | UID/name but not local home equality | `TestAUTHROLEDirectoryPins/home` | `wrong current directory pin admitted` |
| `testdata/PL-FINAL-RECHECK.patch` | Initial authority snapshot without final byte recheck | `TestVIEWFinalRecheckAndConcurrentReaders` | `final authority-byte recheck accepted drift` |
| `testdata/PL-IDENTITY-USE-GATE.patch` | Identity-only narrowing incorrectly gated on use policy | `TestIdentityOnlyIndependence` | `independent current identity refused` |
| `../protectedio/testdata/PL-PROTECTED-MODE.patch` | File metadata without exact permission bits | `TestProtectedFileAndAncestorProtection/mode` | `protection refusal must return no identity or bytes` |
| `../protectedio/testdata/PL-ANCESTOR-MODE.patch` | Ancestor type/owner without write/special-bit protection | `TestProtectedFileAndAncestorProtection/ancestor-mode` | `protection refusal must return no identity or bytes` |
| `../protectedio/testdata/PL-LOCK-INODE.patch` | Any presently valid lock inode | `TestConfigurationLockContinuity/replacement` | `wrong lock refusal` |
| `../protectedio/testdata/PL-ANCESTOR-OWNER.patch` | Safe mode/type without an ancestor-owner boundary | `TestDirectoryAncestorOwnerBoundary` | `ancestor owned by a third UID admitted` |
| `testdata/PL-AUTHORITY-OWNER.patch` | Broker-owned authority instead of root-owned authority | `TestSourceOwnershipPolicies/authority` | `source ownership policy differs from spec` |
| `testdata/PL-LOCK-OWNER.patch` | Broker-owned configuration lock | `TestSourceOwnershipPolicies/lock` | `source ownership policy differs from spec` |
| `testdata/PL-PASSWD-GROUP.patch` | Broker-group-readable passwd policy instead of root group | `TestSourceOwnershipPolicies/passwd` | `source ownership policy differs from spec` |
| `testdata/PL-GROUP-GROUP.patch` | Broker-group-readable group policy instead of root group | `TestSourceOwnershipPolicies/group` | `source ownership policy differs from spec` |
| `testdata/PL-CONFIGURATION-OWNER.patch` | Broker-owned configuration directory | `TestSourceOwnershipPolicies/configuration` | `directory ownership policy differs from spec` |
| `testdata/PL-DATA-ANCESTOR.patch` | Broker-owned ancestors above D | `TestSourceOwnershipPolicies/data` | `directory ownership policy differs from spec` |
| `testdata/PL-STORE-ANCESTOR.patch` | Root-only ancestors above S, excluding its valid broker-owned D | `TestSourceOwnershipPolicies/store` | `directory ownership policy differs from spec` |
| `testdata/PL-PASSWD-UID-UNIQUENESS.patch` | Name/home equality without UID uniqueness | `TestDirectoryUniquenessWitnesses/prepended-passwd-uid` | `ambiguous directory admitted` |
| `testdata/PL-GROUP-GID-UNIQUENESS.patch` | Group names without GID uniqueness | `TestDirectoryUniquenessWitnesses/unrelated-group-gid` | `ambiguous directory admitted` |
| `testdata/PL-ROOT-KEY-UNIQUENESS.patch` | Valid individual roots without root-key uniqueness | `TestRootKeyUniquenessWitness` | `duplicate root key admitted` |
| `testdata/PL-BROKER-UID-ZERO.patch` | Broker identity without the nonzero UID gate | `TestNonRootBrokerWitness/uid` | `root broker identity admitted` |
| `testdata/PL-BROKER-GID-ZERO.patch` | Broker identity without the nonzero GID gate | `TestNonRootBrokerWitness/gid` | `root broker identity admitted` |
| `testdata/PL-DATA-ROW-SWAP.patch` | Store row substituted at the data-directory call site | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-STORE-ROW-SWAP.patch` | Data row substituted at the store-directory call site | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-LOCK-CALL-POLICY.patch` | Broker ownership supplied at gate construction | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-AUTHORITY-CALL-POLICY.patch` | Broker ownership supplied at the authority read (DN-05 locus) | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-CONFIGURATION-CALL-OWNER.patch` | Broker ownership at the configuration-directory call | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-CONFIGURATION-CALL-ANCESTOR.patch` | Broker ancestry at the configuration-directory call | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-PASSWD-CALL-POLICY.patch` | Broker group at the passwd read call | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-GROUP-CALL-POLICY.patch` | Broker group at the group read call | `TestSourcePolicyCallSites/Load` | `composed source policy binding differs` |
| `testdata/PL-BROKER-PROCESS-BINDING.patch` | Document broker IDs substituted for process IDs | `TestBrokerProcessBinding/uid`; `/gid` | `differing from the process admitted` |
| `../testutil/protectedfixture/testdata/PL-FIXTURE-UMASK.patch` | Ambient umask instead of a deterministic fixture leaf | `TestTempDirUmask022` | `reader refused fixture root` |
| `../testutil/protectedfixture/testdata/PL-FIXTURE-TEMP-ROOT.patch` | TMPDIR instead of the actual fixture tree | `TestTempDirUsesGoTempRoot` | `unsafe ancestor` |
| `testdata/PL-RUNTIME-PROTECTEDIO.patch` | Runtime importer of the inactive protected reader | `TestInactiveImportGraph` | `inactive import boundary violated` |
| `testdata/PL-RUNTIME-AUTHORITYV0.patch` | Runtime importer of the inactive authority reader | `TestInactiveImportGraph` | `inactive import boundary violated` |

The identity-use mutant tests intentional asymmetry: imposing the use gate on
the identity-only leg is forbidden over-rejection. The inode mutant replaces
the lock with another empty 0640 file, not a wrongly chmodded substitute.
There are no source-mutant survivors in the recorded U02 run; this finite
plant set is not a completeness proof for every implementation defect.

## Inactivity and unresolved boundaries

`TestInactiveImportGraph` and the toolchain-graph implementation from the
earlier import-guard delivery are retained unchanged. This unit adds exactly
the `internal/protectedio/` and `internal/authorityv0/` consumer rows to its
exact table; no test-helper row is needed because helper production code
imports neither package. Test-only dependencies remain outside the guard.
The former U02 source-walk checker and its checker-specific tests are dropped,
not composed with or preferred over the landed guard. The retained guard's
forwarding, nested-package, ignored-file, symlink, test-variant, tagged and
release-configuration controls remain. `TestU02ImportBoundaryControls` now
uses that same guard to reject a runtime importer of each new package under
the inherited configuration and Linux amd64/arm64 with cgo disabled/enabled,
beside valid exact-consumer and test-only controls. The original
`TestImportBoundaryControls` remains. No other pending-unit grant is added.

Out of contract: activation/enabled startup and lifetime (U03), state and
revocation sequence/publication (later store/View units), exact operator-act
authentication and terminal qualification, installation/provisioning and
dedicated-human creation/history (O-03), C selection (O-21), and final
acceptor approval (O-19). These exclusions follow C1 and U02 section 4, not
test skips. `TestOtherContinuityStaysOpen` pairs production with an explicit
`STOP:O-21` refusal. All other open points remain open. No daemon import,
default change, production fixture selector, provisioning or live protected
file access is part of this delivery.
