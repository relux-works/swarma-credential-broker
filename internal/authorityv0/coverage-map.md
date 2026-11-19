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

## Plants and intended failures

The patches are inert test data, never runtime flags or alternative readers.
Apply each independently to an unmodified isolated source copy. From that
copy, run `git apply --unidiff-zero --check <patch>`, then
`git apply --unidiff-zero <patch>` and the mapped test. All eight mapped tests
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

The identity-use mutant tests intentional asymmetry: imposing the use gate on
the identity-only leg is forbidden over-rejection. The inode mutant replaces
the lock with another empty 0640 file, not a wrongly chmodded substitute.
There are no source-mutant survivors in the recorded U02 run; this finite
plant set is not a completeness proof for every implementation defect.

## Inactivity and unresolved boundaries

`TestInactiveImportGraph` retains its original name and now walks the production
source graph, including forwarding helpers and source under `testdata`.
The exact-package allowlist grants only I02/I03 dependencies. It refuses
undeclared nested packages, prefix aliases, reverse edges, direct/transitive
runtime reachability and directory/file symlink aliases. Paired bounded
instrument plants are in `TestU02ImportBoundaryControls`,
`TestU02TransitiveImportControls` and `TestU02SourceTreeAndSymlinkControls`;
the original `TestImportBoundaryControls` also remains. No grant for another
pending unit is added; its later landing must merge its own exact row.

Out of contract: activation/enabled startup and lifetime (U03), state and
revocation sequence/publication (later store/View units), exact operator-act
authentication and terminal qualification, installation/provisioning and
dedicated-human creation/history (O-03), C selection (O-21), and final
acceptor approval (O-19). These exclusions follow C1 and U02 section 4, not
test skips. `TestOtherContinuityStaysOpen` pairs production with an explicit
`STOP:O-21` refusal. All other open points remain open. No daemon import,
default change, production fixture selector, provisioning or live protected
file access is part of this delivery.
