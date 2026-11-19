# Inactive current authority equality (U02 / I03)

Construction stage C1 authorizes this Linux-only reader against the published
PROPOSED DN-05 amendments. It uses the landed `assemblyv0.AuthorityDocument`
and the concrete protected reader/gate; no accepting filesystem port stub,
daemon import, installation, default change or activation is added.

`New(policy.Config)` defensively copies the operational duplicate fields and
captures the running effective broker UID/GID. Production paths are fixed to
the specified authority/lock, `/etc/passwd`, `/etc/group`, D/store and socket
layout; no exported fixture or alternative-directory backend is provided.
Synthetic tests privately substitute file locations and expected fixture
ownership while retaining real descriptor, mode and `flock` checks.
All seven source policies come from one private table; distinct synthetic
root/broker IDs witness every owner, group, mode, size and ancestor policy.

`Load` joins current canonical, closed authority bytes to protected local
UID/name/home and primary-GID facts under the inode-pinned configuration gate.
Role UIDs are disjoint; the present broker GID has no other primary or explicit
member. This is bounded current equality, not O-03 creation/history proof.
Directory files deliberately refuse duplicate UIDs/GIDs/names anywhere, blank
lines and NIS rows; even an otherwise legitimate UID alias fails closed.
Root authority and broker-owned operational configuration must agree exactly
on installation, broker UID, the observer set and enabled account-label set;
selected legacy `allowed_uids` is empty and socket/store paths are fixed.
Neither source wins a mismatch. Account kind/harness/mode/owner and root-key
membership are checked as data, not signature, enrollment or custody evidence.

`StartupPins` binds exact current authority bytes to this reader. `WithPinned`
rereads and rejoins current facts; revision equality alone is insufficient.
Zero, foreign or caller-modified pins refuse. A same-byte protected atomic
authority replacement is valid; replacing the installer lock inode is not.
No last-known-good authority or directory cache substitutes for a failed read.
Final local rechecks detect file drift during the bounded callback; callers
remain responsible for the later shared state/publication boundary and for
honoring cancellation. U02 implements no revocation sequence or state journal.

`WithIdentity` reads current root/directory pins independently of startup pins,
activation, account-use equality, authority history, managed evidence and UTC.
It does not authenticate an operator act or receipt: those belong to later
units. Invalid or unavailable current identity sources still refuse. C remains
unselectable (`STOP:O-21`); O-01 activation, O-03 history and O-19 final acceptance
remain open. C1 is construction permission, not final acceptor approval.

## Tools and evidence

After sourcing the assigned private Go environment and setting an absolute
`GO`, the required mode-0700 temporary directories and `GOFLAGS=-p=2`:

| Tool | Exact entrypoint | Output |
| --- | --- | --- |
| Formatter | `gofmt -w internal/authorityv0/*.go` | Updated source; private log. |
| Acceptance tests | `go test -race ./internal/authorityv0` | ACTIVATE-DRIFT, AUTHORITY-LOCUS and bounded AUTH-ROLE/VIEW/identity-only witnesses with paired controls. |
| Import guard | `go test -race ./internal/assemblyv0 -run "Test.*Import\|TestU02SourceTree"` | Exact consumer, reverse, transitive, nested and symlink-alias controls. |
| Repository validation | `go vet ./...`; `go test -race ./...` | Standalone commands and actual exit codes in task scratch. |
| Cache narrowing plant | Apply `testdata/PL-AUTHORITY-CACHE.patch` independently in an isolated checkout using `git apply --unidiff-zero --check` and `git apply --unidiff-zero`; run `go test -race ./internal/authorityv0 -run "^TestACTIVATEDriftCurrentBytes/same-revision-bytes$"`. | Intended exact-byte assertion must fail; unchanged control must pass. |

Other plants and every named U02 row are listed in the
[acceptance and narrowing map](coverage-map.md). Original U01 vectors
are consumed without edits; the test fixture derives only the broker numeric
owner/group needed for unprivileged real filesystem checks. No fixture result
is dedicated-human provenance, native qualification or permission for live use.
`Load` can mint fresh pins on repeat calls; startup-only invocation belongs to
the later daemon-wiring unit, not this inactive reader.
