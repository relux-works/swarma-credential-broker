# Linux pre-releases (test profile)

The [workflow](../.github/workflows/release.yml) produces a **PRE-RELEASE draft**
with every `cmd/` main package for Linux amd64/arm64, `SHA256SUMS`,
`provenance.json` and the canonical `release-set.json` fragment. The optional
bot checksum signature is labelled exactly:

> agent-held key, proves nothing about origin

The bot key is available to agents. Neither that key, a tag signature, nor a
checksum signature establishes product origin or release authority. Installer v0
trusts **only the digest of the aggregate release-set manifest**, listing every
artifact digest. The owner approves that one digest **in person before any root
step** (OD-3 plan digest). Two independent reads of each release PR must compare
artifact digests with a second independent build before assembling that set.
The helper below supplies a rebuild comparison, not either review verdict or the
owner's approval. A dedicated release key outside agent sessions remains an
owner key-custody decision (OD-2).

## Book and specification boundary

The Swarma installation book's
[Trust: signatures, manifest, notarization, package channels](https://github.com/relux-works/swarma-docs/blob/main/install-book/ru/04-doverie.md)
chapter describes component signers and a manifest selecting artifact digests.
**Same:** artifact digests belong in the release-set manifest.
**Conflict resolved by the binding interim test-profile ruling:** the shared bot
key cannot supply the book's component trust root; use the owner's in-person
approval of the aggregate set digest until dedicated custody is decided. This
interim profile does not implement the book's future update-key roles.
[Broker specification §9.6](../spec/broker.md#96-qualification) still requires
separate runtime qualification; artifact delivery cannot activate the broker.

## Default-branch workflow and admission

GitHub loads a tag-push workflow from the tag itself. This template therefore
has **no tag-push trigger**. After pushing a tag, an authorized operator dispatches
`release.yml` **on main**, passing the tag as data. All jobs require the dispatch
ref and repository default branch to be `main`; all check out `main` with full
history. The native cgo and draft jobs require the identical policy commit used
by the pure-Go build. Native jobs are skipped when the cgo policy is empty.
If the repository renames its default branch, revise this contract first.

```bash
# After the release controls have landed on main:
git tag -s v1.2.3 -m 'Test pre-release v1.2.3'
git push origin refs/tags/v1.2.3
gh workflow run release.yml --ref main -f tag=v1.2.3
```

Configure a repository **v* tag ruleset** restricting creation, update and deletion
to the authorized release role. Check that setting when adopting this template;
the workflow cannot establish that external setting. Repository workflow/ruleset
administration remains an owner boundary. An independently modified workflow on
a malicious tag is not an execution authority for this main-dispatched flow.
GitHub writers can still create arbitrary release records; the independent build
and owner-approved aggregate digest remain necessary.

[release-admit.sh](../.scripts/release-admit.sh) resolves its policy root from its
own location, requires that checkout at `origin/main`, and refuses local changes
in `.scripts`, `.github/release` or `.github/workflows/release.yml`. It requires:

- An ASCII `v` plus digit tag name, then letters, digits, `.`, `+` or `-`.
- An annotated SSH-signed tag directly targeting a commit, with the internal
  tag name equal to the requested name; lightweight and unsigned tags fail.
- The commit to be an ancestor of `origin/main`. Shallow history and grafts fail;
  replacement objects are ignored. An ancestor can be released, so there is no
  rollback protection.
- The tagged tree's entire `.scripts`, `.github/release` and release workflow
  content/modes to equal the default branch. This intentionally refuses older
  tags whose release controls differ, including a changed admission script or
  allowlist. No script from the tagged tree is executed to admit or build it.
- The tag object and commit to match supplied bindings when present.
- SSH verification using **main's** [allowed_signers](../.github/release/allowed_signers),
  without ambient GPG fallback. This file is **only for TAG verification as a
  consistency check**, under principal `release-tag`, namespace `git`; it is
  **not a trust root**. It is never used to authenticate checksum files.

All actions use full SHA pins. Build has `contents: read`; only draft creation
has `contents: write`. Checkout does not persist credentials. No CI signing key,
OIDC or external signer is configured. Draft creation uses the automatic
`github.token`, not an operator key. Immediately before creation the job rechecks
remote main and tag objects, repeats main's admission and validates the artifact
set. Existing releases are refused; assets are never overwritten. GitHub cannot
atomically bind release creation to ref movement; operator rechecks and the
aggregate owner approval remain required.

## Reproducible build and metadata

[release-build.sh](../.scripts/release-build.sh) requires Go **1.26.10** and a clean
source checkout. Its optional second argument is an absolute source checkout;
the executable builder and metadata helper remain in the default-branch checkout.
Every non-policy `main` under `./cmd/...` is built for amd64 and arm64 with `CGO_ENABLED=0`,
`-mod=readonly -p=2 -trimpath -buildvcs=false -ldflags=-buildid=`, `GOAMD64=v1`,
`GOARM64=v8.0`, empty `GOEXPERIMENT`, `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOENV=off`, `LC_ALL=C` and `TZ=UTC`. Modules are pinned by `go.mod`/`go.sum`.
`SOURCE_DATE_EPOCH` is the tag commit's committer timestamp, recorded as an input;
Go does not use it to normalize binaries. Duplicate command basenames fail.

The main-owned [expected-artifacts](../.github/release/expected-artifacts) file
lists the exact binary basenames, sorted, one per line. No globs, comments,
duplicates or exclusions are accepted. Collection fails for missing or extra
files, symlinks, mismatched input commits or incomplete architecture inputs.
The intermediate pure-Go set is checked against that list minus the explicitly
selected cgo artifacts; only the complete collected set can become a draft.

`provenance.json` records the source commit, Go version, flags, environment and
`SOURCE_DATE_EPOCH`. It describes build inputs; it is not an origin attestation.
`SHA256SUMS` covers all binaries and provenance. `release-set.json` lists the
name and SHA-256 of each binary, provenance and `SHA256SUMS` for incorporation
into the installer's aggregate release-set manifest. The fragment cannot hash
itself; optional `SHA256SUMS.sig` is ancillary consistency evidence and is not an
installer input. JSON uses sorted object keys, sorted artifact names, ASCII,
compact separators and exactly one trailing newline. Example shape:

```json
{"artifacts":[{"name":"example_linux_amd64","sha256":"<64 lowercase hex>"}],"schema":"release-set-fragment/1"}
```

The fragment is an interchange fragment, not a claim that an installer schema
has been implemented here. The aggregate must preserve every included digest.

For local checks, use two independent physical source checkouts at the same
commit and toolchain. Resolve absolute scratch paths before launching Go; set
`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TMPDIR`, `TMP`, `TEMP`,
`GOCACHE`, `GOMODCACHE` and `GOPATH` inside each owned scratch root, and unset
`GOTELEMETRYDIR`. The workflow and operator helper do this automatically.
From a trusted default-branch checkout:

```bash
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-build.sh \
  /absolute/scratch/dist /absolute/scratch/source
cmp /absolute/first/dist/SHA256SUMS /absolute/second/dist/SHA256SUMS
cmp /absolute/first/dist/release-set.json /absolute/second/dist/release-set.json
```

The output directory must not exist. Matching hashes prove reproducibility for
that pair of builds, source and environment; they do not establish origin.

## Independent operator rebuild and optional bot signature

Use the trusted current-main checkout, not a downloaded script or the tag tree.
The operator's GitHub CLI needs release-write access. The helper fetches main
and the requested tag without forcing a moved tag, then runs main's admission.
It requires a draft marked pre-release and the exact bot-key label in its body.

```bash
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-sign.sh v1.2.3
# Optional repository argument when adopting the template:
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-sign.sh v1.2.3 OWNER/REPO
```

[release-sign.sh](../.scripts/release-sign.sh) copies the admitted tag to a fresh
source checkout and independently rebuilds under `.temp/release-sign.*`, with
fresh absolute home/config/cache/temp paths. It compares the local canonical
`SHA256SUMS`, provenance and fragment byte for byte with the pre-release. **Any
mismatch refuses before signature creation or upload.** This compares every
artifact digest with a second build, rather than signing arbitrary downloaded
checksums. It then rechecks admission, remote tag/main and draft state, signs
**the local rebuilt** `SHA256SUMS` using `git config user.signingkey`, uploads
without clobbering, and verifies byte-identical readback of the signature and
metadata. The signature is ancillary; the tag-only allowlist is not consulted
for checksum verification. The helper does not publish or approve a release.
Evidence is retained. Concurrent external publication cannot be prevented by
these CLI checks.

After both required release PR reads compare independent build digests, assemble
the aggregate release-set manifest and obtain the owner's in-person approval of
its digest before any root step. Publishing the pre-release is an explicit
operator action; retain the pre-release flag:

```bash
gh release edit v1.2.3 --repo relux-works/swarma-credential-broker \
  --draft=false --prerelease
```

## Artifact consistency check

Download the binaries and all metadata into a fresh directory. Use a separately
obtained expected **fragment** digest from the reviewed aggregate manifest:

```bash
.scripts/release-verify.sh /absolute/assets EXPECTED_FRAGMENT_SHA256
```

[release-verify.sh](../.scripts/release-verify.sh) and
[release-metadata.py](../.scripts/release-metadata.py) check the supplied fragment
digest, canonical fragment/list, each artifact digest, mandatory provenance and
binary entries. Traversal, duplicate entries and symlinked artifacts fail.
This establishes consistency with the supplied digest, not origin, freshness,
owner approval or runtime qualification. Fetching the expected digest from the
same release supplies no independent approval. The installer must verify the
owner-approved **aggregate** digest and its entire selected artifact set.

## Controls and adoption

```bash
actionlint .github/workflows/release.yml  # If installed; otherwise report missing.
for script in .scripts/release-*.sh; do bash -n "$script" || exit; done
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-test.sh /absolute/new/scratch
```

The scratch test owns its empty home/config/caches, Git repositories and ephemeral
keys, with ambient signing config and SSH agent disabled. Real Git/SSH objects
exercise main/ancestor admission and lightweight, unsigned, inconsistent,
tampered, renamed, off-main, binding and dirty-policy refusals. On-main ancestor
tags that replace admission or its allowlist must fail beside a valid tag.
Real Go builds exercise reproducibility, canonical metadata, changed artifacts,
traversal, duplicates and symlinks. A local GitHub CLI double exercises off-main,
mismatched-digest, missing-label and non-prerelease refusals, plus rebuild/sign,
readback and no-overwrite controls. This is not hosted workflow evidence.
No broker credential, daemon or live release API is touched by the tests.

When copying the template, include `.scripts/release-*` (including both Python 3
helpers and the sourced cgo controls), `.github/release/`, workflow and docs.
Replace the exact expected-artifact list for the adopting repository. Change the repository default in the signing
helper, install the public **tag consistency** pin, verify the v* tag ruleset,
land controls on main, and run scratch controls plus two independent full builds.
Preserve the interim owner-approved aggregate trust boundary. Dedicated key
custody and runtime qualification remain separate owner gates.

## Optional native cgo profile

The broker ships no cgo binary: [cgo-packages](../.github/release/cgo-packages) is
empty. An absent file has the same meaning. Its binary set, pure-Go build flags
and provenance format remain unchanged. Opt-in belongs to each adopting
repository on **main**, not to a tag or to a workflow input. These policy files
are already inside the admission scripts existing release-policy tree check.
This refines build-input handling only; the installation book chapter and
broker specification cited above retain their trust and qualification boundaries.

To opt in, list sorted, unique package paths, one per line, for example:

```text
./cmd/example-nss-probe
```

Paths must be main packages below `./cmd/`, with no traversal, whitespace or
wildcards. Add **both** `example-nss-probe_linux_amd64` and
`example-nss-probe_linux_arm64` to `expected-artifacts`; omission is a refusal,
not permission to exclude a protected executable. A cgo-only main absent from
the policy is never built. A non-policy main always uses `CGO_ENABLED=0`, even
if it has an alternative cgo implementation. Dependency cgo is enabled only
while building an explicitly selected main.

The workflow uses `ubuntu-24.04` for amd64 and `ubuntu-24.04-arm` for arm64.
Each native job runs in the multi-architecture GCC image pinned by digest in
[cgo-toolchain.json](../.github/release/cgo-toolchain.json). It pins GCC 14.2.0
and the image containing glibc 2.36; the digest also freezes compiler support
files, libc patch level and binutils. No runtime package installation, C cross
compiler or emulation is used. The helper refuses a non-native host or compiler
target and mismatched compiler/libc versions. Repinning is a reviewed main
policy change, never an ambient environment override. The image is the
[official GCC image](https://hub.docker.com/_/gcc); its pinned index includes
Linux amd64 and arm64 images.

The C policy fixes `CGO_CFLAGS`, `CGO_CPPFLAGS`, `CGO_CXXFLAGS`, `CGO_FFLAGS`
and `CGO_LDFLAGS`; ambient compiler selection, flag allowlists and include/library
search overrides are discarded. C compilation uses `-O2 -g0`; linking disables
the ELF build ID with `-Wl,--build-id=none`. Go still uses `-mod=readonly -p=2`,
`-trimpath`, `-buildvcs=false` and explicit
`-ldflags="-buildid= -linkmode=external -extldflags=-Wl,--build-id=none"`.

For each architecture, the helper clones the identical admitted commit into
**two independent source paths**, with separate absolute homes, caches, module
stores and temporary directories. Both builds must have identical SHA-256
digests before any output binary or receipt is exported. Private build evidence
remains under the supplied absolute `TMPDIR`. The receipt records compiler
version/banner, target, libc version, linker version, image digest, C and Go
flags, source commit, package list and both-build comparison. Collection checks
both native receipts and their artifact digests, embeds them in the `cgo` array
of `provenance.json`, and regenerates `SHA256SUMS` and canonical `release-set.json`
over the complete exact set. Receipts are build-input records, not signatures.

The receipt field `toolchain.image` is the **policy-declared** image reference,
not an observed container identity. The hosted job selects that same reference
as its container image. A local build outside that image does not attest to
having used it: the compiler version/banner, target, libc version and linker
banner are the observed toolchain facts.

For local independent reconstruction, keep tooling/policy in a reviewed main
checkout and build source in a separate clean checkout. Use the pinned image
on **each native architecture**, Go 1.26.10 and the isolated environment described
above. The internal entry points are:

```bash
# Pure subset; never publish this intermediate directory as the release.
GO=/absolute/path/to/go .scripts/release-build.sh /absolute/pure /absolute/source pure
# On the corresponding native host, in the pinned toolchain environment:
GO=/absolute/path/to/go python3 .scripts/release-profile.py build \
  /absolute/cgo-amd64 /absolute/main-policy /absolute/source amd64
GO=/absolute/path/to/go python3 .scripts/release-profile.py build \
  /absolute/cgo-arm64 /absolute/main-policy /absolute/source arm64
# After transferring both native outputs without modification:
python3 .scripts/release-profile.py collect /absolute/dist /absolute/main-policy \
  SOURCE_COMMIT /absolute/pure /absolute/cgo-amd64 /absolute/cgo-arm64
python3 .scripts/release-profile.py check /absolute/dist /absolute/main-policy
```

The existing optional `release-sign.sh` is pure-Go only: a nonempty cgo policy
makes its ordinary build refuse `cgo-native-builds-required`, before signing or
uploading anything. It must not sign an incomplete subset. Independent native
reconstruction and owner approval of the aggregate digest remain necessary;
this profile neither installs nor qualifies the later adopting consumer.

`release-test.sh` sources `release-cgo-test.sh`. Its real local fixture uses a
main package tagged `linux && cgo` with a `!cgo` fallback, two fresh builds and
an executable C result. Physical and symlinked source paths must both exclude
that dual-mode policy main from the pure subset. The fallback is removed only
for the later omitted-policy control, which exercises a cgo-only main.
The synthetic fixture policy explicitly pins the available local compiler/libc;
it does not claim to execute the production image. Controls check an omitted
policy, a dual-mode non-policy package, wrong architecture, toolchain drift,
compiler-target mismatch, an incomplete/extra artifact set, changed receipted
bytes and canonical receipts with mismatched commit, compiler version or C
flags. An ancestor commit cannot substitute for the pure set build input.
Each new input/target refusal must leave no output directory. A bounded plant
changes the second build and must fail specifically on reproducibility, leaving
no publishable output. The collector positive control uses real local output
and an explicitly synthetic peer receipt; it is not a native peer build claim.
Native arm64 execution and the pinned production image require their actual
runner environments, not that collector fixture or a local CI substitute.
