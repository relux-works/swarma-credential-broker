# Linux releases

The [release workflow](../.github/workflows/release.yml) is a reusable Linux
template. A pushed `v*` tag creates a **draft** containing every `cmd/` main
package for `linux/amd64` and `linux/arm64`, plus `SHA256SUMS`. It neither signs
the checksums in CI nor publishes the draft. The release is an artifact delivery;
the broker's existing runtime qualification and activation gates still apply.

## Trust and admission

The design follows the Swarma installation book's
[Trust: signatures, manifest, notarization, package channels](https://github.com/relux-works/swarma-docs/blob/main/install-book/ru/04-doverie.md)
chapter: the component signs its own artifacts, and consumers independently pin
the component signer. This is the same component-signing boundary, not an
implementation of the installer's manifest, update roles or activation policy.
[Broker specification §9.6](../spec/broker.md#96-qualification)
retains its separate release qualification requirements.

The template reuses full-history checkout, signed annotated tag checks and
pre-publication tag rechecks from
[`swarma-identity/release.yml`](https://github.com/relux-works/swarma-identity/blob/main/.github/workflows/release.yml),
[`a2a-swarm/shared-release.yml`](https://github.com/relux-works/a2a-swarm/blob/main/.github/workflows/shared-release.yml)
and its
[`release-controls.yml`](https://github.com/relux-works/a2a-swarm/blob/main/.github/workflows/release-controls.yml).
The latter's real-object admission controls inform the scratch tests here.
Darwin signing/notarization, OIDC, CI custody and whole-release review machinery
are outside this Linux template's scope.

Admission uses [release-admit.sh](../.scripts/release-admit.sh). It requires:

- A name beginning with `v` and a digit, followed only by ASCII letters,
  digits, `.`, `+` or `-` (for example `v1.2.3` or `v1.2.3-rc.1`).
- An annotated tag directly targeting a commit, with the same internal tag name.
- That commit checked out at `HEAD` and an ancestor of `origin/main`. It need
  not be the latest main commit. Shallow history and grafts are refused, and
  replacement objects are ignored for the ancestry check.
- A valid SSH tag signature under the reviewed
  [allowed_signers](../.github/release/allowed_signers) file, with no ambient
  GPG trust fallback. The push event's tag object must match admission.

`allowed_signers` contains only a public Ed25519 key, without a machine comment,
under the generic principal `release-maintainer`. Its namespaces are `git` for
tags and `file` for checksum signatures. The initial public key comes from
`git config user.signingkey`; no private key is checked in. Key rotation requires
a reviewed change and an independent consumer pin update. Downloading an
allowlist alongside an untrusted release does not establish trust.

All actions use full commit SHA pins. Admission and build have `contents: read`;
only the draft job has `contents: write`. Checkout does not persist credentials.
No repository, organization or environment secrets, private keys, OIDC or
external signing service are used. Draft creation uses GitHub's automatic,
short-lived `github.token` through `GH_TOKEN`; GitHub requires authentication for
release writes. That token is not an operator signing key or a configured secret.
Immediately before creating the draft, the job checks the current remote tag
object and main snapshot again and repeats admission and checksum validation.
A moved tag/main snapshot or an existing release fails closed; reruns do not
overwrite assets. GitHub release creation is not atomic with tag/main movement;
the operator must recheck the intended tag and draft before publication.

## Reproducible build

The builder requires Go **1.26.10**, matching the repository's CI toolchain.
For both architectures it discovers every `main` package under `./cmd/...`,
then builds each with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
`-ldflags=-buildid=`, read-only module resolution and fixed architecture baselines
(`GOAMD64=v1`, `GOARM64=v8.0`). `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`,
empty `GOEXPERIMENT`, `LC_ALL=C` and `TZ=UTC` remove ambient build selections.
`SOURCE_DATE_EPOCH` is always the source commit's committer timestamp. Module
versions and hashes remain pinned by `go.mod` and `go.sum`.

Artifacts are flat files, for example
`swarma-credential-broker_linux_amd64` and
`swarma-demo-codex-executor_linux_arm64`. GNU `sha256sum` writes a sorted,
stable `SHA256SUMS` covering every binary (not itself). Duplicate command
basenames fail rather than overwriting an asset. Future commands requiring CGO
must explicitly revise this contract; the builder will fail rather than silently
change configuration.

For a local build or reproducibility check, use two isolated physical source
checkouts at the same exact commit and toolchain. Set **absolute** `HOME`,
`USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TMPDIR`, `TMP`, `TEMP`,
`GOCACHE`, `GOMODCACHE` and `GOPATH` inside each owned scratch root; unset
`GOTELEMETRYDIR`. Populate each checkout before running. From each source root:

```bash
GO=/absolute/path/to/go1.26.10/bin/go .scripts/release-build.sh /absolute/scratch/dist
```

The output directory must not exist. Compare the two resulting `SHA256SUMS`
files with `cmp`, and run `sha256sum --strict --check SHA256SUMS` inside each
output directory. Identical hashes demonstrate reproducibility for that source,
toolchain, configuration and pair of builds; they do not qualify runtime behavior.

## Operator signing and publication

From a trusted checkout on current main, create and push a signed tag through
the repository's normal authorized release process:

```bash
git tag -s v1.2.3 -m 'Release v1.2.3'
git verify-tag v1.2.3
git push origin refs/tags/v1.2.3
```

Wait for successful draft creation, inspect the intended commit and all assets,
and reconcile any existing/partial draft manually. The operator's GitHub CLI
must be authenticated with release-write access. Run:

```bash
.scripts/release-sign.sh v1.2.3
# Optional repository argument when copying the template:
.scripts/release-sign.sh v1.2.3 OWNER/REPO
```

The helper requires an existing draft, downloads only its `SHA256SUMS` into
`.temp/release-sign.*`, and uses the configured local key with:

```bash
ssh-keygen -Y sign -n file -f "$(git config user.signingkey)" /absolute/path/SHA256SUMS
```

This produces `SHA256SUMS.sig`. A configured public key path requires its matching
private key to be available to `ssh-keygen` locally or through the operator's SSH
agent. The helper verifies the signature against the checked-in allowlist before
upload, refuses to replace an existing signature, downloads both files again,
checks byte identity and verifies the readback signature. It rechecks the same
release ID, tag and draft state before upload and after readback. All local
evidence is retained; it never changes the release's draft state. Concurrent
external publication cannot be prevented by these CLI checks.

Download all binaries into a fresh local asset directory and run the consumer
verifier below. Once the operator accepts the release and verification evidence,
publication is an explicit operator step:

```bash
gh release edit v1.2.3 --repo relux-works/swarma-credential-broker --draft=false
```

## Consumer verification

Use Bash 4+, OpenSSH with `ssh-keygen -Y`, GNU coreutils and an independently
trusted copy of the verifier and signer file. Download all binary assets,
`SHA256SUMS` and `SHA256SUMS.sig` into a fresh directory. For a published release:

```bash
mkdir -p /absolute/downloads/v1.2.3
gh release download v1.2.3 --repo relux-works/swarma-credential-broker \
  --pattern '*_linux_amd64' --pattern '*_linux_arm64' \
  --pattern SHA256SUMS --pattern SHA256SUMS.sig --dir /absolute/downloads/v1.2.3
.scripts/release-verify.sh /absolute/downloads/v1.2.3 /trusted/allowed_signers
```

With no second argument, the verifier uses its own checkout's checked-in
allowlist. It first verifies the SSH signature in the `file` namespace for
`release-maintainer`, then rejects empty, duplicate or non-flat manifest names,
missing/symlinked artifacts and checksum mismatches. It verifies every listed
binary; unrelated extra files are not authenticated. It does not execute a binary
or establish release freshness, rollback protection or runtime qualification.
The manual signature check is:

```bash
ssh-keygen -Y verify -f /trusted/allowed_signers -I release-maintainer -n file \
  -s SHA256SUMS.sig < SHA256SUMS
sha256sum --strict --check SHA256SUMS
```

## Controls

```bash
actionlint .github/workflows/release.yml  # If installed; otherwise report missing.
for script in .scripts/release-*.sh; do bash -n "$script" || exit; done
.scripts/release-test.sh /absolute/fresh/scratch/release-controls
```

The scratch directory must not exist. The control script creates its own empty
home, configuration, caches, temporary directory, Git repository and ephemeral
Ed25519 keys; it disables ambient Git config and the SSH agent. Real signed
objects pair valid main/ancestor controls with lightweight, unsigned, untrusted,
tampered, renamed, off-main and event/checkout mismatch refusals. Real SSH
checksum signatures cover valid artifacts, changed binaries/manifests, an
untrusted key, wrong namespace, symlinks, signed traversal and duplicate entries.
The operator helper's draft-only sequence, upload/readback and no-overwrite
behavior use an explicit local GitHub CLI double, not a hosted service. Logs and
ephemeral fixture material stay under that scratch directory. No production key,
broker credential, daemon or release API is touched by these tests.

When copying this template, copy `.scripts/release-*.sh`, the workflow and docs;
replace the default repository in `release-sign.sh`, install that repository's
independently approved public signer, and pin its selected toolchain in both the
workflow and builder. Preserve the admission refusals and run the controls and
two-build checksum comparison before adopting it.
