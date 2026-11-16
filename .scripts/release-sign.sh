#!/usr/bin/env bash
# Operator-only: use the configured local signing key, never a CI secret.
set +x
set -euo pipefail
export LC_ALL=C
umask 077
fail() { printf 'release signing: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 || $# == 2 ]] || fail 'usage: release-sign.sh TAG [OWNER/REPO]'
tag=$1
repo=${2:-relux-works/swarma-credential-broker}
[[ $tag =~ ^v[0-9][0-9A-Za-z.+-]*$ ]] || fail invalid-tag
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail invalid-repository
root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$root"
signers="$root/.github/release/allowed_signers"
key=$(git config --get user.signingkey)
[[ -n $key ]] || fail missing-configured-key
snapshot() {
  gh release view "$tag" --repo "$repo" --json databaseId,isDraft,tagName \
    --jq '[.databaseId, .isDraft, .tagName] | @tsv'
}
initial=$(snapshot)
IFS=$'\t' read -r release_id draft release_tag <<< "$initial"
[[ $release_id =~ ^[0-9]+$ && $draft == true && $release_tag == "$tag" ]] || fail draft-required
mkdir -p "$root/.temp"
work=$(mktemp -d "$root/.temp/release-sign.XXXXXX")
printf 'Signing evidence: %s\n' "$work"
gh release download "$tag" --repo "$repo" --pattern SHA256SUMS --dir "$work"
ssh-keygen -Y sign -n file -f "$key" "$work/SHA256SUMS"
ssh-keygen -Y verify -f "$signers" -I release-maintainer -n file \
  -s "$work/SHA256SUMS.sig" < "$work/SHA256SUMS" || fail untrusted-signature
[[ $(snapshot) == "$initial" ]] || fail draft-changed
# No --clobber: an existing signature requires operator reconciliation.
gh release upload "$tag" "$work/SHA256SUMS.sig" --repo "$repo"
mkdir "$work/readback"
gh release download "$tag" --repo "$repo" --pattern SHA256SUMS \
  --pattern SHA256SUMS.sig --dir "$work/readback"
cmp "$work/SHA256SUMS" "$work/readback/SHA256SUMS"
cmp "$work/SHA256SUMS.sig" "$work/readback/SHA256SUMS.sig"
ssh-keygen -Y verify -f "$signers" -I release-maintainer -n file \
  -s "$work/readback/SHA256SUMS.sig" < "$work/readback/SHA256SUMS" || fail readback-signature
[[ $(snapshot) == "$initial" ]] || fail draft-changed
printf 'Verified uploaded SHA256SUMS.sig; release remains a draft.\n'
