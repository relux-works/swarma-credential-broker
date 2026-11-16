#!/usr/bin/env bash
# The allowlist must come from an independently trusted checkout or signer pin.
set -euo pipefail
export LC_ALL=C
fail() { printf 'release verification: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 || $# == 2 ]] || fail 'usage: release-verify.sh ASSET_DIRECTORY [ALLOWED_SIGNERS]'
root=$(cd "$(dirname "$0")/.." && pwd -P)
signers=${2:-$root/.github/release/allowed_signers}
signers=$(cd "$(dirname "$signers")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$signers")")
cd "$1"
for asset in SHA256SUMS SHA256SUMS.sig; do
  [[ -f $asset && ! -L $asset ]] || fail missing-or-symlinked-manifest
done
ssh-keygen -Y verify -f "$signers" -I release-maintainer -n file \
  -s SHA256SUMS.sig < SHA256SUMS || fail untrusted-signature

# Accept only the release builder's flat Linux names, never paths or duplicates.
declare -A seen=()
count=0
while IFS= read -r line || [[ -n $line ]]; do
  [[ $line =~ ^[0-9a-f]{64}\ \ ([A-Za-z0-9][A-Za-z0-9._+-]*_linux_(amd64|arm64))$ ]] || fail invalid-checksum-entry
  name=${BASH_REMATCH[1]}
  [[ -z ${seen[$name]:-} ]] || fail duplicate-checksum-entry
  [[ -f $name && ! -L $name ]] || fail missing-or-symlinked-binary
  seen[$name]=1
  count=$((count + 1))
done < SHA256SUMS
[[ $count -gt 0 ]] || fail empty-manifest
sha256sum --strict --check SHA256SUMS
