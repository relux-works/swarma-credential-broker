#!/usr/bin/env bash
# Scratch-only controls. Real Git/SSH verification; GitHub is an explicit double.
set -euo pipefail
export LC_ALL=C
fail() { printf 'release controls: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 && $1 == /* ]] || fail absolute-fresh-scratch-directory-required
source_root=$(cd "$(dirname "$0")/.." && pwd -P)
mkdir "$1"
scratch=$(cd "$1" && pwd -P)
mkdir -p "$scratch"/{home,config,cache,tmp,go-build,go-mod,go-path,bin,work}
export HOME="$scratch/home" USERPROFILE="$scratch/home"
export XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache"
export TMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp"
export GOCACHE="$scratch/go-build" GOMODCACHE="$scratch/go-mod" GOPATH="$scratch/go-path"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
unset SSH_AUTH_SOCK GOTELEMETRYDIR GH_TOKEN GITHUB_TOKEN RELEASE_TAG_OBJECT RELEASE_COMMIT
ssh-keygen -q -t ed25519 -N '' -C '' -f "$scratch/key"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$scratch/other-key"
cd "$scratch/work"
git init -q -b main
git config user.name 'Release fixture'
git config user.email 'release-fixture@example.invalid'
git config gpg.format ssh
git config user.signingkey "$scratch/key"
git config commit.gpgsign true
git config tag.gpgsign true
mkdir -p .github/release .scripts
read -r kind public_key _ < "$scratch/key.pub"
printf 'release-maintainer namespaces="git,file" %s %s\n' "$kind" "$public_key" > .github/release/allowed_signers
cp "$source_root/.scripts/release-sign.sh" .scripts/
printf 'main fixture\n' > content
git add content .github .scripts
git commit -q -S -m 'Create isolated release fixture'
base=$(git rev-parse HEAD)
git update-ref refs/remotes/origin/main "$base"
git tag -s v1.0.0 -m 'Valid release control'
git tag --no-sign v1.0.1
git tag --no-sign -a v1.0.2 -m 'Unsigned annotated control'
git -c "user.signingkey=$scratch/other-key" tag -s v1.0.3 -m 'Untrusted signer control'
git tag -s v1.0.4 -m 'Original tag payload'
git cat-file tag refs/tags/v1.0.4 > "$scratch/original-tag"
sed 's/Original tag payload/Changed tag payload/' "$scratch/original-tag" > "$scratch/tampered-tag"
tampered=$(git hash-object -t tag -w "$scratch/tampered-tag")
git update-ref refs/tags/v1.0.4 "$tampered"
git update-ref refs/tags/v1.0.5 refs/tags/v1.0.0

expect_ok() {
  local name=$1
  shift
  if "$@" > "$scratch/$name.log" 2>&1; then
    printf 'PASS %s (exit 0)\n' "$name"
  else
    local status=$?
    cat "$scratch/$name.log" >&2
    fail "$name: unexpected exit $status"
  fi
}
expect_refusal() {
  local name=$1 reason=$2
  shift 2
  if "$@" > "$scratch/$name.log" 2>&1; then
    fail "$name: unexpected acceptance"
  else
    local status=$?
    [[ $status == 1 ]] || fail "$name: unexpected exit $status"
    grep -F -- "$reason" "$scratch/$name.log" > /dev/null || fail "$name: wrong refusal"
    printf 'PASS %s (expected refusal exit %s: %s)\n' "$name" "$status" "$reason"
  fi
}
admit="$source_root/.scripts/release-admit.sh"
verify="$source_root/.scripts/release-verify.sh"
signers="$scratch/work/.github/release/allowed_signers"

# Real signed objects prove accepted ancestry and each distinct admission refusal.
expect_ok signed_tag_on_main "$admit" v1.0.0
expect_refusal lightweight_tag annotated-tag-required "$admit" v1.0.1
expect_refusal unsigned_tag ssh-signature-required "$admit" v1.0.2
expect_refusal untrusted_tag untrusted-signature "$admit" v1.0.3
expect_refusal tampered_tag untrusted-signature "$admit" v1.0.4
expect_refusal renamed_tag tag-name-mismatch "$admit" v1.0.5
expect_refusal mismatched_event_object tag-object-mismatch env RELEASE_TAG_OBJECT="$base" "$admit" v1.0.0
expect_refusal mismatched_event_commit commit-mismatch env RELEASE_COMMIT=invalid "$admit" v1.0.0
git switch -q -c side
printf 'side fixture\n' >> content
git add content
git commit -q -S -m 'Isolated off-main fixture'
git tag -s v2.0.0 -m 'Signed off-main control'
expect_refusal signed_off_main commit-not-on-main "$admit" v2.0.0
expect_refusal wrong_checkout checkout-mismatch "$admit" v1.0.0
git switch -q main
printf 'advance main\n' >> content
git add content
git commit -q -S -m 'Advance isolated main'
git update-ref refs/remotes/origin/main HEAD
git switch -q --detach "$base"
expect_ok ancestor_tag_on_main "$admit" v1.0.0

# An inert asset exercises signature-before-hash and post-signing tamper refusal.
mkdir "$scratch/assets"
printf 'inert binary fixture\n' > "$scratch/assets/example_linux_amd64"
cd "$scratch/assets"
sha256sum example_linux_amd64 > SHA256SUMS
ssh-keygen -Y sign -n file -f "$scratch/key" SHA256SUMS > "$scratch/file-sign.log" 2>&1
cp SHA256SUMS "$scratch/original-sums"
cp SHA256SUMS.sig "$scratch/original-sig"
expect_ok signed_checksums "$verify" "$scratch/assets" "$signers"
printf 'tampered fixture\n' >> example_linux_amd64
expect_refusal changed_binary FAILED "$verify" "$scratch/assets" "$signers"
printf 'inert binary fixture\n' > example_linux_amd64
printf 'tampered manifest\n' >> SHA256SUMS
expect_refusal changed_manifest untrusted-signature "$verify" "$scratch/assets" "$signers"
cp "$scratch/original-sums" SHA256SUMS
rm SHA256SUMS.sig
ssh-keygen -Y sign -n file -f "$scratch/other-key" SHA256SUMS > "$scratch/other-sign.log" 2>&1
expect_refusal untrusted_checksum_signature untrusted-signature "$verify" "$scratch/assets" "$signers"
rm SHA256SUMS.sig
ssh-keygen -Y sign -n git -f "$scratch/key" SHA256SUMS > "$scratch/namespace-sign.log" 2>&1
expect_refusal wrong_signature_namespace untrusted-signature "$verify" "$scratch/assets" "$signers"
cp "$scratch/original-sig" SHA256SUMS.sig
mv example_linux_amd64 "$scratch/binary"
ln -s "$scratch/binary" example_linux_amd64
expect_refusal symlinked_binary missing-or-symlinked-binary "$verify" "$scratch/assets" "$signers"
rm example_linux_amd64
cp "$scratch/binary" example_linux_amd64

# Even a valid signature must not authorize path traversal or ambiguous entries.
printf '%064d  ../escape_linux_amd64\n' 0 > SHA256SUMS
rm SHA256SUMS.sig
ssh-keygen -Y sign -n file -f "$scratch/key" SHA256SUMS > "$scratch/path-sign.log" 2>&1
expect_refusal signed_path_entry invalid-checksum-entry "$verify" "$scratch/assets" "$signers"
cat "$scratch/original-sums" "$scratch/original-sums" > SHA256SUMS
rm SHA256SUMS.sig
ssh-keygen -Y sign -n file -f "$scratch/key" SHA256SUMS > "$scratch/duplicate-sign.log" 2>&1
expect_refusal signed_duplicate_entry duplicate-checksum-entry "$verify" "$scratch/assets" "$signers"
cp "$scratch/original-sums" SHA256SUMS
cp "$scratch/original-sig" SHA256SUMS.sig

# This GitHub double bounds CLI sequencing only; it is not hosted-release evidence.
cat > "$scratch/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_FIXTURE/calls"
[[ $1 == release ]]
case $2 in
  view)
    printf '42\t%s\tv1.0.0\n' "${GH_FIXTURE_DRAFT:-true}"
    ;;
  download)
    shift 3
    patterns=()
    while [[ $# -gt 0 ]]; do
      case $1 in
        --repo) shift 2 ;;
        --pattern) patterns+=("$2"); shift 2 ;;
        --dir) destination=$2; shift 2 ;;
        *) exit 70 ;;
      esac
    done
    for name in "${patterns[@]}"; do cp "$GH_FIXTURE/$name" "$destination/$name"; done
    ;;
  upload)
    [[ $# == 6 && $5 == --repo ]]
    if [[ -e $GH_FIXTURE/SHA256SUMS.sig ]]; then
      printf 'existing-asset\n' >&2
      exit 1
    fi
    cp "$4" "$GH_FIXTURE/SHA256SUMS.sig"
    ;;
  *) exit 70 ;;
esac
GH
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" GH_FIXTURE="$scratch/draft"
mkdir "$GH_FIXTURE"
cp "$scratch/original-sums" "$GH_FIXTURE/SHA256SUMS"
cd "$scratch/work"
expect_refusal published_release draft-required env GH_FIXTURE_DRAFT=false .scripts/release-sign.sh v1.0.0
[[ ! -e $GH_FIXTURE/SHA256SUMS.sig ]] || fail published-release-wrote-signature
[[ $(wc -l < "$GH_FIXTURE/calls") == 1 ]] || fail published-release-had-side-effects
expect_ok draft_local_signing .scripts/release-sign.sh v1.0.0
cp "$GH_FIXTURE/SHA256SUMS.sig" "$scratch/uploaded-signature"
expect_refusal existing_signature existing-asset .scripts/release-sign.sh v1.0.0
cmp "$scratch/uploaded-signature" "$GH_FIXTURE/SHA256SUMS.sig"
cp "$GH_FIXTURE/SHA256SUMS.sig" "$scratch/assets/SHA256SUMS.sig"
expect_ok draft_signature_consumer "$verify" "$scratch/assets" "$signers"
printf 'Release controls passed; scratch evidence retained at %s\n' "$scratch"
