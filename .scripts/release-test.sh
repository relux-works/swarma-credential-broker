#!/usr/bin/env bash
# Scratch controls use real Git, SSH and Go; GitHub is an explicit local double.
set -euo pipefail
export LC_ALL=C
fail() { printf 'release controls: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 && $1 == /* ]] || fail absolute-fresh-scratch-directory-required
source_root=$(cd "$(dirname "$0")/.." && pwd -P)
go_bin=$(command -v "${GO:-go}")
mkdir "$1"
scratch=$(cd "$1" && pwd -P)
mkdir -p "$scratch"/{home,config,cache,tmp,go-build,go-mod,go-path,bin,work}
export HOME="$scratch/home" USERPROFILE="$scratch/home"
export XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache"
export TMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp" GOTMPDIR="$scratch/tmp"
export GOCACHE="$scratch/go-build" GOMODCACHE="$scratch/go-mod" GOPATH="$scratch/go-path"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GO="$go_bin" GOTOOLCHAIN=local
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
mkdir -p .github/release .github/workflows .scripts cmd/example
read -r kind public_key _ < "$scratch/key.pub"
printf 'release-tag namespaces="git" %s %s\n' "$kind" "$public_key" > .github/release/allowed_signers
cp "$source_root"/.scripts/release-* .scripts/
cp "$source_root/.github/workflows/release.yml" .github/workflows/
cp "$source_root/.github/release/cgo-toolchain.json" .github/release/
printf 'example_linux_amd64\nexample_linux_arm64\n' > .github/release/expected-artifacts
printf 'module example.invalid/releasefixture\n\ngo 1.25\n' > go.mod
printf 'package main\nfunc main() { println("inert release fixture") }\n' > cmd/example/main.go
printf 'main fixture\n' > content
git add .
git commit -q -S -m 'Create isolated release fixture'
base=$(git rev-parse HEAD)
git tag -s v1.0.0 -m 'Valid release control'
git tag -s v1.0.6 refs/tags/v1.0.0 -m 'Nested tag control' 2> "$scratch/nested-tag-create.log"
git tag --no-sign v1.0.1
git tag --no-sign -a v1.0.2 -m 'Unsigned annotated control'
git -c "user.signingkey=$scratch/other-key" tag -s v1.0.3 -m 'Inconsistent signer control'
git tag -s v1.0.4 -m 'Original tag payload'
git cat-file tag refs/tags/v1.0.4 > "$scratch/original-tag"
sed 's/Original tag payload/Changed tag payload/' "$scratch/original-tag" > "$scratch/tampered-tag"
tampered=$(git hash-object -t tag -w "$scratch/tampered-tag")
git update-ref refs/tags/v1.0.4 "$tampered"
git update-ref refs/tags/v1.0.5 refs/tags/v1.0.0

# R1 witnesses: both malicious trees are main ancestors, but cannot select policy.
printf '#!/usr/bin/env bash\nexit 0\n' > .scripts/release-admit.sh
git add .scripts/release-admit.sh
git commit -q -S -m 'Fixture tag edits admission'
git tag -s v1.1.0 -m 'Admission replacement control'
git restore --source="$base" -- .scripts/release-admit.sh
read -r kind other_public _ < "$scratch/other-key.pub"
printf 'release-tag namespaces="git" %s %s\n' "$kind" "$other_public" > .github/release/allowed_signers
git add .scripts/release-admit.sh .github/release/allowed_signers
git commit -q -S -m 'Fixture tag edits signer policy'
git -c "user.signingkey=$scratch/other-key" tag -s v1.2.0 -m 'Allowlist replacement control'
git restore --source="$base" -- .github/release/allowed_signers
git add .github/release/allowed_signers
git commit -q -S -m 'Restore default-branch policy'
printf './cmd/example\n' > .github/release/cgo-packages
git add .github/release/cgo-packages
git commit -q -S -m 'Fixture tag edits cgo opt-in'
git tag -s v1.3.0 -m 'Cgo policy replacement control'
git rm -q .github/release/cgo-packages
git commit -q -S -m 'Restore empty cgo policy'
git update-ref refs/remotes/origin/main HEAD
main=$(git rev-parse HEAD)
git switch -q -c side
printf 'side fixture\n' >> content
git add content
git commit -q -S -m 'Isolated off-main fixture'
git tag -s v2.0.0 -m 'Signed off-main control'
git switch -q main
git clone --quiet --bare . "$scratch/origin.git"
git remote add origin "$scratch/origin.git"

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
admit="$scratch/work/.scripts/release-admit.sh"
verify="$scratch/work/.scripts/release-verify.sh"
sign="$scratch/work/.scripts/release-sign.sh"

# The hook exercises policy reads and the workflow's bundle transfer, not a real second UID.
expect_ok policy_head_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/work" rev-parse HEAD
expect_ok policy_admission_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$admit" v1.0.0
expect_git_refusal() {
  local name=$1 reason=$2
  shift 2
  if env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$@" > "$scratch/$name.log" 2>&1; then
    fail "$name: unexpected acceptance"
  else
    local status=$?
    [[ $status == 128 ]] || fail "$name: unexpected exit $status"
    grep -F -- "$reason" "$scratch/$name.log" > /dev/null || fail "$name: wrong refusal"
    printf 'PASS %s (expected Git refusal exit %s: %s)\n' "$name" "$status" "$reason"
  fi
}
expect_ownership_refusal() {
  local name=$1
  shift
  expect_git_refusal "$name" 'detected dubious ownership' "$@"
}
expect_ownership_refusal policy_head_trust_not_persisted \
  env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git rev-parse HEAD
# A planted scratch-home exception must be visible to that same ownership probe.
git config --file "$HOME/.gitconfig" --add safe.directory "$scratch/work"
expect_ok policy_head_persisted_trust_visible env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" \
  GIT_TEST_ASSUME_DIFFERENT_OWNER=1 git rev-parse HEAD
rm "$HOME/.gitconfig"
expect_ownership_refusal policy_head_persisted_control_removed \
  env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git rev-parse HEAD
expect_ownership_refusal policy_head_wrong_trust \
  git -c safe.directory="$scratch/other-source" rev-parse HEAD

# Execute the actual workflow transfer commands so a direct-clone regression is observable.
mkdir "$scratch/bundle-transfer"
python3 - "$source_root/.github/workflows/release.yml" > "$scratch/container-source-transfer.sh" <<'TRANSFER'
import pathlib
import sys
workflow = pathlib.Path(sys.argv[1]).read_text()
cgo = workflow.split("\n  cgo:\n", 1)[1].split("\n  draft:\n", 1)[0]
print("set -euo pipefail")
for line in cgo.splitlines():
    if " bundle create " in line or (" clone " in line and '"$work/source"' in line):
        print(line.strip())
TRANSFER
expect_ok policy_bundle_clone_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  policy_root="$scratch/work" work="$scratch/bundle-transfer" bash "$scratch/container-source-transfer.sh"
expect_ok policy_bundle_clone_head env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/bundle-transfer/source" -C "$scratch/bundle-transfer/source" rev-parse HEAD
expect_ok policy_bundle_clone_matches_policy cmp \
  "$scratch/policy_head_scoped_trust.log" "$scratch/policy_bundle_clone_head.log"
expect_ok policy_bundle_clone_release_commit env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/bundle-transfer/source" -C "$scratch/bundle-transfer/source" rev-parse 'refs/tags/v1.0.0^{commit}'
printf '%s\n' "$base" > "$scratch/expected-release-commit"
expect_ok policy_bundle_clone_preserves_release cmp \
  "$scratch/expected-release-commit" "$scratch/policy_bundle_clone_release_commit.log"
# Bundle's gentle setup reports unsafe repositories as unavailable, on both tested Git versions.
expect_git_refusal policy_bundle_without_trust 'Need a repository to create a bundle.' \
  git bundle create "$scratch/untrusted.bundle" --all
expect_git_refusal policy_bundle_wrong_trust 'Need a repository to create a bundle.' \
  git -c safe.directory="$scratch/other-source" bundle create "$scratch/wrong-trust.bundle" --all
[[ ! -e $scratch/untrusted.bundle && ! -e $scratch/wrong-trust.bundle ]] || fail refused-bundle-partial-output
expect_refusal policy_admission_rejects_changed_tree tagged-release-policy-differs \
  env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$admit" v1.3.0

# Real signed objects prove each distinct admission refusal beside a valid ancestor.
expect_ok ancestor_tag_on_main "$admit" v1.0.0
expect_refusal tag_owned_cgo_policy tagged-release-policy-differs "$admit" v1.3.0
expect_refusal lightweight_tag annotated-tag-required "$admit" v1.0.1
expect_refusal unsigned_tag ssh-signature-required "$admit" v1.0.2
expect_refusal untrusted_tag inconsistent-tag-signature "$admit" v1.0.3
expect_refusal tampered_tag inconsistent-tag-signature "$admit" v1.0.4
expect_refusal renamed_tag tag-name-mismatch "$admit" v1.0.5
expect_refusal nested_tag direct-commit-required "$admit" v1.0.6
expect_refusal mismatched_event_object tag-object-mismatch env RELEASE_TAG_OBJECT="$base" "$admit" v1.0.0
expect_refusal mismatched_event_commit commit-mismatch env RELEASE_COMMIT=invalid "$admit" v1.0.0
expect_refusal signed_off_main commit-not-on-main "$admit" v2.0.0
expect_refusal tagged_admission_edit tagged-release-policy-differs "$admit" v1.1.0
expect_refusal tagged_allowlist_edit tagged-release-policy-differs "$admit" v1.2.0
expect_ok signed_tag_on_main "$admit" v1.0.0
git switch -q --detach "$base"
expect_refusal wrong_checkout default-checkout-required "$admit" v1.0.0
git switch -q main
printf '\n# local policy drift\n' >> .scripts/release-admit.sh
expect_refusal dirty_policy dirty-release-policy "$admit" v1.0.0
git restore --source="$main" -- .scripts/release-admit.sh

# Real Go build of an inert fixture; every digest/metadata control uses its output.
git clone --quiet --no-local --no-checkout . "$scratch/build-source"
git -C "$scratch/build-source" checkout --quiet --detach "$base"
printf 'untracked source\n' > "$scratch/build-source/untracked.go"
expect_refusal dirty_build_source dirty-build-source .scripts/release-build.sh "$scratch/refused-dist" "$scratch/build-source"
[[ ! -e $scratch/refused-dist ]] || fail dirty-source-partial-output
rm "$scratch/build-source/untracked.go"
expect_ok fixture_build .scripts/release-build.sh "$scratch/assets" "$scratch/build-source"
fragment=$(sha256sum "$scratch/assets/release-set.json")
fragment=${fragment%% *}
expect_ok digest_control "$verify" "$scratch/assets" "$fragment"
printf 'changed\n' >> "$scratch/assets/example_linux_amd64"
expect_refusal changed_binary artifact-digest-mismatch "$verify" "$scratch/assets" "$fragment"
# Restore a single owned fixture artifact by rebuilding it, without replacing policy.
rm "$scratch/assets/example_linux_amd64"
# A separate directory also proves deterministic Go outputs and metadata.
git clone --quiet --no-local --no-checkout . "$scratch/second-source"
git -C "$scratch/second-source" checkout --quiet --detach "$base"
expect_ok fixture_second_build .scripts/release-build.sh "$scratch/second" "$scratch/second-source"
cp "$scratch/second/example_linux_amd64" "$scratch/assets/example_linux_amd64"
expect_ok fixture_reproducibility cmp "$scratch/assets/SHA256SUMS" "$scratch/second/SHA256SUMS"
expect_ok metadata_reproducibility cmp "$scratch/assets/release-set.json" "$scratch/second/release-set.json"
cp "$scratch/assets/SHA256SUMS" "$scratch/original-sums"
cp "$scratch/assets/release-set.json" "$scratch/original-fragment"
printf '%064d  ../escape_linux_amd64\n' 0 > "$scratch/assets/SHA256SUMS"
expect_refusal path_entry invalid-checksum-entry "$verify" "$scratch/assets" "$fragment"
cat "$scratch/original-sums" "$scratch/original-sums" > "$scratch/assets/SHA256SUMS"
expect_refusal duplicate_entry duplicate-checksum-entry "$verify" "$scratch/assets" "$fragment"
cp "$scratch/original-sums" "$scratch/assets/SHA256SUMS"
mv "$scratch/assets/example_linux_amd64" "$scratch/binary"
ln -s "$scratch/binary" "$scratch/assets/example_linux_amd64"
expect_refusal symlinked_binary missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
rm "$scratch/assets/example_linux_amd64"
cp "$scratch/binary" "$scratch/assets/example_linux_amd64"
printf ' ' >> "$scratch/assets/release-set.json"
expect_refusal changed_fragment fragment-digest-mismatch "$verify" "$scratch/assets" "$fragment"
noncanonical=$(sha256sum "$scratch/assets/release-set.json")
expect_refusal noncanonical_fragment release-set-mismatch-or-noncanonical "$verify" "$scratch/assets" "${noncanonical%% *}"
cp "$scratch/original-fragment" "$scratch/assets/release-set.json"
mv "$scratch/assets/provenance.json" "$scratch/provenance"
expect_refusal missing_provenance missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
mv "$scratch/provenance" "$scratch/assets/provenance.json"
mv "$scratch/assets/SHA256SUMS" "$scratch/sums"
ln -s "$scratch/sums" "$scratch/assets/SHA256SUMS"
expect_refusal symlinked_manifest missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
rm "$scratch/assets/SHA256SUMS"
mv "$scratch/sums" "$scratch/assets/SHA256SUMS"
expect_ok restored_digest_control "$verify" "$scratch/assets" "$fragment"

# This GitHub double bounds CLI sequencing, not hosted-release behavior.
cat > "$scratch/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_FIXTURE/calls"
[[ $1 == release ]]
case $2 in
  view)
    printf '42\t%s\t%s\t%s\t%s\n' "${GH_FIXTURE_DRAFT:-true}" "${GH_FIXTURE_PRERELEASE:-true}" "$3" "${GH_FIXTURE_LABEL:-true}"
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
    [[ $4 == */dist/SHA256SUMS.sig ]] || exit 70
    cp "$4" "$GH_FIXTURE/SHA256SUMS.sig"
    ;;
  *) exit 70 ;;
esac
GH
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" GH_FIXTURE="$scratch/draft"
mkdir "$GH_FIXTURE"
cp "$scratch/assets"/{SHA256SUMS,provenance.json,release-set.json} "$GH_FIXTURE/"
cd "$scratch/work"
# Rejection must occur before any signature/upload; nearby successful build signs.
expect_refusal operator_off_main commit-not-on-main "$sign" v2.0.0
[[ ! -e $GH_FIXTURE/calls && ! -e $GH_FIXTURE/SHA256SUMS.sig ]] || fail off-main-side-effects
expect_refusal published_release labelled-prerelease-draft-required env GH_FIXTURE_DRAFT=false "$sign" v1.0.0
expect_refusal non_prerelease labelled-prerelease-draft-required env GH_FIXTURE_PRERELEASE=false "$sign" v1.0.0
expect_refusal missing_label labelled-prerelease-draft-required env GH_FIXTURE_LABEL=false "$sign" v1.0.0
printf '%064d  example_linux_amd64\n' 0 > "$GH_FIXTURE/SHA256SUMS"
expect_refusal mismatched_draft rebuild-digest-mismatch "$sign" v1.0.0
[[ ! -e $GH_FIXTURE/SHA256SUMS.sig ]] || fail mismatch-uploaded-signature
[[ ! -e $(find .temp -path '*/dist/SHA256SUMS.sig' -print -quit) ]] || fail mismatch-created-signature
cp "$scratch/original-sums" "$GH_FIXTURE/SHA256SUMS"
expect_ok draft_local_signing "$sign" v1.0.0
cp "$GH_FIXTURE/SHA256SUMS.sig" "$scratch/uploaded-signature"
# Check the exact local file bytes with the fixture key, independently of the helper.
printf 'fixture namespaces="file" %s %s\n' "$kind" "$public_key" > "$scratch/fixture-file-signers"
expect_ok rebuilt_signature ssh-keygen -Y verify -f "$scratch/fixture-file-signers" \
  -I fixture -n file -s "$GH_FIXTURE/SHA256SUMS.sig" < "$scratch/original-sums"
expect_refusal existing_signature existing-asset "$sign" v1.0.0
expect_ok no_signature_overwrite cmp "$scratch/uploaded-signature" "$GH_FIXTURE/SHA256SUMS.sig"
expect_refusal cgo_controls_direct_invocation run-release-test-required bash "$source_root/.scripts/release-cgo-test.sh"
source "$source_root/.scripts/release-cgo-test.sh"
# Finite template assertions cover the reviewed workflow contract, not hosted execution.
workflow_policy() {
  python3 - "$source_root" "${1:-$source_root/.github/workflows/release.yml}" \
    "${2:-$source_root/.scripts/release-admit.sh}" <<'POLICY'
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
workflow = pathlib.Path(sys.argv[2]).read_text()
assert "  workflow_dispatch:" in workflow and not re.search(r"^  push:", workflow, re.M)
assert workflow.count("github.ref == 'refs/heads/main' && github.event.repository.default_branch == 'main'") == 3
assert workflow.count("          ref: main\n") == 3
assert "runner: ubuntu-24.04\n" in workflow and "runner: ubuntu-24.04-arm\n" in workflow
assert "image: ${{ needs.build.outputs.cgo_image }}" in workflow
assert "needs.build.outputs.cgo == 'false' && needs.cgo.result == 'skipped'" in workflow
assert "needs.cgo.result == 'success'" in workflow
cgo = workflow.split("\n  cgo:\n", 1)[1].split("\n  draft:\n", 1)[0]
assert not re.search(r"\bgit\b[^\n;]*\bconfig\b", workflow), "workflow-persistent-git-config-forbidden"
assert "GIT_CONFIG_" not in workflow, "workflow-config-env-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", cgo), "cgo-wildcard-trust-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", workflow), "workflow-wildcard-trust-forbidden"
assert 'git -c safe.directory="$policy_root" bundle create "$work/source.bundle" --all' in cgo, "cgo-bundle-scoped-trust-required"
assert 'git clone --quiet --no-checkout "$work/source.bundle" "$work/source"' in cgo, "cgo-bundle-clone-required"
assert 'git -c safe.directory="$policy_root" rev-parse HEAD' in cgo, "cgo-head-scoped-trust-required"
assert cgo.index("policy_root=$(pwd -P)") < cgo.index('safe.directory="$policy_root"'), "cgo-policy-root-required-before-git"
assert workflow.count("safe.directory") == cgo.count('safe.directory="$policy_root"') == 2, "workflow-unexpected-trust-forbidden"
admission = pathlib.Path(sys.argv[3]).read_text()
assert not re.search(r"\bgit\b[^\n;]*\bconfig\b", admission), "admission-persistent-git-config-forbidden"
assert "GIT_CONFIG_" not in admission, "admission-config-env-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", admission), "admission-wildcard-trust-forbidden"
assert 'command git -c safe.directory="$root" -c core.commitGraph=false "$@"' in admission, "admission-scoped-trust-required"
assert admission.count("safe.directory") == 1, "admission-unexpected-trust-forbidden"
draft = workflow.split("\n  draft:\n", 1)[1]
assert "      !cancelled() && github.ref" in draft and "always()" not in draft, "draft-must-respect-cancellation"
assert "python3 .scripts/release-profile.py collect" in workflow
assert "--draft --prerelease" in workflow
assert "agent-held key, proves nothing about origin" in workflow
assert "python3 .scripts/release-metadata.py check" in workflow
assert "persist-credentials: true" not in workflow
assert "secrets." not in workflow and "id-token:" not in workflow
assert "permissions: {}" in workflow and workflow.count("contents: write") == 1
assert all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in re.findall(r"uses: [^@]+@(\S+)", workflow))
signers = (root / ".github/release/allowed_signers").read_text()
assert 'namespaces="git"' in signers and 'namespaces="git,file"' not in signers
assert "allowed_signers" not in (root / ".scripts/release-verify.sh").read_text()
docs = (root / "docs/releasing.md").read_text()
readme = (root / "README.md").read_text()
assert "agent-held key, proves nothing about origin" in docs and "agent-held key, proves nothing about origin" in readme
assert "in person before any root" in docs
assert "not a trust root" in docs
assert "SOURCE_DATE_EPOCH" in docs and "provenance.json" in readme
print("Default-branch dispatch, pre-release label, action pins, permissions, docs and tag-only pin: OK")
POLICY
}
expect_ok workflow_default_branch_and_prerelease_policy workflow_policy
# Each persistent-write spelling must be rejected in both production surfaces.
for config_write in '--global --add' '--system --add' '--file "$HOME/.gitconfig" --add' '--add'; do
  case $config_write in
    --global*) write_scope=global ;;
    --system*) write_scope=system ;;
    --file*) write_scope=file ;;
    *) write_scope=add ;;
  esac
  sed "/safe.directory=\"\$policy_root\" rev-parse HEAD/a\\          git config $config_write safe.directory \"\$policy_root\"" \
    "$source_root/.github/workflows/release.yml" > "$scratch/persisted-$write_scope-cgo.yml"
  expect_refusal "workflow_persisted_${write_scope}_trust_rejected" workflow-persistent-git-config-forbidden \
    workflow_policy "$scratch/persisted-$write_scope-cgo.yml"
  sed "/^git() /a\\command git config $config_write safe.directory \"\$root\"" \
    "$source_root/.scripts/release-admit.sh" > "$scratch/persisted-$write_scope-admit.sh"
  expect_refusal "admission_persisted_${write_scope}_trust_rejected" admission-persistent-git-config-forbidden \
    workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/persisted-$write_scope-admit.sh"
done
# Adjacent mutations reject missing, widened and wrong-path bundle/HEAD trust.
sed 's/git -c safe.directory="$policy_root" bundle/git bundle/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/untrusted-cgo.yml"
expect_refusal workflow_untrusted_cgo_clone_rejected cgo-bundle-scoped-trust-required \
  workflow_policy "$scratch/untrusted-cgo.yml"
sed 's/safe.directory="$policy_root"/safe.directory="*"/g' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wildcard-cgo.yml"
expect_refusal workflow_wildcard_cgo_trust_rejected cgo-wildcard-trust-forbidden \
  workflow_policy "$scratch/wildcard-cgo.yml"
sed 's/safe.directory="$policy_root"/safe.directory="$work"/g' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wrong-path-cgo.yml"
expect_refusal workflow_wrong_path_cgo_trust_rejected cgo-bundle-scoped-trust-required \
  workflow_policy "$scratch/wrong-path-cgo.yml"
sed 's/git -c safe.directory="$policy_root" rev-parse/git rev-parse/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/untrusted-head-cgo.yml"
expect_refusal workflow_untrusted_cgo_head_rejected cgo-head-scoped-trust-required \
  workflow_policy "$scratch/untrusted-head-cgo.yml"
sed 's#git clone --quiet --no-checkout "$work/source.bundle"#git clone --quiet --no-checkout "$policy_root"#' \
  "$source_root/.github/workflows/release.yml" > "$scratch/direct-cgo-clone.yml"
expect_refusal workflow_direct_cgo_clone_rejected cgo-bundle-clone-required \
  workflow_policy "$scratch/direct-cgo-clone.yml"
# Environment config and other workflow jobs cannot widen the two scoped exceptions.
sed '/POLICY_COMMIT: /a\          GIT_CONFIG_COUNT: "1"\n          GIT_CONFIG_KEY_0: safe.directory\n          GIT_CONFIG_VALUE_0: "*"' \
  "$source_root/.github/workflows/release.yml" > "$scratch/env-wildcard-cgo.yml"
expect_refusal workflow_env_wildcard_trust_rejected workflow-config-env-forbidden \
  workflow_policy "$scratch/env-wildcard-cgo.yml"
sed 's/git clone --quiet --no-local/git -c safe.directory="*" clone --quiet --no-local/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wildcard-build.yml"
expect_refusal workflow_other_job_wildcard_rejected workflow-wildcard-trust-forbidden \
  workflow_policy "$scratch/wildcard-build.yml"
sed 's/safe.directory="$root"/safe.directory="*"/' \
  "$source_root/.scripts/release-admit.sh" > "$scratch/wildcard-admit.sh"
expect_refusal admission_wildcard_trust_rejected admission-wildcard-trust-forbidden \
  workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/wildcard-admit.sh"
sed 's/ -c safe.directory="$root"//' \
  "$source_root/.scripts/release-admit.sh" > "$scratch/untrusted-admit.sh"
expect_refusal admission_unscoped_trust_rejected admission-scoped-trust-required \
  workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/untrusted-admit.sh"
# The finite workflow checker must reject the formerly non-cancellable draft.
sed 's/!cancelled()/always()/' "$source_root/.github/workflows/release.yml" > "$scratch/uncancellable-draft.yml"
expect_refusal workflow_uncancellable_draft_rejected draft-must-respect-cancellation \
  workflow_policy "$scratch/uncancellable-draft.yml"
printf 'Release controls passed; scratch evidence retained at %s\n' "$scratch"
