#!/usr/bin/env bash
# Sourced by release-test.sh: reuse its isolated fixture and assertion helpers.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  printf 'release cgo controls: run-release-test-required\n' >&2
  exit 1
fi

# The empty profile must collect the identical pure-Go set, including provenance.
profile="$scratch/work/.scripts/release-profile.py"
expect_ok empty_profile_collection python3 "$profile" collect "$scratch/collected-pure" "$scratch/work" "$base" "$scratch/assets"
expect_ok empty_profile_unchanged cmp "$scratch/assets/SHA256SUMS" "$scratch/collected-pure/SHA256SUMS"

# Real cgo builds use the local native compiler, repinned only in this synthetic
# policy. This does not execute or qualify the production toolchain image.
git clone --quiet --no-local "$scratch/work" "$scratch/cgo-policy"
profile_root="$scratch/cgo-policy"
cd "$profile_root"
git config user.name 'Release fixture'
git config user.email 'release-fixture@example.invalid'
git config gpg.format ssh
git config user.signingkey "$scratch/key"
mkdir -p cmd/{cgoexample,unlisted,nonpolicy}
cat > cmd/cgoexample/main.go <<'CGO'
//go:build linux && cgo

package main

/* static int answer(void) { return 42; } */
import "C"

func main() {
	if C.answer() != 42 {
		panic("unexpected C result")
	}
}
CGO
cp cmd/cgoexample/main.go cmd/unlisted/main.go
printf '//go:build !cgo\n\npackage main\nfunc main() { println("pure control") }\n' > cmd/nonpolicy/main.go
printf '//go:build cgo\n\npackage main\nfunc main() { panic("cgo must not select this package") }\n' > cmd/nonpolicy/cgo.go
printf './cmd/cgoexample\n' > .github/release/cgo-packages
printf '%s\n' cgoexample_linux_{amd64,arm64} example_linux_{amd64,arm64} nonpolicy_linux_{amd64,arm64} \
  > .github/release/expected-artifacts
python3 - "$profile_root" <<'LOCAL_PIN'
import json, pathlib, subprocess, sys
path = pathlib.Path(sys.argv[1]) / ".github/release/cgo-toolchain.json"
pin = json.loads(path.read_text())
pin["compiler_version"] = subprocess.check_output(["gcc", "-dumpfullversion"], text=True).strip()
pin["libc_version"] = subprocess.check_output(["getconf", "GNU_LIBC_VERSION"], text=True).strip()
path.write_text(json.dumps(pin, sort_keys=True) + "\n")
LOCAL_PIN
git add .
git commit -q -S -m 'Add inert optional cgo profile fixture'
cgo_commit=$(git rev-parse HEAD)
native_arch=$("$go_bin" env GOHOSTARCH)
case $native_arch in amd64) other_arch=arm64 ;; arm64) other_arch=amd64 ;; *) fail unsupported-control-host ;; esac
profile="$profile_root/.scripts/release-profile.py"
cat > "$scratch/bin/go-observe" <<'OBSERVE'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == build ]]; then
  printf '%s\t%s\n' "${CGO_ENABLED:-unset}" "${!#}" >> "$GO_BUILD_LOG"
fi
"$GO_REAL" "$@"
if [[ $1 == build && ${CGO_MUTATE_SECOND:-0} == 1 && $PWD == */second/source ]]; then
  while [[ $# -gt 0 ]]; do
    if [[ $1 == -o ]]; then printf 'nondeterministic control\n' >> "$2"; break; fi
    shift
  done
fi
OBSERVE
chmod +x "$scratch/bin/go-observe"
export GO_REAL="$go_bin" GO_BUILD_LOG="$scratch/cgo-builds.log" GO="$scratch/bin/go-observe"

# Native-only selection and policy completeness fail before creating output.
expect_refusal cgo_without_native_inputs cgo-native-builds-required .scripts/release-build.sh "$scratch/cgo-refused" "$profile_root"
expect_refusal cross_cgo_runner native-cgo-runner-required python3 "$profile" build \
  "$scratch/cross-refused" "$profile_root" "$profile_root" "$other_arch"
[[ ! -e $scratch/cgo-refused && ! -e $scratch/cross-refused ]] || fail native-refusal-partial-output
cp .github/release/expected-artifacts "$scratch/cgo-expected"
printf 'example_linux_amd64\nexample_linux_arm64\n' > .github/release/expected-artifacts
expect_refusal cgo_missing_expected_artifact cgo-artifact-not-expected python3 "$profile" info "$profile_root"
cp "$scratch/cgo-expected" .github/release/expected-artifacts
cp .github/release/cgo-toolchain.json "$scratch/cgo-pin"
sed 's/"compiler_version": "[^"]*"/"compiler_version": "0.0.0"/' "$scratch/cgo-pin" > .github/release/cgo-toolchain.json
expect_refusal cgo_compiler_drift cgo-compiler-version-mismatch python3 "$profile" build \
  "$scratch/compiler-refused" "$profile_root" "$scratch/build-source" "$native_arch"
sed 's/"libc_version": "[^"]*"/"libc_version": "glibc 0.0"/' "$scratch/cgo-pin" > .github/release/cgo-toolchain.json
expect_refusal cgo_libc_drift cgo-libc-version-mismatch python3 "$profile" build \
  "$scratch/libc-refused" "$profile_root" "$scratch/build-source" "$native_arch"
cp "$scratch/cgo-pin" .github/release/cgo-toolchain.json

# An unlisted cgo-only main is never compiled; a dual-mode non-policy command
# executes its pure-Go branch, and the observer rejects any wider cgo build.
expect_ok cgo_profile_pure_build .scripts/release-build.sh "$scratch/cgo-pure" "$profile_root" pure
# Logical source paths must not bypass the exact policy-package exclusion.
ln -s "$profile_root" "$scratch/cgo-policy-link"
expect_ok cgo_policy_physical_source_path .scripts/release-build.sh "$scratch/cgo-pure-link" "$scratch/cgo-policy-link" pure
expect_ok cgo_policy_source_path_equivalence cmp "$scratch/cgo-pure/SHA256SUMS" "$scratch/cgo-pure-link/SHA256SUMS"
expect_ok nonpolicy_pure_control "$scratch/cgo-pure/nonpolicy_linux_$native_arch"
expect_ok cgo_native_two_independent_builds python3 "$profile" build \
  "$scratch/cgo-$native_arch" "$profile_root" "$profile_root" "$native_arch"
expect_ok cgo_fixture_executes "$scratch/cgo-$native_arch/cgoexample_linux_$native_arch"
build_id_control() {
  python3 - "$go_bin" "$scratch/cgo-$native_arch/cgoexample_linux_$native_arch" <<'BUILD_ID'
import subprocess, sys
assert not subprocess.check_output([sys.argv[1], "tool", "buildid", sys.argv[2]], text=True).strip()
assert "Build ID:" not in subprocess.check_output(["readelf", "--notes", sys.argv[2]], text=True)
BUILD_ID
}
# Inspect the actual native executable, not just the configured linker flags.
expect_ok cgo_empty_go_and_elf_build_ids build_id_control
selection_control() {
  python3 - "$GO_BUILD_LOG" "$scratch/cgo-pure" "$scratch/cgo-$native_arch" <<'SELECTION'
import pathlib, sys
rows = [line.split("\t") for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert [package for enabled, package in rows if enabled == "1"] == ["./cmd/cgoexample"] * 2
assert all("unlisted" not in package for enabled, package in rows)
assert all(enabled == "0" for enabled, package in rows if "nonpolicy" in package)
assert not list(pathlib.Path(sys.argv[2]).glob("cgoexample_*"))
assert not list(pathlib.Path(sys.argv[3]).glob("nonpolicy_*"))
SELECTION
}
expect_ok cgo_selection_no_implicit_opt_in selection_control

# A bounded second-build plant must trigger the reproducibility refusal, not a
# compiler/setup error; no publishable binary or receipt may survive it.
expect_refusal cgo_reproducibility_plant cgo-reproducibility-mismatch env CGO_MUTATE_SECOND=1 \
  python3 "$profile" build "$scratch/repro-refused" "$profile_root" "$profile_root" "$native_arch"
[[ ! -e $scratch/repro-refused ]] || fail reproducibility-partial-output

# Collector controls use real local output plus an explicitly synthetic peer
# receipt. They prove collection gates, not a peer-architecture native build.
python3 - "$scratch" "$native_arch" "$other_arch" <<'PEER'
import hashlib, json, pathlib, sys
root, native, other = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
peer = root / ("cgo-" + other)
peer.mkdir()
name = "cgoexample_linux_" + other
(peer / name).write_bytes(b"synthetic peer collector control\n")
receipt = json.loads((root / ("cgo-" + native) / ("cgo_linux_" + native + ".json")).read_bytes())
receipt["architecture"] = other
receipt["toolchain"]["target"] = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[other]
receipt["reproducibility"]["sha256"] = {name: hashlib.sha256((peer / name).read_bytes()).hexdigest()}
(peer / ("cgo_linux_" + other + ".json")).write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
PEER
expect_refusal cgo_missing_architecture native-cgo-artifacts-required python3 "$profile" collect \
  "$scratch/partial-refused" "$profile_root" "$cgo_commit" "$scratch/cgo-pure" "$scratch/cgo-$native_arch"
expect_ok cgo_collector_synthetic_peer_control python3 "$profile" collect "$scratch/cgo-collected" \
  "$profile_root" "$cgo_commit" "$scratch/cgo-pure" "$scratch/cgo-amd64" "$scratch/cgo-arm64"
provenance_control() {
  python3 - "$scratch/cgo-collected" "$scratch/cgo-pin" <<'PROVENANCE'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
pin = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
profiles = json.loads((root / "provenance.json").read_bytes())["cgo"]
assert [profile["architecture"] for profile in profiles] == ["amd64", "arm64"]
names = {entry["name"] for entry in json.loads((root / "release-set.json").read_bytes())["artifacts"]}
checksums = (root / "SHA256SUMS").read_text()
for profile in profiles:
    assert profile["toolchain"]["compiler_version"] == pin["compiler_version"]
    assert profile["toolchain"]["libc_version"] == pin["libc_version"]
    assert profile["toolchain"]["image"] == pin["image"]
    assert profile["environment"]["CGO_ENABLED"] == "1"
    assert profile["reproducibility"]["independent_builds"] == 2
    for name, digest in profile["reproducibility"]["sha256"].items():
        assert name in names and f"{digest}  {name}\n" in checksums
PROVENANCE
}
# Both selected architecture entries must reach checksums, fragment and provenance;
# the peer entry remains synthetic and cannot establish a native peer build.
expect_ok cgo_complete_metadata_control provenance_control
printf 'unexpected\n' > "$scratch/cgo-collected/extra_linux_amd64"
expect_refusal cgo_unexpected_artifact unexpected-artifact-set python3 "$profile" check "$scratch/cgo-collected" "$profile_root"
rm "$scratch/cgo-collected/extra_linux_amd64"
printf 'changed\n' >> "$scratch/cgo-$native_arch/cgoexample_linux_$native_arch"
expect_refusal cgo_changed_receipted_binary cgo-receipt-digest-mismatch python3 "$profile" collect \
  "$scratch/digest-refused" "$profile_root" "$cgo_commit" "$scratch/cgo-pure" "$scratch/cgo-amd64" "$scratch/cgo-arm64"

# Omitting opt-in cannot silently enable cgo or release an incomplete set.
: > .github/release/cgo-packages
git add .github/release/cgo-packages
git commit -q -S -m 'Omit cgo opt-in negative control'
expect_refusal cgo_omitted_policy_not_built unexpected-artifact-set .scripts/release-build.sh \
  "$scratch/omitted-cgo" "$profile_root"
[[ ! -e $scratch/omitted-cgo/cgoexample_linux_$native_arch ]] || fail omitted-cgo-was-built
export GO="$go_bin"
cd "$scratch/work"
