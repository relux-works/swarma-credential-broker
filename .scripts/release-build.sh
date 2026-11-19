#!/usr/bin/env bash
# Build non-policy Linux cmd main packages with the pure-Go release configuration.
set -euo pipefail
export LC_ALL=C TZ=UTC GOTOOLCHAIN=local GOWORK=off GOENV=off
export CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=
export GOFLAGS='-mod=readonly -p=2'
fail() { printf 'release build: %s\n' "$1" >&2; exit 1; }
[[ ( $# == 1 || $# == 2 || ( $# == 3 && $3 == pure ) ) && $1 == /* ]] || fail absolute-new-output-directory-required
out=$1
go_bin=${GO:-go}
policy_root=$(cd "$(dirname "$0")/.." && pwd -P)
cgo_packages=$(python3 "$policy_root/.scripts/release-profile.py" packages "$policy_root")
[[ -z $cgo_packages || ${3:-} == pure ]] || fail cgo-native-builds-required
root=${2:-$(git rev-parse --show-toplevel)}
[[ $root == /* ]] || fail absolute-source-directory-required
cd "$root"
root=$(pwd -P)
[[ -z $(git status --porcelain --untracked-files=all) ]] || fail dirty-build-source
commit=$(git rev-parse HEAD)
[[ $("$go_bin" env GOVERSION) == go1.26.10 ]] || fail go1.26.10-required
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || fail invalid-source-epoch
mkdir "$out"
printf 'Go: %s; SOURCE_DATE_EPOCH=%s\n' "$("$go_bin" env GOVERSION)" "$SOURCE_DATE_EPOCH"
for arch in amd64 arm64; do
  export GOARCH=$arch
  packages=$("$go_bin" list -f '{{if eq .Name "main"}}{{.ImportPath}} {{.Dir}}{{end}}' ./cmd/...)
  [[ -n $packages ]] || fail no-command-packages
  while read -r package directory; do
    [[ -n $package ]] || continue
    relative="./${directory#"$root/"}"
    case $'\n'"$cgo_packages"$'\n' in *$'\n'"$relative"$'\n'*) continue ;; esac
    name=${package##*/}
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || fail invalid-command-name
    binary="$out/${name}_linux_$arch"
    [[ ! -e $binary ]] || fail duplicate-command-name
    "$go_bin" build -trimpath -buildvcs=false -ldflags=-buildid= -o "$binary" "$package"
  done <<< "$packages"
done
cd "$out"
python3 "$policy_root/.scripts/release-metadata.py" create "$out" "$commit" \
  "$("$go_bin" env GOVERSION)" "$SOURCE_DATE_EPOCH"
sha256sum --strict --check SHA256SUMS
python3 "$policy_root/.scripts/release-profile.py" pure-check "$out" "$policy_root"
