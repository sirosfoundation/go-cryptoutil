#!/usr/bin/env bash
# Release every module of go-cryptoutil under ONE common version.
#
#   scripts/release.sh v0.7.0            dry run: check everything, print tags
#   scripts/release.sh v0.7.0 --push     create annotated tags and push them
#
# Why prefixed tags: the Go toolchain locates a nested module (one with its own
# go.mod in a subdirectory) by the tag "<subdir>/vX.Y.Z". A plain "vX.Y.Z" tag
# versions only the root module. So a release of v0.7.0 is the tag set
#   v0.7.0, brainpool/v0.7.0, ecparams/v0.7.0, pkcs11pool/v0.7.0
# all on the same commit. The module list is discovered from go.mod files.
#
# This script never edits go.mod files. A nested module may keep requiring an
# older published root version: Go's minimal version selection picks the
# highest required version in the consumer's build, which is fine. Bump a
# nested require ONLY when that module's code needs a newer root API, and do
# it in a normal PR before releasing (tags must point at main, so the require
# must already name a published tag). A `replace` directive in a nested go.mod
# is an error: consumers ignore it (see scripts/check-nested-modules.sh).
#
# Environment:
#   REMOTE                        remote to compare with and push to (default origin)
#   RELEASE_SKIP_GO_CHECKS=1      skip vet/test/build (dry run only; for testing this script)
set -euo pipefail

usage() { echo "usage: $0 <vX.Y.Z> [--push]" >&2; exit 2; }
die() { echo "ERROR: $*" >&2; exit 1; }

version=${1:-}; [ -n "$version" ] || usage
push=0
case "${2:-}" in "") ;; --push) push=1 ;; *) usage ;; esac
[ $# -le 2 ] || usage
REMOTE=${REMOTE:-origin}
skip_go=${RELEASE_SKIP_GO_CHECKS:-0}

[[ $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "version '$version' is not plain semver vX.Y.Z"
# Go requires a /vN module path suffix for v2 and later; these modules have
# none, so only v0.x.y and v1.x.y tags can resolve.
[[ $version =~ ^v[01]\. ]] || die "major version ${version%%.*} needs a /vN module path suffix; only v0 and v1 are supported"
[ "$push" = 0 ] || [ "$skip_go" = 0 ] || die "RELEASE_SKIP_GO_CHECKS is not allowed with --push"

export GOWORK=off
cd "$(git rev-parse --show-toplevel)"

# --- git state ---------------------------------------------------------------
git fetch --quiet "$REMOTE" --tags
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on branch main"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$REMOTE/main")" ] \
    || die "HEAD is not equal to $REMOTE/main (pull or push first)"

# --- modules and tags --------------------------------------------------------
mapfile -t nested < <(find . -mindepth 2 -name go.mod -not -path './.git/*' -printf '%h\n' | sed 's|^\./||' | sort)
modules=(. "${nested[@]}")
tags=("$version")
for d in "${nested[@]}"; do tags+=("$d/$version"); done

# Strictly greater than every existing tag of every module (local + remote).
existing=$( { git tag --list; git ls-remote --tags "$REMOTE" | sed -E 's|.*refs/tags/||; s|\^\{\}$||'; } | sort -u)
for t in $existing; do
    v=${t##*/}
    [[ $v =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [ "$v" != "$version" ] || die "tag $t already exists; $version is not new"
    [ "$(printf '%s\n%s\n' "$v" "$version" | sort -V | tail -n1)" = "$version" ] \
        || die "$version is not greater than existing tag $t"
done

# --- module checks -----------------------------------------------------------
scripts/check-nested-modules.sh --check-tags

if [ "$skip_go" = 1 ]; then
    echo "WARNING: skipping vet/test/build (RELEASE_SKIP_GO_CHECKS=1)" >&2
else
    for m in "${modules[@]}"; do
        echo "== checking module $m"
        (cd "$m" && go vet -mod=readonly ./... && go test -race -mod=readonly ./... && go build -mod=readonly ./...) \
            || die "module $m failed vet/test/build"
    done
fi

# The checks must not have modified the tree we are about to tag.
[ -z "$(git status --porcelain)" ] || die "module checks modified the working tree"

# --- tag and push ------------------------------------------------------------
commit=$(git rev-parse HEAD)
echo "Release $version at $(git rev-parse --short HEAD) would create tags:"
printf '  %s\n' "${tags[@]}"
if [ "$push" = 0 ]; then
    echo "Dry run only. Re-run with --push to create and push these tags."
    exit 0
fi

created=()
for t in "${tags[@]}"; do
    if git tag -a "$t" -m "go-cryptoutil $version" "$commit"; then
        created+=("$t")
    else
        [ ${#created[@]} -eq 0 ] || git tag -d "${created[@]}" >/dev/null
        die "could not create tag $t; rolled back"
    fi
done
git push --atomic "$REMOTE" "${tags[@]/#/refs/tags/}" \
    || { git tag -d "${created[@]}" >/dev/null; die "push failed; local tags removed"; }
echo "Released $version: ${tags[*]}"
