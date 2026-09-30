#!/usr/bin/env bash
# Verify that a release is complete and consistent on the remote:
# every module tag for <version> (vX.Y.Z, brainpool/vX.Y.Z, ...) exists on
# $REMOTE (default origin) and all of them point at the SAME commit.
#
#   scripts/check-release-tags.sh vX.Y.Z [--on-branch REF]
#
# --on-branch REF  additionally require that commit to be reachable from REF
#                  (e.g. origin/main), as scripts/release.sh guarantees.
#
# Annotated tags are peeled to the commit they point at. Used by the release
# workflow (.github/workflows/release.yml); safe to run locally.
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
version=${1:-}; [ -n "$version" ] || { echo "usage: $0 <vX.Y.Z> [--on-branch REF]" >&2; exit 2; }
branch=
case "${2:-}" in
    "") ;;
    --on-branch) branch=${3:-}; [ -n "$branch" ] || exit 2 ;;
    *) exit 2 ;;
esac
[[ $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$ ]] \
    || die "'$version' is not semver vX.Y.Z[-suffix]"

cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/lib-modules.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib-modules.sh"
REMOTE=${REMOTE:-origin}

remote_refs=$(git ls-remote --tags "$REMOTE") || die "cannot list tags of remote $REMOTE"
# Commit a tag points at: the peeled entry (annotated tag) wins over the direct one.
tag_commit() {
    awk -v a="refs/tags/$1^{}" -v l="refs/tags/$1" \
        '$2==a {peeled=$1} $2==l {direct=$1} END {print (peeled!="" ? peeled : direct)}' <<<"$remote_refs"
}

rc=0 want= 
while read -r t; do
    c=$(tag_commit "$t")
    if [ -z "$c" ]; then
        echo "ERROR: tag $t is not published on $REMOTE" >&2; rc=1; continue
    fi
    echo "$t -> $c"
    if [ -z "$want" ]; then want=$c
    elif [ "$c" != "$want" ]; then
        echo "ERROR: tag $t points at $c, but $version points at $want" >&2; rc=1
    fi
done < <(release_tags "$version")

if [ "$rc" = 0 ] && [ -n "$branch" ]; then
    git merge-base --is-ancestor "$want" "$branch" \
        || { echo "ERROR: release commit $want is not on $branch" >&2; rc=1; }
fi
[ "$rc" = 0 ] && echo "release tags for $version OK (all at $want)"
exit "$rc"
