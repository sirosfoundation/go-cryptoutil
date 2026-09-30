#!/usr/bin/env bash
# Consistency checks for the nested Go modules of go-cryptoutil.
#
# Fails (exit 1) when a nested go.mod
#   * contains a `replace` directive. A replace is honoured only in the main
#     module of a build, so it works locally but is silently ignored for
#     consumers, who then resolve a different (published) version than the one
#     that was tested.
#   * with --check-tags: requires a sibling/root module at a version that has
#     no matching tag on the remote $REMOTE (default origin) (so `go build -mod=readonly` would fail for consumers).
#
# Usage: scripts/check-nested-modules.sh [--check-tags]
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ROOT_PATH=github.com/sirosfoundation/go-cryptoutil
check_tags=0
[ "${1:-}" = "--check-tags" ] && check_tags=1

rc=0
REMOTE=${REMOTE:-origin}
remote_tags=
if [ "$check_tags" = 1 ]; then
    remote_tags=$(git ls-remote --tags "$REMOTE" | awk '{print $2}' | sed 's/\^{}$//') \
        || { echo "ERROR: cannot list tags of remote $REMOTE" >&2; exit 1; }
fi
mapfile -t mods < <(find . -mindepth 2 -name go.mod -not -path './.git/*' -printf '%h\n' | sed 's|^\./||' | sort)

for dir in "${mods[@]}"; do
    gomod="$dir/go.mod"
    if grep -nE '^[[:space:]]*replace([[:space:]]|\()' "$gomod" >/dev/null; then
        echo "ERROR: $gomod contains a replace directive; consumers ignore it:" >&2
        grep -nE '^[[:space:]]*replace([[:space:]]|\()' "$gomod" | sed 's/^/    /' >&2
        rc=1
    fi
    if [ "$check_tags" = 1 ]; then
        while read -r path ver; do
            [ -n "$path" ] || continue
            sub=${path#"$ROOT_PATH"}; sub=${sub#/}
            tag="${sub:+$sub/}$ver"
            # Check the remote, not the local tag namespace: a tag that only
            # exists in this clone is not published and consumers cannot resolve it.
            if ! grep -qxF "refs/tags/$tag" <<<"$remote_tags"; then
                echo "ERROR: $gomod requires $path $ver but tag $tag is not published on $REMOTE" >&2
                rc=1
            fi
        done < <(sed -nE "s|^[[:space:]]*(require[[:space:]]+)?(${ROOT_PATH}(/[^[:space:]]*)?)[[:space:]]+(v[^[:space:]]+).*|\2 \4|p" "$gomod")
    fi
done

[ "$rc" = 0 ] && echo "nested module checks OK (${#mods[@]} nested modules)"
exit "$rc"
