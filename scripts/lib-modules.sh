# shellcheck shell=bash
# Shared helpers, sourced by release.sh, check-release-tags.sh and
# run-module-checks.sh. Not executable on its own.
# Must be sourced from inside the repository (uses the git toplevel).

# Prints the directory of every Go module, root first ("."), nested ones sorted
# and relative to the repository root. Discovered from go.mod files so a new
# nested module is picked up without editing any script.
discover_modules() {
    local top; top=$(git rev-parse --show-toplevel) || return 1
    echo .
    (cd "$top" && find . -mindepth 2 -name go.mod -not -path './.git/*' -printf '%h\n' | sed 's|^\./||' | sort)
}

# Prints the release tag of every module for a version: "vX.Y.Z" for the root
# and "<dir>/vX.Y.Z" for each nested module.
release_tags() {
    local version=$1 d
    echo "$version"
    discover_modules | while read -r d; do [ "$d" = . ] || echo "$d/$version"; done
}
