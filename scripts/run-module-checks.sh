#!/usr/bin/env bash
# vet, race-test and -mod=readonly build for every module, each on its own with
# GOWORK=off (the way a consumer resolves it). Used by release.sh and by the
# release workflow. Exits non-zero, naming the module, on the first failure.
set -euo pipefail
export GOWORK=off
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/lib-modules.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib-modules.sh"
while read -r m; do
    echo "== checking module $m"
    (cd "$m" && go vet -mod=readonly ./... && go test -race -mod=readonly ./... && go build -mod=readonly ./...) \
        || { echo "ERROR: module $m failed vet/test/build" >&2; exit 1; }
done < <(discover_modules)
