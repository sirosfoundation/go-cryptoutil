#!/usr/bin/env bash
# Tests for scripts/release.sh dry-run/push logic using a temp clone with a
# local bare "origin". Never touches the real remote. Go checks are skipped in
# the dry-run cases and run for real (on minimal modules) in the --push case.
set -uo pipefail
src=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fails=0
ok()   { echo "ok   - $1"; }
bad()  { echo "FAIL - $1"; fails=$((fails+1)); }
expect() { # name want_rc cmd...
    local name=$1 want=$2; shift 2
    out=$("$@" 2>&1); rc=$?
    if [ "$rc" = "$want" ]; then ok "$name"; else bad "$name (rc=$rc want=$want): $out"; fi
}

git init -q --bare -b main "$tmp/origin.git"
git clone -q "$tmp/origin.git" "$tmp/w" 2>/dev/null
cd "$tmp/w" || exit 1
git config user.email t@example.org; git config user.name t
mkdir -p scripts brainpool ecparams
cp "$src"/scripts/release.sh "$src"/scripts/check-nested-modules.sh "$src"/scripts/check-release-tags.sh "$src"/scripts/run-module-checks.sh "$src"/scripts/lib-modules.sh scripts/
R=github.com/sirosfoundation/go-cryptoutil
printf 'module %s\n\ngo 1.26\n' "$R" > go.mod
printf 'module %s/brainpool\n\ngo 1.26\n\nrequire %s v0.6.0\n' "$R" "$R" > brainpool/go.mod
printf 'module %s/ecparams\n\ngo 1.26\n\nrequire %s/brainpool v0.2.0\n' "$R" "$R" > ecparams/go.mod
git add -A; git commit -qm init; git push -q origin HEAD:main
git tag v0.6.0; git tag brainpool/v0.2.0; git tag ecparams/v0.1.0; git push -q origin --tags
export RELEASE_SKIP_GO_CHECKS=1 RELEASE_NO_DISPATCH=1
rel=scripts/release.sh

expect "dry run ok" 0 $rel v0.7.0
echo "$out" | grep -q 'ecparams/v0.7.0' && echo "$out" | grep -q 'brainpool/v0.7.0' \
    && [ -z "$(git tag -l v0.7.0)" ] && ok "dry run lists tags, creates none" || bad "dry run output: $out"
expect "not semver" 1 $rel 0.7.0
expect "prerelease rejected" 1 $rel v0.7.0-rc1
expect "v2 rejected (needs /v2 module path)" 1 $rel v2.0.0
expect "not greater than existing" 1 $rel v0.6.0
expect "older than nested tag" 1 $rel v0.1.5
expect "skip checks refused with --push" 1 $rel v0.7.0 --push

echo dirty > junk; git add junk
expect "dirty tree" 1 $rel v0.7.0
git reset -q; rm junk

git commit -q --allow-empty -m local
expect "ahead of origin/main" 1 $rel v0.7.0
git reset -q --hard origin/main

printf 'replace %s => ../\n' "$R" >> brainpool/go.mod
git commit -qam replace; git push -q origin HEAD:main
expect "replace directive rejected" 1 $rel v0.7.0
git revert --no-edit HEAD >/dev/null; git push -q origin HEAD:main

printf 'module %s/ecparams\n\ngo 1.26\n\nrequire %s/brainpool v0.9.0\n' "$R" "$R" > ecparams/go.mod
git commit -qam badreq; git push -q origin HEAD:main
expect "require of unpublished version rejected" 1 $rel v0.7.0
git revert --no-edit HEAD >/dev/null; git push -q origin HEAD:main

printf 'module %s/ecparams\n\ngo 1.26\n\nrequire %s/brainpool v0.3.0\n' "$R" "$R" > ecparams/go.mod
git tag brainpool/v0.3.0
git commit -qam localreq; git push -q origin HEAD:main
expect "require of local-only tag rejected" 1 $rel v0.7.0
git tag -d brainpool/v0.3.0 >/dev/null; git revert --no-edit HEAD >/dev/null; git push -q origin HEAD:main

git checkout -q -b other
expect "not on main" 1 $rel v0.7.0
git checkout -q main

# --push path (bypass the skip-checks refusal by running real go checks is too
# slow here, so exercise tagging via an empty-module repo where go passes).
unset RELEASE_SKIP_GO_CHECKS
mkdir -p brainpool ecparams
printf 'package x\n' > x.go; printf 'package x\n' > brainpool/x.go; printf 'package x\n' > ecparams/x.go
# remove nested requires that would need the network
printf 'module %s/brainpool\n\ngo 1.26\n' "$R" > brainpool/go.mod
printf 'module %s/ecparams\n\ngo 1.26\n' "$R" > ecparams/go.mod
git add -A; git commit -qm code; git push -q origin HEAD:main
expect "push release" 0 $rel v0.7.0 --push
want="v0.7.0 brainpool/v0.7.0 ecparams/v0.7.0"
got=$(git ls-remote --tags origin | grep -v '\^{}$' | sed -E 's|.*refs/tags/||' | grep -E '^(v|[a-z]+/v)0\.7\.0$' | sort | tr '\n' ' ')
[ "$got" = "$(echo $want | tr ' ' '\n' | sort | tr '\n' ' ')" ] && ok "tags pushed to fake remote" || bad "remote tags: $got"
c=$(git rev-parse 'v0.7.0^{commit}'); [ "$(git rev-parse 'ecparams/v0.7.0^{commit}')" = "$c" ] && ok "same commit" || bad "commit mismatch"
[ "$(git cat-file -t v0.7.0)" = tag ] && ok "annotated" || bad "not annotated"
expect "re-release rejected" 1 $rel v0.7.0

# --- scripts/check-release-tags.sh (what the release workflow runs) ----------
chk=scripts/check-release-tags.sh
expect "tags consistent" 0 $chk v0.7.0
expect "tags consistent and on origin/main" 0 $chk v0.7.0 --on-branch origin/main
expect "version with no tags" 1 $chk v0.8.0
expect "not semver" 1 $chk 0.7.0
expect "injection-shaped tag rejected" 1 $chk 'v0.7.0;echo'
git checkout -q -b side; git commit -q --allow-empty -m side; git push -q origin side
git tag -a v0.9.0 -m x; git tag -a brainpool/v0.9.0 -m x; git tag -a ecparams/v0.9.0 -m x; git tag -a pkcs11pool/v0.9.0 -m x
git push -q origin --tags
expect "tags complete but commit not on main" 1 $chk v0.9.0 --on-branch origin/main
git checkout -q main
git tag -a v0.9.1 -m x; git tag -a brainpool/v0.9.1 -m x   # ecparams/v0.9.1 deliberately missing
git push -q origin --tags
expect "missing nested tag rejected" 1 $chk v0.9.1
git commit -q --allow-empty -m next; git push -q origin HEAD:main
git tag -a v0.9.2 -m x; git tag -a brainpool/v0.9.2 -m x; git tag -a ecparams/v0.9.2 -m x
git tag -f brainpool/v0.9.2 -a -m y HEAD~1 >/dev/null 2>&1
git push -q origin --tags -f
expect "tags at different commits rejected" 1 $chk v0.9.2
git tag -a v0.10.0-rc1 -m x; git tag -a brainpool/v0.10.0-rc1 -m x; git tag -a ecparams/v0.10.0-rc1 -m x
git push -q origin --tags
expect "prerelease tag set accepted" 0 $chk v0.10.0-rc1
for bad_v in v0.8.0-. v0.8.0-a..b v0.8.0-01 v0.8.0- v01.0.0 v0.8.0+build; do
    expect "malformed version $bad_v rejected" 1 $chk "$bad_v"
done

[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
