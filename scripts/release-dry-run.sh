#!/usr/bin/env bash
#
# release-dry-run.sh — exercise the (never-run) `release-action` job end to end on
# a throwaway tag, WITHOUT publishing to npm or advancing the floating `v0` tag,
# then clean up after itself.
#
# Why it is safe:
#   * The tag is `v0.0.0-test`. It ends in `-test`, which the `publish-npm` job
#     skips via its `if:` guard — so nothing ever reaches npm.
#   * `-test` makes it a prerelease, so `release-action` marks the GitHub Release
#     `--prerelease` and does NOT move `v0`.
#   * It deletes the tag + release on exit (trap), so no lasting state remains.
#
# It verifies the three things that have never actually run in CI:
#   1. a GitHub Release was created,
#   2. the tag's tree contains the built `dist/action/index.js` (what `uses:` runs),
#   3. `v0` was left untouched, and `publish-npm` was skipped.
#
# Prereqs: `gh` authenticated with write access; a clean checkout on the branch
# you intend to release from. Run:  npm run release:dry
set -euo pipefail

TAG="v0.0.0-test"
MAJOR="v0"

echo "==> Preflight"
gh auth status >/dev/null 2>&1 || { echo "  ✗ gh is not authenticated (run: gh auth login)"; exit 1; }
if [ -n "$(git status --porcelain)" ]; then
  echo "  ✗ working tree is not clean — commit or stash first"; exit 1
fi
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
  echo "  ✗ $TAG already exists on origin — delete it first (gh release delete $TAG --cleanup-tag)"; exit 1
fi
SHA="$(git rev-parse HEAD)"
BEFORE_V0="$(git ls-remote --tags origin "$MAJOR" 2>/dev/null || true)"
echo "  ✓ clean tree on $SHA; $TAG is free"

echo "==> Pushing throwaway tag $TAG"
git tag "$TAG"
git push origin "refs/tags/$TAG"

# From here on, always clean up — even on failure or Ctrl-C.
cleanup() {
  echo "==> Cleaning up $TAG (release + tag, local + remote)"
  gh release delete "$TAG" --yes --cleanup-tag >/dev/null 2>&1 || true
  git push origin --delete "refs/tags/$TAG" >/dev/null 2>&1 || true
  git tag -d "$TAG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Waiting for the Release workflow to start"
RUN_ID=""
for _ in $(seq 1 30); do
  RUN_ID="$(gh run list --workflow=release.yml -L 15 --json databaseId,headSha,createdAt -q \
    'map(select(.headSha=="'"$SHA"'")) | sort_by(.createdAt) | last | .databaseId' 2>/dev/null || true)"
  [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] && break
  sleep 4
done
if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
  echo "  ✗ could not find the Release run for $SHA — check the Actions tab"; exit 1
fi
echo "  run id: $RUN_ID  (watching…)"
gh run watch "$RUN_ID" --exit-status || echo "  ! workflow reported failure — verifying anyway (see ✗ below)"

echo "==> Verifying outcome"
git fetch --force --tags origin >/dev/null 2>&1 || true
ok=1

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "  ✓ GitHub Release $TAG was created"
else
  echo "  ✗ no GitHub Release $TAG"; ok=0
fi

if git cat-file -e "$TAG:dist/action/index.js" 2>/dev/null; then
  echo "  ✓ dist/action/index.js is present in the $TAG tree (Action would resolve)"
else
  echo "  ✗ dist/action/index.js missing from the $TAG tree"; ok=0
fi

AFTER_V0="$(git ls-remote --tags origin "$MAJOR" 2>/dev/null || true)"
if [ "$BEFORE_V0" = "$AFTER_V0" ]; then
  echo "  ✓ $MAJOR untouched (prerelease correctly did not advance the major tag)"
else
  echo "  ✗ $MAJOR moved — the prerelease guard failed"; ok=0
fi

NPM_CONCLUSION="$(gh run view "$RUN_ID" --json jobs -q \
  '.jobs[] | select(.name|test("publish-npm")) | .conclusion' 2>/dev/null || true)"
if [ "$NPM_CONCLUSION" = "skipped" ]; then
  echo "  ✓ publish-npm was skipped (nothing hit npm)"
else
  echo "  ✗ publish-npm conclusion was '${NPM_CONCLUSION:-<none>}' — expected 'skipped'"; ok=0
fi

echo
if [ "$ok" -eq 1 ]; then
  echo "==> DRY RUN PASSED — release-action works end to end. Safe to cut the real v0.1.0."
else
  echo "==> DRY RUN FOUND ISSUES — resolve the ✗ items above before releasing."
  exit 1
fi
