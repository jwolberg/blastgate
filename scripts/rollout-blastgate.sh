#!/usr/bin/env bash
#
# rollout-blastgate.sh — adopt Blastgate across your other repos by opening a PR
# in each that adds a one-line caller of the shared reusable workflow. Idempotent:
# skips the source repo and any repo that already has the workflow. Opens PRs only
# — it never merges. Requires the Blastgate Action to be published
# (`uses: jwolberg/blastgate@v0`). See docs/runbooks/rollout.md.
#
# Usage:
#   scripts/rollout-blastgate.sh <repo> [<repo> ...]   # owner/name or bare name
#   scripts/rollout-blastgate.sh --all                 # every non-archived repo you own
set -euo pipefail

OWNER="$(gh api user -q .login)"
BRANCH="add-blastgate-gate"
WF_PATH=".github/workflows/blastgate.yml"

CALLER="$(cat <<'YAML'
name: Blastgate
on: [pull_request]
jobs:
  blastgate:
    uses: jwolberg/blastgate/.github/workflows/blastgate-reusable.yml@v0
YAML
)"

if [ "${1:-}" = "--all" ]; then
  mapfile -t REPOS < <(gh repo list "$OWNER" --no-archived --source --limit 200 \
    --json nameWithOwner -q '.[].nameWithOwner')
else
  [ "$#" -gt 0 ] || { echo "usage: $0 --all | <repo> [<repo> ...]"; exit 1; }
  REPOS=("$@")
fi

for repo in "${REPOS[@]}"; do
  [[ "$repo" == */* ]] || repo="$OWNER/$repo"
  echo "==> $repo"
  if [ "$repo" = "$OWNER/blastgate" ]; then echo "    skip (source repo self-gates)"; continue; fi
  if gh api "repos/$repo/contents/$WF_PATH" >/dev/null 2>&1; then
    echo "    skip (already has $WF_PATH)"; continue
  fi
  default="$(gh api "repos/$repo" -q .default_branch)"
  sha="$(gh api "repos/$repo/git/ref/heads/$default" -q .object.sha)"
  gh api -X POST "repos/$repo/git/refs" -f ref="refs/heads/$BRANCH" -f sha="$sha" >/dev/null 2>&1 || true
  gh api -X PUT "repos/$repo/contents/$WF_PATH" \
    -f message="ci: add Blastgate supply-chain gate" \
    -f branch="$BRANCH" \
    -f content="$(printf '%s' "$CALLER" | base64 | tr -d '\n')" >/dev/null
  gh pr create --repo "$repo" --base "$default" --head "$BRANCH" \
    --title "ci: add Blastgate supply-chain gate" \
    --body "Adds the Blastgate reachability gate on PRs via the shared reusable workflow (jwolberg/blastgate). Fails a PR only on a demonstrable attacker->secret path." \
    >/dev/null && echo "    PR opened"
done

echo "==> Done. Review and merge each PR; run scripts/require-checks.sh in each repo to make it a required check."
