#!/usr/bin/env bash
#
# require-checks.sh — make the CI (`quality`) and Blastgate (`self-scan`) gates
# REQUIRED on `main`, so a red check blocks merge. A workflow that only reports is
# advice; this makes it a gate. Idempotent — re-run to update.
#
# `enforce_admins=false` so a solo maintainer can still admin-merge their own PRs
# (see docs/runbooks/branch-protection.md §1.1). Set REVIEWS=0 to drop the approval
# requirement while solo; REVIEWS=1 (default) keeps it for contributor PRs.
set -euo pipefail

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
REVIEWS="${REVIEWS:-1}"

echo "==> Requiring checks 'quality' + 'self-scan' on ${REPO}@main (reviews=${REVIEWS})"
gh api -X PUT "repos/${REPO}/branches/main/protection" --input - <<JSON
{
  "required_status_checks": {
    "strict": true,
    "checks": [{ "context": "quality" }, { "context": "self-scan" }]
  },
  "required_pull_request_reviews": { "required_approving_review_count": ${REVIEWS} },
  "enforce_admins": false,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo "==> Applied. Required checks now:"
gh api "repos/${REPO}/branches/main/protection" \
  -q '.required_status_checks.checks[].context' | sed 's/^/    - /'
