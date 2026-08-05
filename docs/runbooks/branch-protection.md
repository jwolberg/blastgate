---
title: Configure forge branch protection
last-verified: 2026-08-05
anchor: RB-branch-protection
---

The `.claude/hooks/block-main-merge.sh` hook stops *agents* from merging/pushing
to `main`. Forge-side **branch protection** is the complement: it stops a
*human* (or a stray force-push from the web UI) from bypassing review. Set it up
once per repo. ~2 minutes; costs nothing.

## [1] GitHub

Settings → Branches → add a ruleset / protection rule for `main`:

- [ ] Require a pull request before merging (≥ 1 approval)
- [ ] Require review from **Code Owners** (pairs with a `.github/CODEOWNERS`)
- [ ] Require status checks to pass — the CI `quality` job **and** the Blastgate
  `self-scan` job (so a reachable-path finding blocks merge)
- [ ] Require branches to be up to date before merging
- [ ] Block force pushes
- [ ] Restrict deletions

CLI — send a JSON **body** via `--input`, *not* `-F key.subkey=…` flags. The dotted
flags do **not** build the nested objects this endpoint needs; they fail with a 422
(`"required_pull_request_reviews", "required_status_checks" weren't supplied`). Note
`restrictions` must be JSON `null`, not an empty string.

```bash
gh api -X PUT repos/<owner>/<repo>/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "checks": [{ "context": "quality" }, { "context": "self-scan" }] },
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true
  },
  "enforce_admins": false,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Verify with `gh api repos/<owner>/<repo>/branches/main/protection`. Or run
[`scripts/require-checks.sh`](../../scripts/require-checks.sh) (`REVIEWS=0` while
solo), which applies exactly this for the current repo with both required checks.

### [1.1] `enforce_admins` and solo maintainers

`enforce_admins` decides whether the review / status-check / require-PR rules also
apply to repo **admins**:

- **Team repos → `true`.** Nobody, admins included, bypasses a reviewed green PR.
- **Solo maintainers → `false`.** With `true` *and* `required_approving_review_count ≥ 1`
  you can never merge your own PRs: GitHub forbids approving your own PR and gives
  admins no bypass, so every solo PR is stranded. Setting it `false` keeps the review
  requirement for *contributor* PRs (you review theirs) while letting you merge your
  own through GitHub's "merge without waiting for requirements" admin bypass.
  `allow_force_pushes` and `allow_deletions` stay enforced for everyone regardless of
  this flag.

## [2] GitLab

Settings → Repository → Protected branches (and Merge request approvals):

- [ ] Protect `main`: Allowed to merge = Maintainers; Allowed to push = No one
- [ ] Allowed to force push = off
- [ ] Require approvals ≥ 1 (Settings → Merge requests → Approvals)
- [ ] Pipelines must succeed (Settings → Merge requests → "Pipelines must succeed")

## [3] Why both layers

The hook is local + agent-scoped (it can be bypassed by running git in a
non-Claude terminal — by design, that's the human gate). Branch protection is
server-side and unconditional. Together: agents never merge; humans merge only
through a reviewed, green PR/MR.
