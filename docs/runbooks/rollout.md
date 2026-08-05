---
title: Roll Blastgate out across your repos
last-verified: 2026-08-05
anchor: RB-rollout
---

Adopt Blastgate in many repos with near-zero work each. Prerequisite: the Action
is **published** (`uses: jwolberg/blastgate@v0` resolves — see
[`release.md`](release.md)). Two paths; pick by whether you have a GitHub org.

## [1] Personal account — reusable workflow + a rollout PR per repo

The recipe lives once in this repo's
[`.github/workflows/blastgate-reusable.yml`](../../.github/workflows/blastgate-reusable.yml)
(a `workflow_call` job). Each consumer repo gets a one-line caller, so upgrades
happen in one place.

Consumer repo `.github/workflows/blastgate.yml`:

```yaml
name: Blastgate
on: [pull_request]
jobs:
  blastgate:
    uses: jwolberg/blastgate/.github/workflows/blastgate-reusable.yml@v0
```

Open that PR everywhere with one command (idempotent — skips repos that already
have it; opens PRs, never merges):

```bash
scripts/rollout-blastgate.sh repo-a repo-b        # specific repos
scripts/rollout-blastgate.sh --all                # every non-archived repo you own
```

Review and merge each PR, then make the check block merges (§3).

## [2] GitHub organization — one ruleset, zero per-repo files

If the repos live in an **org**, skip the per-repo files entirely. Org Settings →
**Rulesets** → New branch ruleset targeting `main` across selected repos:

- **Require workflows to pass before merging** → point at
  `jwolberg/blastgate/.github/workflows/blastgate-reusable.yml@v0`.

GitHub then injects and enforces the gate org-wide. This does §1 **and** §3 at
once for every repo. (Org-only; personal accounts use §1.)

## [3] Make it a required check (per repo)

A workflow that runs but doesn't block is advice. In each adopting repo, require
the check so a red scan stops the merge:

```bash
REVIEWS=0 scripts/require-checks.sh    # while solo; omit REVIEWS to require 1 approval
```

See [`branch-protection.md`](branch-protection.md) for the underlying policy and
the `enforce_admins` / solo-maintainer note. (The `require-checks.sh` in this repo
requires `quality` + `self-scan`; adapt the check contexts to each repo's jobs.)

## [4] Local + agent layer (once per machine)

Independent of CI: install the plugin globally so a commit/install that opens a
path is blocked before a PR even exists.

```
/plugin marketplace add jwolberg/blastgate
/plugin install blastgate@blastgate
```
