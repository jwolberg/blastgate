---
title: "Empirical scan — 25 of the top-100 GitHub repos"
anchor: EVAL-2026-08-06
date: 2026-08-06
tool: blastgate 0.1.0 (branch feat/0039-0040-graphcap-yarn-pnpm)
---

# Empirical scan — 25 of the top-100 GitHub repos (2026-08-06)

Ran the blastgate gate against a 25-repo sample of the most-starred GitHub repos to
(a) see how real-world CI/supply-chain posture scores, (b) validate the 0039 cap
fix and 0040 yarn/pnpm coverage on real inputs, and (c) measure finding precision.

## [1] Method

- **Sample:** 25 top-100-by-stars repos, purposively weighted toward repos with real
  CI (where the tool has signal); includes 5 non-JS/large repos (go, rust, kubernetes,
  tensorflow, ansible) for breadth. This is a **biased sample**, not a random draw — see
  [§6](#6-caveats--threats-to-validity).
- **Fetch:** blobless sparse clone (`--filter=blob:none --sparse`) of only the paths the
  tool reads (`.github/`, root lockfiles, `.gitlab-ci.yml`, `.circleci/`, `.mcp.json`,
  `.claude/`, `.cursor/`, `package.json`, `Gemfile.lock`, `setup.py`, `requirements.txt`).
- **Scan:** `blastgate <dir> --json`, **whole-repo mode (no `--base`)**. Verdict derived
  from the exit code + finding tiers: exit 1 + a `fail` finding → FAIL; exit 1 + none →
  UNKNOWN; exit 0 + a `warn` finding → WARN; else PASS.
- **Important scope note:** whole-repo mode evaluates *standing* posture (fork/injection
  jobs holding secrets, agent grants). The **dependency/supply-chain layer is diff-gated**
  — npm/yarn/pnpm/Ruby/Python findings only form against a `--base` (a simulated untrusted
  PR), so they do **not** appear here. Deps coverage is validated separately (unit + e2e +
  real-repo CLI smoke on 0040). This run exercises the CI, agent, and cross-provider layers.

## [2] Results at a glance

**8 FAIL · 1 WARN · 16 PASS** across 25 repos; **22 findings** total (20 `fail`-tier,
2 `warn`-tier). **0 UNKNOWN.**

| Verdict | Repo | Workflows | Lockfile | Findings | Class |
|---|---|--:|---|--:|---|
| 🔴 FAIL | electron/electron | 50 | yarn | 4 | untrusted-text → secret |
| 🔴 FAIL | facebook/react | 22 | yarn | 3 (+1 warn) | untrusted-text → secret; committed hook |
| 🔴 FAIL | sveltejs/svelte | 4 | pnpm | 3 | untrusted-text → secret |
| 🔴 FAIL | angular/angular | 13 | pnpm | 2 | untrusted-text → secret |
| 🔴 FAIL | facebook/react-native | 29 | yarn | 2 | untrusted-text → secret |
| 🔴 FAIL | nodejs/node | 42 | — | 2 | untrusted-text → secret |
| 🔴 FAIL | vitejs/vite | 12 | pnpm | 2 | untrusted-text → secret |
| 🔴 FAIL | vuejs/core | 9 | pnpm | 2 | untrusted-text → secret |
| 🟡 WARN | storybookjs/storybook | 17 | yarn | 1 | agent grant over baseline |
| 🟢 PASS | vercel/next.js | 37 | pnpm | 0 | — |
| 🟢 PASS | freeCodeCamp/freeCodeCamp | 21 | pnpm | 0 | — |
| 🟢 PASS | microsoft/vscode | 16 | npm | 0 | — |
| 🟢 PASS | tensorflow/tensorflow | 17 | — | 0 | — |
| 🟢 PASS | babel/babel | 13 | yarn | 0 | — |
| 🟢 PASS | denoland/deno | 11 | — | 0 | — |
| 🟢 PASS | webpack/webpack | 10 | yarn | 0 | — |
| 🟢 PASS | axios/axios | 8 | npm | 0 | — |
| 🟢 PASS | mrdoob/three.js | 6 | npm | 0 | — |
| 🟢 PASS | prettier/prettier | 16 | yarn | 0 | — |
| 🟢 PASS | rust-lang/rust | 4 | yarn | 0 | — |
| 🟢 PASS | tailwindlabs/tailwindcss | 4 | pnpm | 0 | — |
| 🟢 PASS | expressjs/express | 4 | — | 0 | — |
| 🟢 PASS | golang/go | 0 | — | 0 | — |
| 🟢 PASS | kubernetes/kubernetes | 0 | — | 0 | — |
| 🟢 PASS | ansible/ansible | 0 | — | 0 | — |

## [3] The FAIL class: untrusted event text → a secret-bearing job

All 8 FAILs are the **same shape** (`entryKind: untrusted-text-injection`, labels
`ASI01:2026` / `MCP10:2025`): a workflow triggered by an untrusted event
(`issue_comment`, `issues`, `pull_request_target`) reads attacker-authored text
(`comment.body`, `issue.body/title`, `pull_request.title/body`) inside a job that also
holds a secret or credential. This is the CI "pwn-request / injection" class.

A striking cluster: **vue, vite, and svelte all ship the same `ecosystem-ci-trigger.yml`
job** — an `issue_comment`-triggered dispatcher holding an `ECOSYSTEM_CI_GITHUB_APP_*`
credential. The pattern propagated across the ecosystem. Others: electron's issue-triage
App creds, react's Discord webhooks, react-native's autorebase bot token, node's
`GITHUB_TOKEN`/Slack webhook.

The **WARN** is orthogonal: `storybookjs/storybook`'s committed `.cursor/mcp.json` grants
a filesystem capability (`~/.wallaby/mcp/`) that exceeds the least-privilege baseline
(`MCP02:2025`) — an agent-config advisory, not a CI path.

## [4] Precision review — what these findings actually mean

Flagging is cheap; **being right is the product.** I hand-reviewed 5 of the flagged jobs
against the source. The finding *class* is correct, but current detection **over-flags**:

| Job | Verdict by tool | On review | Why |
|---|---|---|---|
| vite `ecosystem-ci-trigger#trigger` | FAIL | **False positive** | Guarded by an in-*script* `getCollaboratorPermissionLevel` check (throws for non-triage users) + a "PR pushed after comment" anti-TOCTOU check; the comment body is read via `env:` and string-split, never shell-interpolated. |
| node `label-flaky-test#label` | FAIL | **FP / low** | `if: github.event.label.name == 'flaky-test'` — a maintainer must apply the label (effectively actor-gated); body read via `env: BODY` (the GitHub-recommended safe pattern). |
| node `notify-on-review-wanted` | FAIL | **Low, partly real** | Label-gated (`review wanted`), but the untrusted title is written unquoted to `$GITHUB_OUTPUT` (`title=$TITLE_PR`) — a minor output-injection vector; payoff limited to a Slack notification. |
| electron `issue-opened#{add-to-issue-triage,set-labels}` | FAIL | **Worth review** | Triggered by *any* opened issue whose body contains `# Expected Behavior` — **not** actor-gated — and holds `ISSUE_TRIAGE_GH_APP_CREDS`. Body is handled via `env:` + markdown-AST parse (relatively safe), but the reachability from a fully untrusted trigger to an App credential is real and merits maintainer review. |

**Takeaway.** The tool reliably surfaces the right *class* (untrusted-text co-located with
a secret) but does not yet model two things that separate a true exploit from safe
automation:
1. **In-step / in-script actor guards** — `getCollaboratorPermissionLevel`-style checks and
   label-gating (`github.event.label.name`) that the `if:`-only guard detector (0017) misses.
2. **Safe handling vs. injection** — untrusted text passed via `env:` and parsed is very
   different from text interpolated directly into a `run:` block or `${{ }}` shell context.

At current precision this class is **"review-worthy," not "confirmed-exploitable."** That
gap is the actionable output of this run → filed as a precision ticket (see [§7](#7-follow-ups)).

## [5] 0039 & 0040 validation on real inputs

**0039 (cap → verdict on large repos): confirmed, with honest attribution.**
- **0 UNKNOWN across all 25**, including the largest: node (42 workflows), electron (50),
  next.js (37), tensorflow (17), vscode (16). Every big repo got a real verdict.
- **But 0039 is not what rescued these repos.** Direct measurement of the reachability cost
  today: electron `entries×sinks = 4×39 = 156`, node `2×22 = 44`, next.js `0×34 = 0`,
  freeCodeCamp `0×29 = 0` — all **far below** the old 200k pair cap. The entry-narrowing
  from 0041/0042 (already on `main`: fork-triggerable now requires an untrusted checkout;
  injection requires a specific shape) had already cut entry counts, so on current `main`
  these repos would evaluate *even under the old quadratic metric*.
- 0039's value is **structural / defense-in-depth**: it swaps the `O(entries×sinks)` per-pair
  search for an `O(entries×(nodes+edges))` per-entry BFS and recalibrates the guard to that
  real cost, so legitimate breadth can't trip the cap. Its user-visible proof is the
  **synthetic 230k-pair repro test** (which the old metric fails and the new one passes),
  not this sample. Net: the cap is not suppressing real top-100 repos today.

**0040 (yarn/pnpm coverage): high real-world relevance.**
- Lockfile distribution of the sample: **pnpm 7, yarn 8, npm 3, none/non-JS 7.**
- **15 of 25 (60%) use yarn or pnpm** — repos that got *zero* dependency-layer analysis
  before 0040 (svelte, angular, vite, vue, freeCodeCamp, tailwindcss, next.js; electron,
  react, react-native, storybook, babel, prettier, rust, webpack). Under a `--base` PR
  context these now feed the same `runs-in → job → secret` synthesis as npm.

## [6] Caveats / threats to validity

- **Purposive sample, not random** — weighted toward CI-heavy JS repos; the true top-100 has
  many docs/educational repos that would trivially PASS (no workflows). The 8/25 FAIL rate is
  **not** a top-100 base rate.
- **Whole-repo mode only** — the supply-chain/deps findings (the flagship cross-layer path)
  are diff-gated and absent here; this run is CI/agent posture, not a full picture.
- **Precision** — the FAIL findings are review-worthy candidates, not confirmed exploits (see
  [§4](#4-precision-review--what-these-findings-actually-mean)).
- **Point-in-time** — HEAD of each default branch on 2026-08-06; repos change.

## [7] Follow-ups

- **New ticket (precision):** teach the injection detector about in-step/in-script actor
  guards (`getCollaboratorPermissionLevel`, label-gating) and distinguish `env:`-safe
  handling from direct shell/`${{ }}` interpolation — to cut the false positives in [§4].
- Re-run with `--base` against a set of real merged PRs to exercise the deps/supply-chain
  layer (including the new yarn/pnpm path) on live diffs.

Raw per-repo JSON: `scratchpad/eval/out/*.json` (ephemeral); harness: `scratchpad/eval/run.sh`.
