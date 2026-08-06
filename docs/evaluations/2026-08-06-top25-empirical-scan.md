---
title: "Empirical scan — 50 of the top-100 GitHub repos (two batches of 25)"
anchor: EVAL-2026-08-06
date: 2026-08-06
tool: blastgate 0.1.0 (branch feat/0039-0040-graphcap-yarn-pnpm)
---

# Empirical scan — 50 of the top-100 GitHub repos (2026-08-06)

Ran the blastgate gate against **50** of the most-starred GitHub repos (two batches of
25, no overlap) to (a) see how real CI/supply-chain posture scores, (b) validate the
0039 cap fix and 0040 yarn/pnpm coverage on real inputs, and (c) measure finding precision.

## [1] Method

- **Sample:** 50 top-100-by-stars repos, purposively weighted toward repos with real CI
  (where the tool has signal); includes non-JS/large repos (go, rust, k8s, tensorflow,
  ansible, pytorch, spring-boot, laravel, godot, elasticsearch, terraform, rails, neovim)
  for breadth, plus 2 educational repos. **Biased sample, not a random draw** — see [§6](#6-caveats).
- **Fetch:** blobless sparse clone (`--filter=blob:none --sparse`) of only the paths the
  tool reads (`.github/`, root lockfiles, `.gitlab-ci.yml`, `.circleci/`, `.mcp.json`,
  `.claude/`, `.cursor/`, `package.json`, `Gemfile.lock`, `setup.py`, `requirements.txt`).
- **Scan:** `blastgate <dir> --json`, **whole-repo mode (no `--base`)**. Verdict derived
  from exit code + finding tiers: exit 1 + a `fail` finding → FAIL; exit 1 + none → UNKNOWN;
  exit 0 + a `warn` finding → WARN; else PASS.
- **Scope note:** whole-repo mode evaluates *standing* posture (fork/injection jobs holding
  secrets, agent grants). The **dependency/supply-chain layer is diff-gated** — npm/yarn/pnpm/
  Ruby/Python findings only form against a `--base` (a simulated untrusted PR), so they do
  **not** appear in the whole-repo tables. A dedicated `--base` deps pass over real
  dependency-change commits is in [§5.1](#51-deps-layer---base-pass-on-real-dependency-change-commits);
  this whole-repo run exercises the CI, agent, and cross-provider layers.

## [2] Results at a glance

**Combined (50 repos): 18 FAIL · 2 WARN · 30 PASS · 0 UNKNOWN.**
50 findings total (46 `fail`-tier, 4 `warn`-tier).
Per batch: batch 1 = 8 FAIL / 1 WARN / 16 PASS; batch 2 = 10 FAIL / 1 WARN / 14 PASS.

**Finding subclasses (of the 46 fail-tier):**

| Subclass | Count | Confidence |
|---|--:|---|
| `workflow_run` artifact-injection (0042 — real shell-splice sink) | 4 | **High** (see [§4](#4-precision)) |
| untrusted event text co-located with a secret (co-presence) | 42 | Review-worthy; material FP rate |

The 2 `warn`s + a further 3 `warn`-tier findings are `privileged-hook` (committed
`.claude/settings.json` shell hooks) and 1 `injectable-agent-surface` (an MCP grant over
baseline) — advisory, not attacker-controllable.

### [2.1] Batch 1

| Verdict | Repo | Wf | Lockfile | Findings |
|---|---|--:|---|--:|
| 🔴 FAIL | electron/electron | 50 | yarn | 4 |
| 🔴 FAIL | facebook/react | 22 | yarn | 3 (+1 warn) |
| 🔴 FAIL | sveltejs/svelte | 4 | pnpm | 3 |
| 🔴 FAIL | angular/angular | 13 | pnpm | 2 |
| 🔴 FAIL | facebook/react-native | 29 | yarn | 2 |
| 🔴 FAIL | nodejs/node | 42 | — | 2 |
| 🔴 FAIL | vitejs/vite | 12 | pnpm | 2 |
| 🔴 FAIL | vuejs/core | 9 | pnpm | 2 |
| 🟡 WARN | storybookjs/storybook | 17 | yarn | 1 (mcp grant) |
| 🟢 PASS | next.js(37) · freeCodeCamp(21) · tensorflow(17) · vscode(16) · babel(13) · deno(11) · webpack(10) · axios(8) · three.js(6) · prettier(16) · rust(4) · tailwind(4) · express(4) · go(0) · k8s(0) · ansible(0) | | | 0 |

### [2.2] Batch 2

| Verdict | Repo | Wf | Lockfile | Findings | Notable |
|---|---|--:|---|--:|---|
| 🔴 FAIL | ant-design/ant-design | 33 | — | 7 | DingTalk bot tokens via issue/PR/discussion text |
| 🔴 FAIL | n8n-io/n8n | 93 | pnpm | 5 (+1 warn) | CLA-check job holds an App private key |
| 🔴 FAIL | huggingface/transformers | 57 | circleci | 4 | comment-triggered bot tokens |
| 🔴 FAIL | pytorch/pytorch | 146 | — | 3 | **2× workflow_run artifact-injection** + Claude Code agent job |
| 🔴 FAIL | elastic/elasticsearch | 7 | — | 2 | issue title → BuildKite API token |
| 🔴 FAIL | EbookFoundation/free-programming-books | 7 | — | 1 | **workflow_run artifact-injection** |
| 🔴 FAIL | django/django | 17 | — | 1 | PR title/body → GITHUB_TOKEN pr:write |
| 🔴 FAIL | grafana/grafana | 92 | yarn | 1 | **workflow_run artifact-injection** |
| 🔴 FAIL | home-assistant/core | 13 | — | 1 | issue body → GitHub Models (AI) job |
| 🔴 FAIL | neovim/neovim | 23 | — | 1 | PR title → labeler GITHUB_TOKEN |
| 🟡 WARN | supabase/supabase | 47 | pnpm,mcp | 1 | committed `.claude` shell hook |
| 🟢 PASS | TypeScript(17) · fastapi(21) · fastify(20) · langchain(27) · mui(17) · nest(1) · rails(10) · laravel(5) · spring-boot(10) · terraform(11) · godot(9) · excalidraw(11) · vue-v2(2) · awesome(1) | | | 0 | |

## [3] The dominant class: untrusted event text → a secret-bearing job

44 of 46 fail-tier findings are `untrusted-text-injection` (labels `ASI01:2026` /
`MCP10:2025`): a workflow triggered by an untrusted event (`issue_comment`, `issues`,
`discussion`, `pull_request_target`) reads attacker-authored text inside a job that also
holds a secret/credential. Recurring shapes across the 50:

- **CI-dispatch bots** — vue/vite/svelte's shared `ecosystem-ci-trigger.yml`, n8n's CLA
  check — hold an App private key and read the triggering comment.
- **Notification bots** — ant-design → DingTalk, react → Discord, node → Slack — interpolate
  the issue/PR title into a third-party notify action.
- **AI-agent jobs** (a fast-growing shape) — pytorch's `claude-code.yml`, home-assistant's
  `detect-non-english-issues` (GitHub Models) — feed untrusted issue/comment text to an LLM
  in a credentialed job. This is the literal ASI01 prompt-injection threat the tool targets.

The other 2 fail findings (+ pytorch's 2, grafana, Ebook = 4 total) are the
**`workflow_run` artifact-injection** class (0042): a `workflow_run` job downloads an
artifact built by the untrusted `pull_request` run and splices its contents into a shell
(`$(<file)`), injecting attacker-controlled data into a privileged command.

## [4] Precision review — what these findings actually mean

Flagging is cheap; **being right is the product.** I hand-reviewed **8** flagged jobs
against source. The finding *class* is correct, but confidence varies sharply by subclass:

**High-confidence (the `workflow_run` artifact-injection class, 4 findings).** These key on
a real sink — untrusted artifact content spliced into a shell — not mere co-presence.
`EbookFoundation/free-programming-books#comment-pr.yml` is the exact case documented as a
true positive when 0042 shipped; pytorch's two `claude-*-triage` jobs and grafana's
`external-pr-notify-handler` are the same shape. **Treat these as actionable.**

**Review-worthy but over-flagged (the co-presence class, 42 findings).** Detection fires on
(untrusted text) + (secret in job) without modeling *guards* or *handling*:

| Job | Tool | On review |
|---|---|---|
| vite `ecosystem-ci-trigger` | FAIL | **FP** — guarded by an in-*script* `getCollaboratorPermissionLevel` check; body read via `env:`, string-split, never shell-interpolated |
| node `label-flaky-test` | FAIL | **FP/low** — `if:` gated on a maintainer-applied label; body via `env: BODY` (safe pattern) |
| pytorch `claude-code` | FAIL | **FP** — deliberately hardened: untrusted text only feeds boolean `contains()` guards ("Keep the comment text out of claude_args"), never reaches the agent as free text |
| node `notify-on-review-wanted` | FAIL | **Low** — label-gated, but title written unquoted to `$GITHUB_OUTPUT` (minor output-injection) |
| ant-design `issue-open-check` | FAIL | **Plausible TP** — the DingTalk step has no per-step actor guard and interpolates `issue.title` directly into a third-party notify action |
| electron `issue-opened` | FAIL | **Worth review** — any issue body triggers a job holding `ISSUE_TRIAGE_GH_APP_CREDS`; not actor-gated |

**Takeaway.** The tool reliably surfaces the right *class*, and the artifact-injection
subclass is high-confidence. But the co-presence subclass (the bulk of the 46 fails) has a
**material false-positive rate** driven by two unmodeled facts:
1. **In-step / in-script actor guards** — `getCollaboratorPermissionLevel`, `check-user-permission`
   actions, and label-gating (`github.event.label.name`) that the `if:`-only detector (0017) misses.
2. **Safe handling vs. injection** — untrusted text via `env:` + parse (or boolean `contains()`)
   is very different from direct `${{ }}`/shell interpolation.

So for the co-presence subclass the gate's "fail" today reads as **"review-worthy," not
"confirmed-exploitable."** Closing that gap is the actionable output of this run →
[ticket 0044](#7-follow-ups).

## [5] 0039 & 0040 validation on real inputs

**0039 (cap → verdict on large repos): confirmed at scale, with honest attribution.**
- **0 UNKNOWN across all 50**, including the largest: **pytorch (146 workflows)**, n8n (93),
  grafana (92), transformers (57), electron (50), node (42), supabase (47), next.js (37) —
  every one produced a real verdict.
- **0039 is not what rescued the batch-1 motivating repos.** Measured cost today: electron
  `entries×sinks = 156`, node `44`, next.js `0` — all far below the old 200k cap (the
  entry-narrowing from 0041/0042, already on `main`, had cut entry counts). 0039's value is
  **structural**: `O(entries×sinks)` per-pair search → `O(entries×(nodes+edges))` per-entry
  BFS, with the guard recalibrated to real cost so legitimate breadth (e.g. pytorch's 146
  workflows) can't trip it. Its user-visible proof is the **synthetic 230k-pair repro test**,
  not this sample. Net: the cap is not suppressing real top-100 repos.

**0040 (yarn/pnpm coverage): high real-world relevance.**
- Lockfile distribution of the 50: **pnpm 11, yarn 11, npm 5, none/non-JS 23.**
- **22 of 50 (44%) use yarn or pnpm** — repos that got *zero* dependency-layer analysis before
  0040. Under a `--base` PR context these now feed the same `runs-in → job → secret` synthesis
  as npm.

### [5.1] Deps-layer `--base` pass on real dependency-change commits

Whole-repo mode ([§1](#1-method)) can't exercise the diff-gated supply-chain layer, so a second
pass scanned **17 JS repos** (pnpm 9, yarn 5, npm 3) each at its **most-recent lockfile-changing
commit with `--base <parent>`** — a real dependency diff. Results:

- **Robustness: 0 parse errors, 0 UNKNOWN across all 17.** 0040's yarn/pnpm parsers (and the npm
  parser) handled real-world lockfiles — Berry, workspaces, hundreds of packages — cleanly,
  including vite's **103-entry** and TypeScript's **68-entry** diffs (248 new-dependency entries
  emitted in total). Real lockfiles are far messier than the fixtures; none tripped the parser.
- **Precision: 0 deps-driven findings, 0 false positives.** Not one repo FAILed because of a
  dependency change. Every FAIL was the *same* injection finding as whole-repo mode — the
  verdict was **identical to whole-repo for all 17**. The reachability gate held (R14): an
  added/bumped dep only fails if it reaches a **fork-triggerable install job holding a secret**,
  which none of these well-run repos expose. A benign (or large) bump is correctly absorbed with
  no new finding.
- This confirms the flagship cross-layer path is silent on benign bumps and would fire only on
  the genuine pwn-request-install shape (demonstrated by the 0040 fixtures + the real-repo CLI
  smoke test, where an injected fork-install-secret job does produce the FAIL).

## [6] Caveats

- **Purposive sample, not random** — weighted toward CI-heavy repos; the true top-100 has many
  docs/educational repos that trivially PASS. The 18/50 FAIL rate is **not** a top-100 base rate.
- **Whole-repo mode only** — the supply-chain/deps findings (the flagship cross-layer path) are
  diff-gated and absent here; this is CI/agent posture, not a full picture.
- **Precision** — co-presence FAILs are review-worthy candidates, not confirmed exploits ([§4](#4-precision)).
- **Point-in-time** — HEAD of each default branch on 2026-08-06.

## [7] Follow-ups

- **Ticket 0044 (precision):** teach the injection detector about in-step/in-script actor guards
  (`getCollaboratorPermissionLevel`, `check-user-permission`, label-gating) and distinguish
  `env:`-safe / boolean-`contains()` handling from direct shell/`${{ }}` interpolation — to cut
  the co-presence false positives in [§4](#4-precision).
- ~~Re-run with `--base` against real dependency-change commits to exercise the deps/supply-chain
  layer on live diffs.~~ **Done — see [§5.1](#51-deps-layer---base-pass-on-real-dependency-change-commits):**
  17 repos, 0 parse errors, 0 deps-layer false positives.
- Consider a distinct, higher-severity tier or label for the `workflow_run` artifact-injection
  class, which the review found to be high-confidence.

Raw per-repo JSON: `scratchpad/eval/out{,2}/*.json` (ephemeral); harnesses: `scratchpad/eval/run.sh`, `run2.sh`.
