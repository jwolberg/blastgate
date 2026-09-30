---
title: "Re-scan of the 50-repo sample under the proven-exploit fail contract"
anchor: EVAL-2026-09-29
date: 2026-09-29
tool: blastgate 0.1.0 (branch feat/precision-core, after 0045–0050 and 0054)
---

# Re-scan under the proven-exploit fail contract (2026-09-29)

Re-ran the 2026-08-06 sample (`scripts/eval-repos.txt`) with `scripts/eval-scan.sh` after the Precision Core changes. The plan is `docs/plans/2026-09-29-001-feat-precision-core-plan.md` (R12). Every fail was hand-verified against source.

## [1] Results at a glance

| | 2026-08-06 (post-0044) | 2026-09-29 |
|---|--:|--:|
| Repos FAIL | 13 | **0** |
| Fail-tier findings | 27 | **0** |
| Repos WARN only | — | 6 |
| Warn-tier findings | — | 15 |
| UNKNOWN (parse/eval error) | 0 | 0 |

The drop is the contract working: a `fail` now requires attacker input reaching an execution sink in a privileged job that holds a secret or code-write access, with evidence. Co-presence of untrusted text and a secret no longer fails.

## [2] Hand verification of fails

The first re-scan (before 0054) left **4 fails, all false positives**:

| Repo / workflow | Evidence | Verdict |
|---|---|---|
| pytorch `claude-distributed-triage.yml:41` | `ISSUE_NUM=$(cat issue_number.txt)`, then `^[0-9]+$` check | FP: assignment of a validated number |
| pytorch `claude-issue-triage-run.yml:58` | same pattern | FP |
| pytorch `hardened-pr-review-run.yml:349` | `HASH=$(cat .github/workflows/… \| sha256sum)` | FP: assignment, trusted committed files |
| grafana `external-pr-notify-handler.yml:73` | `PR_NUMBER=$(cat /tmp/pr-number/pr-number.txt)`, then numeric check | FP |

Ticket 0054 (plan U10, KTD9) made the artifact-splice detector assignment- and quote-aware. After it, **0 fails remain**. The zero is honest but vacuous: this sample now contains no proven exploit, so fail precision is untestable here. Fail *recall* needs the labeled benchmark (Track 3).

## [3] The four 2026-08-06 artifact-injection findings, re-adjudicated

The plan originally assumed these stay `fail`. That premise was wrong.

- **free-programming-books `comment-pr.yml:44` → warn (correct).** `gh pr comment $(<PRurl)` splices the artifact unquoted into `gh`'s arguments. That is argument injection, not code execution. The job holds no secret, only `GITHUB_TOKEN` with `pull-requests: write`, which is a warn under R3.
- **pytorch `claude-*-triage` ×2 and grafana `external-pr-notify-handler` → no finding (correct).** Assignments of validated numbers, per §2.

## [4] Warn findings (15 in 6 repos)

| Class | Count | Repos | Why warn |
|---|--:|---|---|
| action-input | 9 | ant-design (DingTalk ×6 + token), react (Discord ×3) | Issue/PR title/body in a third-party notify action's `with:`; injectability depends on the action's code |
| execution sink, PR-write token only | 1 | free-programming-books | Argument injection; token cannot change code (R3) |
| privileged-hook / agent grant (unchanged advisory classes) | 5 | react, n8n, supabase, storybook | Committed Claude Code hooks / MCP grant over baseline |

Every warn with an untrusted-text entry carries `file:line` evidence and no payload.

## [5] False-negative spot checks (repos that failed in August, now silent)

- **electron `issue-opened.yml`:** body only in `if: contains(...)` and passed via `env:` to github-script. Correctly silent.
- **django `check_pr_quality.yml`, vuejs/core `ecosystem-ci-trigger.yml`:** title/body via `env:`. Correctly silent.
- **transformers `ai-review.yml`:** body only in `startsWith(...)` guards. Correctly silent.
- **home-assistant `detect-non-english-issues.yml`: a gap.** The issue title/body go via `env:` into github-script, which sends them to GitHub Models while holding `issues: write`. `env:` protects the shell, not an LLM, so this is prompt injection. It would be a warn at most (no secret or code-write), but today it produces **no finding**. LLM calls from github-script and `actions/ai-inference` are not recognized as agent ingestion. That belongs to Track 2 (agent-in-CI modeling).

## [6] Caveats

- **Same purposive sample** as 2026-08-06; not a base rate.
- **HEAD moved** since August; SHAs are in §7. Some differences may be repo changes, not tool changes.
- **Two owner names were reconstructed** (`fastapi/fastapi`, `laravel/laravel`); the August doc gave short names only.
- **Whole-repo mode only**; the diff-gated dependency layer is not exercised here.

## [7] Per-repo results

| Repo | SHA | Fail | Warn |
|---|---|--:|--:|
| EbookFoundation/free-programming-books | `07fdc1d` | 0 | 1 |
| angular/angular | `fc9b2d6` | 0 | 0 |
| ansible/ansible | `a900ea9` | 0 | 0 |
| ant-design/ant-design | `f9fb37a` | 0 | 7 |
| axios/axios | `2426e03` | 0 | 0 |
| babel/babel | `41a16f6` | 0 | 0 |
| denoland/deno | `1b48a20` | 0 | 0 |
| django/django | `5a4511a` | 0 | 0 |
| elastic/elasticsearch | `28b7cf1` | 0 | 0 |
| electron/electron | `03703ae` | 0 | 0 |
| excalidraw/excalidraw | `35e854e` | 0 | 0 |
| expressjs/express | `7ef9844` | 0 | 0 |
| facebook/react | `7c6ac13` | 0 | 4 |
| facebook/react-native | `085caf0` | 0 | 0 |
| fastapi/fastapi | `3e33a03` | 0 | 0 |
| fastify/fastify | `19d5be0` | 0 | 0 |
| freeCodeCamp/freeCodeCamp | `ee45eb3` | 0 | 0 |
| godotengine/godot | `cd9c5d5` | 0 | 0 |
| golang/go | `1e963f8` | 0 | 0 |
| grafana/grafana | `b4da222` | 0 | 0 |
| hashicorp/terraform | `e3b5fc1` | 0 | 0 |
| home-assistant/core | `19946e8` | 0 | 0 |
| huggingface/transformers | `f339035` | 0 | 0 |
| kubernetes/kubernetes | `7c596ad` | 0 | 0 |
| langchain-ai/langchain | `a9780cd` | 0 | 0 |
| laravel/laravel | `aa0cf12` | 0 | 0 |
| microsoft/TypeScript | `b85298b` | 0 | 0 |
| microsoft/vscode | `990afc8` | 0 | 0 |
| mrdoob/three.js | `2db4284` | 0 | 0 |
| mui/material-ui | `6780195` | 0 | 0 |
| n8n-io/n8n | `191a22e` | 0 | 1 |
| neovim/neovim | `d5e7c7e` | 0 | 0 |
| nestjs/nest | `8843023` | 0 | 0 |
| nodejs/node | `f71d644` | 0 | 0 |
| prettier/prettier | `a777bd8` | 0 | 0 |
| pytorch/pytorch | `a6b28b6` | 0 | 0 |
| rails/rails | `54f1ea3` | 0 | 0 |
| rust-lang/rust | `5c543b0` | 0 | 0 |
| sindresorhus/awesome | `bc98e51` | 0 | 0 |
| spring-projects/spring-boot | `ab1843b` | 0 | 0 |
| storybookjs/storybook | `13e072e` | 0 | 1 |
| supabase/supabase | `92952bf` | 0 | 1 |
| sveltejs/svelte | `020242d` | 0 | 0 |
| tailwindlabs/tailwindcss | `fa81d69` | 0 | 0 |
| tensorflow/tensorflow | `1154e44` | 0 | 0 |
| vercel/next.js | `3854a98` | 0 | 0 |
| vitejs/vite | `5e4b9ca` | 0 | 0 |
| vuejs/core | `4ab865a` | 0 | 0 |
| vuejs/vue | `9e88707` | 0 | 0 |
| webpack/webpack | `d3b058f` | 0 | 0 |

Raw JSON (with payloads, local only) was written to the session scratchpad and is not committed.
