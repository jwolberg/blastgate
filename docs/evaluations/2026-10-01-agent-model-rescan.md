---
title: "Re-scan of the 50-repo sample under the agent-in-CI Rule-of-Two verdict"
anchor: EVAL-2026-10-01
date: 2026-10-01
tool: blastgate 0.1.0 (branch feat/agent-in-ci, after 0055–0060 and 0062)
---

# Re-scan under the agent-in-CI verdict (2026-10-01)

Re-ran the 50-repo sample (`scripts/eval-repos.txt`) with
`SCAN_FLAGS=--public scripts/eval-scan.sh` after the agent-in-CI units. The plan is
`docs/plans/2026-10-01-001-feat-agent-in-ci-model-plan.md` (U7, R12). Every repo in the sample
is public, so visibility was `public`: Actions logs count as an exfiltration channel.
Every fail and every agent workflow was hand-reviewed against source.

## [1] Results at a glance

| | 2026-09-29 (Precision Core) | 2026-10-01 |
|---|--:|--:|
| Repos scanned | 50 | 50 |
| Repos FAIL | 0 | **0** |
| Fail-tier findings | 0 | **0** |
| Warn-tier findings | 15 | 20 |
| Agent findings (Rule-of-Two assessed) | — | 2 (both warn) |

The five new warns are both home-assistant LLM steps (§2) and three warns from a new gh-aw
workflow (§3).

## [2] Every agent finding, with its legs

| Repo / workflow | Agent step | Direct | Access | Exfil | Tier | Hand verdict |
|---|---|---|---|---|---|---|
| home-assistant `detect-non-english-issues.yml:65` | `actions/ai-inference` (tool-less) | held — any `issues` author | missing — tool-less | held — token writes issues; public logs | warn | Correct. Prompt injection into a model that cannot act; the 2026-09-29 "gap" is closed (R12). |
| home-assistant `detect-duplicate-issues.yml` | `actions/ai-inference` (tool-less) | held | missing — tool-less | held | warn | Correct. The title/body reach the model through a github-script step that reads the issue in-script (see §4). |

Both pin `actions/ai-inference` by SHA, so the reason also notes the unrecorded SHA (R9).
A tool-less step can never fail (R8), whatever its version.

## [3] Hand verification of fails

The first pass of this re-scan had **2 fails, both false positives**, on home-assistant
`quality-scale-reviewer.lock.yml` (`GH_AW_GITHUB_MCP_SERVER_TOKEN`, `GH_AW_GITHUB_TOKEN`).
They came from the Precision Core fork-PR rule (0048), not from the agent model. The
workflow is a GitHub Agentic Workflows (gh-aw) lock file. A `workflow_run` job checks out
the PR head, and every later `run:` step runs gh-aw's own runtime
(`${RUNNER_TEMP}/gh-aw/actions/*.sh`, the MCP gateway, the Copilot launch). None runs PR
code. 0048 treats any `run:` after an untrusted checkout as running attacker code, which
over-reaches here. The PR tree reaches that job only through the Copilot agent, which is
the agent class.

Per the plan's stop condition this was raised. The user chose to fix it in this branch
(ticket 0062): in a gh-aw-compiled job, a `run:` step on gh-aw runtime paths is not
execution evidence. After 0062 the three gh-aw paths are warns, and **0 fails remain**.

## [4] Agent workflows with no finding (false-negative review)

| Repo / workflow | Agent | Why silent | Verdict |
|---|---|---|---|
| storybook `claude.yml` | claude-code-action | `author_association` guard on the job | Correct |
| storybook `claude-code-review.yml` | claude-code-action | `pull_request` plus an `author_association` guard | Correct |
| pytorch `claude-autorevert-advisor.yml` | claude-code-action | `workflow_dispatch` only | Correct |
| n8n `test-evals-mcp.yml` | — | `workflow_call` / `workflow_dispatch` only | Correct |
| pytorch `claude-issue-triage-run.yml`, `claude-distributed-triage.yml`, `hardened-pr-review-run.yml` | claude-code-action | `workflow_run` relays an issue/PR from an upstream workflow; the agent reads it by number | Known gap: multi-hop relay is out of scope (plan Scope Boundaries). `claude-distributed-triage.yml` sets `allowed_bots: '*'` — follow-up |

The first pass also missed home-assistant `detect-duplicate-issues.yml`, because its
github-script step reads the issue in-script rather than through `${{ github.event.* }}`.
U2 now taints the outputs of such a step (fix in 0056), and it is the second warn in §2.

## [5] Caveats

- **Same purposive sample** as 2026-08-06 and 2026-09-29; not a base rate. Only 9 workflows in
  4 of the 50 repos use a recognized agent action, and none has a proven agent exploit. So
  agent-fail precision is untestable on this sample. The three incident fixtures (U6)
  are the positive evidence.
- **Six clones were silently empty on the first pass.** Network timeouts left sparse
  checkouts with no `.github/` that scanned as clean. They were re-cloned and every repo
  was checked for a populated `.github/` before these numbers were taken.
- **HEAD moved** since 2026-09-29; SHAs are in §6.

## [6] Per-repo results (non-zero only)

| Repo | SHA | Fail | Warn |
|---|---|--:|--:|
| EbookFoundation/free-programming-books | `07fdc1d` | 0 | 1 |
| ant-design/ant-design | `820e1a8` | 0 | 7 |
| facebook/react | `7c6ac13` | 0 | 4 |
| home-assistant/core | `52a8769` | 0 | 5 |
| n8n-io/n8n | `56aa3d8` | 0 | 1 |
| storybookjs/storybook | `9e4f791` | 0 | 1 |
| supabase/supabase | `be976be` | 0 | 1 |

The other 43 repos: 0 fail, 0 warn.
