---
title: OpenSSF Scorecard Dangerous-Workflow vs the agent Rule of Two
date: 2026-10-01
tags: [scorecard, upstream, agents, distribution]
anchor: LRN-scorecard-dw
---

# OpenSSF Scorecard Dangerous-Workflow vs the agent Rule of Two

Scope note for the upstream track (public-crawler plan U9, R10). Documentation only. Every
Scorecard claim cites a path at one pinned commit.

**Pinned commit:** `c42b791d24f1e5863600f3f3029141b15b932d4e` (HEAD of `main` on 2026-10-01).
Paths below are relative to <https://github.com/ossf/scorecard/tree/c42b791d24f1e5863600f3f3029141b15b932d4e>.

## [1] What Dangerous-Workflow detects and how it scores

- **Registration.** `checks/dangerous_workflow.go` registers `Dangerous-Workflow`, builds raw data via
  `raw.DangerousWorkflow`, then runs the probe group `probes.DangerousWorkflows`. That group is exactly
  two probes (`probes/entries.go`): `hasDangerousWorkflowScriptInjection` and
  `hasDangerousWorkflowUntrustedCheckout`.
- **Parsing.** `checks/raw/dangerous_workflow.go` parses each `.github/workflows/*` file with
  `actionlint` and runs two passes per file.
- **Untrusted checkout.** `validateUntrustedCodeCheckout` applies only when the workflow triggers on
  `pull_request_target` or `workflow_run`. It flags a step whose `uses:` contains `actions/checkout` and
  whose `with.ref` contains `github.event.pull_request` or `github.event.workflow_run`. A checkout with
  no `ref` is skipped. The probe's `def.yml` states it does not detect safe use, e.g. label gating
  (`probes/hasDangerousWorkflowUntrustedCheckout/def.yml`).
- **Script injection.** `validateScriptInjection` looks only at `run:` steps (`actionlint.ExecRun`).
  It extracts each `${{ ... }}` expression and matches a fixed regex of attacker-controlled fields
  (`issue.title`, `comment.body`, `pull_request.head.ref`, `github.head_ref`, `toJSON(github)` ...). It does
  **not** consider the workflow trigger, the job's secrets or permissions, or `uses:` step inputs.
- **Finding model.** Each probe emits one `OutcomeTrue` finding per hit (with file, line, snippet) or one
  `OutcomeFalse`; `OutcomeNotApplicable` if the repo has no workflows (`probes/*/impl.go`).
- **Scoring.** `checks/evaluation/dangerous_workflow.go`: any `OutcomeTrue` from either probe gives
  `CreateMinScoreResult` (0); otherwise max (10); no workflows is inconclusive. The check is binary.
  `UniqueProbesEqual` against a hard-coded two-probe list means a third probe must be added there too, or
  the check returns an internal error.
- **Docs.** Risk is `Critical`; `docs/checks/internal/checks.yaml` lists two patterns only and says the
  highest score needs all workflows to avoid them.

## [2] The gap against Blastgate's agent Rule-of-Two verdict

Blastgate fails only when an outsider can directly trigger a recognized agent step, a granted tool can
read a credential in that step's scope, and an exfiltration leg holds (ADR-0002, `docs/decisions/0002-agent-rule-of-two-verdict.md`).

| Scenario                                                                                   | Scorecard at the pin | Why                                                                   |
| ------------------------------------------------------------------------------------------ | -------------------- | --------------------------------------------------------------------- |
| `issues`/`issue_comment` workflow runs `google-github-actions/run-gemini-cli` with secrets | No finding           | The agent is a `uses:` step; script injection scans `run:` only.      |
| `pull_request_target` runs `claude-code-action` with `allowed_non_write_users: '*'`        | No finding           | No `actions/checkout` of a PR ref, so the checkout probe stays false. |
| Agent step reading `${{ github.event.comment.body }}` in a `prompt:` input                 | No finding           | Expressions are checked only inside `run:` scripts.                   |
| Agent step with tools but no secrets (or secrets scrubbed)                                 | No finding           | Correct outcome. Blastgate also warns, not fails.                     |

Scorecard has no notion of an action's trigger gate, tool defaults, or secret scope. Related open issues
show maintainer interest in secret awareness (`#3277` "Dangerous workflow warns when script injection +
secrets used"), false-positive concern (`#1311`), and deferring to CodeQL (`#4490`). I found no open
issue or discussion about AI agent steps (search of `ossf/scorecard` issues on 2026-10-01; `#4982`
is an unrelated "agent security checks for AI agent projects" proposal, closed). Not exhaustive.

## [3] Smallest upstreamable addition

**A new probe `hasDangerousWorkflowAgentInjection`** in `probes/`, added to `probes.DangerousWorkflows`.
Shape per `probes/README.md`: `def.yml`, `impl.go`, `impl_test.go`; name is a true/false question.

- **Raw data.** Extend `checker.DangerousWorkflowData` with a third `DangerousWorkflowAgentInjection`
  type, populated by a third pass in `checks/raw/dangerous_workflow.go` (the existing
  `validateGitHubActionWorkflowPatterns` pipeline already hands it a parsed workflow).
- **Fires (OutcomeTrue) only when all hold on one step:** (a) the `uses:` action matches the profile
  table below at a covered ref; (b) the job is triggered by an outsider-reachable event with no actor
  gate (gate absent, or opened by the profile's wildcard input) and no job/`needs:` guard; (c) the
  step's own `with:` or `env:` passes a secret (`${{ secrets.* }}`) or the job holds a write
  `permissions:`/OIDC grant; (d) tools that can read or send it are granted (profile-specific).
- **Per-action profile table** (from `src/analyzers/ci/agents.ts`; sources fetched 2026-10-01):

  | Action                                 | Covered | Gate         | Wildcard opens gate                       | Cite                                                                                              |
  | -------------------------------------- | ------- | ------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------- |
  | `anthropics/claude-code-action`        | v1.x    | write-access | `allowed_non_write_users`, `allowed_bots` | <https://github.com/anthropics/claude-code-action/blob/v1/docs/security.md>                       |
  | `openai/codex-action`                  | v1.x    | write-access | `allow-users: '*'`                        | <https://github.com/openai/codex-action/blob/v1/docs/security.md>                                 |
  | `google-github-actions/run-gemini-cli` | v0.x    | none         | n/a                                       | <https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g> |

- **False-positive posture.** Same stance as ADR-0002: unknown is false, never true. Uncovered
  versions, SHA pins without a recorded version, non-literal gate inputs, and any missing leg produce
  `OutcomeFalse`, so recall is traded for precision. The `def.yml` should state, as the checkout probe
  does, what is not detected. Blastgate's graph-wide logic (job `needs:`, per-sink scrubbing) would be
  reduced to a static, per-step approximation here; the full verdict stays in Blastgate.
- **Mapping to the model.** One `OutcomeTrue` finding per offending step with location and snippet,
  matching the two existing probes. Lifecycle `experimental` first (`probes/README.md`).
- **Scoring decision to settle with maintainers.** Today any `True` drops the whole check to 0
  (`checks/evaluation/dangerous_workflow.go`), so the new probe would change scores for existing repos.
  Options: join the check as-is, or ship as a probe with no score effect (not verified: whether a probe can
  exist outside any check; `probes.MustRegister` takes a check list, see `probes/hasDangerousWorkflowUntrustedCheckout/impl.go`).

## [4] Maintainer process

- `CONTRIBUTING.md`: step 1 is "Identify an existing issue ... or submit an issue describing your
  proposed change"; maintainers respond; then fork and open a PR. Commits need a DCO sign-off (`-s`).
  Behavior changes that need discussion should go through an issue first (it says so for linter changes;
  for probes the rule is the general step 1).
- `probes/README.md`: probes are found by "browsing through the Scorecard GitHub issues"; lifecycle
  states `Experimental`/`Stable`/`Deprecated`. No separate probe-proposal template or design-doc
  requirement appears in either file at the pin.
- `CONTRIBUTING.md` points new checks to `checks/write.md` (not read; not needed for a probe).
- Practical path: open an issue with this note's gap table and a proposed probe, ask whether it should
  affect the Dangerous-Workflow score, then send a PR. Process links:
  <https://github.com/ossf/scorecard/blob/c42b791d24f1e5863600f3f3029141b15b932d4e/CONTRIBUTING.md>,
  <https://github.com/ossf/scorecard/blob/c42b791d24f1e5863600f3f3029141b15b932d4e/probes/README.md>.

## [5] Open risks

- **Profile maintenance.** Action gates and defaults change; a hard-coded table in Go ages. Blastgate's
  own profiles already needed source-level re-checks (`docs/learnings/verify-action-defaults-at-source.md`).
- **Neutrality.** Naming specific vendor actions in a neutral project's core check may draw pushback;
  a data-driven table (YAML) may be preferred. Unverified.
- **Score churn / CodeQL deferral.** A new probe flips scores for existing repos (see [3]); `#4490`
  suggests maintainers may prefer CodeQL for this class.
- **Static approximation.** Scorecard parses one workflow at a time with no cross-job graph; reusable
  workflows and `needs:` guards may be missed, risking false negatives (acceptable) or, if mishandled,
  false positives (not acceptable under our posture).
- **Not verified:** whether maintainers would accept a vendor-specific probe; that `main` has not moved
  since the pin; the content of `checks/write.md`; the `#4982` thread beyond its closed state.
