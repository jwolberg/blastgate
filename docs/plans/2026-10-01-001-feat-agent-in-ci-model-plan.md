---
title: Agent-in-CI Model - Plan
type: feat
date: 2026-10-01
topic: agent-in-ci-model
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
product_contract_source: ce-brainstorm
execution: code
---

# Agent-in-CI Model - Plan

## Goal Capsule

- **Objective:** Decide when an AI agent running in CI is a proven exploit. Blastgate judges each agent step against the Agents Rule of Two (untrusted input, sensitive access, an exfiltration channel), fails only when all three hold in readable configuration, and warns otherwise.
- **Product authority:** `STRATEGY.md` (Agent-in-CI modeling track) → this Product Contract. The fail contract in `docs/plans/2026-09-29-001-feat-precision-core-plan.md` (R1, R7–R10) still governs every fail. The crawler, the OpenSSF Scorecard contribution, and other checks are not active scope.
- **Open blockers:** None.

---

## Product Contract

### Summary

Blastgate recognizes the major coding-agent actions and tool-less LLM steps in GitHub workflows.
It judges each against a versioned, cited profile of that action's trigger gate and tool defaults.
An agent step fails only when an outsider can trigger it directly, it can read a secret or code-write credential, and it has a way to get that data out. Every other agent finding is a warn.

### Problem Frame

Precision Core made every untrusted-text-to-agent path a warn, because Blastgate could not tell whether an agent could actually be steered into leaking anything.
That left the attack class `STRATEGY.md` targets, AI agents in CI, unable to produce a fail. It also blocks the crawler, which would otherwise find nothing to disclose and could mislabel exposed agent repos as passes.
Today Blastgate recognizes `claude-code-action`-style actions by name only (`AGENT_ACTION_RE` in `src/analyzers/ci/injection.ts`). It does not recognize `run-gemini-cli`, `codex-action`, or `actions/ai-inference`, and it does not read any agent's trigger gate or tool configuration.
The 2026-09-29 re-scan found a missed case: home-assistant passes issue text through `env:` into a GitHub Models call, which is prompt injection but produced no finding.
Public incidents show that the risk depends on configuration. Comment and Control leaked keys through claude-code-action, Copilot, and Gemini CLI workflows. A run-gemini-cli advisory (CVSS 10) escalated a GitHub issue to GCP project compromise via an OIDC credential.

### Key Decisions

- **Direct triggering can fail; indirect content injection warns.** An outsider who can trigger the agent themselves is a proven path. An agent that reads outsider content only when a write-access user triggers it needs a maintainer action, so it warns. Governs R3, R7. (session-settled: user-approved — chosen over "both fail" and "score, don't gate": matches the bar of clearly seeing the exploit.)
- **Judge agents against per-action profiles, not generic inference.** Each recognized action has a versioned profile citing its own security docs or advisories. Assuming every agent has every tool would turn most agent repos into fails. Governs R2, R9. (session-settled: user-approved — chosen over capability-maximal inference: precise and citable, at the cost of maintaining the table.)
- **Tool-less LLM steps are in scope as warns.** `actions/ai-inference` and github-script calls to GitHub Models ingest untrusted text but cannot exfiltrate directly. Governs R8. (session-settled: user-approved.)
- **On a public repo, Actions logs count as an exfiltration channel.** An agent that can read a secret can print it in an encoded form that log masking misses, which is how Comment and Control leaked keys. Governs R5. (session-settled: user-approved.)
- **The crawler waits for this work.** Without an agent verdict, the crawler's target population (repos running agents in CI) would yield no disclosable fails and misleading passes. (session-settled: user-directed — chosen over "measure now, publish later" and "3-state public labels".)

### Requirements

**Recognition**

- R1. Blastgate recognizes as agent steps: `claude-code-action`, `codex-action`, `run-gemini-cli`, and tool-less LLM steps (`actions/ai-inference`; `actions/github-script` calling GitHub Models).
- R2. Each recognized action has a profile recording its default trigger gate, the inputs that bypass it, the inputs that grant tools, its tool defaults, and the version range the profile covers; every entry cites the action's own documentation or advisory.

**Rule of Two**

- R3. Untrusted input (direct) holds when an outsider can trigger the agent step itself: its trigger is attacker-reachable and the action's write-access gate is absent or bypassed (for example `allowed_non_write_users`, `allow-users`, or `allow-bots` allowing outsiders), with no recognized guard on the job.
- R4. Sensitive access holds when the agent has a tool able to read process environment or runner files while its job holds a named secret, a code-write `GITHUB_TOKEN`, or `id-token: write`. Credential rules are those of Precision Core R3 / 0047, and the agent's own model API key counts.
- R5. An exfiltration channel holds when the agent has a shell or network tool, can write to a public surface (comments, PRs, issues), or runs in a public repository whose Actions logs are publicly readable.

**Verdict**

- R6. An agent step is `fail` only when R3, R4, and R5 all hold from configuration Blastgate can read, and the finding carries Precision Core evidence (agent step `file:line`, the capability reached, a local-only payload).
- R7. An agent step that ingests outsider content but can only be triggered by write-access users is `warn` (indirect injection), as is any agent step where a Rule-of-Two leg is missing.
- R8. A tool-less LLM step that ingests untrusted text, including text passed through `env:`, is `warn` and never `fail`.
- R9. An agent step whose action version no profile covers, or whose tool or gate configuration Blastgate cannot read, is `warn` with a reason naming what is unknown.
- R10. Every agent warn names which Rule-of-Two legs hold and which are missing.

**Proof**

- R11. Labeled fixtures reproduce the public cases: a bypassed-gate claude-code-action with shell tools (the Comment and Control shape), the run-gemini-cli OIDC shape, and the PromptPwnd shape. Each must fail with evidence, and each hardened counterpart (gate intact, tools restricted, or secrets removed) must warn or pass.
- R12. The 50-repo sample stays free of unverified fails, and the home-assistant workflow becomes an agent-ingested warn.

### Acceptance Examples

- AE1. **Covers R3–R6.** **Given** an `issue_comment` workflow running `claude-code-action` with `allowed_non_write_users: "*"` and shell tools allowed, holding `ANTHROPIC_API_KEY`, **then** the finding is `fail` with evidence at the agent step.
- AE2. **Covers R7.** **Given** the same workflow without `allowed_non_write_users`, **then** the finding is `warn` naming indirect injection.
- AE3. **Covers R4, R10.** **Given** AE1 but with tools restricted to `Bash(gh issue view:*)`, **then** the finding is `warn` naming the missing sensitive-access leg.
- AE4. **Covers R8, R12.** **Given** an `issues` workflow passing the title and body via `env:` into github-script that calls GitHub Models, holding `issues: write`, **then** the finding is an agent-ingested `warn`.
- AE5. **Covers R9.** **Given** a recognized agent action pinned to a version outside every profile's range, **then** the finding is `warn` naming the uncovered version.

### Scope Boundaries

**Deferred for later**

- Multi-hop flows where an LLM's output is written to `$GITHUB_OUTPUT` and executed by a later step.
- Agents beyond the four recognized (aider, opencode, Copilot coding agent, custom harnesses); they stay on today's name match as warns.
- Runtime evidence from public Actions logs (which tools an agent actually used).

**Outside this work**

- The crawler, the public pass index, and private disclosure. These are the next brainstorm.
- The OpenSSF Scorecard Dangerous-Workflow contribution.

<!-- ce-section: work-relationships -->
### How This Work Fits Together

This plan owns the agent verdict. The broader breakdown is the current understanding, not a committed roadmap.

- **Crawler (next):** Depends on this plan. It scans repos running agents in CI and discloses fails privately; a fail-capable agent verdict is what gives it something to disclose.
- **Scorecard contribution:** Enables reach. It would upstream the simplest direct-trigger pattern from this plan into OpenSSF Scorecard's Dangerous-Workflow check. Still to decide when.
- **Static-serving secrets check:** Can proceed independently of this plan. It covers a secret file shipped in the deploy artifact (not excluded by `.gcloudignore`/`.dockerignore`, `COPY . .`) and served by a route over the project root; the 2026-05-30 `situation` incident is the motivating case.

### Dependencies / Assumptions

- Precision Core is merged (PRs #36, #37): the fail contract, evidence, and payload surfaces are reused unchanged.
- Agent action defaults change often. Each profile is only as current as its cited source, so profiles carry version ranges and an unknown version warns (R9).
- claude-code-action's `allowed_non_write_users` bypass applies only when `github_token` is passed, not with GitHub App authentication, per its security docs. Planning confirms the equivalent conditions for the other actions.

### Outstanding Questions

**Deferred to Planning**

- The exact profile fields and current defaults for each action, verified against each action's docs at the pinned versions.
- How R3 treats an `issues: opened` trigger where the action's own gate checks the actor who opened the issue.
- How R4 decides which tool grants can read environment or files for each action (for example Codex's `safety-strategy`).

### Sources / Research

- `src/analyzers/ci/injection.ts` — current `AGENT_ACTION_RE` and sink classification (`classifyUntrustedText`).
- `src/engine/checks.ts` — the fail contract (`tierFor`, `proof`, `evidenceFor`).
- `docs/evaluations/2026-09-29-precision-core-rescan.md` §5 — the home-assistant missed case.
- [claude-code-action security docs](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md) — write-access gate, `allowed_non_write_users`, tool restriction.
- [Codex GitHub Action](https://developers.openai.com/codex/github-action) — `allow-users`, `allow-bots`, `safety-strategy`.
- [run-gemini-cli trust-model advisory GHSA-wpqr-6v78-jr5g](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g) and [Pillar Security's OIDC write-up](https://www.pillar.security/blog/a-wif-of-fresh-access-how-a-github-issue-on-gemini-cli-led-to-gcp-project-compromise).
- [CSA research note: Comment and Control](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-ci-prompt-injection-202608/) and [Aikido: PromptPwnd](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents).
- GitHub code search, 2026-10-01: about 19.5k workflow files use `claude-code-action`, 1.3k `codex-action`, 1.2k `run-gemini-cli`, 800 `actions/ai-inference`.
