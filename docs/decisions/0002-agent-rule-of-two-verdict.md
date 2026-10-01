---
id: 0002
title: AI agents in CI fail only when all three Rule-of-Two legs hold
anchor: ADR-0002
status: accepted
date: 2026-10-01
supersedes:
superseded-by:
---

Plan: `docs/plans/2026-10-01-001-feat-agent-in-ci-model-plan.md`. Code:
`src/analyzers/ci/agents.ts` (profiles + assessment), `src/engine/checks.ts` (`agentProven`).

## [1] Context

Precision Core (`docs/plans/2026-09-29-001-feat-precision-core-plan.md`) made every
untrusted-text-to-agent path a warn: its R1/R5 let only shell-interpolated text fail, and it
held agent ingestion at warn "until Track 2 can show the agent reaches a secret plus an exfil
channel". So the attack class Blastgate targets — an outsider steering an AI agent in CI into
leaking credentials (Comment and Control, the run-gemini-cli OIDC advisory, PromptPwnd) —
could never fail, and the crawler would have had nothing to disclose.

## [2] Decision

Judge each recognized agent step (claude-code-action, codex-action, run-gemini-cli) against
the Agents Rule of Two using a cited, versioned profile of that action's trigger gate and
tool defaults. It fails only when:

1. **Direct trigger** — an outsider can trigger the agent step itself (gate absent or opened
   by `'*'`, no guard on the job, step, or a `needs:` job);
2. **Sensitive access** — a granted tool can read a credential in the agent step's own scope;
3. **Exfiltration** — a shell or network tool, a token that writes a public surface, or public
   Actions logs;

and the profile covers the pinned version, and the path's own sink is a credential the agent
can read (per-sink: a scrubbed secret warns even when another credential fails). Every other
agent finding warns, naming each leg as held, missing, or unknown. Tool-less LLM steps always
warn. This supersedes Precision Core R1/R5 for agent steps only; its evidence and payload
rules apply unchanged.

## [3] Alternatives rejected

- **Fail on any agent ingestion** — fails nearly every agent repo on co-presence, the false-fail
  pattern Precision Core removed.
- **Capability-maximal inference** (assume every agent has every tool) — same result; not
  citable against the action's documented defaults.
- **Fail indirect injection** (agent triggered by a write-access user reading outsider text) —
  needs a maintainer action, so not a demonstrated exploit; it warns.

## [4] Consequences

- Profiles must be maintained as actions change; uncovered versions, branch refs, and (until
  SHAs are recorded, ticket 0065) SHA pins warn as unknown — a deliberate recall cost.
- Only explicitly granted tools count; claude's default tool set counts as none. A
  command-scoped shell counts for reading env (PromptPwnd's `$SECRET` expansion), pending
  verification for Claude Code (ticket 0063).
- On the 50-repo sample the agent model produced no fails
  (`docs/evaluations/2026-10-01-agent-model-rescan.md`); the incident fixtures are the
  positive evidence.

## [5] Amendment (2026-10-01, ticket 0070): claude's default tools read the workspace

The [4] bullet "claude's default tool set counts as none" is superseded for file reads. Claude
Code runs its built-in read-only commands (`cat`, `ls`, `grep`, ...) and file reads inside the
working directory with no grant "in every mode" (https://code.claude.com/docs/en/permissions,
"Read-only commands"). Verified headless on CLI 2.1.287, the version claude-code-action
v1.0.239 pins: with no grants, `cat .git/config` ran; `echo $SECRET` was denied ("couldn't check
the variable's value"); `cat` of a file outside the working directory was denied. So a claude
step with no grants holds file read for the workspace (checkout-persisted tokens,
`gha-creds-*.json`) but not env read, shell, or network. On the 50-repo sample this changed no
finding (re-scan of the same clones with both engines).
