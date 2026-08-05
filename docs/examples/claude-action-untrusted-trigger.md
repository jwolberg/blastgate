---
title: "Dogfood example — a privileged agent on an untrusted trigger"
anchor: EX-claude-action
last-verified: 2026-08-05
---

# Dogfood example: a privileged agent on an untrusted trigger

A real finding Blastgate produced by scanning a real repository (`volscan`) during
development. It is the canonical cross-layer / agent-identity case: a job reachable by
**anyone** that holds **write credentials and an API key**, driving an **agent**.

## The scan

```bash
$ node dist/cli/index.js ../volscan --base main
blastgate: 2 reachable path(s) — FAIL

✗ FAIL  issue_comment/pull_request_review_comment/pull_request_review reaches job claude
        → .github/workflows/claude.yml#claude → GITHUB_TOKEN (contents:write, pull-requests:write, issues:write, id-token:write)
      sink: credential GITHUB_TOKEN (contents:write, pull-requests:write, issues:write, id-token:write)  [ASI03:2026]
      why:  Job .github/workflows/claude.yml#claude is triggered by untrusted input (issues, issue_comment,
            pull_request_review_comment, pull_request_review) and holds credential GITHUB_TOKEN (...), which is
            exfiltratable from an untrusted run.
      fix:  Remove GITHUB_TOKEN (...) from the untrusted-triggerable job, or restrict its triggers to trusted events.

✗ FAIL  issue_comment/pull_request_review_comment/pull_request_review reaches job claude
        → .github/workflows/claude.yml#claude → ANTHROPIC_API_KEY
      sink: credential ANTHROPIC_API_KEY  [ASI03:2026]
      why:  ... triggered by untrusted input ... and holds credential ANTHROPIC_API_KEY ...
      fix:  Remove ANTHROPIC_API_KEY from the untrusted-triggerable job, or restrict its triggers to trusted events.
```

## The workflow (as found)

```yaml
on:
  issues:            { types: [opened, assigned] }
  issue_comment:     { types: [created] }
  pull_request_review_comment: { types: [created] }
  pull_request_review:         { types: [submitted] }

jobs:
  claude:
    # Only act when @claude is explicitly mentioned, so unrelated issue/PR
    # activity doesn't spend Actions minutes or API tokens.
    if: |
      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude')) || ...
    permissions:
      contents: write
      pull-requests: write
      issues: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Why this is a true positive (not noise)

The `if:` looks like a guard, but it only checks whether the body **contains
`@claude`** — nothing about *who* wrote it. The workflow's own comment gives it away:
*"so unrelated issue/PR activity doesn't spend Actions minutes."* It is a **cost
filter, not a security control.** An attacker simply includes `@claude` in a malicious
comment.

There is **no `author_association` check and no actor allowlist**, so any outside user
can trigger the job. That job runs with `contents:write` + `pull-requests:write` +
`issues:write` + `id-token:write` and holds `ANTHROPIC_API_KEY`, and it feeds the
attacker-controlled comment body straight into an agent.

### The attack (OWASP ASI03 — Identity & Privilege Abuse)

1. An external user opens an issue or comments: `@claude … <prompt injection>`.
2. The job fires (the `@claude` filter passes) with a write-scoped token + the API key.
3. `claude-code-action` treats the comment as input → **prompt injection into a
   write-privileged agent**: push commits (`contents:write`), modify/approve PRs
   (`pull-requests:write`), manipulate issues, mint an OIDC token (`id-token:write`),
   or exfiltrate the API key.

For `issues`/`issue_comment` the job runs on the default branch, so this is
prompt-injection of a privileged agent rather than untrusted *code* execution — still
a full compromise of the job's authority.

## The fix

Two independent controls — apply **both**:

1. **Add a real actor gate** (the security control): require a trusted
   `author_association` (or a `github.actor` allowlist) in addition to the `@claude`
   mention.
2. **Least privilege** (reduce blast radius): grant only the permissions the job uses;
   drop `id-token:write` unless you use cloud OIDC federation.

```yaml
name: Claude Code

on:
  issues:            { types: [opened, assigned] }
  issue_comment:     { types: [created] }
  pull_request_review_comment: { types: [created] }
  pull_request_review:         { types: [submitted] }

jobs:
  claude:
    # Gate on an explicit @claude mention (cost) AND a trusted author association
    # (security) — an outside user cannot trigger the privileged job.
    if: |
      (github.event_name == 'issues' &&
        contains(github.event.issue.body, '@claude') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.issue.author_association)) ||
      (github.event_name == 'issue_comment' &&
        contains(github.event.comment.body, '@claude') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)) ||
      (github.event_name == 'pull_request_review_comment' &&
        contains(github.event.comment.body, '@claude') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)) ||
      (github.event_name == 'pull_request_review' &&
        contains(github.event.review.body, '@claude') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.review.author_association))
    runs-on: ubuntu-latest
    permissions:
      contents: write # only if @claude pushes commits/branches; otherwise `read`
      pull-requests: write
      issues: write
      # id-token: write  # drop unless you use cloud OIDC federation
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## What this demonstrates

- **The cross-layer / identity value proposition.** A single-layer workflow linter
  might flag "broad permissions" or "untrusted trigger" in isolation; Blastgate reports
  the *reachable path* — untrusted trigger → this job → these specific credentials — as
  one finding with a fix and an OWASP label.
- **A precision boundary (tracked as ticket 0017).** Blastgate v1 does not yet parse
  the `if:` actor guard, so it cannot distinguish a properly actor-gated job from an
  unguarded one. It is deliberately **fail-closed**: an `if:` it does not recognize as
  an actor restriction (like this `@claude`-mention filter) is treated as *no guard* —
  which is exactly right here. Ticket 0017 will let Blastgate *downgrade a genuinely
  actor-gated* job to a warning while still flagging the broad scope, without weakening
  cases like this one.
