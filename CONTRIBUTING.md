# Contributing to Blastgate

Blastgate is a change-time security gate. Contributions are welcome from anyone —
you do **not** need to be a collaborator to contribute. This guide explains how to
propose changes and, just as importantly, the security posture the project holds
itself to. Because Blastgate flags over-privileged CI, untrusted triggers, and
supply-chain footholds in *other* people's repos, its own repo has to be a clean
example of the same rules.

For reporting a security vulnerability, **do not** open a public PR or issue — see
[`SECURITY.md`](./SECURITY.md).

## How contributing works (fork → branch → PR)

You contribute through a pull request from your own fork. Nobody — maintainers
included — pushes directly to `main`; the final merge is always human-reviewed.

1. **Fork** the repo and clone your fork.
2. **Branch** off `main` with a descriptive name
   (`fix/parse-workflow-if`, `feat/gitlab-ci-layer`).
3. **Make the change** with tests (see [Tests](#tests-are-not-optional)).
4. **Open a PR** against `main`. Fill in the PR template — it front-loads the
   review checklist.
5. A maintainer reviews. CI must be green and any
   [code-owned paths](#who-can-merge-what) need a maintainer's approval before it
   can merge.

### What to expect as an outside contributor

- **CI won't run automatically on your first PR.** GitHub requires a maintainer to
  approve workflow runs for outside contributors. This is deliberate — your PR
  runs `npm ci` (which can execute dependency lifecycle scripts) and builds/tests
  your code on our runner, and we don't auto-run untrusted code. A maintainer will
  click **Approve and run**; after your first merged PR it runs automatically.
- **You have full read access and can PR anything**, including workflow and engine
  changes. The gates below decide what can *merge*, never what you can *propose*.

## Local setup

Requires Node `>= 20` and npm (this project is npm-first — it dogfoods its own
`package-lock.json`, so please don't switch it to another package manager).

```bash
npm ci              # install exactly from the lockfile
npm run build       # tsup bundle (CLI + action + plugin)
npm run typecheck   # tsc
npm run lint        # eslint
npm run format      # prettier --write  (or format:check to verify)
npm test            # vitest
```

Before you push, run the same gate CI runs:

```bash
npm run format:check && npm run typecheck && npm run lint && npm run build && npm test
```

## Tests are not optional

Blastgate is a correctness-critical security tool. Every behavior change needs a
test, and the test is the spec:

- **Write the failing test first**, then make it pass.
- **Make it adversarial, not green-rigged.** Exercise the real edge case — a
  genuinely reachable path, a genuinely guarded one, a malformed workflow. A test
  that only asserts the happy path, or is tautological / over-mocked, is worse than
  no test because it hides regressions.
- A change that adds or fixes a finding archetype should add both a **true
  positive** (it fires when it should) and a **true negative** (it stays quiet
  when it shouldn't fire). Precision over recall is a core project value.

## Security rules for changes that touch CI or the Action

These are non-negotiable because they are the exact things Blastgate exists to
catch. A PR that violates one will be asked to change:

- **Keep workflows least-privilege.** Any workflow must declare an explicit
  `permissions:` block, scoped to only what the job uses. The default is
  `contents: read`. Do not rely on the repo/org default token scopes.
- **Never add `pull_request_target`, `workflow_run`, or other untrusted triggers
  to a job that holds a secret or a write-scoped token.** That is the canonical
  fork-reachable-secret path. If you need CI to use a secret, it must run only on
  trusted triggers (e.g. `push` to `main`, or a `pull_request` gated by a real
  actor check — an `author_association` allowlist, *not* a body-content filter).
- **Don't add secrets to the fork-triggerable job.** Today `ci.yml` holds no
  secrets; keep it that way unless there's a reviewed reason.
- **Pin third-party actions** you introduce to a commit SHA, not a floating tag.
  First-party `actions/*` may stay on major-version tags.
- **The Action's built `dist/` is release infrastructure.** If you change engine
  code that the Action bundles, rebuild it and call that out in the PR so a
  maintainer can verify the bundle matches source.

If you're changing an agent/MCP config (`.mcp.json`, `.claude/settings.json`),
grant the minimum capability the change needs — over-baseline grants are a finding
Blastgate reports on itself.

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`.
- One logical change per commit; imperative subject, ~70 chars or less.
- Reference the issue/ticket you're closing in the PR body (`Closes #12`).

## Who can merge what

- **`main` is a protected branch.** No direct pushes; every change lands through a
  reviewed, green PR. The final merge is performed by a human maintainer.
- **[`CODEOWNERS`](./.github/CODEOWNERS)** requires a maintainer's review on the
  security-sensitive surfaces: `.github/`, `.gitlab/`, `action.yml`, `dist/`,
  `src/`, and the lockfile. You can propose changes to these; a maintainer signs
  off before they merge.

## Licensing

Blastgate is licensed under **Apache-2.0** (see [`LICENSE`](./LICENSE)). By
submitting a contribution you agree that it is your own work (or you have the right
to submit it) and that it will be licensed under Apache-2.0.

## Questions

Open a regular issue for bugs, false positives, or feature ideas. For anything that
looks like a real vulnerability, use [`SECURITY.md`](./SECURITY.md) instead of a
public issue.
