---
title: Adopt Blastgate and respond to a finding
last-verified: 2026-08-05
anchor: RB-adopt-blastgate
---

How to turn Blastgate on for a repository and what to do when it fails a change.
Blastgate fails **only** on a reachable path to a secret/credential sink; it warns
(does not fail) on lower-severity capability paths. Fixing the path is always
preferred over accepting it.

Blastgate runs at three points in a change's life — **local hook → CI PR gate →
pre-merge review** — all off the same engine. This runbook turns each on in that
order, then covers responding to a finding.

## [1] Try it locally first

```bash
npx blastgate .                 # whole-repo scan; exit non-zero = a fail verdict
npx blastgate . --base main     # add change signals (new deps, .npmrc) vs a ref
npx blastgate . --json          # machine-readable findings (has the finding `id`)
npx blastgate . --format md     # human-readable report (the same one CI posts on the PR)
```

A clean repo prints a PASS line and exits 0. Run it against a branch that adds a
dependency or edits a workflow to see change signals light up (`--base`). Use
`--format md` when you want a shareable report (`> blastgate-report.md`) rather than
terminal output.

## [2] Enable the CI/PR gate (the Action)

Add `.github/workflows/blastgate.yml`:

```yaml
name: Blastgate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # required: the base ref must be available for diff signals
      - uses: jwolberg/blastgate@v0
```

`fetch-depth: 0` matters — without the base ref, new-dependency / changed-config
signals do not appear. The Action defaults its diff base to the PR base ref, fails
the check on a reachable path, and posts per-finding annotations plus the full
markdown report (the same output as `blastgate --format md`) as the job summary a
reviewer reads at merge time.

## [2.1] Other CI providers (GitLab, CircleCI)

Blastgate also reads `.gitlab-ci.yml` and `.circleci/config.yml` when present.

- **GitLab CI** is a full gate: a merge-request-triggerable job holding a CI/CD
  credential variable fails the same way a GitHub fork job does. (GitLab's *protected*
  variables are withheld from fork-MR pipelines — Blastgate flags the reachable shape;
  confirm the variable isn't exposed to fork pipelines.)
- **CircleCI is advisory only.** Whether a **forked-PR build receives your secrets is a
  CircleCI project setting** ("Pass secrets to builds from forked pull requests"),
  configured in the CircleCI UI — it is **not** in `.circleci/config.yml`. Blastgate reads
  repo files, so it cannot see that toggle and will **not** fail a change on it (a false
  PASS would be worse than an honest gap). Instead it emits an advisory warning naming any
  secret a job references. **You must verify that setting is disabled yourself.**

## [3] Enable the agent-loop gate (the plugin)

Inside Claude Code:

```
/plugin marketplace add jwolberg/blastgate
/plugin install blastgate@blastgate
```

The `PreToolUse` hooks then **deny** a `git commit` / `git push` or an edit to
`package.json` / `.github/workflows/**` / `.mcp.json` that would create a reachable
path; the `PostToolUse` hook **blocks** (react-only) after an `npm install`. The
`blastgate_check_change` MCP tool and `/blastgate` command are advisory self-checks —
the hook is the enforcement layer.

## [4] Respond to a finding

Every finding gives you: the `path` (entry → … → sink), the `sink`, the `reason` it
is reachable, a `fix`, and the OWASP label(s).

**[4.1] Fix the path (preferred).** Break any edge on it. Typical fixes:

- Install-script → secret: gate lifecycle scripts (`npm ci --ignore-scripts`) or
  remove the secret from the untrusted-triggerable job.
- Fork-triggerable job holding a secret: remove the secret from that job, or restrict
  the trigger to trusted events.
- Over-privileged agent grant: scope the MCP server / `Bash(...)` rule down, or drop it.

**[4.2] Accept a specific finding (auditable override).** If a finding is a reviewed,
accepted risk, acknowledge it by **id** — this downgrades it from fail to a reported
warning. It never silently disables the gate; the acknowledgement is a committed file
that shows up in the diff and git history.

1. Get the id: `npx blastgate . --base <ref> --json` and copy the finding's `id`
   (shaped `entry:...=>sink:...`).
2. Commit `.blastgate/acknowledged.json`:

   ```json
   {
     "acknowledged": [
       { "id": "entry:fork-pr:.github/workflows/ci.yml#test=>sink:secret:AWS_SECRET_ACCESS_KEY",
         "reason": "reviewed 2026-08-05 — secret is read-only and scoped; accepted by @you" }
     ]
   }
   ```

3. Re-run: the acknowledged finding now shows as a warning and the gate passes. Any
   **un-acknowledged** fail finding still fails — you cannot blanket-disable the gate.

## [5] Provenance regression check (opt-in, network)

The one check that reaches the npm registry is off by default. Enable it with
`--provenance` (needs `--base` for a version baseline) to flag a dependency that lost
its npm attestations between versions. Keep it out of the fast offline hook path;
run it in CI or on demand.
