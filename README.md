# Blastgate

**The supply-chain attacks landing in 2026 don't live inside any one layer — they
live in the path _between_ layers, where nothing is looking.** Installing a dependency
runs its lifecycle scripts with the authority of wherever they run; handing a coding
agent shell access is a standing capability an attacker can drive. A repository is an
**execution surface**, and its real danger is never a risky artifact in isolation — it
is the **reachable route** from something an attacker controls to something sensitive:
a malicious `preinstall` that runs in a CI job holding an AWS key on fork-triggered
pull requests; an over-broad agent grant sitting on a prompt-injectable surface.

Every existing scanner sees one layer and stops at its edge — dependency tools score
the package, workflow tools audit the job, MCP scanners inspect the agent grant. None
computes the connective path that turns three separate "maybe" signals into one
demonstrable attack. **That path is the gap. Blastgate is the gate that computes it.**

Blastgate models your dependencies, your CI, and your agent/MCP configuration as **one
directed graph** and asserts a single property on every change: _no reachable path
connects an attacker-controllable entry point to a sensitive sink._ It reports a
finding only when there is a demonstrable path — a new install script that runs in a
fork-triggerable job that holds an AWS key — never merely a risky-looking pattern. A
repository with no such path passes; a failure names the concrete path, the sink it
reaches, why it is reachable, a fix, and the OWASP category.

It ships as a CI/PR gate, a local CLI, a GitHub Action, and a Claude Code plugin
(enforcement hooks + an MCP self-check tool + a `/blastgate` command) — all driven by
one engine, so every surface produces identical findings.

## Who it's for

- **Teams whose CI holds secrets and accepts external pull requests.** Fork-triggered
  workflows with credential access are the highest-value target in most repos;
  Blastgate is the gate that fails the PR before an untrusted change can reach them.
- **Teams adopting coding agents / MCP servers.** Committed `.mcp.json` and
  `.claude/settings.json` grants are a blast radius most teams never audit. Blastgate
  measures it and flags over-privilege against a least-privilege baseline.
- **npm / PyPI / RubyGems maintainers** worried about supply-chain compromise —
  install-time execution and newly introduced dependencies, evaluated offline from the
  lockfile (plus opt-in npm provenance regressions).
- **Security engineers** who want a gate with a low false-positive rate: it fails only
  on a reachable secret/credential path, and warns (does not fail) on lower-severity
  capability paths.

## Why it's needed — the threats it catches

Each row below is a live 2026 attack shape, and each is invisible to any single-layer
tool because the danger is the _connective_ path — the row's middle column — not any
one artifact on it:

| Threat                                                                                                                               | The concrete path Blastgate catches                                                                                                                         | OWASP             |
| ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| **Install-script supply-chain worm** (e.g. Shai-Hulud: a `preinstall` stealer that sweeps npm/GitHub/AWS/Vault creds and propagates) | A newly added dependency's install script runs in a `pull_request_target` job that holds `AWS_SECRET_ACCESS_KEY`                                            | `ASI04` / `MCP04` |
| **CI `pwn-request`**                                                                                                                 | A `pull_request_target` (or `workflow_run` / issue-comment) job runs untrusted code while holding secrets or an over-broad `GITHUB_TOKEN`                   | `ASI03`           |
| **npm provenance regression** (the CVE-2025-54313 shape)                                                                             | A dependency that _had_ npm attestations and silently _lost_ them between versions — a strong compromise signal (opt-in, `--provenance`)                    | `ASI04` / `MCP04` |
| **Over-privileged coding agent**                                                                                                     | A committed MCP server rooted at `/` or an unrestricted `Bash(*)` / wrapper-bypass grant — a prompt-injectable path to out-of-repo filesystem/network/shell | `ASI01` / `MCP02` |
| **Slopsquatting & unsigned agent marketplaces**                                                                                      | A newly introduced dependency or agent grant from an unaudited source, evaluated for reachability rather than trusted by name                               | `ASI04` / `MCP02` |

Each of these is named and modeled in [`docs/threat-model.md`](docs/threat-model.md),
which also maps every OWASP category Blastgate emits.

### What a finding looks like

```text
✗ FAIL  added dependency evil-pkg@1.0.0 → evil-pkg@1.0.0 → .github/workflows/ci.yml#test → AWS_SECRET_ACCESS_KEY
      sink: credential AWS_SECRET_ACCESS_KEY  [ASI04:2026, MCP04:2025]
      why:  New or changed dependency evil-pkg@1.0.0 declares an install script that executes in job
            .github/workflows/ci.yml#test, which a fork PR triggers via pull_request_target (base-repo
            context, so it carries repo secrets) and which holds credential AWS_SECRET_ACCESS_KEY,
            which the script can exfiltrate.
      fix:  Gate lifecycle scripts in that job (e.g. run `npm ci --ignore-scripts`) or remove
            AWS_SECRET_ACCESS_KEY from .github/workflows/ci.yml#test.
```

## How it works

Blastgate builds a single graph from the repository's manifests, lockfile, CI
workflows, and agent/MCP configuration.

- **Dependency / install layer** — install-time execution and newly added or changed
  dependencies across **npm** (lifecycle scripts, `package-lock.json` / `yarn.lock` /
  `pnpm-lock.yaml` diff, `.npmrc`, provenance regressions), **Python** (`setup.py`,
  `requirements.txt` diff), and **RubyGems** (`Gemfile.lock` diff, native-extension
  gems). A dependency an untrusted change introduces that runs code at install is the
  shared shape across all three. (`yarn.lock` / `pnpm-lock.yaml` omit npm's
  `hasInstallScript` flag, so an added dep is treated install-capable — precision comes
  from reachability, as with gems.)
- **CI layer** — which jobs execute install/build steps, which secrets and token
  permissions each job holds, and which jobs are triggerable by untrusted input —
  across **GitHub Actions** (`pull_request_target` and other secret-bearing events — a
  plain fork `pull_request` gets a read-only token and no secrets, so it is not a
  credential path), **GitLab CI**
  (merge-request pipelines, CI/CD variables), and **CircleCI** (advisory only: its
  forked-PR-secret exposure is a project setting outside the repo — Blastgate surfaces
  it rather than falsely passing; see the threat model).
- **Agent / MCP layer** — the filesystem, network, shell, and tool capabilities granted
  by committed agent/MCP configuration, checked against a least-privilege baseline.

Edges encode reachability: an install script executes within a job, a job holds a
secret, an agent grant reaches a capability. A finding is the shortest path per (entry,
sink) from an attacker-controllable entry point — a new or modified dependency, an
untrusted trigger, or a prompt-injectable agent surface — to a sensitive sink. Findings
are ranked by sink sensitivity and entry-point exposure, and each is labeled with its
OWASP Agentic Top 10 (2026) and MCP Top 10 (draft) category.

## Why reachability

Precision is the primary design constraint. A check fails only on a genuinely reachable
path; the presence of a pattern alone does not produce a finding. A `postinstall` script
in a job that holds no secrets and is not triggerable by untrusted input is not
reported. This keeps findings actionable and avoids the false-positive rate of
pattern-matching tools. A human can accept a finding via a committed
`.blastgate/acknowledged.json` (by id) or the more expressive `.blastgate/policy.json`
(accept by finding id, sink identity, or archetype, with an optional review-by date) —
an auditable exception that downgrades a finding to a reported warning, never a silent
kill switch: blanket/wildcard rules are rejected at parse, and a rule introduced by the
same change is ignored (a PR cannot self-approve its own finding).

## Positioning

Inventory tools (StepSecurity Dev Machine Guard) enumerate what exists. Single-layer
tools assess one layer each — dependencies (Socket, Aikido, Endor), CI workflows
(Harden-Runner, OpenSSF Scorecard), or MCP configuration (Invariant `mcp-scan`, Cisco
`mcp-scanner`). None computes the connective, cross-layer reachable path. Blastgate is
that connective layer and does not replace the per-layer scanners — it composes their
signals into a path. The full tool-by-tool contrast is in
[`docs/threat-model.md`](docs/threat-model.md).

## Interfaces

- **CI/PR gate** — exits non-zero on a reachable path and surfaces the finding on the
  pull request.
- **Local CLI** — runs against the same repository and produces the same findings.
- **Claude Code plugin** (`plugin/`) — enforces the same gate inside an agent session
  as deterministic hooks on commit and dependency installation, and exposes an advisory
  tool the agent can call to evaluate a proposed change before it acts. See
  [`plugin/README.md`](plugin/README.md).

## Usage

### Where it fits in your workflow

Blastgate is the same engine run at three moments, each catching a reachable path
earlier than the last:

1. **Local, while you work** — the Claude Code plugin gates a `git commit` /
   `git push` or an `npm install` that would open a path, so it never leaves your
   machine. Run `npx blastgate .` by hand anytime for the same check.
2. **On the pull request** — the GitHub Action runs on every `pull_request`, fails
   the check on a reachable path, and posts the finding on the PR.
3. **At pre-merge review** — the same report (`--format md`) is the job summary a
   reviewer reads before approving, so the merge decision sees the attack path.

One engine and one `Finding` shape back all three, so a change that passes locally
passes in CI for the same reason — the surfaces cannot disagree.

### Local CLI

```bash
npx blastgate .                 # scan the current repo; exits non-zero on a fail verdict
npx blastgate . --base main     # add diff signals (new deps, .npmrc changes) vs a ref
npx blastgate . --provenance    # opt-in npm provenance-regression check (needs --base)
npx blastgate . --json          # emit the findings array as JSON (has each finding `id`)
npx blastgate . --format md      # human-readable markdown report (share it, or > report.md)
npx blastgate . --advisories     # opt-in CVE/advisory enrichment of reachable deps (never gates)
npx blastgate . --record runs/   # append a run record for the trend dashboard
npx blastgate report runs/ --out trend.html   # static HTML trend over recorded runs
```

A fail verdict (a reachable path to a secret or credential) exits non-zero; a clean
repo or warn-only findings (lower-sensitivity capability paths) exit zero. The
`--format md` report leads with the verdict and a "where this runs" banner, gives one
section per finding (the attacker→sink path, why it is reachable, the fix, and the
OWASP label), and closes with what to do next — it is the same report the Action posts
as its PR job summary.

### GitHub Action

Runs the same engine as the CLI — findings are identical (asserted by test). It
defaults the diff base to the pull request's base ref, so change signals light up
automatically, and surfaces findings as PR annotations plus a job-summary report (the
same output as `blastgate --format md`).

```yaml
# .github/workflows/blastgate.yml
name: Blastgate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # so the base ref is available for diff signals
      - uses: jwolberg/blastgate@v0
```

## Scope

**Supported today.** One engine, one finding shape across all surfaces:

- **Ecosystems** — npm (lifecycle scripts, `package-lock.json` / `yarn.lock` /
  `pnpm-lock.yaml` diff, `.npmrc`, provenance), Python (`setup.py`, `requirements.txt`
  diff), RubyGems (`Gemfile.lock` diff).
- **CI providers** — GitHub Actions and GitLab CI (full gate), CircleCI (advisory only —
  the fork-secret toggle is out-of-repo).
- **Agent / MCP** — committed grants checked against a least-privilege baseline.
- **Exceptions** — `.blastgate/policy.json` / `acknowledged.json` (auditable, specific,
  self-approval-guarded).
- **Opt-in enrichment** — npm provenance regressions (`--provenance`) and CVE/GHSA
  advisories on reachable deps (`--advisories`), deliberately **enrichment, not gating**:
  Blastgate fails only on a reachable path, never because a package is known-bad by name.
- **History** — per-run records (`--record`) and a static HTML trend (`blastgate report`).

**On the roadmap.** Maven / Gradle (build-script execution — the design spike recommends
GO, see [`docs/learnings/`](docs/learnings)); more Python lockfiles (poetry / uv / Pipfile);
a hosted collaboration dashboard (the current dashboard is local/static only).

**Out of scope.** Analysis of deployed or running targets. See [`docs/plans/`](docs/plans)
for the product plan, [`docs/threat-model.md`](docs/threat-model.md) for the model, and
[`docs/implementation-notes.md`](docs/implementation-notes.md) for recorded decisions.

## Status

Functional across all surfaces, ecosystems, and CI providers. One engine backs the CLI
(`blastgate`), the GitHub Action, the Claude Code plugin hooks, and the
`blastgate_check_change` MCP self-check. Ecosystems (npm, Python, RubyGems), CI providers
(GitHub, GitLab, advisory CircleCI), the exception-policy engine, opt-in provenance and
CVE-advisory enrichment, and the run-record trend report are all wired, and the engine is
covered by unit tests plus a fixture-repo regression suite (a true-positive and
true-negative repo per shipped check). Remaining before a public release: publishing the
Action's built artifact for third-party consumers.

## License

Apache-2.0.
