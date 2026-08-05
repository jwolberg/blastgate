# Blastgate

**Blastgate fails a change when it opens a reachable path from something an attacker
controls to something sensitive — across your dependencies, your CI, and your agent
configuration at once.** It is a change-time security gate that reports a finding only
when there is a demonstrable path (a new install script that runs in a
fork-triggerable job that holds an AWS key), never merely a risky-looking pattern.

It ships as a CI/PR gate, a local CLI, a GitHub Action, and a Claude Code plugin
(enforcement hooks + an MCP self-check tool + a `/blastgate` command) — all driven by
one engine, so every surface produces identical findings.

## What it is

A repository is an execution surface. Installing a dependency runs its lifecycle
scripts with the authority of the environment they run in; handing a coding agent
shell or filesystem access is a standing capability an attacker can drive. Blastgate
models that surface as **one directed graph** across three layers, and asserts a single
property: *no reachable path connects an attacker-controllable entry point to a
sensitive sink.* A repository with no such path passes; a failure names the concrete
path, the sink it reaches, why it is reachable, a fix, and the OWASP category.

## Who it's for

- **Teams whose CI holds secrets and accepts external pull requests.** Fork-triggered
  workflows with credential access are the highest-value target in most repos;
  Blastgate is the gate that fails the PR before an untrusted change can reach them.
- **Teams adopting coding agents / MCP servers.** Committed `.mcp.json` and
  `.claude/settings.json` grants are a blast radius most teams never audit. Blastgate
  measures it and flags over-privilege against a least-privilege baseline.
- **npm package maintainers** worried about supply-chain compromise — install-script
  behavior and npm provenance regressions, evaluated offline from the lockfile.
- **Security engineers** who want a gate with a low false-positive rate: it fails only
  on a reachable secret/credential path, and warns (does not fail) on lower-severity
  capability paths.

## Why it's needed — the threats it catches

Existing tools each see one layer. None computes the *connective* path that spans
layers, which is exactly where these real attacks live:

| Threat | The concrete path Blastgate catches | OWASP |
| --- | --- | --- |
| **Install-script supply-chain worm** (e.g. Shai-Hulud: a `preinstall` stealer that sweeps npm/GitHub/AWS/Vault creds and propagates) | A newly added dependency's install script runs in a fork-triggerable job that holds `AWS_SECRET_ACCESS_KEY` | `ASI04` / `MCP04` |
| **CI `pwn-request`** | A `pull_request_target` / fork `pull_request` job runs untrusted code while holding secrets or an over-broad `GITHUB_TOKEN` | `ASI03` |
| **npm provenance regression** (the CVE-2025-54313 shape) | A dependency that *had* npm attestations and silently *lost* them between versions — a strong compromise signal (opt-in, `--provenance`) | `ASI04` / `MCP04` |
| **Over-privileged coding agent** | A committed MCP server rooted at `/` or an unrestricted `Bash(*)` / wrapper-bypass grant — a prompt-injectable path to out-of-repo filesystem/network/shell | `ASI01` / `MCP02` |
| **Slopsquatting & unsigned agent marketplaces** | A newly introduced dependency or agent grant from an unaudited source, evaluated for reachability rather than trusted by name | `ASI04` / `MCP02` |

Each of these is named and modeled in [`docs/threat-model.md`](docs/threat-model.md),
which also maps every OWASP category Blastgate emits.

### What a finding looks like

```text
✗ FAIL  added dependency evil-pkg@1.0.0 → evil-pkg@1.0.0 → .github/workflows/ci.yml#test → AWS_SECRET_ACCESS_KEY
      sink: credential AWS_SECRET_ACCESS_KEY  [ASI04:2026, MCP04:2025]
      why:  New or changed dependency evil-pkg@1.0.0 declares an install script that executes in job
            .github/workflows/ci.yml#test, which is triggered by untrusted input (fork PRs) and holds
            credential AWS_SECRET_ACCESS_KEY, which the script can exfiltrate.
      fix:  Gate lifecycle scripts in that job (e.g. run `npm ci --ignore-scripts`) or remove
            AWS_SECRET_ACCESS_KEY from .github/workflows/ci.yml#test.
```

## How it works

Blastgate builds a single graph from the repository's manifests, lockfile, CI
workflows, and agent/MCP configuration.

- **Dependency / install layer** — lifecycle scripts (`preinstall`, `install`,
  `postinstall`), newly added or changed dependencies, registry and `.npmrc` changes,
  and npm provenance regressions.
- **CI layer** — which jobs execute install/build steps, which secrets and token
  permissions each job holds, and which jobs are triggerable by untrusted input (for
  example `pull_request_target` or pull requests from forks).
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
pattern-matching tools. A human can accept a specific finding by id in a committed
`.blastgate/acknowledged.json` — an auditable, per-finding override that downgrades it
to a reported warning, never a silent kill switch.

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

### Local CLI

```bash
npx blastgate .                 # scan the current repo; exits non-zero on a fail verdict
npx blastgate . --base main     # add diff signals (new deps, .npmrc changes) vs a ref
npx blastgate . --provenance    # opt-in npm provenance-regression check (needs --base)
npx blastgate . --json          # emit the findings array as JSON
```

A fail verdict (a reachable path to a secret or credential) exits non-zero; a clean
repo or warn-only findings (lower-sensitivity capability paths) exit zero.

### GitHub Action

Runs the same engine as the CLI — findings are identical (asserted by test). It
defaults the diff base to the pull request's base ref, so change signals light up
automatically, and surfaces findings as PR annotations plus a job-summary table.

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

## Scope (v1)

npm and GitHub Actions. Other package ecosystems, other CI providers, CVE/known-vuln
scanning, and analysis of deployed or running targets are out of scope for v1. See
[`docs/plans/`](docs/plans) for the product plan, [`docs/threat-model.md`](docs/threat-model.md)
for the model, and [`docs/implementation-notes.md`](docs/implementation-notes.md) for
recorded decisions.

## Status

Functional across all surfaces. One engine backs the CLI (`blastgate`), the GitHub
Action, the Claude Code plugin hooks, and the `blastgate_check_change` MCP self-check;
the opt-in provenance-regression check is wired; and the engine is covered by a
fixture-repo regression suite (a true-positive and true-negative repo per shipped
check). Remaining before a public release: publishing the Action's built artifact for
third-party consumers.

## License

Apache-2.0.
