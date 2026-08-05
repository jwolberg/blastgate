# Blastgate

Blastgate is a static analysis tool that identifies reachable attack paths across a
repository's dependency supply chain, CI configuration, and committed agent/MCP
configuration. It reports a finding only when an attacker-controllable entry point
has a concrete path to a sensitive sink such as a secret or credential. It runs as a
CI/PR gate and as a local command-line tool.

## Purpose

Installing a dependency, or granting a coding agent execution access, runs untrusted
code with the authority of the surrounding environment. Existing tools evaluate each
layer in isolation: dependency scanners assess packages, workflow-hardening tools
assess CI permissions, and agent/MCP scanners assess agent configuration. None of
them determines whether a weakness in one layer can reach a sensitive resource in
another. Blastgate addresses that gap by evaluating reachability across all three
layers, so a finding represents a demonstrable path rather than the presence of a
risky pattern.

## How it works

Blastgate builds a single graph from the repository's manifests, lockfile, CI
workflows, and agent/MCP configuration.

- **Dependency / install layer** — lifecycle scripts (`preinstall`, `install`,
  `postinstall`), newly added or changed dependencies, registry and `.npmrc`
  changes, and npm provenance regressions.
- **CI layer** — which jobs execute install or build steps, which secrets and token
  permissions each job holds, and which jobs are triggerable by untrusted input
  (for example `pull_request_target` or pull requests from forks).
- **Agent / MCP layer** — the filesystem, network, shell, and tool capabilities
  granted by committed agent/MCP configuration.

Edges encode reachability: an install script executes within a job, a job holds a
secret, an agent grant reaches a capability. A finding is the shortest path from an
attacker-controllable entry point — a new or modified dependency, an untrusted
trigger, or a prompt-injectable agent surface — to a sensitive sink. Findings are
ranked by sink sensitivity and entry-point exposure, and each is labeled with its
OWASP Agentic Top 10 (2026) and MCP Top 10 category.

Each check is a pass/fail assertion. A repository with no reachable path passes. A
failure reports the path, the sink it reaches, the reason it is reachable, and a
remediation.

## Why reachability

Precision is the primary design constraint. A check fails only on a genuinely
reachable path; the presence of a pattern alone does not produce a finding. For
example, a `postinstall` script in a job that holds no secrets and is not triggerable
by untrusted input is not reported. This keeps findings actionable and avoids the
high false-positive rate of pattern-matching tools.

## Interfaces

- **CI/PR gate** — exits non-zero on a reachable path and surfaces the finding on the
  pull request.
- **Local CLI** — runs against the same repository and produces the same findings.
- **Claude Code plugin** (`plugin/`) — runs the same checks inside an agent session
  as deterministic hooks on commit and dependency installation, and exposes a tool
  the agent can call to evaluate a proposed change before it is applied. See
  [`plugin/README.md`](plugin/README.md).

## Usage

### Local CLI

```bash
npx blastgate .                 # scan the current repo; exits non-zero on a fail verdict
npx blastgate . --base main     # add diff signals (new deps, .npmrc changes) vs a ref
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

npm and GitHub Actions. Other package ecosystems, other CI providers, and analysis of
deployed or running targets are out of scope for v1. See [`docs/plans/`](docs/plans)
for the product plan and [`docs/implementation-notes.md`](docs/implementation-notes.md)
for recorded decisions.

## Status

Early development, but functional across all surfaces. The reachability engine, the
local CLI (`blastgate`), the GitHub Action, the Claude Code plugin hooks, and the
`blastgate_check_change` MCP self-check all share one engine implementation. A
reachable secret/credential path fails the gate; a human can accept a specific finding
by id in a committed `.blastgate/acknowledged.json` (an auditable override that
downgrades it to a reported warning — never a silent kill switch). The opt-in npm
provenance-regression check (`--provenance`, the one network-touching check) is wired
too. Still to come: a fixture-repo test suite and the threat-model document.

## License

Apache-2.0.
