# Architecture

> Evergreen system overview — **edit in place** (unlike append-only ADRs). Keep
> it matching the shipped code; `/session-end`'s consistency check and
> `/document-audit` flag drift. Headings carry `[N]` / `[N.M]` anchors so any
> part is greppable (`grep -n "\[2\]" docs/architecture.md`) and referenceable
> as `ARCH#2`.

anchor: ARCH

## [1] Overview

Blastgate is a static, offline gate that models a repository's dependencies, CI
workflows, and agent/MCP configuration as one directed graph. It reports a finding only
for a reachable path from an attacker-controllable entry point to a sensitive sink, and
fails only when that path is a proven exploit with `file:line` evidence
([`threat-model.md` §3.4](threat-model.md#34-the-gate-precision-over-recall--r14)). One
engine backs every surface: the CLI, the GitHub Action, the Claude Code plugin hooks,
and the MCP self-check. The surfaces cannot disagree because none of them re-implements
the engine.

## [2] Components

All source lives under `src/`. The public library entry is `src/index.ts`.

### [2.1] Layer analyzers — `src/analyzers/`

Pure functions from collected file contents to an `AnalyzerResult` (nodes, intra-layer
edges, diagnostics; `src/analyzers/types.ts`). They never touch the filesystem or the
network, and never add cross-layer edges.

| Analyzer                 | Reads                                                             | Emits                                                                                                                                                      |
| ------------------------ | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `deps/`                  | `package.json`, `package-lock.json`, `.npmrc` (+ base-ref copies) | new/changed dependencies with install scripts; `.npmrc` hygiene. `deps/provenance.ts` is the opt-in, network-backed provenance check                       |
| `jsdeps/`                | `yarn.lock`, `pnpm-lock.yaml`                                     | added/bumped deps, treated as install-capable (no `hasInstallScript` flag)                                                                                 |
| `pydeps/`, `rubygems/`   | `setup.py`, `requirements.txt`; `Gemfile.lock`                    | install-time execution in Python and RubyGems                                                                                                              |
| `ci/`                    | `.github/workflows/*.yml`                                         | CI jobs, their secrets and token permissions, fork-PR and untrusted-text entries, agent-step assessments (see [2.2])                                       |
| `gitlabci/`, `circleci/` | `.gitlab-ci.yml`, `.circleci/config.yml`                          | MR-triggerable jobs holding CI/CD variables; CircleCI is advisory only                                                                                     |
| `agent/`                 | `.mcp.json`, `.claude/settings.json`, agent instruction files     | agent/MCP grants by capability class (filesystem, network, shell, tool); privileged command hooks; review-time instruction-file changes (`config-diff.ts`) |
| `exec/`                  | the repo's own lifecycle scripts                                  | CI-divergent execution (code that behaves differently under CI), warn-only                                                                                 |
| `integrity/`             | Blastgate's own gate config                                       | removal of Blastgate's enforcement by the change (`gate-tamper`)                                                                                           |

### [2.2] The GitHub Actions analyzer — `src/analyzers/ci/`

The largest analyzer, and the source of most fail-eligible entries.

- `parse.ts` — workflow parsing: trigger normalization, permission resolution, secret
  references, actor and permission guards, untrusted-checkout and install-step
  detection.
- `injection.ts` — where attacker-authored event text lands. Each reference is
  classified into a sink class: `execution` (inside `run:` or a github-script
  `script:`, or an unquoted artifact splice in a `workflow_run` job), `agent-ingested`,
  `action-input`, or `unrecognized`. Env-passed and compared values produce nothing.
  Only `execution` can fail directly. `relayedTextEvents()` resolves `workflow_run`
  chains across files (by upstream `name:`, transitively), so an agent job handed an
  issue by an issue-triggered upstream is judged with those relayed events (0067).
- `agents.ts` — cited, versioned profiles of AI agent actions (`claude-code-action`,
  `codex-action`, `run-gemini-cli`, plus tool-less LLM steps such as
  `actions/ai-inference`). Each agent step is assessed against the Agents Rule of Two:
  direct trigger, sensitive access, and exfiltration, each `held`, `missing`, or
  `unknown`, with a reason. A ref outside the profile's range is `unknown` and can only
  warn; a SHA pin resolves through `agent-release-shas.ts` (generated by
  `scripts/refresh-agent-shas.sh`) to its release before the range check (0065). Only
  explicitly granted tools count; a wildcard-scoped shell (`Bash(cmd:*)`) still reads
  env through `$SECRET` expansion but is not a general shell (0063/0064). The result
  rides on the entry node as `AgentAssessment` (`src/graph/types.ts`), and a fail also
  requires the path's own sink to be a credential the agent can read.
- `locate.ts` — maps a YAML key path to its source line through the parser (never a
  text search), so fail evidence cites the right step. A missing location demotes the
  finding to warn instead of crashing.

### [2.3] Graph — `src/graph/`

- `types.ts` — the node model: `entry`, `dependency`, `ci-job`, `agent-grant`, `sink`.
  Entry kinds include `new-dependency`, `fork-pr`, `untrusted-text-injection`,
  `injectable-agent-surface`, `agent-config-change`, `ci-divergent`, `privileged-hook`,
  and `gate-tamper`. Sinks are `secret`, `credential`, or `privileged-capability`.
- `graph.ts` — `AttackGraph`, a thin wrapper over graphology.
- `reachability.ts` — one single-source BFS per entry, keeping the shortest path per
  (entry, sink).
- `caps.ts` — a cost ceiling (`|entries| × (|nodes| + |edges|)`). Above it the search is
  skipped and the run fails closed to `unknown`.
- `ranking.ts` — severity score from sink sensitivity and entry exposure, plus OWASP
  labels (`src/taxonomy/`).

### [2.4] Engine — `src/engine/`

- `build.ts` — runs the analyzers over `EngineInputs`, merges their results into one
  graph, and adds the cross-layer edges (an install-script dependency `runs-in` a CI job
  that installs and is attacker-triggerable). Repository visibility (`public`,
  `private`, `unknown`) enters here for the agent exfiltration leg.
- `checks.ts` — turns reachable paths into `Finding`s: path labels, a reason and
  remediation derived from the path's shape, and evidence. `proof()` decides whether a
  path is a proven exploit. Only these entries can produce a fail: untrusted text in an
  `execution` sink, a fork PR whose job runs code after checking out the PR head, a new
  dependency whose install script runs in such a job, a GitLab MR pipeline job, or an
  agent step with all three Rule-of-Two legs held against a credential its tools can
  read.
- `acknowledge.ts`, `policy.ts` — the committed exception files
  (`.blastgate/acknowledged.json`, `.blastgate/policy.json`). A match downgrades fail to
  warn. Blanket rules are rejected at parse, and only rules already on the base ref are
  honored.
- `gate.ts` — `runEngine()`, the single entry point every surface calls (build → checks
  → exceptions → verdict). Verdict precedence is `fail > unknown > warn > pass`;
  `gateBlocks()` blocks on `fail` or `unknown`.

### [2.5] Findings — `src/findings/finding.ts`

The stable `Finding` shape all surfaces render: id, tier, score, path, entry, sink,
reason, remediation, OWASP labels, and optional `evidence` (`file`, `line`, `capability`,
and on fails a fixed illustrative `payload`). Payloads are constants per sink class,
never derived from repo content. `withoutPayload()` strips them for every surface except
local text output and `--json --include-payloads`.

### [2.6] Surfaces

- **CLI** — `src/cli/`. `index.ts` parses flags and dispatches. `collect.ts` reads a
  checkout into `EngineInputs` through the `RepoFs` port (`node-fs.ts` is the Node
  fs + `git show <ref>:<path>` adapter). `render.ts` produces text, JSON, and markdown.
- **GitHub Action** — `action.yml` → `src/action/index.ts`. Defaults `--base` to the PR
  base ref, reads `repository.private` from the event payload for visibility, writes
  annotations and a markdown job summary. No payloads.
- **Claude Code plugin** — `plugin/`. Hooks (`plugin/hooks/hooks.json`) call
  `blastgate check --gate <phase>` (`src/cli/gate.ts`): `PreToolUse` gates can deny a
  commit, push, or manifest/workflow/MCP-config edit; the `PostToolUse` install gate can
  only react. `src/cli/shell-guard.ts` classifies shell commands so wrapped or chained
  commands still reach the gate and verification bypasses are denied.
- **MCP self-check** — `src/mcp/` serves `blastgate_check_change` over stdio. Advisory
  only; the hooks are the enforcement layer.
- **Run history** — `src/report/`. `--record <dir>` writes a versioned run record;
  `blastgate report <dir>` renders a static HTML trend.

## [3] Data flow

1. A surface resolves the repo path, the optional base ref, and visibility (`--public`
   on the CLI; the event payload in the Action).
2. `collect.ts` reads each layer's files at head and, with a base ref, at base. It also
   loads exception files, keeping only base-ref rules and reporting new ones as ignored.
3. With `--provenance` or `--advisories`, the CLI makes the only network calls (npm
   packuments, OSV) and passes the results in. The engine core stays offline.
4. `runEngine()` builds the graph: analyzers emit nodes and edges, the engine synthesizes
   cross-layer edges.
5. If the reachability cost exceeds the cap, the run is `unknown`. Otherwise BFS finds
   the shortest path per (entry, sink).
6. `checks.ts` ranks, labels, describes, and attaches evidence to each path. A path is
   `fail` only when the sink is a secret or code-write credential, the entry is
   fail-eligible, and evidence locates it; everything else is `warn`.
7. Exceptions downgrade matched fails. The verdict is computed and the surface renders
   it, stripping payloads from any shareable output.

## [4] Key decisions

Accepted ADRs live in [`decisions/`](decisions) (ADR-0002: the agent Rule-of-Two
verdict). Other load-bearing decisions live in the plans' KTD sections and in
[`implementation-notes.md`](implementation-notes.md):

- **One engine, one finding shape** (KTD10) — every surface calls `runEngine()`; parity
  is asserted by `test/action.parity.test.ts`.
- **Offline core** (KTD6) — network enrichment is opt-in, done by the CLI, and never
  gates.
- **Fail only on a proven exploit** — Precision Core plan,
  [`plans/2026-09-29-001-feat-precision-core-plan.md`](plans/2026-09-29-001-feat-precision-core-plan.md).
  Contract in [`threat-model.md` §3.4](threat-model.md#34-the-gate-precision-over-recall--r14).
- **Agents judged by the Rule of Two** — agent-in-CI plan,
  [`plans/2026-10-01-001-feat-agent-in-ci-model-plan.md`](plans/2026-10-01-001-feat-agent-in-ci-model-plan.md).
- **Fail closed** (0020) — an un-evaluable layer or an over-cap graph is `unknown`,
  which blocks in CI.
- **No kill switch** (KTD12) — the only way past a fail is a specific, committed,
  base-ref exception.
- **No payloads on public surfaces** (0049 / R10).

Evidence for the precision contract: the 50-repo re-scans in
[`evaluations/`](evaluations) (2026-09-29 and 2026-10-01).

## [5] External dependencies & services

- **Runtime libraries** — `graphology` + `graphology-shortest-path` (graph and BFS),
  `yaml` (workflow parsing with source positions). See `package.json`.
- **npm registry** — packuments for `--provenance` (`src/registry/packument.ts`).
- **OSV** — CVE/GHSA advisories for `--advisories` (`src/registry/osv.ts`,
  `src/enrichment/advisories.ts`).
- **git** — `git show` for base-ref reads, through `src/cli/node-fs.ts`.

Nothing else is called. Release and rollout steps are in [`runbooks/`](runbooks).

## [6] Conventions

- **Analyzers are pure emitters.** No I/O, no cross-layer edges; those belong to
  `collect.ts` and `build.ts`.
- **Every fail carries evidence.** A new fail-eligible path needs a source line from
  `locate.ts`; without one it warns.
- **Unknown is not missing.** Anything Blastgate cannot read from configuration (an
  unprofiled agent ref, unreadable visibility) is `unknown` and may only warn.
- **Fixture pairs prove each fail class.** `test/fixtures/` holds a true-positive and a
  true-negative repo per check; `test/engine.e2e.test.ts` requires proof on every fail.
- **Ticket ids in comments.** Code comments cite the ticket (`0057`) or plan item
  (`R5`, `KTD6`) that introduced a rule, so the reasoning can be traced.
