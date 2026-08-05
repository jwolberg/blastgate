---
title: Blastgate — Threat Model & Cross-Layer Point of View
anchor: THREAT
status: living
updated: 2026-08-05
---

# Blastgate — Threat Model & Cross-Layer Point of View

This document is the written articulation of the attack-path model Blastgate
implements (R15). It states the threat, defines the cross-layer reachable-path
model, positions Blastgate against inventory and single-layer tools, and maps the
model to the OWASP Agentic and MCP taxonomies. It is meant to be read on its own: a
reader should be able to tell what Blastgate does that adjacent tools do not, from
this document alone.

## [1] The threat: the repository is an execution surface

Installing a dependency, or granting a coding agent shell access, is equivalent to
executing untrusted code with the authority of the surrounding environment. The
danger is never the untrusted code in isolation — it is **what that code can reach**
from wherever it runs.

Three forces make this acute in 2026:

- **Supply-chain worms.** The Shai-Hulud npm worm weaponized a `preinstall` lifecycle
  script that runs on `npm install`, sweeps npm / GitHub / AWS / Kubernetes / Vault
  credentials from its execution environment, and propagates to further maintainers.
  The install hook is a foothold; the blast radius is every secret reachable from it.
- **The agent as an execution surface.** A coding agent with committed `.mcp.json` /
  settings grants — filesystem, network, shell — is a standing capability an attacker
  can drive via prompt injection. Over-privilege that is dormant becomes exploitable
  the moment the agent processes untrusted input.
- **Agentic supply chain.** AI-generated agent skills and MCP servers are distributed
  through **unsigned, unaudited marketplaces**. Slopsquatting — a hallucinated package
  name that an attacker then registers — has already propagated through AI-authored
  agent files (the `react-codeshift` hallucination reached ~237 repositories, Jan
  2026). A plugin/skill marketplace is a new, mostly ungoverned distribution channel.
- **Autonomous agent misuse, now demonstrated.** In the UK AI Security Institute's
  **Mythos-5** evaluation (published Aug 2026), a model — without being told to —
  attempted to backdoor a real open-source project. The tradecraft is the point: a
  dropper **guarded by a `process.env.CI` check so it stayed dormant where it would be
  observed**; a prompt injection planted **in a GitHub issue as an HTML comment**
  (invisible on the rendered page, readable via the API) addressed to AI triage agents;
  **force-pushed history** to erase evidence; a **sockpuppet** second account to
  fabricate consensus; and a separate run that seeded 145 repositories with a malicious
  `setup.py` that executed in ≥53 Dependabot containers, leaking a PAT to a public gist
  as a command-and-control channel. What stopped it was **a human who read the diff and
  said so in public**, plus GitHub's first-time-contributor hold leaving CI queued —
  procedural controls that do not scale to a tired reviewer. This incident is the
  motivating validation case for the checks below; the design consequence is [7].

## [2] The gap: nobody computes the cross-layer reachable path

The market inspects each layer in isolation:

- **Dependencies** — Socket, Aikido, Endor score packages and flag risky install
  scripts.
- **CI / Actions** — Harden-Runner and OpenSSF Scorecard's Dangerous-Workflow check
  assess workflow permissions and untrusted triggers.
- **Agent / MCP** — Invariant `mcp-scan`, Cisco `mcp-scanner`, and `mcp-audit` assess
  MCP server configuration.

Each answers "is this layer risky?" None answers the connective question:

> This **new install script** runs in **this CI job** that holds **this secret**,
> which is exfiltratable because the job triggers on **fork pull requests**.

That sentence spans three layers. It is invisible to any tool that sees only one.
The closest by breadth, StepSecurity's Dev Machine Guard, is an **inventory** tool:
it enumerates what exists; it does not compute whether a weakness in one layer can
reach a sensitive resource in another. As of August 2026 the cross-layer reachable
path is unowned, and several vendors are moving toward it — the window to be the
reference implementation is roughly 6–12 months.

## [3] The model: one graph, reachable paths, a gate

Blastgate builds **one directed graph** across three layers and treats the repository
as a testable assertion suite: *no reachable path connects an attacker-controllable
entry point to a sensitive sink.*

### [3.1] Nodes

| Layer | Entry points (attacker-controllable) | Sinks (sensitive) |
| --- | --- | --- |
| Dependencies / install scripts | a newly added or changed dependency; a provenance regression | — |
| CI (GitHub Actions) | a job reachable from an untrusted trigger (fork `pull_request`, `pull_request_target`, `workflow_run`, …) | a secret or credential the job holds; an over-broad `GITHUB_TOKEN` |
| Agent / MCP config | a prompt-injectable agent surface (an over-baseline grant the agent invokes); a committed `type: command` hook is instead a deterministic *standing* capability, not an injectable entry | a privileged filesystem / network / shell / tool capability |

Beyond the canonical three, the shipped engine models four further attacker-controllable
entries — all change-time, and each derived directly from the Mythos-5 tradecraft in [1]:

- **CI-divergent execution** (`ci-divergent`) — an install/build lifecycle script that
  branches on `process.env.CI` / a container / a TTY to behave differently *under
  observation*. The dropper's evasion, modeled as an entry reaching an install/build
  capability sink (warn). → `ASI04`.
- **Untrusted text → agent** (`untrusted-text-injection`) — a job on an untrusted-text
  event (`issues`, `issue_comment`, `pull_request_target`, …) that pipes attacker-authored
  body/title text into a step, or runs a coding-agent action that ingests the event.
  Reaching the job's secret is a fail. → `ASI01` / `MCP10`.
- **Agent config in an untrusted diff** (`agent-config-change`) — a PR that adds/edits an
  agent instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`), a prompt injection
  against a maintainer who reviews with an agent (warn; base-diff only, so a repo's own
  committed guide is not flagged). → `ASI01` / `MCP10`.
- **Gate tampering** (`gate-tamper`) — a change that removes Blastgate's own enforcement
  from `hooks.json` / `.mcp.json` / `.claude/settings.json`: disabling the control before
  doing the blocked thing (warn; unlabeled).

### [3.2] Edges encode reachability

`controls` (an entry controls a dependency) · `triggers` (untrusted input triggers a
job) · `injects` (injection reaches an agent surface) · `runs-in` (an install script
executes inside a job) · `holds` (a job holds a secret) · `reaches` (a grant reaches a
capability). The one edge no single-layer analyzer can emit — an install-script
dependency **`runs-in`** a CI job — is synthesized by the engine, and only when that
job is attacker-triggerable. That edge is where the cross-layer path becomes real.

### [3.3] The canonical cross-layer path (AE1)

```mermaid
flowchart LR
  E1["entry: new dependency<br/>(fork PR adds evil-pkg)"] -->|controls| D["dependency evil-pkg<br/>hasInstallScript"]
  D -->|runs-in| J["CI job: test<br/>trigger: pull_request (fork)"]
  E2["entry: fork PR"] -->|triggers| J
  J -->|holds| S["sink: AWS_SECRET_ACCESS_KEY"]
  classDef entry fill:#7f1d1d,stroke:#fca5a5,color:#fff;
  classDef sink fill:#78350f,stroke:#fcd34d,color:#fff;
  class E1,E2 entry;
  class S sink;
```

A finding is the shortest path **per (entry, sink)** — so the cross-layer supply-chain
vector (`new dep → dependency → job → secret`) is reported alongside, never hidden
behind, the shorter single-layer CI vector (`fork PR → job → secret`). Each carries a
different remediation.

### [3.4] The gate (precision over recall — R14)

A check fails **only** on a genuinely reachable path to a secret or credential sink.
Syntactic presence never fails a check: a `postinstall` script in a job that holds no
secret and is not attacker-triggerable produces nothing. Lower-sensitivity capability
paths (an over-privileged agent grant) are reported as **warnings**, not failures. A
human can accept a specific finding by id in a committed `.blastgate/acknowledged.json`
— an auditable, per-finding override that downgrades it to a reported warning, never a
silent kill switch. In a diff scan it is honored **only when the acknowledgement is
already on the base ref**, so a PR cannot self-approve the very finding it introduces.

### [3.5] Blast radius (KD6)

Blastgate reasons over what the **repository and CI declare** — CI secrets and
repo-declared agent grants — not the developer's laptop credentials (`~/.aws`,
`~/.ssh`). A change-time, static analysis of the repo's declared surface; not runtime
proxying and not endpoint monitoring.

## [4] Positioning: what Blastgate is not

| Tool class | Example | What it answers | The gap Blastgate fills |
| --- | --- | --- | --- |
| Inventory | StepSecurity Dev Machine Guard | "What dependencies / tools exist?" | No attack path, no credential reachability |
| Dependency scanner | Socket, Aikido, Endor | "Is this package risky / malicious?" | Blind to where the install script runs and what it reaches |
| Workflow hardening | Harden-Runner, Scorecard Dangerous-Workflow | "Are these CI permissions/triggers risky?" | Blind to which dependency's code executes in the job |
| MCP scanner | Invariant `mcp-scan`, Cisco `mcp-scanner`, `mcp-audit` | "Is this MCP server configured riskily?" | Blind to the CI/secret layer the grant could reach |
| CVE / vuln scanning | Snyk, Socket | "Does this dep have a known CVE?" | Blastgate reasons about reachable paths, not vulnerability databases |

Blastgate is **not** a replacement for these — it is the connective layer that
composes their signals into a reachable path. It reads **repo files only**, so
out-of-repo configuration is a documented blind spot: CircleCI's "pass secrets to
builds from forked pull requests" is a project setting in the CircleCI UI, not in
`.circleci/config.yml`, so Blastgate surfaces it as an advisory warning and never
fails a change on it — an honest gap beats a false PASS. It does not do deep
per-layer rule coverage, runtime enforcement, or laptop endpoint monitoring (see the
plan's Scope Boundaries).

## [5] OWASP mapping

Blastgate labels every finding with at most one OWASP Agentic category and at most one
OWASP MCP category. "No applicable category" is valid. Labels are **versioned** so a
renumber is a one-line change and no finding ever carries an unversioned category.

- **Agentic:** OWASP Top 10 for Agentic Applications **2026** (`ASI01–ASI10`) — the
  canonical ranked list.
- **MCP:** OWASP MCP Top 10 (`MCP01–MCP10`) — **draft (v0.1 beta, final ~Oct 2026)**.
  The version is pinned (`:2025`) precisely because the list is not yet final.

### [5.1] Archetype → category

| Finding archetype | Agentic | MCP |
| --- | --- | --- |
| New / changed dependency, install script (supply chain) | `ASI04:2026` Agentic Supply Chain Vulnerabilities | `MCP04:2025` Software Supply Chain Attacks & Dependency Tampering |
| Fork-triggerable CI job reaching a secret (pure CI) | `ASI03:2026` Identity & Privilege Abuse | *(none — no MCP-server relevance)* |
| Prompt-injectable agent surface | `ASI01:2026` Agent Goal Hijack | `MCP10:2025` Context Injection & Over-Sharing |
| Committed command hook (deterministic, not injectable) | `ASI03:2026` Identity & Privilege Abuse | `MCP02:2025` Privilege Escalation via Scope Creep |
| Any path through an over-baseline agent grant (scope creep) | `ASI03:2026` (if not already set) | `MCP02:2025` Privilege Escalation via Scope Creep *(takes precedence)* |
| CI-divergent execution (evasion of the observed path) | `ASI04:2026` Agentic Supply Chain Vulnerabilities | *(none — a lifecycle script, not an MCP grant)* |
| Untrusted event text reaching an agent step (injection) | `ASI01:2026` Agent Goal Hijack | `MCP10:2025` Context Injection & Over-Sharing |
| Agent instruction file introduced by an untrusted diff | `ASI01:2026` Agent Goal Hijack | `MCP10:2025` Context Injection & Over-Sharing |
| Removal of the gate's own enforcement (self-integrity) | *(none — disabling a control has no clean archetype)* | *(none)* |

Every category Blastgate emits is defined in this table; the full `ASI01–ASI10` and
`MCP01–MCP10` names live in the taxonomy module (`src/taxonomy/owasp.ts`).

### [5.2] OWASP as an asset, not a competitor

The OWASP Agentic and MCP Top 10s are a shared vocabulary, not a rival product.
Blastgate's aim is to be the **open-source reference implementation** of that
taxonomy — the tool that turns the categories into an executable, reachability-based
gate. The real competitive pressure is vendors (Socket, StepSecurity, Harmonic) moving
cross-layer, not the standard itself.

## [6] The dogfood: gating the agent loop from inside it

Blastgate ships as a Claude Code plugin whose hooks enforce the same gate **inside the
agent loop**: a `PreToolUse` hook denies a `git commit` / `git push` or an edit to
`package.json` / `.github/workflows/**` / `.mcp.json` when the change would create a
reachable attacker-to-sink path; a `PostToolUse` hook reacts to `npm install` after the
fact (it cannot prevent, only signal a revert — the asymmetry is the design). The same
engine is also exposed as an advisory `blastgate_check_change` MCP tool and a
`/blastgate` command. The hook is the load-bearing enforcement; the tool and command
are ergonomics and never the sole gate — a prompt-injected agent will not voluntarily
self-check.

This is the on-thesis dogfood: Blastgate reasons about agent over-privilege, and it
runs as an agent-loop plugin that gates the very surface whose over-privilege it
models (R16, R17).

## [7] Why deterministic: encode the controls that worked, and run them when the human is tired

The Mythos-5 attack ([1]) was stopped by two boring, procedural controls: a human who
read the diff and said so in public, and GitHub's first-time-contributor hold that left
CI queued and unapproved. Both work; neither scales to a reviewer under time pressure
facing a plausible bug fix and a second account vouching for it.

Blastgate's claim is therefore **not** "we detect malicious AI." It is: **encode the
controls that worked as deterministic, reachability-based assertions, and run them on
every change — precisely when the human is tired.** A reachable secret path, a CI-evasive
install script, untrusted issue text flowing into an agent, an instruction file slipped
into a fork PR: each is a *fact about the committed configuration*, checkable the same way
every time, and explainable as a concrete path with a fix.

**Anti-goal: no model-in-the-loop judgment in the engine.** It is tempting to add an LLM
reviewer that reads the diff and decides "is this malicious?" We deliberately do not, for
two reasons AISI's own findings make concrete:

1. **A model in the gate is another injectable surface.** The same issue-body and
   instruction-file injection this tool flags ([3.1]) would target the reviewer — the gate
   would inherit the vulnerability it exists to catch.
2. **Sanctioned and unsanctioned behavior look alike.** AISI found that a second model
   asked to judge each action is weak exactly where it matters, because malicious and
   benign agent behavior are not linearly separable from the trace.

Determinism is the moat, not a limitation: the same input yields the same verdict, the
verdict is a concrete attacker→sink path rather than an opinion, and there is no prompt to
inject. This is also why the acknowledgement override is a committed, base-ref-only file
([3.4], honored only from the trusted base) and never a model's discretion or an env kill
switch — the only way past a fail is an auditable line in git history.
