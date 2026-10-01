---
name: Blastgate
last_updated: 2026-10-01
---

# Blastgate Strategy

## Target problem

Teams are wiring AI coding agents into CI, where a single comment from a stranger can steer an agent that holds secrets. It's hard because the danger is a cross-layer path (untrusted text → agent → token → exfil channel), and every existing scanner sees only one layer.

## Our approach

Enforce the Agents Rule of Two as a provable graph reachability property. Report only a demonstrable path, never a risky-looking pattern, so that a failure is always worth acting on. We don't compete on pattern breadth or runtime/LLM detection.

## Who it's for

**Primary:** Security and platform engineers at AI-forward companies deploying coding agents in CI - they're hiring Blastgate to prove, on every PR, that no agent can be steered into leaking a secret.

## Key metrics

- **Fail-tier precision** - share of `fail` findings confirmed exploitable on hand review; measured by re-running the public-repo scan eval (`docs/evaluations/`).
- **Benchmark recall vs zizmor** - known-vulnerable agent-in-CI workflows caught out of a labeled corpus, reported side by side with zizmor.
- **Confirmed disclosures** - real vulnerabilities reported and acknowledged by maintainers or vendors.
- **Repos listed** - public agent-in-CI repos on the crawler's pass list (`jwolberg/blastgate-registry`), each at a scanned SHA.
- **Reports acknowledged** - crawler-filed private vulnerability reports that a maintainer accepted, fixed, or published with credit.
- **External adopters** - repos not owned by us running the Blastgate Action by choice; measured via GitHub code search. Secondary: opt-in adoption is not the distribution path.

## Tracks

### Precision core

Make every `fail` finding practically exploitable: real taint tracking from untrusted text into `run:` steps and agent prompts; demote or remove co-presence findings.

_Why it serves the approach:_ one false fail breaks the "always worth acting on" promise.

### Agent-in-CI modeling

Model agent actions (claude-code-action, gemini-cli, copilot) as graph nodes - which untrusted input reaches the prompt, and which tools, tokens, and exfil channels the agent can reach - so the Rule of Two becomes a checkable property.

_Why it serves the approach:_ this is the new attack surface the reachability bet is aimed at.

### Public evidence

A labeled benchmark, a large scan of public repos running AI agents in CI, responsible disclosures, and a writeup.

_Why it serves the approach:_ it is the proof that reachability beats pattern-matching.

### Distribution

Blastgate goes to the repos; maintainers never have to run or install anything. A crawler we operate finds public repos running AI agents in CI, scans them, publishes the ones that pass on a public registry, and privately reports proven exploits through GitHub private vulnerability reporting - fails are never published. In parallel, upstream the agent check into OpenSSF Scorecard's Dangerous-Workflow check, which already scans everyone (`docs/learnings/scorecard-dangerous-workflow-upstream.md`). npm, the Marketplace Action, the Claude Code plugin, and the MCP self-check stay available as opt-in surfaces for teams that want the gate on every PR.

_Why it serves the approach:_ a tool people must install never spreads, but a proven, privately reported exploit gets a maintainer's attention - and each fixed report is public evidence that reachability beats pattern-matching. See `docs/plans/2026-10-01-002-feat-public-crawler-plan.md`.

## Not working on

- Runtime or LLM-based prompt-injection detection - a different product, and it breaks the proven-path-only promise.
- Matching zizmor's breadth of workflow lint rules.
- More ecosystems or CI providers before the agent-in-CI layer ships.

## Marketing

**One-liner:** Blastgate proves whether your AI agents can be hijacked into leaking secrets.

**Key message:** Every other scanner sees one layer. Blastgate computes the path across CI, dependencies, and agent config - and fails only when that path is real.
