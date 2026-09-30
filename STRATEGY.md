---
name: Blastgate
last_updated: 2026-09-29
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
- **External adopters** - repos not owned by us running the Blastgate Action; measured via GitHub code search.

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

npm, the Marketplace Action, the Claude Code plugin, and a standalone MCP server so any agent (Claude Code, Codex, Muse, Dots, …) can self-check a change before it acts.

_Why it serves the approach:_ no one adopts what they can't install - and agents calling the gate enforce the Rule of Two from the inside.

## Not working on

- Runtime or LLM-based prompt-injection detection - a different product, and it breaks the proven-path-only promise.
- Matching zizmor's breadth of workflow lint rules.
- More ecosystems or CI providers before the agent-in-CI layer ships.

## Marketing

**One-liner:** Blastgate proves whether your AI agents can be hijacked into leaking secrets.

**Key message:** Every other scanner sees one layer. Blastgate computes the path across CI, dependencies, and agent config - and fails only when that path is real.
