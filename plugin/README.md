# Blastgate — Claude Code plugin

This plugin runs the Blastgate reachability checks inside a Claude Code session,
using the same engine as the CI gate, invoked at three surfaces.

## Surfaces

| Surface | Trigger | Role |
| --- | --- | --- |
| Hooks (`hooks/hooks.json`) | Fire on matching tool calls | Enforcement — run regardless of model behavior |
| MCP tool (`.mcp.json`, `blastgate_check_change`) | Called by the agent | Lets the agent evaluate a proposed change before applying it |
| `/blastgate` (`skills/blastgate/SKILL.md`) | Invoked by a person | Manual scan |

The hooks are the enforcement mechanism. The MCP tool and command are convenience
surfaces and do not substitute for the hooks: an agent subject to prompt injection
cannot be relied on to call them.

## Pre- vs post-tool-use hooks

`PreToolUse` hooks can block an action; `PostToolUse` hooks cannot. Blastgate
therefore:

- Blocks at `git commit`, `git push`, and edits to `package.json`,
  `.github/workflows/**`, and `.mcp.json`, before the change is committed.
- Runs after `npm install` — a dependency's contents exist only after installation —
  and reports a finding for the agent to revert.

The commit-time block prevents a reachable path from leaving the working tree even if
a dependency install is not caught beforehand.

## Local development

```bash
claude --plugin-dir ./plugin
```

Then invoke `/blastgate`, or trigger the hooks by committing or installing a
dependency.

## Installation (once published)

```
/plugin marketplace add jwolberg/blastgate
/plugin install blastgate@blastgate
```

## CLI contract

The plugin is a wrapper over two commands provided by `bin/blastgate`, which is
currently a stub that passes by default (set `BLASTGATE_DEMO_DENY=1` to exercise the
block path):

- `blastgate check --gate <phase>` — reads hook JSON on stdin; exits non-zero or
  emits a deny decision on a reachable path. This is the same engine the CI gate uses.
- `blastgate mcp` — stdio MCP server exposing `blastgate_check_change`.
