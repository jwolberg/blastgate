---
title: Read an action's source at the pinned tag before encoding its defaults
date: 2026-10-01
tags: [agents, profiles, vendor-docs]
anchor: LRN-vendor-source
---

# Read an action's source at the pinned tag before encoding its defaults

## [1] What happened

The agent-in-CI plan was "verified against vendor docs", yet U1's re-check against each
action's **source** (via `gh api repos/<o>/<r>/contents/<path>?ref=<tag>`) overturned two
defaults the plan relied on:

- **codex-action `allow-users`** — the plan said names only. `src/checkActorPermissions.ts`
  admits *every* user on `'*'` (all tags v1.0–v1.12); only `allow-bot-users` rejects `'*'`.
  A docs page had been read as the whole truth.
- **run-gemini-cli `--yolo` allowlist bypass** — the plan keyed it on action version < 0.1.22.
  Diffing `action.yml` across 0.1.21/0.1.22 showed nothing security-relevant; the fix is in the
  **Gemini CLI** (0.39.1), which the action installs as `latest` — so it keys on the step's
  `gemini_cli_version`, not the action tag.

Later reviews found a third gap the same way: the `allowed_bots: '*'` risk is scoped to
*public* repositories in claude-code-action's own security doc.

## [2] The lesson

- For a profile default that can flip a fail, read the action's `action.yml` and the code that
  enforces the input, at the exact tag being pinned. Docs pages summarize; source decides.
- Check which component owns a behavior (action vs the CLI it installs) before keying a rule on
  a version.
- Keep the plan's "stop and ask if a default differs" condition — it caught both.
