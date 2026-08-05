/**
 * The `blastgate_check_change` MCP tool (U13) — the agent-facing self-check.
 *
 * It wraps the U7 engine (never re-implements it, KTD10) and is **advisory**: it
 * returns the same `Finding` verdict the CLI gate produces, but never blocks
 * (KTD12 — the pre-commit hook is the enforcement layer; a prompt-injected agent
 * will not voluntarily self-check, so this can never be the sole gate).
 */

import { collectInputs, type RepoFs } from '../cli/collect';
import { type GateResult, runEngine } from '../engine/gate';
import type { Finding, Verdict } from '../findings/finding';

const CHANGE_KINDS = ['dependency', 'install-script', 'workflow', 'mcp-config', 'other'] as const;

export const CHECK_CHANGE_TOOL = {
  name: 'blastgate_check_change',
  description:
    'Check whether the current repository state — including a change you just made — opens a ' +
    'reachable cross-layer attack path from an attacker-controllable entry point (a new/changed ' +
    'dependency, an untrusted CI trigger, or a prompt-injectable agent surface) to a sensitive ' +
    'sink (a secret, credential, or privileged capability). Advisory only: it returns a verdict ' +
    'and the ranked path, sink, reason, fix, and OWASP labels; it never blocks. Call it before ' +
    'committing a dependency/workflow/MCP-config change to see if it would fail the gate.',
  inputSchema: {
    type: 'object',
    properties: {
      file_path: {
        type: 'string',
        description: 'The file you added or edited (a hint; the scan is repository-wide).',
      },
      change_kind: {
        type: 'string',
        enum: [...CHANGE_KINDS],
        description: 'The kind of change (a hint).',
      },
      base: {
        type: 'string',
        description: 'Git ref to diff against for change signals (defaults to HEAD).',
      },
    },
  },
} as const;

export interface CheckChangeResult {
  /** Human-readable summary for the agent to read. */
  text: string;
  /** Machine-readable verdict + findings (the shared Finding shape). */
  structured: { verdict: Verdict; findings: Finding[] };
}

const ADVISORY =
  'Advisory only — Blastgate does not block here; the pre-commit hook is the enforcement layer.';

function line(f: Finding): string {
  const labels = f.labels.length > 0 ? ` [${f.labels.join(', ')}]` : '';
  return `- [${f.tier}] ${f.path.join(' → ')}\n  sink: ${f.sink.kind} ${f.sink.identity}${labels}\n  fix: ${f.remediation}`;
}

function summarize(result: GateResult): string {
  if (result.findings.length === 0) {
    return `OK — no reachable attacker→sink path in the current repository state.\n\n${ADVISORY}`;
  }
  const fails = result.findings.filter((f) => f.tier === 'fail').length;
  const head =
    result.verdict === 'fail'
      ? `REACHABLE PATH (fail) — ${fails} path(s) reach a secret/credential sink. This change would fail the gate.`
      : `WARNING (warn) — ${result.findings.length} lower-severity capability path(s); no secret/credential is reachable.`;
  return `${head}\n${result.findings.map(line).join('\n')}\n\n${ADVISORY}`;
}

/**
 * Run the engine over the project directory and format the tool result. Throws a
 * plain Error on malformed input; the server turns that into a structured tool
 * error (isError) so the agent sees it and the server stays up.
 */
export function checkChange(fs: RepoFs, args: unknown, defaultBase = 'HEAD'): CheckChangeResult {
  if (typeof args !== 'object' || args === null || Array.isArray(args)) {
    throw new Error('arguments must be an object');
  }
  const a = args as Record<string, unknown>;
  if (a.file_path !== undefined && typeof a.file_path !== 'string') {
    throw new Error('file_path must be a string');
  }
  if (
    a.change_kind !== undefined &&
    !CHANGE_KINDS.includes(a.change_kind as (typeof CHANGE_KINDS)[number])
  ) {
    throw new Error(`change_kind must be one of: ${CHANGE_KINDS.join(', ')}`);
  }
  const base = typeof a.base === 'string' ? a.base : defaultBase;

  const result = runEngine(collectInputs(fs, { base }));
  return {
    text: summarize(result),
    structured: { verdict: result.verdict, findings: result.findings },
  };
}
