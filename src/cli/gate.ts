/**
 * CLI — plugin hook-gate mode (U9, R16/KTD12).
 *
 * `blastgate check --gate <phase>` reuses the U7 gate and emits the deterministic
 * hook payloads the plugin's hooks consume. The asymmetry is the design (KTD12):
 * `PreToolUse` phases can DENY a change before it lands; the `dependency-install`
 * `PostToolUse` phase can only BLOCK react-only after the fact.
 */

import { gateFails, type GateResult } from '../engine/gate';

/** PreToolUse phases — a reachable path denies the action before it lands. */
export const PRE_PHASES = new Set([
  'pre-commit',
  'pre-push',
  'manifest-edit',
  'workflow-edit',
  'mcp-config-edit',
  // 0025: a Bash command classified as a commit/push verb (however wrapped).
  'shell-pre',
]);

/** PostToolUse phases — react-only; can block/signal a revert, cannot prevent. */
export const POST_PHASES = new Set([
  'dependency-install',
  // 0025: a Bash command classified as an install verb.
  'shell-post',
]);

/**
 * A gate-bypass attempt (0025): the command disables commit/push verification
 * (`--no-verify`, `core.hooksPath=…`). A PreToolUse phase DENIES it; a PostToolUse
 * phase can only warn (react-only). Denying the bypass is the whole point — an
 * agent that can turn the gate off before doing the blocked thing is the obvious
 * hole.
 */
export function bypassOutput(phase: string, command: string): HookOutput {
  const reason =
    `Blastgate: this command disables commit/push verification (gate-bypass attempt) — ` +
    `"${command}". Run without \`--no-verify\` / \`core.hooksPath\` overrides.`;
  if (POST_PHASES.has(phase)) {
    return { stdout: '', stderr: `${reason}\n`, exitCode: 0 };
  }
  const payload = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
  return { stdout: `${JSON.stringify(payload)}\n`, exitCode: 0 };
}

export interface HookOutput {
  stdout: string;
  /** A loud warning shown to the user (e.g. an UNKNOWN verdict) without blocking. */
  stderr?: string;
  exitCode: number;
}

/** The ranked-path reason string shared by deny and block payloads. */
function reasonFrom(result: GateResult): string {
  const top = result.findings.find((f) => f.tier === 'fail') ?? result.findings[0];
  if (!top) {
    return '';
  }
  const labels = top.labels.length > 0 ? ` [${top.labels.join(', ')}]` : '';
  return `Reachable path: ${top.path.join(' → ')}. ${top.reason} Fix: ${top.remediation}${labels}`;
}

/**
 * Emit the hook payload for a phase given the engine result. A non-fail verdict
 * emits nothing (allow). Unknown phases are treated as PreToolUse (deny-capable).
 */
export function hookOutput(phase: string, result: GateResult): HookOutput {
  if (result.verdict === 'unknown') {
    // Fail-closed but non-blocking locally (0020): a hung/errored evaluation is
    // never a silent pass — warn loudly and let the developer proceed; CI blocks.
    const n = result.diagnostics.filter((d) => d.level === 'error').length;
    return {
      stdout: '',
      stderr:
        `blastgate: could not fully evaluate this change — UNKNOWN, not a pass ` +
        `(${n} evaluation error(s)). Allowing locally; re-run \`blastgate\` — CI blocks on UNKNOWN.\n`,
      exitCode: 0,
    };
  }
  if (!gateFails(result.verdict)) {
    return { stdout: '', exitCode: 0 };
  }

  if (POST_PHASES.has(phase)) {
    const payload = {
      decision: 'block',
      reason: `Revert this install — it opens a reachable path. ${reasonFrom(result)}`,
    };
    return { stdout: `${JSON.stringify(payload)}\n`, exitCode: 0 };
  }

  const payload = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reasonFrom(result),
    },
  };
  return { stdout: `${JSON.stringify(payload)}\n`, exitCode: 0 };
}
