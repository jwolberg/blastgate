/**
 * CLI — human + machine rendering of engine results (U9).
 *
 * Renders from the shared `Finding` shape only (KTD10) — `--json` and the hook
 * reasons draw from the same data, so every surface stays in parity (R7).
 */

import { gateBlocks, type GateResult } from '../engine/gate';

/** Human output: each ranked path (entry → … → sink), the sink, why, the fix, and labels. */
export function renderText(result: GateResult): string {
  const lines: string[] = [];

  if (result.verdict === 'unknown') {
    // Could-not-evaluate is never a PASS (0020): show it, and any error, plainly.
    lines.push(
      'blastgate: could not fully evaluate the change — UNKNOWN (blocking in CI, not a pass)',
    );
    for (const e of result.diagnostics.filter((d) => d.level === 'error')) {
      lines.push(`      error: ${e.message}`);
    }
    if (result.findings.length === 0) {
      lines.push('');
      return lines.join('\n');
    }
    lines.push(''); // fall through to also list any partial findings
  } else if (result.findings.length === 0) {
    return 'blastgate: no reachable attacker→sink path. PASS\n';
  } else {
    const header = result.verdict === 'fail' ? 'FAIL' : 'WARN';
    lines.push(`blastgate: ${result.findings.length} reachable path(s) — ${header}`);
  }

  for (const f of result.findings) {
    const tag = f.tier === 'fail' ? '✗ FAIL' : '! WARN';
    const labels = f.labels.length > 0 ? `  [${f.labels.join(', ')}]` : '';
    lines.push('');
    lines.push(`${tag}  ${f.path.join(' → ')}`);
    lines.push(`      sink: ${f.sink.kind} ${f.sink.identity}${labels}`);
    lines.push(`      why:  ${f.reason}`);
    lines.push(`      fix:  ${f.remediation}`);
  }
  lines.push('');
  return lines.join('\n');
}

/** Machine output: the full findings array as valid JSON (R7 parity source). */
export function renderJson(result: GateResult): string {
  return `${JSON.stringify(result.findings, null, 2)}\n`;
}

/** Scan/CI exit code: non-zero on a fail OR an un-evaluable (unknown) run; pass/warn exit 0 (0020). */
export function scanExitCode(result: GateResult): number {
  return gateBlocks(result.verdict) ? 1 : 0;
}
