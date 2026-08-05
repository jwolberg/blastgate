/**
 * CLI — human + machine rendering of engine results (U9).
 *
 * Renders from the shared `Finding` shape only (KTD10) — `--json` and the hook
 * reasons draw from the same data, so every surface stays in parity (R7).
 */

import { gateFails, type GateResult } from '../engine/gate';

/** Human output: each ranked path (entry → … → sink), the sink, why, the fix, and labels. */
export function renderText(result: GateResult): string {
  if (result.findings.length === 0) {
    return 'blastgate: no reachable attacker→sink path. PASS\n';
  }

  const header = result.verdict === 'fail' ? 'FAIL' : 'WARN';
  const lines: string[] = [`blastgate: ${result.findings.length} reachable path(s) — ${header}`];

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

/** Scan exit code: non-zero only on a fail verdict; pass/warn exit 0 (KTD4). */
export function scanExitCode(result: GateResult): number {
  return gateFails(result.verdict) ? 1 : 0;
}
