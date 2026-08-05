/**
 * CLI — human + machine rendering of engine results (U9).
 *
 * Renders from the shared `Finding` shape only (KTD10) — `--json`, the markdown
 * report, the Action job summary, and the hook reasons all draw from the same
 * data, so every surface stays in parity (R7).
 */

import type { Finding } from '../findings/finding';
import { gateBlocks, type GateResult } from '../engine/gate';

/**
 * Where Blastgate sits in a development workflow — one shared source so the CLI,
 * the markdown report, and the GitHub Action all say the same thing (U9). This is
 * the "how/when does this fit my workflow" guidance surfaced next to every result.
 */
export const WORKFLOW_GUIDANCE = {
  /** The three moments the same engine runs, earliest to latest. */
  stages: 'local commit/install hook → CI pull-request gate → pre-merge review',
  /** The gate policy in one line, so a reader knows what a verdict means. */
  policy:
    'Blastgate fails only on a reachable path to a secret or credential sink; ' +
    'lower-severity capability paths are reported as warnings without failing.',
  /** Where to read the full adoption + response walkthrough. */
  runbook: 'docs/runbooks/adopt-blastgate.md',
};

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
      lines.push(workflowFooterText());
      lines.push('');
      return lines.join('\n');
    }
    lines.push(''); // fall through to also list any partial findings
  } else if (result.findings.length === 0) {
    return `blastgate: no reachable attacker→sink path. PASS\n\n${workflowFooterText()}\n`;
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
    if (f.acknowledged) {
      lines.push(`      accepted: ${f.acknowledged}`);
    }
    lines.push(`      why:  ${f.reason}`);
    lines.push(`      fix:  ${f.remediation}`);
    if (f.advisories && f.advisories.length > 0) {
      lines.push(`      advisories: ${f.advisories.map((a) => a.id).join(', ')}`);
    }
  }
  lines.push('');
  lines.push(workflowFooterText());
  lines.push('');
  return lines.join('\n');
}

/** One compact line telling the reader where this check runs and where to read more. */
function workflowFooterText(): string {
  return `Runs at: ${WORKFLOW_GUIDANCE.stages}  ·  docs: ${WORKFLOW_GUIDANCE.runbook}`;
}

/** Machine output: the full findings array as valid JSON (R7 parity source). */
export function renderJson(result: GateResult): string {
  return `${JSON.stringify(result.findings, null, 2)}\n`;
}

/**
 * Human-readable Markdown report (U9). Renders natively in a GitHub PR comment /
 * job summary and reads cleanly in a terminal pager. The GitHub Action uses this
 * for its job summary too, so the PR surface and `blastgate --format md` are one
 * report (KTD10 / R7 parity). Drawn only from `Finding` + the run verdict.
 */
export function renderMarkdown(result: GateResult): string {
  const lines: string[] = [];

  lines.push(...markdownHeader(result));

  // "Where this runs" — the workflow guidance, next to the findings (U9).
  lines.push('');
  lines.push(`**Where this runs:** ${WORKFLOW_GUIDANCE.stages}  `);
  lines.push(`_${WORKFLOW_GUIDANCE.policy}_`);

  for (const f of result.findings) {
    lines.push('', '---', '', ...markdownFinding(f));
  }

  lines.push('', '---', '', markdownNextSteps(result), '');
  return lines.join('\n');
}

/** The verdict headline + one-line meaning. */
function markdownHeader(result: GateResult): string[] {
  const n = result.findings.length;
  if (result.verdict === 'pass') {
    return [
      '## 🛡 Blastgate — ✅ PASS',
      '',
      'No reachable path connects an attacker-controllable entry point to a secret, credential, or privileged capability.',
    ];
  }
  if (result.verdict === 'unknown') {
    const out = [
      '## 🛡 Blastgate — ⚠️ UNKNOWN',
      '',
      'Blastgate could not fully evaluate the change, so the run **blocks in CI** rather than passing (fail-closed).',
    ];
    const errors = result.diagnostics.filter((d) => d.level === 'error');
    if (errors.length > 0) {
      out.push('');
      for (const e of errors) {
        out.push(`- error: ${inlineText(e.message)}`);
      }
    }
    return out;
  }
  const badge = result.verdict === 'fail' ? '❌ FAIL' : '⚠️ WARN';
  const meaning =
    result.verdict === 'fail'
      ? 'A reachable path connects an attacker-controllable entry point to a secret or credential. This **blocks the gate** until the path is broken or the finding is acknowledged.'
      : 'A reachable path reaches a privileged capability. This is **reported, not blocking**.';
  return [`## 🛡 Blastgate — ${badge} (${n} reachable path${n === 1 ? '' : 's'})`, '', meaning];
}

/** One finding as a section: heading, the path, then why / fix / sink / labels. */
function markdownFinding(f: Finding): string[] {
  const mark = f.tier === 'fail' ? '❌' : '⚠️';
  const chain = f.path.map((n) => `\`${n.replace(/`/g, '')}\``).join(' → ');
  const out = [
    `### ${mark} ${inlineText(f.path[0] ?? f.entry.label)} → … → ${sinkIcon(f)} ${inlineText(f.sink.identity)}`,
    '',
    chain,
    '',
  ];
  if (f.acknowledged) {
    out.push(`- **accepted:** ${inlineText(f.acknowledged)} _(downgraded fail → warn)_`);
  }
  out.push(`- **why:** ${inlineText(f.reason)}`);
  out.push(`- **fix:** ${inlineText(f.remediation)}`);
  out.push(`- **sink:** ${f.sink.kind} \`${f.sink.identity}\``);
  if (f.advisories && f.advisories.length > 0) {
    out.push(`- **advisories:** ${f.advisories.map((a) => `\`${a.id}\``).join(', ')}`);
  }
  if (f.labels.length > 0) {
    out.push(`- **OWASP:** ${f.labels.map((l) => `\`${l}\``).join(', ')}`);
  }
  return out;
}

/** Closing guidance tailored to the verdict — what to do next. */
function markdownNextSteps(result: GateResult): string {
  if (result.verdict === 'fail' || result.verdict === 'warn') {
    return (
      '**Next:** break any edge on the path (preferred — the fixes above), or record a reviewed ' +
      'exception in `.blastgate/acknowledged.json` by finding id (`blastgate --json` prints the `id`). ' +
      `See [${WORKFLOW_GUIDANCE.runbook}](${WORKFLOW_GUIDANCE.runbook}).`
    );
  }
  return (
    '**Where to add it:** run Blastgate on every `pull_request` (the Action) and as a local commit/install hook (the plugin), ' +
    `so a reachable path is caught before it lands. See [${WORKFLOW_GUIDANCE.runbook}](${WORKFLOW_GUIDANCE.runbook}).`
  );
}

/** A glyph hinting at the sink's sensitivity. */
function sinkIcon(f: Finding): string {
  return f.sink.kind === 'privileged-capability' ? '🛠' : '🔑';
}

/** Collapse newlines/pipes so a reason/path can't break a markdown line or table cell. */
function inlineText(s: string): string {
  return s.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
}

/** Scan/CI exit code: non-zero on a fail OR an un-evaluable (unknown) run; pass/warn exit 0 (0020). */
export function scanExitCode(result: GateResult): number {
  return gateBlocks(result.verdict) ? 1 : 0;
}
