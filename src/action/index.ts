/**
 * GitHub Action wrapper (U10) — a thin surface over the same engine the CLI runs
 * (KTD10). `runActionCore` is literally `runEngine(collectInputs(...))`, so the
 * Action and the CLI cannot drift: parity is structural, asserted by
 * `test/action.parity.test.ts`. This file only adds PR surfacing (annotations +
 * a job-summary table) and the Action's env-driven input handling.
 */

import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { collectInputs, type CollectOptions, type RepoFs } from '../cli/collect';
import { nodeRepoFs } from '../cli/node-fs';
import { scanExitCode } from '../cli/render';
import { type GateResult, runEngine } from '../engine/gate';
import type { Finding } from '../findings/finding';

/** The exact engine call the CLI makes — the shared entrypoint that makes parity structural. */
export function runActionCore(fs: RepoFs, opts: CollectOptions = {}): GateResult {
  return runEngine(collectInputs(fs, opts));
}

/** Injected surfacing sinks so the Action is testable without a real runner. */
export interface ActionEnv {
  fs: RepoFs;
  base?: string;
  provenance?: boolean;
  /** A single PR annotation (`::error`/`::warning`). */
  annotate: (level: 'error' | 'warning', message: string) => void;
  /** The job-summary markdown (appended to `$GITHUB_STEP_SUMMARY`). */
  summary: (markdown: string) => void;
}

function annotationMessage(f: Finding): string {
  const labels = f.labels.length > 0 ? ` [${f.labels.join(', ')}]` : '';
  return `${f.path.join(' → ')} — ${f.reason} Fix: ${f.remediation}${labels}`;
}

/** Escape a cell so a path/reason containing `|` can't break the markdown table. */
function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function summaryTable(result: GateResult): string {
  if (result.findings.length === 0) {
    return '## Blastgate\n\n✓ No reachable attacker→sink path. **PASS**\n';
  }
  const verdict = result.verdict === 'fail' ? 'FAIL' : 'WARN';
  const rows = result.findings.map((f) => {
    const tier = f.tier === 'fail' ? '🔴 fail' : '🟡 warn';
    const labels = f.labels.join(', ') || '—';
    return `| ${tier} | ${cell(f.path.join(' → '))} | ${cell(f.sink.identity)} | ${labels} | ${cell(f.remediation)} |`;
  });
  return [
    '## Blastgate',
    '',
    `**${verdict}** — ${result.findings.length} reachable path(s).`,
    '',
    '| Tier | Path | Sink | OWASP | Fix |',
    '| --- | --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
}

/** Run the engine, surface findings on the PR, and return the process exit code. */
export function runAction(env: ActionEnv): number {
  const result = runActionCore(env.fs, env.base !== undefined ? { base: env.base } : {});
  for (const f of result.findings) {
    env.annotate(f.tier === 'fail' ? 'error' : 'warning', annotationMessage(f));
  }
  env.summary(summaryTable(result));
  return scanExitCode(result);
}

// ---- GitHub Actions runtime wiring (the only part with real process I/O) ----

/** GitHub sets `INPUT_<NAME>` from an action input; empty string means unset. */
function input(name: string): string | undefined {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v && v.length > 0 ? v : undefined;
}

/** `::error::` / `::warning::` workflow commands, escaped per the Actions spec. */
function emitAnnotation(level: 'error' | 'warning', message: string): void {
  const escaped = message.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  process.stdout.write(`::${level} title=Blastgate::${escaped}\n`);
}

function writeSummary(markdown: string): void {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) {
    try {
      appendFileSync(file, `${markdown}\n`);
      return;
    } catch {
      /* fall through to stdout */
    }
  }
  process.stdout.write(`${markdown}\n`);
}

function main(): number {
  const path = input('path') ?? '.';
  // Default the diff base to the PR base ref so the Action gets change signals for free.
  const base = input('base') ?? process.env.GITHUB_BASE_REF ?? undefined;
  const provenance = input('provenance') === 'true';
  if (provenance) {
    emitAnnotation(
      'warning',
      'provenance check requested but not available yet (U8, network-gated); running offline.',
    );
  }
  return runAction({
    fs: nodeRepoFs(path),
    base,
    provenance,
    annotate: emitAnnotation,
    summary: writeSummary,
  });
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  process.exit(main());
}
