/**
 * GitHub Action wrapper (U10) — a thin surface over the same engine the CLI runs
 * (KTD10). `runActionCore` is literally `runEngine(collectInputs(...))`, so the
 * Action and the CLI cannot drift: parity is structural, asserted by
 * `test/action.parity.test.ts`. This file only adds PR surfacing (annotations +
 * a job-summary table) and the Action's env-driven input handling.
 */

import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { collectInputs, type CollectOptions, type RepoFs } from '../cli/collect';
import { nodeRepoFs } from '../cli/node-fs';
import { renderMarkdown, scanExitCode } from '../cli/render';
import type { RepoVisibility } from '../engine/build';
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
  /** Repository visibility from the event payload (KTD5); absent = `unknown`. */
  visibility?: RepoVisibility;
  /** A single PR annotation (`::error`/`::warning`). */
  annotate: (level: 'error' | 'warning', message: string) => void;
  /** The job-summary markdown (appended to `$GITHUB_STEP_SUMMARY`). */
  summary: (markdown: string) => void;
}

function annotationMessage(f: Finding): string {
  const labels = f.labels.length > 0 ? ` [${f.labels.join(', ')}]` : '';
  // Location + capability only — PR annotations are public (0049 / R10: no payload).
  const at = f.evidence ? ` At ${f.evidence.file}:${f.evidence.line}.` : '';
  return `${f.path.join(' → ')} — ${f.reason}${at} Fix: ${f.remediation}${labels}`;
}

/** `repository.private` from the workflow event payload; anything unreadable is `unknown`. */
export function visibilityFromEvent(payload: string | null): RepoVisibility {
  if (payload === null) {
    return 'unknown';
  }
  try {
    const priv = (JSON.parse(payload) as { repository?: { private?: unknown } })?.repository
      ?.private;
    return priv === true ? 'private' : priv === false ? 'public' : 'unknown';
  } catch {
    return 'unknown';
  }
}

/** The collect options the Action scans with. */
export function actionCollectOptions(env: ActionEnv): CollectOptions {
  return {
    ...(env.base !== undefined ? { base: env.base } : {}),
    visibility: env.visibility ?? 'unknown',
  };
}

/** Run the engine, surface findings on the PR, and return the process exit code. */
export function runAction(env: ActionEnv): number {
  const result = runActionCore(env.fs, actionCollectOptions(env));
  for (const f of result.findings) {
    env.annotate(f.tier === 'fail' ? 'error' : 'warning', annotationMessage(f));
  }
  // The job summary is the same markdown report as `blastgate --format md`, so the
  // PR surface and the CLI cannot drift (KTD10 / R7 parity).
  env.summary(renderMarkdown(result));
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

function readEventPayload(): string | null {
  const file = process.env.GITHUB_EVENT_PATH;
  if (!file) {
    return null;
  }
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
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
    visibility: visibilityFromEvent(readEventPayload()),
    annotate: emitAnnotation,
    summary: writeSummary,
  });
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  process.exit(main());
}
