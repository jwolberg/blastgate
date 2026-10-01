/**
 * Crawl scan + ingest (U3, KTD3) — runs scripts/eval-scan.sh over the delta and turns its
 * output into ledger `RepoScan` records. The verdict comes from an explicit table, never
 * from the exit code alone:
 *
 *   exit 0, no findings                          -> pass
 *   exit 0, warn-tier findings only              -> warn
 *   any fail-tier finding                        -> fail
 *   exit 1 w/o fail finding, exit >1, bad JSON   -> unknown
 *   clone could not be completed                 -> clone-failed
 *
 * Privacy: per-repo JSON carries payloads (`--include-payloads`, local evaluation only).
 * Only `{id, archetype}` of fail-tier findings is ever copied out of it.
 */

import { execFile } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FailFinding, RepoScan, ScanVerdict } from './ledger';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SHA_RE = /^[0-9a-f]{40}$/;

export interface RunResult {
  stdout: string;
  /** Process exit code; non-zero for any failure to run. */
  code: number;
}
/** Injectable process runner so tests (and callers) control how scripts execute. */
export type Runner = (cmd: string, args: string[], env: NodeJS.ProcessEnv) => Promise<RunResult>;

export const defaultRunner: Runner = (cmd, args, env) =>
  new Promise((res) => {
    execFile(cmd, args, { env, maxBuffer: 64 * 1024 * 1024 }, (err, stdout) =>
      res({
        stdout,
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
      }),
    );
  });

export interface ScanOptions {
  /** Clone cache. Reused across runs for the bulk scan. */
  workdir: string;
  /** Receives index.tsv plus one JSON per repo (payloads included; keep local). */
  outdir: string;
  /** Extra env for the script, e.g. EVAL_REMOTE_BASE / BLASTGATE_CLI (tests). */
  env?: NodeJS.ProcessEnv;
  runner?: Runner;
  /** Defaults to scripts/eval-scan.sh in this repo. */
  scriptPath?: string;
  /** Clock for `scannedAt`. */
  now?: () => Date;
  /** Skip reading the version from the CLI. */
  engineVersion?: string;
}

/**
 * Archetype of a finding, derived only from its structure: `<entry.kind>-><sink.kind>`
 * (e.g. `pull_request_target->agent`). Never from repo content or payloads.
 */
export function archetypeOf(f: { entry?: { kind?: unknown }; sink?: { kind?: unknown } }): string {
  const e = typeof f.entry?.kind === 'string' ? f.entry.kind : 'unknown';
  const s = typeof f.sink?.kind === 'string' ? f.sink.kind : 'unknown';
  return `${e}->${s}`;
}

interface Parsed {
  tiers: { fail: boolean; warn: boolean; any: boolean };
  failFindings: FailFinding[];
}

/** Parse a per-repo findings file; null if it is not a JSON array of objects. */
function parseFindings(text: string): Parsed | null {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(data)) return null;
  const failFindings: FailFinding[] = [];
  let warn = false;
  for (const f of data) {
    if (typeof f !== 'object' || f === null) return null;
    const o = f as { id?: unknown; tier?: unknown; entry?: never; sink?: never };
    if (o.tier === 'fail') {
      if (typeof o.id !== 'string' || o.id === '') return null;
      failFindings.push({ id: o.id, archetype: archetypeOf(o) });
    } else if (o.tier === 'warn') warn = true;
    else return null;
  }
  return {
    tiers: { fail: failFindings.length > 0, warn, any: data.length > 0 },
    failFindings,
  };
}

/** The KTD3 table. `parsed` is null when the JSON was missing or unparseable. */
export function deriveVerdict(
  exitCode: number,
  parsed: Parsed | null,
): { verdict: ScanVerdict; failFindings: FailFinding[] } {
  if (parsed?.tiers.fail) return { verdict: 'fail', failFindings: parsed.failFindings };
  if (parsed === null || exitCode !== 0) return { verdict: 'unknown', failFindings: [] };
  return { verdict: parsed.tiers.warn ? 'warn' : 'pass', failFindings: [] };
}

const fileName = (repo: string): string => `${repo.replace('/', '__')}.json`;

async function engineVersionOf(opts: ScanOptions, env: NodeJS.ProcessEnv): Promise<string> {
  if (opts.engineVersion) return opts.engineVersion;
  const cli = env.BLASTGATE_CLI ?? join(ROOT, 'dist', 'cli', 'index.js');
  const r = await (opts.runner ?? defaultRunner)('node', [cli, '--version'], env);
  const m = /(\d+\.\d+\.\d+[^\s]*)/.exec(r.stdout);
  if (r.code !== 0 || !m?.[1]) throw new Error(`could not read engine version from ${cli}`);
  return m[1];
}

/**
 * Scan `repos` (owner/repo) with scripts/eval-scan.sh `--public` and return one RepoScan
 * per repo that produced a row. Throws if the script itself cannot run at all.
 */
export async function scanRepos(
  repos: readonly string[],
  opts: ScanOptions,
): Promise<Record<string, RepoScan>> {
  if (repos.length === 0) return {};
  const env: NodeJS.ProcessEnv = { ...process.env, ...opts.env, SCAN_FLAGS: '--public' };
  const runner = opts.runner ?? defaultRunner;
  const engineVersion = await engineVersionOf(opts, env);
  const scannedAt = (opts.now?.() ?? new Date()).toISOString();

  mkdirSync(opts.outdir, { recursive: true });
  const list = join(opts.outdir, 'repos.txt');
  writeFileSync(list, `${repos.join('\n')}\n`);
  const script = opts.scriptPath ?? join(ROOT, 'scripts', 'eval-scan.sh');
  const run = await runner('bash', [script, opts.workdir, opts.outdir, list], env);
  if (run.code !== 0) throw new Error(`eval-scan.sh failed with exit ${run.code}`);

  const wanted = new Set(repos);
  const out: Record<string, RepoScan> = {};
  const tsv = readFileSync(join(opts.outdir, 'index.tsv'), 'utf8');
  for (const line of tsv.split('\n')) {
    if (line.trim() === '') continue;
    const [repo, sha, exit] = line.split('\t');
    if (!repo || !wanted.has(repo)) continue;
    if (exit === 'clone-failed' || !sha || !SHA_RE.test(sha)) {
      // No usable tree: never a pass. A malformed row is treated like a failed clone.
      out[repo] = {
        fullSha: SHA_RE.test(sha ?? '') ? (sha as string) : '0'.repeat(40),
        engineVersion,
        verdict: 'clone-failed',
        scannedAt,
        failFindings: [],
      };
      continue;
    }
    let text = '';
    try {
      text = readFileSync(join(opts.outdir, fileName(repo)), 'utf8');
    } catch {
      /* missing output -> unparseable -> unknown */
    }
    const code = /^\d+$/.test(exit ?? '') ? Number(exit) : 1;
    const { verdict, failFindings } = deriveVerdict(code, parseFindings(text));
    out[repo] = { fullSha: sha, engineVersion, verdict, scannedAt, failFindings };
  }
  return out;
}

export type ReverifyStatus = 'still-fails' | 'resolved' | 'head-mismatch' | 'unknown';

export interface ReverifyOptions extends Omit<ScanOptions, 'workdir'> {
  /** A run-scoped directory that must not already hold anything: never a cached clone. */
  freshWorkdir: string;
  /** Fail finding ids that were about to be reported. */
  expectedFindingIds: readonly string[];
  /** The remote default-branch HEAD the caller just resolved. */
  remoteHead: string;
}

/**
 * Re-scan one repo in a fresh workdir before filing a report (KTD3/KTD6 step 4).
 *  - unknown: the fresh scan was clone-failed/unknown (cannot vouch either way).
 *  - head-mismatch: the scanned SHA is not `remoteHead` (remote moved, or a stale tree).
 *  - still-fails: a fail-tier finding from `expectedFindingIds` is still present.
 *  - resolved: otherwise (pass/warn, or fails only on ids that were not being reported).
 */
export async function reverify(
  repo: string,
  opts: ReverifyOptions,
): Promise<{ status: ReverifyStatus; scan: RepoScan }> {
  let existing: string[] = [];
  try {
    existing = readdirSync(opts.freshWorkdir);
  } catch {
    /* does not exist: fresh */
  }
  if (existing.length > 0) {
    throw new Error(`reverify needs a fresh workdir, but ${opts.freshWorkdir} is not empty`);
  }
  const scan = (await scanRepos([repo], { ...opts, workdir: opts.freshWorkdir }))[repo];
  if (!scan) throw new Error(`eval-scan.sh produced no row for ${repo}`);
  if (scan.verdict === 'clone-failed' || scan.verdict === 'unknown') {
    return { status: 'unknown', scan };
  }
  if (scan.fullSha !== opts.remoteHead) return { status: 'head-mismatch', scan };
  const expected = new Set(opts.expectedFindingIds);
  const stillThere = scan.failFindings.some((f) => expected.has(f.id));
  return { status: stillThere ? 'still-fails' : 'resolved', scan };
}
