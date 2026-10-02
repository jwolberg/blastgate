/**
 * Crawler orchestrator (U8, KTD1/KTD4/KTD8). Internal tooling: its own tsup entry, never part
 * of the npm package.
 *
 *   scan    SCAN job  (no secrets): discover -> delta -> scan -> compose reports -> re-verify.
 *                      Writes ONE file, scan-result.json: verdicts, finding ids, archetypes and
 *                      composed reports. No payloads, no raw findings.
 *   submit  SUBMIT job (holds secrets, never clones): recover -> apply scans -> submit -> track ->
 *                      persist ledger -> build site -> (optionally) publish.
 *   publish SUBMIT job, separate step so the registry deploy key is only present there.
 *
 * Every stage and all I/O sit behind an injectable dependency so tests run the whole thing with
 * zero network writes. Logs carry counts only, never a repo name paired with a verdict.
 */

import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import type { Finding } from '../findings/finding';
import { type CrawlConfig, parseCrawlConfig } from './config';
import {
  DESCRIPTION_MAX,
  SUMMARY_MAX,
  composeReport,
  reportFooter,
  reportHeader,
  reportSummaryPrefix,
} from './disclose';
import {
  type DiscoverResult,
  type Eligibility,
  assertOwnerLogin,
  checkEligible,
  discover,
} from './discover';
import {
  type DiscoveryState,
  parseDiscoveryState,
  serializeDiscoveryState,
  validateDiscoveryState,
} from './discovery-state';
import {
  GitHubRateLimitError,
  type GitHubClient,
  type RateLimitInfo,
  createGitHubClient,
  isPlainRepoName,
} from './github';
import {
  type Ledger,
  type RepoScan,
  applyScan,
  delta,
  SCAN_VERDICTS,
  emptyLedger,
  lsRemoteHeads,
  parseLedger,
  recoverSubmitting,
  serializeLedger,
} from './ledger';
import { publishSite } from './publish';
import { type Runner, archetypeOf, childEnv, defaultRunner, reverify, scanRepos } from './scan';
import { renderSite } from './site';
import { type SubmitCandidate, submitAll } from './submit';
import { trackAll } from './track';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_CAP = 100;
const MAX_CHECK_FACTOR = 3;
const REVERIFY_STATUSES = ['still-fails', 'resolved', 'head-mismatch', 'unknown'] as const;

// ---------------------------------------------------------------- result file

/** One log line per rate-limited response: header values only, no URL or repo (0085). */
export function formatRateLimit(info: RateLimitInfo): string {
  const fields = (['limit', 'remaining', 'used', 'reset', 'retryAfter'] as const)
    .filter((k) => info[k] !== undefined)
    .map((k) => `${k === 'retryAfter' ? 'retry-after' : k}=${info[k]}`);
  return `crawl: rate limited (${info.status}, ${info.route}, ${info.resource ?? 'resource?'})${fields.length ? ': ' + fields.join(' ') : ''}`;
}

export interface ScanResultFile {
  /** `<cli version>+<blastgate commit sha>`. */
  engineVersion: string;
  /** Every repo discovery returned this run (drives the site's "still discovered" filter). */
  discovered: string[];
  truncated: string[];
  partial: string[];
  scans: Record<string, RepoScan>;
  candidates: SubmitCandidate[];
  /** Fail finding ids per rescanned repo (empty = rescanned and clean). Not-rescanned repos are absent. */
  currentFails: Record<string, string[]>;
  /** Incremental discovery state for the next run; submit validates it and commits it (0083). */
  discoveryState?: DiscoveryState;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isStrArr = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === 'string');

const SHA_RE = /^[0-9a-f]{40}$/;
const MAX_ENGINE_VERSION = 200;
const MAX_ID = 1000;
const MAX_ARCHETYPE = 200;

export interface ParsedScanResult extends ScanResultFile {
  /** Entries refused by validation (counts only; never written back). */
  dropped: { scans: number; candidates: number };
}

/** A scan row the scan job may legitimately produce; anything else is forged or corrupt. */
function validScan(v: unknown): v is RepoScan {
  if (!isObj(v)) return false;
  const { fullSha, engineVersion, verdict, scannedAt, failFindings } = v;
  if (typeof fullSha !== 'string' || !SHA_RE.test(fullSha)) return false;
  if (
    typeof engineVersion !== 'string' ||
    engineVersion === '' ||
    engineVersion.length > MAX_ENGINE_VERSION
  ) {
    return false;
  }
  if (typeof verdict !== 'string' || !(SCAN_VERDICTS as readonly string[]).includes(verdict)) {
    return false;
  }
  if (typeof scannedAt !== 'string' || Number.isNaN(Date.parse(scannedAt))) return false;
  if (new Date(scannedAt).toISOString() !== scannedAt) return false;
  if (!Array.isArray(failFindings)) return false;
  // fail <=> at least one failing finding (the KTD3 verdict table).
  if ((verdict === 'fail') !== failFindings.length > 0) return false;
  return failFindings.every(
    (f) =>
      isObj(f) &&
      typeof f.id === 'string' &&
      f.id !== '' &&
      f.id.length <= MAX_ID &&
      typeof f.archetype === 'string' &&
      f.archetype !== '' &&
      f.archetype.length <= MAX_ARCHETYPE,
  );
}

/**
 * Is this candidate something composeReport could have produced for a scan we also hold? The
 * scan job is untrusted (KTD1): its text is posted under Jay's name, so the repo, the finding
 * ids, the archetype, and the report's fixed header/footer must all agree with the scan rows.
 */
function validCandidate(
  c: unknown,
  scans: Record<string, RepoScan>,
  discovered: ReadonlySet<string>,
  engineVersion: string,
): c is SubmitCandidate {
  if (!isObj(c)) return false;
  const { repo, archetype, findingIds, report, reverify } = c;
  if (typeof repo !== 'string' || !isPlainRepoName(repo) || !discovered.has(repo)) return false;
  const scan = scans[repo];
  if (scan?.verdict !== 'fail') return false;
  if (typeof archetype !== 'string' || !isStrArr(findingIds) || findingIds.length === 0) {
    return false;
  }
  if (new Set(findingIds).size !== findingIds.length) return false;
  const stored = new Map(scan.failFindings.map((f) => [f.id, f.archetype]));
  if (!findingIds.every((id) => stored.get(id) === archetype)) return false;
  if (!(REVERIFY_STATUSES as readonly unknown[]).includes(reverify)) return false;
  if (!isObj(report)) return false;
  const { summary, description } = report;
  if (typeof summary !== 'string' || typeof description !== 'string') return false;
  if (summary.length > SUMMARY_MAX || !summary.startsWith(reportSummaryPrefix(repo))) return false;
  return (
    description.length <= DESCRIPTION_MAX &&
    description.startsWith(reportHeader(repo, findingIds.length)) &&
    description.endsWith(reportFooter(engineVersion, scan.fullSha))
  );
}

/**
 * Validate a scan-result file produced by another job. Throws on a wrong shape; entries that
 * are well-shaped but invalid (bad repo name, undiscovered repo, ids the scan never failed,
 * report text that is not composeReport's) are dropped and counted.
 */
export function parseScanResult(text: string): ParsedScanResult {
  const bad = (why: string): never => {
    throw new Error(`invalid scan result: ${why}`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return bad('not JSON');
  }
  if (!isObj(raw)) return bad('not an object');
  if (typeof raw.engineVersion !== 'string') bad('engineVersion');
  for (const k of ['discovered', 'truncated', 'partial'] as const) {
    if (!isStrArr(raw[k])) bad(k);
  }
  if (!isObj(raw.scans)) bad('scans');
  if (!isObj(raw.currentFails)) bad('currentFails');
  for (const v of Object.values(raw.currentFails as Record<string, unknown>)) {
    if (!isStrArr(v)) bad('currentFails');
  }
  if (!Array.isArray(raw.candidates)) bad('candidates');

  // Strict, and fatal: a forged state would otherwise be committed to the ops repo.
  const discoveryState =
    raw.discoveryState === undefined ? undefined : validateDiscoveryState(raw.discoveryState);

  const engineVersion = raw.engineVersion as string;
  const discovered = (raw.discovered as string[]).filter(isPlainRepoName);
  const known = new Set(discovered);
  const dropped = { scans: 0, candidates: 0 };

  const scans: Record<string, RepoScan> = {};
  for (const [repo, scan] of Object.entries(raw.scans as Record<string, unknown>)) {
    if (isPlainRepoName(repo) && known.has(repo) && validScan(scan)) scans[repo] = scan;
    else dropped.scans++;
  }
  const currentFails: Record<string, string[]> = {};
  for (const [repo, ids] of Object.entries(raw.currentFails as Record<string, string[]>)) {
    if (isPlainRepoName(repo) && known.has(repo)) currentFails[repo] = ids;
  }
  const candidates: SubmitCandidate[] = [];
  for (const c of raw.candidates as unknown[]) {
    if (validCandidate(c, scans, known, engineVersion)) candidates.push(c);
    else dropped.candidates++;
  }
  return {
    engineVersion,
    discovered,
    truncated: raw.truncated as string[],
    partial: raw.partial as string[],
    scans,
    candidates,
    currentFails,
    ...(discoveryState ? { discoveryState } : {}),
    dropped,
  };
}

// ---------------------------------------------------------------- files

function readLedgerFile(path: string): Ledger {
  return existsSync(path) ? parseLedger(readFileSync(path, 'utf8')) : emptyLedger();
}

function readConfigFile(path: string): CrawlConfig {
  return parseCrawlConfig(existsSync(path) ? readFileSync(path, 'utf8') : '{}');
}

const evalFileName = (repo: string): string => `${repo.replace('/', '__')}.json`;

// ---------------------------------------------------------------- scan

export interface ScanArgs {
  ledger: string;
  config: string;
  out: string;
  cap?: number;
  /** Discovery state file (ops/discovery.json); a missing file means a fresh sweep. */
  discovery?: string;
  /**
   * Scope the run to one account's repos (0086). The discovery state is neither read nor
   * emitted, so a scoped check run never touches the global sweep.
   */
  owner?: string;
}

/** What runScan needs from discovery; the state-related fields are absent in simple fakes. */
export type ScanDiscovery = Pick<DiscoverResult, 'repos' | 'truncated' | 'partial'> &
  Partial<
    Pick<
      DiscoverResult,
      'state' | 'complete' | 'rateLimited' | 'budgetExhausted' | 'timedOut' | 'searches'
    >
  >;

export interface ScanDeps {
  /** Read-only client (search + metadata). */
  client: GitHubClient;
  discover: (
    client: GitHubClient,
    ctx: {
      state: DiscoveryState | undefined;
      budget: number;
      /** Epoch ms, judged by `clock` (the scan's own clock, so tests and runs agree). */
      deadline?: number;
      clock?: () => number;
      owner?: string;
    },
  ) => Promise<ScanDiscovery>;
  lsRemoteHeads: (repos: readonly string[]) => Promise<Map<string, string | null>>;
  scanRepos: typeof scanRepos;
  reverify: typeof reverify;
  /** Authoritative public/non-fork/non-archived check; runs only for the capped selection. */
  isEligible: (client: GitHubClient, repo: string) => Promise<Eligibility>;
  /** Extra env for eval-scan.sh (tests point it at local remotes and a stub CLI). */
  scanEnv?: NodeJS.ProcessEnv;
  cliVersion: () => Promise<string>;
  blastgateSha: () => Promise<string>;
  now: () => Date;
  log: (line: string) => void;
}

/** Bound for git subprocesses (push/pull/rev-parse). */
const EXEC_TIMEOUT_MS = 120_000;

/** Run a subprocess for its trimmed stdout; kills it and rejects after `timeoutMs`. Never prompts. */
export function execOut(
  cmd: string,
  args: string[],
  cwd: string,
  timeoutMs = EXEC_TIMEOUT_MS,
): Promise<string> {
  return new Promise((res, rej) => {
    execFile(
      cmd,
      args,
      { cwd, timeout: timeoutMs, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } },
      (err, stdout) => (err ? rej(err) : res(stdout.trim())),
    );
  });
}

export function defaultScanDeps(env: NodeJS.ProcessEnv): ScanDeps {
  const runner: Runner = defaultRunner;
  return {
    client: createGitHubClient({
      ...(env.GITHUB_TOKEN ? { token: env.GITHUB_TOKEN } : {}),
      onRateLimit: (info) => console.error(formatRateLimit(info)),
    }),
    discover: (client, ctx) =>
      discover({
        client,
        budget: ctx.budget,
        ...(ctx.deadline !== undefined ? { deadline: ctx.deadline } : {}),
        ...(ctx.clock ? { clock: ctx.clock } : {}),
        ...(ctx.state ? { state: ctx.state } : {}),
        ...(ctx.owner !== undefined ? { owner: ctx.owner } : {}),
      }),
    lsRemoteHeads: (repos) => lsRemoteHeads(repos),
    scanRepos,
    reverify,
    isEligible: checkEligible,
    cliVersion: async () => {
      const cli = env.BLASTGATE_CLI ?? join(ROOT, 'dist', 'cli', 'index.js');
      const r = await runner('node', [cli, '--version'], childEnv(env), 30_000);
      const m = /(\d+\.\d+\.\d+[^\s]*)/.exec(r.stdout);
      if (r.code !== 0 || !m?.[1]) throw new Error('could not read the blastgate CLI version');
      return m[1];
    },
    blastgateSha: async () => {
      const fromEnv = env.BLASTGATE_SHA?.trim();
      if (fromEnv) return fromEnv;
      return execOut('git', ['rev-parse', 'HEAD'], ROOT);
    },
    now: () => new Date(),
    log: (l) => console.log(l),
  };
}

/** Fail-tier findings of one repo from the local eval output (payloads present: stripped by composeReport). */
function readFailFindings(evalDir: string, repo: string): Finding[] | null {
  try {
    const data: unknown = JSON.parse(readFileSync(join(evalDir, evalFileName(repo)), 'utf8'));
    if (!Array.isArray(data)) return null;
    return data.filter((f): f is Finding => isObj(f) && f.tier === 'fail');
  } catch {
    return null;
  }
}

export async function runScan(args: ScanArgs, deps: ScanDeps): Promise<ScanResultFile> {
  const { owner } = args;
  if (owner !== undefined) assertOwnerLogin(owner);
  const ledger = readLedgerFile(args.ledger);
  const config = readConfigFile(args.config);
  const priorState =
    owner === undefined && args.discovery !== undefined && existsSync(args.discovery)
      ? parseDiscoveryState(readFileSync(args.discovery, 'utf8'))
      : undefined;
  const out = resolve(args.out);
  mkdirSync(out, { recursive: true });

  // A rate limit must never kill the job and discard the run: discovery ends early, and the
  // scan proceeds with the repos already known.
  let found: ScanDiscovery;
  try {
    found = await deps.discover(deps.client, {
      state: priorState,
      budget: config.discoveryBudget,
      deadline: deps.now().getTime() + config.discoveryMinutes * 60_000,
      clock: () => deps.now().getTime(),
      ...(owner !== undefined ? { owner } : {}),
    });
  } catch (e) {
    if (!(e instanceof GitHubRateLimitError)) throw e;
    deps.log('scan: discovery stopped by a rate limit; continuing with known repos');
    found = {
      repos: priorState ? Object.keys(priorState.repos).sort() : [],
      truncated: priorState?.sweep.truncated ?? [],
      partial: priorState?.sweep.partial ?? [],
      ...(priorState ? { state: priorState } : {}),
      rateLimited: true,
    };
  }
  const heads = await deps.lsRemoteHeads(found.repos);
  const engineVersion = `${await deps.cliVersion()}+${await deps.blastgateSha()}`;
  const cap = args.cap ?? DEFAULT_CAP;
  // Full priority order first; metadata is then fetched only while the cap is unfilled (and at
  // most MAX_CHECK_FACTOR x cap times), so the cost follows the cap, not the discovery size.
  const plan = delta(ledger, heads, engineVersion, Number.POSITIVE_INFINITY);
  const selected: string[] = [];
  let checks = 0;
  let ineligible = 0;
  let eligibilityErrors = 0;
  for (const entry of plan.selected) {
    if (selected.length >= cap || checks >= cap * MAX_CHECK_FACTOR) break;
    checks++;
    const verdict = await deps.isEligible(deps.client, entry.repo);
    if (verdict === 'eligible') selected.push(entry.repo);
    else if (verdict === 'ineligible') ineligible++;
    else eligibilityErrors++;
  }
  const deferred = plan.selected.length - checks;

  const evalDir = join(out, 'eval');
  const scans = await deps.scanRepos(selected, {
    workdir: join(out, 'work'),
    outdir: evalDir,
    ...(deps.scanEnv ? { env: deps.scanEnv } : {}),
    engineVersion,
    now: deps.now,
  });

  const currentFails: Record<string, string[]> = {};
  const candidates: SubmitCandidate[] = [];
  let reverifyErrors = 0;
  let unreadable = 0;
  let n = 0;
  for (const [repo, scan] of Object.entries(scans)) {
    if (scan.verdict === 'pass' || scan.verdict === 'warn' || scan.verdict === 'fail') {
      currentFails[repo] = scan.failFindings.map((f) => f.id);
    }
    if (scan.verdict !== 'fail') continue;

    const failing = readFailFindings(evalDir, repo);
    if (failing === null) {
      unreadable++;
      continue;
    }
    const head = heads.get(repo);
    const allIds = scan.failFindings.map((f) => f.id);
    let status: SubmitCandidate['reverify'] = 'unknown';
    let stillIds = new Set<string>();
    const dir = join(out, 'reverify', String(n++));
    try {
      const r = await deps.reverify(repo, {
        freshWorkdir: join(dir, 'work'),
        outdir: join(dir, 'eval'),
        ...(deps.scanEnv ? { env: deps.scanEnv } : {}),
        engineVersion,
        now: deps.now,
        expectedFindingIds: allIds,
        remoteHead: head ?? '',
      });
      status = r.status;
      stillIds = new Set(r.scan.failFindings.map((f) => f.id));
    } catch {
      reverifyErrors++;
    }

    const groups = new Map<string, Finding[]>();
    for (const f of failing) {
      const a = archetypeOf(f);
      groups.set(a, [...(groups.get(a) ?? []), f]);
    }
    for (const [archetype, findings] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
      const findingIds = findings.map((f) => f.id);
      const groupStatus =
        status === 'still-fails' && !findingIds.some((id) => stillIds.has(id))
          ? 'resolved'
          : status;
      candidates.push({
        repo,
        archetype,
        findingIds,
        report: composeReport({
          repo,
          sha: scan.fullSha,
          findings,
          blastgateVersion: engineVersion,
        }),
        reverify: groupStatus,
      });
    }
  }

  const result: ScanResultFile = {
    engineVersion,
    discovered: found.repos,
    truncated: found.truncated,
    partial: found.partial,
    scans,
    candidates,
    currentFails,
    ...(found.state && owner === undefined ? { discoveryState: found.state } : {}),
  };
  writeFileSync(join(out, 'scan-result.json'), `${JSON.stringify(result, null, 2)}\n`);

  const verdicts: Record<string, number> = {};
  for (const s of Object.values(scans)) verdicts[s.verdict] = (verdicts[s.verdict] ?? 0) + 1;
  deps.log(
    `scan: discovered ${found.repos.length}, truncated shards ${found.truncated.length}, partial shards ${found.partial.length}, ` +
      `selected ${selected.length}, deferred ${deferred}, head-unresolved ${plan.skipped.length}, ` +
      `ineligible ${ineligible}, eligibility errors ${eligibilityErrors}`,
  );
  if (found.state) {
    deps.log(
      `scan: discovery ${found.complete ? 'sweep complete' : `sweep in progress, ${found.state.sweep.pending.length} shard(s) pending`}; ` +
        `searches ${found.searches ?? 0}/${config.discoveryBudget}; ` +
        `${found.rateLimited ? 'stopped by rate limit' : found.timedOut ? `stopped by time limit (${config.discoveryMinutes} min)` : found.budgetExhausted ? 'stopped by budget' : 'not interrupted'}`,
    );
  }
  deps.log(
    `scan: verdict counts ${
      Object.entries(verdicts)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join(' ') || 'none'
    }; candidates ${candidates.length}; ` +
      `reverify errors ${reverifyErrors}; unreadable ${unreadable}`,
  );
  return result;
}

// ---------------------------------------------------------------- persist

export interface GitPersistOptions {
  ledgerPath: string;
  /** Where the discovery state lives; committed together with the ledger. */
  discoveryPath?: string;
  /** The ops repo checkout; defaults to the ledger's directory. */
  repoDir?: string;
  exec?: (args: string[], cwd: string) => Promise<string>;
}

const gitExec = (args: string[], cwd: string): Promise<string> => execOut('git', args, cwd);

/**
 * Durable save: write the ledger (and the discovery state, if given), then commit and push
 * them in the ops checkout as one commit.
 */
export function gitPersist(
  opts: GitPersistOptions,
): (ledger: Ledger, discovery?: DiscoveryState) => Promise<void> {
  const repoDir = opts.repoDir ?? dirname(resolve(opts.ledgerPath));
  const exec = opts.exec ?? gitExec;
  return async (ledger, discovery) => {
    writeFileSync(opts.ledgerPath, serializeLedger(ledger));
    const files = [relative(repoDir, resolve(opts.ledgerPath))];
    if (discovery && opts.discoveryPath) {
      writeFileSync(opts.discoveryPath, serializeDiscoveryState(discovery));
      files.push(relative(repoDir, resolve(opts.discoveryPath)));
    }
    await exec(['add', '--', ...files], repoDir);
    const changed = await exec(['status', '--porcelain', '--', ...files], repoDir);
    if (changed.trim() === '') return;
    await exec(
      [
        '-c',
        'user.name=blastgate-crawler',
        '-c',
        'user.email=blastgate-crawler@users.noreply.github.com',
        'commit',
        '-q',
        '--no-gpg-sign',
        '-m',
        'crawl: update ledger',
      ],
      repoDir,
    );
    try {
      await exec(['push', '-q', 'origin', 'HEAD'], repoDir);
    } catch {
      // Someone (Jay, editing config) pushed meanwhile: rebase once and retry.
      const branch = await exec(['rev-parse', '--abbrev-ref', 'HEAD'], repoDir);
      await exec(['pull', '--rebase', '-q', 'origin', branch.trim()], repoDir);
      await exec(['push', '-q', 'origin', 'HEAD'], repoDir);
    }
  };
}

// ---------------------------------------------------------------- submit

export interface SubmitArgs {
  ledger: string;
  config: string;
  in: string;
  site: string;
  killSwitch?: string;
  /** Registry remote; publishing happens only when this is set AND config.publishSite is on. */
  remote?: string;
}

export interface SubmitDeps {
  /** Client holding the reporting token. */
  client: GitHubClient;
  /** `discovery` rides in the same commit as the ledger. */
  persist: (ledger: Ledger, discovery?: DiscoveryState) => Promise<void>;
  publish: (siteDir: string, remoteUrl: string) => Promise<void>;
  now: () => Date;
  log: (line: string) => void;
  submitAll?: typeof submitAll;
  trackAll?: typeof trackAll;
  renderSite?: typeof renderSite;
}

function writeSite(dir: string, files: Record<string, string>): void {
  const root = resolve(dir);
  rmSync(root, { recursive: true, force: true });
  for (const [name, content] of Object.entries(files)) {
    const target = resolve(root, name);
    if (relative(root, target).startsWith('..')) throw new Error('site file escapes the site dir');
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

async function maybePublish(
  config: CrawlConfig,
  siteDir: string,
  remote: string | undefined,
  deps: Pick<SubmitDeps, 'publish' | 'log'>,
): Promise<void> {
  if (!config.publishSite) {
    deps.log('publish skipped (publishSite is off)');
  } else if (!remote) {
    deps.log('publish skipped (no remote given)');
  } else {
    await deps.publish(siteDir, remote);
    deps.log('published');
  }
}

/** Returns the process exit code. Throws only for bad input, before any write. */
export async function runSubmit(args: SubmitArgs, deps: SubmitDeps): Promise<number> {
  const config = readConfigFile(args.config);
  const result = parseScanResult(readFileSync(args.in, 'utf8'));
  const iso = (): string => deps.now().toISOString();

  // Every ledger write carries the validated discovery state, so progress is never lost.
  const persist = (l: Ledger): Promise<void> => deps.persist(l, result.discoveryState);

  let ledger = readLedgerFile(args.ledger);
  const recovered = recoverSubmitting(ledger, iso());
  if (recovered !== ledger) {
    ledger = recovered;
    await persist(ledger);
  }
  if (result.dropped.scans > 0 || result.dropped.candidates > 0) {
    deps.log(
      `submit: dropped ${result.dropped.scans} scan(s) and ${result.dropped.candidates} candidate(s) failing validation`,
    );
  }
  for (const [repo, scan] of Object.entries(result.scans)) ledger = applyScan(ledger, repo, scan);

  const killSwitch = args.killSwitch !== undefined && existsSync(args.killSwitch);
  const sub = await (deps.submitAll ?? submitAll)({
    ledger,
    candidates: result.candidates,
    config,
    client: deps.client,
    killSwitch,
    persist,
    now: deps.now,
  });
  ledger = sub.ledger;

  let ok = true;
  let flagged = 0;
  if (config.reporterLogin !== '') {
    try {
      const currentFails = new Map(
        Object.entries(result.currentFails).map(([r, ids]) => [r, new Set(ids)]),
      );
      const t = await (deps.trackAll ?? trackAll)({
        ledger,
        client: deps.client,
        reporterLogin: config.reporterLogin,
        now: iso(),
        currentFails,
      });
      ledger = t.ledger;
      flagged = t.flagged.length;
    } catch {
      ok = false;
      deps.log('track: failed (ledger kept as-is)');
    }
  } else {
    deps.log('track: skipped (no reporterLogin)');
  }

  // The ledger is the one thing that cannot be rederived: save it before the site is touched.
  await persist(ledger);

  const counts = Object.entries(sub.summary.counts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');
  deps.log(
    `submit: ${counts || 'no candidates'}${sub.summary.stoppedReason ? `; stopped: ${sub.summary.stoppedReason}` : ''}; ` +
      `mode ${config.submitMode ? 'live' : 'dry-run'}; kill switch ${killSwitch ? 'on' : 'off'}; flagged ${flagged}`,
  );

  try {
    const files = (deps.renderSite ?? renderSite)(ledger, {
      generatedAt: iso(),
      discovered: new Set(result.discovered),
    });
    writeSite(args.site, files);
    deps.log(`site: built ${Object.keys(files).length} file(s)`);
    await maybePublish(config, args.site, args.remote, deps);
  } catch {
    ok = false;
    deps.log('site: build or publish failed (ledger already saved)');
  }
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------- publish step

export async function runPublish(
  args: { config: string; site: string; remote: string },
  deps: Pick<SubmitDeps, 'publish' | 'log'>,
): Promise<number> {
  const config = readConfigFile(args.config);
  try {
    await maybePublish(config, args.site, args.remote, deps);
    return 0;
  } catch {
    deps.log('publish: failed');
    return 1;
  }
}

// ---------------------------------------------------------------- CLI

const USAGE = `usage:
  crawl scan    --ledger <path> --config <path> --out <dir> [--cap N] [--discovery <path>] [--owner <login>]
  crawl submit  --ledger <path> --config <path> --in <scan-result.json> --site <dir> [--kill-switch <path>] [--remote <url>] [--discovery <path>]
  crawl publish --config <path> --site <dir> --remote <url>`;

const REGISTRY_AUTHOR = {
  name: 'Blastgate Registry',
  email: 'blastgate-registry@users.noreply.github.com',
};

export async function main(argv: string[], env: NodeJS.ProcessEnv): Promise<number> {
  const [cmd, ...rest] = argv;
  const need = (v: string | undefined, name: string): string => {
    if (!v) throw new Error(`missing --${name}\n${USAGE}`);
    return v;
  };
  const { values } = parseArgs({
    args: rest,
    options: {
      ledger: { type: 'string' },
      config: { type: 'string' },
      out: { type: 'string' },
      cap: { type: 'string' },
      discovery: { type: 'string' },
      in: { type: 'string' },
      site: { type: 'string' },
      'kill-switch': { type: 'string' },
      remote: { type: 'string' },
      owner: { type: 'string' },
    },
  });
  const log = (l: string): void => console.log(l);
  const publish = (dir: string, remoteUrl: string): Promise<void> =>
    publishSite(dir, { remoteUrl, branch: 'gh-pages', author: REGISTRY_AUTHOR });

  if (cmd === 'scan') {
    const cap = values.cap === undefined ? undefined : Number(values.cap);
    if (cap !== undefined && (!Number.isInteger(cap) || cap < 0)) throw new Error('bad --cap');
    await runScan(
      {
        ledger: need(values.ledger, 'ledger'),
        config: need(values.config, 'config'),
        out: need(values.out, 'out'),
        ...(cap !== undefined ? { cap } : {}),
        ...(values.discovery ? { discovery: values.discovery } : {}),
        ...(values.owner !== undefined ? { owner: values.owner } : {}),
      },
      defaultScanDeps(env),
    );
    return 0;
  }
  if (cmd === 'submit') {
    const ledger = need(values.ledger, 'ledger');
    return runSubmit(
      {
        ledger,
        config: need(values.config, 'config'),
        in: need(values.in, 'in'),
        site: need(values.site, 'site'),
        ...(values['kill-switch'] ? { killSwitch: values['kill-switch'] } : {}),
        ...(values.remote ? { remote: values.remote } : {}),
      },
      {
        client: createGitHubClient({
          ...(env.GITHUB_TOKEN ? { token: env.GITHUB_TOKEN } : {}),
          onRateLimit: (info) => console.error(formatRateLimit(info)),
        }),
        persist: gitPersist({
          ledgerPath: ledger,
          ...(values.discovery ? { discoveryPath: values.discovery } : {}),
        }),
        publish,
        now: () => new Date(),
        log,
      },
    );
  }
  if (cmd === 'publish') {
    return runPublish(
      {
        config: need(values.config, 'config'),
        site: need(values.site, 'site'),
        remote: need(values.remote, 'remote'),
      },
      { publish, log },
    );
  }
  throw new Error(USAGE);
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(resolve(entry)).href) {
  main(process.argv.slice(2), process.env).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(`crawl: ${(e as Error).message}`);
      process.exitCode = 1;
    },
  );
}
