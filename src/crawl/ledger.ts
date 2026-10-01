/**
 * Crawl ledger (U2, KTD4) — durable private state for the public crawler: what was
 * scanned (per repo) and what was disclosed (per finding set). Pure module: no I/O,
 * every function returns a new ledger. The caller reads/commits the JSON file.
 *
 * Safety posture: a ledger that cannot be parsed THROWS. It is never reset to empty,
 * because an empty ledger would forget disclosures and re-file reports.
 */

import { execFile } from 'node:child_process';
import type { Verdict } from '../findings/finding';
import { isPlainRepoName } from './github';

export const LEDGER_SCHEMA_VERSION = 1 as const;

/** A scan outcome. `clone-failed` is crawler-only: a clone that could not complete is never a pass. */
export type ScanVerdict = Verdict | 'clone-failed';

export const SCAN_VERDICTS: readonly ScanVerdict[] = [
  'pass',
  'warn',
  'fail',
  'unknown',
  'clone-failed',
];

export const DISCLOSURE_STATES = [
  'held',
  'queued',
  'submitting',
  'submitted',
  'fixed',
  'declined',
  'published-credited',
  'resolved-before-report',
] as const;
export type DisclosureState = (typeof DISCLOSURE_STATES)[number];

export interface FailFinding {
  id: string;
  archetype: string;
}

export interface RepoScan {
  /** Full 40-char SHA; the site shortens it for display. */
  fullSha: string;
  engineVersion: string;
  verdict: ScanVerdict;
  /** ISO timestamp. */
  scannedAt: string;
  failFindings: FailFinding[];
}

export interface Disclosure {
  repo: string;
  findingIds: string[];
  archetype: string;
  state: DisclosureState;
  reportUrl?: string;
  ghsaId?: string;
  reason?: string;
  /** Dry run only: the exact request body that would have been POSTed. */
  wouldSend?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface Ledger {
  schemaVersion: typeof LEDGER_SCHEMA_VERSION;
  repos: Record<string, RepoScan>;
  disclosures: Disclosure[];
  /** Archetypes sent back to held by a false-positive report (KTD6.2 tripwire); sorted, unique. Absent = none. */
  trippedArchetypes?: string[];
}

export const UNCERTAIN_REASON = 'submission state uncertain';
export const REASON_NO_PVR = 'no PVR';
export const REASON_NOT_ALLOWLISTED = 'archetype not allowlisted';
export const REASON_RATE_LIMITED = 'rate limited (HTTP';

/**
 * Held reasons a later run may re-evaluate: no PVR (optionally with the HTTP status that caused
 * it), a non-allowlisted archetype (config may have changed), and a rate-limit hold. Everything
 * else (uncertain state, send failed, duplicate, tripped archetype) is final.
 */
export function isRetryableHold(d: Pick<Disclosure, 'reason'>): boolean {
  const r = d.reason ?? '';
  return (
    r === REASON_NO_PVR ||
    r.startsWith(`${REASON_NO_PVR} (HTTP `) ||
    r === REASON_NOT_ALLOWLISTED ||
    r.startsWith(REASON_RATE_LIMITED)
  );
}

const SHA_RE = /^[0-9a-f]{40}$/;

export function emptyLedger(): Ledger {
  return { schemaVersion: LEDGER_SCHEMA_VERSION, repos: {}, disclosures: [] };
}

// ---------------------------------------------------------------- parse / serialize

function fail(msg: string): never {
  throw new Error(`invalid crawl ledger: ${msg}`);
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function str(o: Record<string, unknown>, k: string, where: string): string {
  const v = o[k];
  if (typeof v !== 'string' || v === '') fail(`${where}.${k} must be a non-empty string`);
  return v;
}

function optStr(o: Record<string, unknown>, k: string, where: string): string | undefined {
  const v = o[k];
  if (v === undefined) return undefined;
  if (typeof v !== 'string') fail(`${where}.${k} must be a string`);
  return v;
}

function optObj(
  o: Record<string, unknown>,
  k: string,
  where: string,
): Record<string, unknown> | undefined {
  const v = o[k];
  if (v === undefined) return undefined;
  if (!isObj(v)) fail(`${where}.${k} must be an object`);
  return v;
}

function parseScan(v: unknown, repo: string): RepoScan {
  const where = `repos["${repo}"]`;
  if (!isObj(v)) fail(`${where} must be an object`);
  const fullSha = str(v, 'fullSha', where);
  if (!SHA_RE.test(fullSha)) fail(`${where}.fullSha must be a 40-char lowercase hex sha`);
  const verdict = str(v, 'verdict', where) as ScanVerdict;
  if (!SCAN_VERDICTS.includes(verdict)) fail(`${where}.verdict "${verdict}" is not recognized`);
  const ff = v.failFindings;
  if (!Array.isArray(ff)) fail(`${where}.failFindings must be an array`);
  return {
    fullSha,
    engineVersion: str(v, 'engineVersion', where),
    verdict,
    scannedAt: str(v, 'scannedAt', where),
    failFindings: ff.map((f, i) => {
      if (!isObj(f)) fail(`${where}.failFindings[${i}] must be an object`);
      return { id: str(f, 'id', where), archetype: str(f, 'archetype', where) };
    }),
  };
}

function parseDisclosure(v: unknown, i: number): Disclosure {
  const where = `disclosures[${i}]`;
  if (!isObj(v)) fail(`${where} must be an object`);
  const state = str(v, 'state', where) as DisclosureState;
  if (!DISCLOSURE_STATES.includes(state)) fail(`${where}.state "${state}" is not recognized`);
  const ids = v.findingIds;
  if (!Array.isArray(ids) || ids.length === 0 || !ids.every((x) => typeof x === 'string')) {
    fail(`${where}.findingIds must be a non-empty string array`);
  }
  return normalizeDisclosure({
    repo: str(v, 'repo', where),
    findingIds: ids as string[],
    archetype: str(v, 'archetype', where),
    state,
    reportUrl: optStr(v, 'reportUrl', where),
    ghsaId: optStr(v, 'ghsaId', where),
    reason: optStr(v, 'reason', where),
    wouldSend: optObj(v, 'wouldSend', where),
    createdAt: str(v, 'createdAt', where),
    updatedAt: str(v, 'updatedAt', where),
  });
}

/** Parse a ledger. Throws on anything malformed or of an unknown schemaVersion — never returns empty. */
export function parseLedger(text: string): Ledger {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return fail(`not valid JSON (${(e as Error).message})`);
  }
  if (!isObj(raw)) fail('top level must be an object');
  if (raw.schemaVersion !== LEDGER_SCHEMA_VERSION) {
    fail(`unsupported schemaVersion ${JSON.stringify(raw.schemaVersion)} (expected 1)`);
  }
  if (!isObj(raw.repos)) fail('repos must be an object');
  if (!Array.isArray(raw.disclosures)) fail('disclosures must be an array');
  const repos: Record<string, RepoScan> = {};
  for (const [name, scan] of Object.entries(raw.repos)) repos[name] = parseScan(scan, name);
  const tripped = raw.trippedArchetypes;
  if (
    tripped !== undefined &&
    (!Array.isArray(tripped) || !tripped.every((x) => typeof x === 'string' && x !== ''))
  ) {
    fail('trippedArchetypes must be an array of non-empty strings');
  }
  return {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    repos,
    disclosures: raw.disclosures.map(parseDisclosure),
    ...(tripped && tripped.length > 0 ? { trippedArchetypes: normalizeTripped(tripped) } : {}),
  };
}

const normalizeTripped = (a: readonly string[]): string[] => [...new Set(a)].sort();

/** Fixed key order, optional keys only when set, finding ids sorted. */
function normalizeDisclosure(d: Disclosure): Disclosure {
  return {
    repo: d.repo,
    findingIds: [...d.findingIds].sort(),
    archetype: d.archetype,
    state: d.state,
    ...(d.reportUrl !== undefined ? { reportUrl: d.reportUrl } : {}),
    ...(d.ghsaId !== undefined ? { ghsaId: d.ghsaId } : {}),
    ...(d.reason !== undefined ? { reason: d.reason } : {}),
    ...(d.wouldSend !== undefined ? { wouldSend: d.wouldSend } : {}),
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  };
}

const idsKey = (ids: readonly string[]): string => [...ids].sort().join('\n');

/** Serialize with stable key order (repos by name, disclosures by repo then ids) so diffs stay minimal. */
export function serializeLedger(ledger: Ledger): string {
  const repos: Record<string, RepoScan> = {};
  for (const name of Object.keys(ledger.repos).sort()) {
    const s = ledger.repos[name] as RepoScan;
    repos[name] = {
      fullSha: s.fullSha,
      engineVersion: s.engineVersion,
      verdict: s.verdict,
      scannedAt: s.scannedAt,
      failFindings: s.failFindings.map((f) => ({ id: f.id, archetype: f.archetype })),
    };
  }
  const disclosures = ledger.disclosures
    .map(normalizeDisclosure)
    .sort(
      (a, b) =>
        a.repo.localeCompare(b.repo) ||
        idsKey(a.findingIds).localeCompare(idsKey(b.findingIds)) ||
        a.createdAt.localeCompare(b.createdAt),
    );
  const tripped = ledger.trippedArchetypes?.length
    ? { trippedArchetypes: normalizeTripped(ledger.trippedArchetypes) }
    : {};
  return `${JSON.stringify({ schemaVersion: LEDGER_SCHEMA_VERSION, repos, disclosures, ...tripped }, null, 2)}\n`;
}

/** Send an archetype back to held (KTD6.2 tripwire). Idempotent; `_now` is accepted for call-site symmetry. */
export function tripArchetype(ledger: Ledger, archetype: string, _now: string): Ledger {
  void _now;
  return {
    ...ledger,
    trippedArchetypes: normalizeTripped([...(ledger.trippedArchetypes ?? []), archetype]),
  };
}

// ---------------------------------------------------------------- scans

/** Record (replace) a repo's latest scan. */
export function applyScan(ledger: Ledger, repo: string, scan: RepoScan): Ledger {
  if (!SHA_RE.test(scan.fullSha))
    throw new Error(`applyScan: fullSha must be a 40-char sha for ${repo}`);
  if (!SCAN_VERDICTS.includes(scan.verdict))
    throw new Error(`applyScan: bad verdict ${scan.verdict}`);
  return { ...ledger, repos: { ...ledger.repos, [repo]: { ...scan } } };
}

// ---------------------------------------------------------------- disclosures

/** Legal moves. `submitting -> held` is the crash-recovery edge; `submitting` is never retried. */
const ALLOWED: Record<DisclosureState, readonly DisclosureState[]> = {
  held: ['queued', 'resolved-before-report'],
  queued: ['held', 'submitting', 'resolved-before-report'],
  submitting: ['submitted', 'held'],
  submitted: ['fixed', 'declined', 'published-credited'],
  fixed: ['published-credited'],
  declined: [],
  'published-credited': [],
  'resolved-before-report': [],
};

export interface DisclosureKey {
  repo: string;
  findingIds: readonly string[];
}

export interface NewDisclosure extends DisclosureKey {
  archetype: string;
  state: 'held' | 'queued';
  reason?: string;
  now: string;
}

/**
 * Create a disclosure. Duplicate guard (KTD6.5): refused if any non-`resolved-before-report`
 * disclosure for the same repo already covers one of these finding ids — including
 * `submitting` and recovered-`held` entries, since those may already have been filed.
 */
export function createDisclosure(ledger: Ledger, d: NewDisclosure): Ledger {
  if (d.state !== 'held' && d.state !== 'queued') {
    throw new Error(`createDisclosure: initial state must be held or queued, got ${d.state}`);
  }
  if (d.findingIds.length === 0) throw new Error('createDisclosure: findingIds must be non-empty');
  const ids = new Set(d.findingIds);
  const clash = ledger.disclosures.find(
    (x) =>
      x.repo === d.repo &&
      x.state !== 'resolved-before-report' &&
      x.findingIds.some((id) => ids.has(id)),
  );
  if (clash) {
    throw new Error(
      `createDisclosure: ${d.repo} already has a disclosure (${clash.state}) covering finding ids ${[...ids].filter((i) => clash.findingIds.includes(i)).join(', ')}`,
    );
  }
  const created = normalizeDisclosure({
    repo: d.repo,
    findingIds: [...d.findingIds],
    archetype: d.archetype,
    state: d.state,
    ...(d.reason !== undefined ? { reason: d.reason } : {}),
    createdAt: d.now,
    updatedAt: d.now,
  });
  return { ...ledger, disclosures: [...ledger.disclosures, created] };
}

export interface TransitionOpts {
  now: string;
  reportUrl?: string;
  ghsaId?: string;
  reason?: string;
}

/**
 * Index of the disclosure for a key. A finding set can have several entries over time (a
 * `resolved-before-report` one, then a fresh one when it is re-detected): prefer the latest
 * live entry, and fall back to the latest terminal one so callers get a clear "illegal move".
 */
function findDisclosure(ledger: Ledger, key: DisclosureKey): number {
  const k = idsKey(key.findingIds);
  let terminal = -1;
  for (let i = ledger.disclosures.length - 1; i >= 0; i--) {
    const d = ledger.disclosures[i] as Disclosure;
    if (d.repo !== key.repo || idsKey(d.findingIds) !== k) continue;
    if (d.state !== 'resolved-before-report') return i;
    if (terminal < 0) terminal = i;
  }
  return terminal;
}

/** Move a disclosure to a new state, throwing on an illegal move. `submitted` requires `reportUrl`. */
export function transition(
  ledger: Ledger,
  key: DisclosureKey,
  to: DisclosureState,
  opts: TransitionOpts,
): Ledger {
  const idx = findDisclosure(ledger, key);
  const cur = ledger.disclosures[idx];
  if (!cur)
    throw new Error(`transition: no disclosure for ${key.repo} [${key.findingIds.join(', ')}]`);
  if (!ALLOWED[cur.state].includes(to)) {
    throw new Error(`transition: illegal move ${cur.state} -> ${to} for ${key.repo}`);
  }
  const reportUrl = opts.reportUrl ?? cur.reportUrl;
  if (to === 'submitted' && !reportUrl)
    throw new Error('transition: submitted requires a reportUrl');
  const next = normalizeDisclosure({
    ...cur,
    state: to,
    reportUrl,
    ghsaId: opts.ghsaId ?? cur.ghsaId,
    reason: opts.reason ?? (to === 'held' ? cur.reason : undefined),
    updatedAt: opts.now,
  });
  return { ...ledger, disclosures: ledger.disclosures.map((d, i) => (i === idx ? next : d)) };
}

/** Dry run: attach the exact would-send request body to a `queued` disclosure (no state change). */
export function recordWouldSend(
  ledger: Ledger,
  key: DisclosureKey,
  wouldSend: Record<string, unknown>,
  now: string,
): Ledger {
  const idx = findDisclosure(ledger, key);
  const cur = ledger.disclosures[idx];
  if (!cur) throw new Error(`recordWouldSend: no disclosure for ${key.repo}`);
  if (cur.state !== 'queued') {
    throw new Error(`recordWouldSend: ${key.repo} is ${cur.state}, expected queued`);
  }
  const next = normalizeDisclosure({ ...cur, wouldSend, updatedAt: now });
  return { ...ledger, disclosures: ledger.disclosures.map((d, i) => (i === idx ? next : d)) };
}

/**
 * Startup recovery (AE7): a `submitting` entry means a run died between "about to POST" and
 * "URL recorded", so the report may or may not exist. Hold it for Jay; never retry.
 */
export function recoverSubmitting(ledger: Ledger, now: string): Ledger {
  if (!ledger.disclosures.some((d) => d.state === 'submitting')) return ledger;
  return {
    ...ledger,
    disclosures: ledger.disclosures.map((d) =>
      d.state === 'submitting'
        ? normalizeDisclosure({ ...d, state: 'held', reason: UNCERTAIN_REASON, updatedAt: now })
        : d,
    ),
  };
}

// ---------------------------------------------------------------- delta

export type DeltaReason =
  | 'listed-pass-old-engine'
  | 'listed-pass-changed'
  | 'pending-disclosure'
  | 'new'
  | 'changed'
  | 'old-engine';

export interface DeltaEntry {
  repo: string;
  reason: DeltaReason;
}

export interface DeltaResult {
  /** Repos to scan this run, highest priority first, at most `cap`. */
  selected: DeltaEntry[];
  /** Repos whose head could not be resolved (null) — skipped this run, to be reported. */
  skipped: string[];
  /** Eligible repos beyond the cap, left for a later run. */
  deferred: number;
}

/**
 * A `fail` repo still owes a disclosure: one is queued or held for a retryable reason, or some
 * of its failing finding ids are covered by no disclosure at all (deferred by the throttle,
 * re-verify inconclusive, ...). It must be rescanned even when nothing upstream changed, or the
 * report would never be retried.
 */
function hasPendingDisclosure(ledger: Ledger, repo: string, scan: RepoScan): boolean {
  const mine = ledger.disclosures.filter((d) => d.repo === repo);
  if (mine.some((d) => d.state === 'queued' || (d.state === 'held' && isRetryableHold(d)))) {
    return true;
  }
  const covered = new Set(mine.flatMap((d) => d.findingIds));
  return scan.failFindings.some((f) => !covered.has(f.id));
}

/**
 * Which repos to scan (R2). Eligible: new, head SHA changed, last scanned by a different
 * engine version ("older" = not equal; versions are opaque strings here), or a `fail` with a
 * disclosure still pending. Priority: listed passes whose engine or SHA changed (so the public
 * list is re-vouched first, AE6), then pending disclosures, then new repos, then the rest
 * oldest-scanned first; ties break by repo name for determinism.
 */
export function delta(
  ledger: Ledger,
  heads: ReadonlyMap<string, string | null>,
  engineVersion: string,
  cap: number,
): DeltaResult {
  const skipped: string[] = [];
  const eligible: Array<DeltaEntry & { rank: number; at: string }> = [];
  for (const [repo, head] of heads) {
    if (head === null) {
      skipped.push(repo);
      continue;
    }
    const prev = ledger.repos[repo];
    if (!prev) {
      eligible.push({ repo, reason: 'new', rank: 2, at: '' });
      continue;
    }
    const oldEngine = prev.engineVersion !== engineVersion;
    const changed = prev.fullSha !== head;
    if (prev.verdict === 'pass' && (oldEngine || changed)) {
      const reason = oldEngine ? 'listed-pass-old-engine' : 'listed-pass-changed';
      eligible.push({ repo, reason, rank: 0, at: prev.scannedAt });
    } else if (prev.verdict === 'fail' && hasPendingDisclosure(ledger, repo, prev)) {
      eligible.push({ repo, reason: 'pending-disclosure', rank: 1, at: prev.scannedAt });
    } else if (changed) {
      eligible.push({ repo, reason: 'changed', rank: 3, at: prev.scannedAt });
    } else if (oldEngine) {
      eligible.push({ repo, reason: 'old-engine', rank: 3, at: prev.scannedAt });
    }
  }
  eligible.sort(
    (a, b) => a.rank - b.rank || a.at.localeCompare(b.at) || a.repo.localeCompare(b.repo),
  );
  const limit = Math.max(0, cap);
  return {
    selected: eligible.slice(0, limit).map(({ repo, reason }) => ({ repo, reason })),
    skipped,
    deferred: Math.max(0, eligible.length - limit),
  };
}

// ---------------------------------------------------------------- head resolution

/** Runs `git` with these args and resolves its stdout; rejects on failure. Injectable for tests. */
export type GitExec = (args: string[]) => Promise<string>;

const defaultExec: GitExec = (args) =>
  new Promise((resolve, reject) => {
    execFile(
      'git',
      args,
      { timeout: 30_000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
  });

/**
 * Resolve each repo's default-branch HEAD via `git ls-remote`, with bounded parallelism.
 * Any failure, empty output, or non-`owner/repo` name yields `null` (skipped, never scanned).
 */
export async function lsRemoteHeads(
  repos: readonly string[],
  opts: { exec?: GitExec; concurrency?: number } = {},
): Promise<Map<string, string | null>> {
  const exec = opts.exec ?? defaultExec;
  const workers = Math.max(1, opts.concurrency ?? 8);
  const out = new Map<string, string | null>();
  let next = 0;
  const one = async (repo: string): Promise<string | null> => {
    if (!isPlainRepoName(repo)) return null;
    try {
      const stdout = await exec(['ls-remote', `https://github.com/${repo}.git`, 'HEAD']);
      const m = /^([0-9a-f]{40})\s+HEAD\s*$/m.exec(stdout);
      return m?.[1] ?? null;
    } catch {
      return null;
    }
  };
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      const repo = repos[i];
      if (repo === undefined) return;
      out.set(repo, await one(repo));
    }
  };
  await Promise.all(Array.from({ length: Math.min(workers, repos.length) }, worker));
  return out;
}
