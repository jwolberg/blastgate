/**
 * Persisted discovery state (0083). Discovery is incremental: one run works a queue of search
 * shards under a request budget, and the queue plus the repos found so far survive between
 * runs in `ops/discovery.json`.
 *
 * Trust (KTD1): the scan job (contents: read) produces the state and the submit job writes it,
 * so submit validates it as strictly as it does the rest of scan-result.json, and the scan job
 * validates the committed file it loads.
 */

import { AGENT_PROFILES } from '../analyzers/ci/agents';
import { isPlainRepoName } from './github';

export const DISCOVERY_SCHEMA_VERSION = 1;

/** GitHub does not index files larger than this; the top of every size range. */
export const MAX_FILE_SIZE = 1_000_000;

/**
 * Size ranges a saturated whole-range shard is split into, from where agent workflow files
 * actually fall: most are 1-6 KB, almost none exceed 20 KB. Fine at the dense low end, one tail
 * range above 20,000. Contiguous and non-overlapping; a saturated range still bisects further.
 */
export const DEFAULT_SIZE_SEEDS: readonly (readonly [number, number])[] = (() => {
  const edges: number[] = [];
  for (let e = 250; e <= 3000; e += 250) edges.push(e);
  for (let e = 3500; e <= 6000; e += 500) edges.push(e);
  for (let e = 7000; e <= 12000; e += 1000) edges.push(e);
  for (let e = 14000; e <= 20000; e += 2000) edges.push(e);
  const out: [number, number][] = [];
  let lo = 0;
  for (const hi of edges) {
    out.push([lo, hi]);
    lo = hi + 1;
  }
  out.push([lo, MAX_FILE_SIZE]);
  return out;
})();

/** One unit of search work: a code-search query narrowed by size range and/or filename. */
export interface Shard {
  action: string;
  size: [number, number];
  filename?: string;
  depth: number;
}

export interface DiscoverySweep {
  /** ISO time the sweep began; doubles as the sweep id. */
  startedAt: string;
  /** Work queue, in processing order. Empty once the sweep is complete. */
  pending: Shard[];
  /** Set when the queue emptied; the next run starts a new sweep. */
  completedAt?: string;
  /** Shard queries over the search cap that could not be fully covered, this sweep. */
  truncated: string[];
  /** Shard queries GitHub reported incomplete or that failed, this sweep. */
  partial: string[];
}

export interface DiscoveryState {
  schemaVersion: 1;
  sweep: DiscoverySweep;
  /** Every known repo and the sweep that last saw it. */
  repos: Record<string, { lastSeenSweep: string }>;
}

export const MAX_STATE_REPOS = 500_000;
export const MAX_PENDING = 200_000;
export const MAX_QUERY_LIST = 5_000;
const MAX_QUERY_LEN = 400;
const MAX_DEPTH = 64;
const FILENAME_RE = /^[A-Za-z0-9._-]{1,100}$/;

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const isIso = (v: unknown): v is string =>
  typeof v === 'string' && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v;

const knownActions = (): Set<string> => new Set(AGENT_PROFILES.map((p) => p.action));

/**
 * Fresh sweep: one root shard per action covering every size. Each root is probed first and
 * only seeded into DEFAULT_SIZE_SEEDS if it is saturated, so a small action costs no more than
 * paging it.
 */
export function newSweep(startedAt: string, actions: readonly string[]): DiscoverySweep {
  return {
    startedAt,
    pending: actions.map((action): Shard => ({ action, size: [0, MAX_FILE_SIZE], depth: 0 })),
    truncated: [],
    partial: [],
  };
}

function validShard(v: unknown, actions: Set<string>): v is Shard {
  if (!isObj(v)) return false;
  if (Object.keys(v).some((k) => !['action', 'size', 'filename', 'depth'].includes(k))) {
    return false;
  }
  if (typeof v.action !== 'string' || !actions.has(v.action)) return false;
  const { size, depth, filename } = v;
  if (!Array.isArray(size) || size.length !== 2) return false;
  const [lo, hi] = size as unknown[];
  if (!Number.isInteger(lo) || !Number.isInteger(hi)) return false;
  if ((lo as number) < 0 || (hi as number) > MAX_FILE_SIZE || (lo as number) > (hi as number)) {
    return false;
  }
  if (!Number.isInteger(depth) || (depth as number) < 0 || (depth as number) > MAX_DEPTH) {
    return false;
  }
  return filename === undefined || (typeof filename === 'string' && FILENAME_RE.test(filename));
}

function queryList(v: unknown): v is string[] {
  return (
    Array.isArray(v) &&
    v.length <= MAX_QUERY_LIST &&
    v.every((q) => typeof q === 'string' && q.length <= MAX_QUERY_LEN)
  );
}

/** Strict validation of untrusted state. Throws `invalid discoveryState: <why>`. */
export function validateDiscoveryState(raw: unknown): DiscoveryState {
  const bad = (why: string): never => {
    throw new Error(`invalid discoveryState: ${why}`);
  };
  if (!isObj(raw)) return bad('not an object');
  if (Object.keys(raw).some((k) => !['schemaVersion', 'sweep', 'repos'].includes(k))) {
    bad('unexpected key');
  }
  if (raw.schemaVersion !== DISCOVERY_SCHEMA_VERSION) bad('schemaVersion');
  const { sweep, repos } = raw;
  if (!isObj(sweep)) return bad('sweep');
  if (
    Object.keys(sweep).some(
      (k) => !['startedAt', 'pending', 'completedAt', 'truncated', 'partial'].includes(k),
    )
  ) {
    bad('unexpected sweep key');
  }
  if (!isIso(sweep.startedAt)) bad('sweep.startedAt');
  if (sweep.completedAt !== undefined && !isIso(sweep.completedAt)) bad('sweep.completedAt');
  if (!Array.isArray(sweep.pending) || sweep.pending.length > MAX_PENDING) bad('sweep.pending');
  const actions = knownActions();
  if (!(sweep.pending as unknown[]).every((s) => validShard(s, actions))) bad('shard');
  if (!queryList(sweep.truncated)) bad('sweep.truncated');
  if (!queryList(sweep.partial)) bad('sweep.partial');
  if (!isObj(repos)) return bad('repos');
  const entries = Object.entries(repos);
  if (entries.length > MAX_STATE_REPOS) bad('too many repos');
  for (const [name, e] of entries) {
    if (!isPlainRepoName(name)) bad('repo name');
    if (!isObj(e) || Object.keys(e).length !== 1 || !isIso(e.lastSeenSweep)) bad('repo entry');
  }
  return raw as unknown as DiscoveryState;
}

export function parseDiscoveryState(text: string): DiscoveryState {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('invalid discoveryState: not JSON');
  }
  return validateDiscoveryState(raw);
}

/** Stable text form (sorted repos) so an unchanged state makes no commit. */
export function serializeDiscoveryState(state: DiscoveryState): string {
  const repos = Object.fromEntries(
    Object.entries(state.repos).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  return `${JSON.stringify({ ...state, repos }, null, 1)}\n`;
}
