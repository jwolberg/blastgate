/**
 * Discovery (R1, KTD2): find public, non-fork, non-archived repos whose workflows
 * reference a recognized agent action. GitHub code search returns at most 1,000 hits
 * per query, so a saturated shard is split by `size:` (bisection), then — for a
 * single-size bucket — by `filename:` variants, to a depth cap. Whatever cannot be
 * covered is reported (`truncated`: hits beyond the cap; `partial`: GitHub said the
 * results were incomplete), never silently lost.
 */

import { AGENT_PROFILES } from '../analyzers/ci/agents';
import {
  DEFAULT_SIZE_SEEDS,
  MAX_FILE_SIZE,
  type DiscoveryState,
  type Shard,
  newSweep,
} from './discovery-state';
import { GitHubRateLimitError, isPlainRepoName, type GitHubClient } from './github';

export { isPlainRepoName };

/** Code search returns at most this many hits per query. */
const SEARCH_CAP = 1000;
const PER_PAGE = 100;
const MAX_PAGES = SEARCH_CAP / PER_PAGE;

/** Common names for agent workflows; used to split a bucket that size cannot. */
export const DEFAULT_FILENAME_VARIANTS: readonly string[] = [
  'claude.yml',
  'claude.yaml',
  'claude-code-review.yml',
  'claude-review.yml',
  'claude-pr-review.yml',
  'claude-code.yml',
  'codex.yml',
  'codex-review.yml',
  'gemini.yml',
  'gemini-cli.yml',
  'gemini-review.yml',
  'gemini-dispatch.yml',
  'ai-inference.yml',
  'ai.yml',
  'ci.yml',
  'review.yml',
  'pr-review.yml',
  'triage.yml',
  'issue-triage.yml',
  'main.yml',
];

export interface DiscoverOptions {
  client: GitHubClient;
  /** Action literals to search; defaults to every recognized agent action. */
  actions?: readonly string[];
  /** Max shard-splitting depth before a shard is reported truncated. */
  maxDepth?: number;
  filenameVariants?: readonly string[];
  /** Persisted state from earlier runs. Missing, or its sweep complete = a new sweep starts. */
  state?: DiscoveryState;
  /** Max search requests this run may spend; default unlimited. */
  budget?: number;
  /** Ranges a saturated whole-range shard splits into; defaults to DEFAULT_SIZE_SEEDS, [] = bisect. */
  sizeSeeds?: readonly (readonly [number, number])[];
  /** Clock for sweep ids. */
  now?: () => Date;
  /**
   * Restrict every query to this account's repos (`user:<owner>`), for a scoped check run
   * (0086). An owner run never resumes `state`: it always starts a fresh, separate sweep.
   */
  owner?: string;
}

export interface DiscoverResult {
  /** Sorted `owner/repo` of every known repo (all of state.repos): the delta and site input. */
  repos: string[];
  /** Shard queries (this sweep) with more than the search cap that could not be split further. */
  truncated: string[];
  /** Shard queries (this sweep) GitHub kept reporting as incomplete, or that failed. */
  partial: string[];
  /** The state to persist for the next run. */
  state: DiscoveryState;
  /** The queue emptied: this run finished the sweep. */
  complete: boolean;
  /** A rate limit that outlasted the client's retries ended discovery for this run. */
  rateLimited: boolean;
  /** The per-run search budget ran out. */
  budgetExhausted: boolean;
  /** Search requests spent this run. */
  searches: number;
}

interface Page {
  total: number;
  incomplete: boolean;
  names: string[];
}

class BudgetExhausted extends Error {}

const isWholeRange = (s: Shard): boolean => s.size[0] === 0 && s.size[1] === MAX_FILE_SIZE;

/** A GitHub login: alphanumerics and single inner hyphens, at most 39 characters. */
export function isOwnerLogin(owner: string): boolean {
  return /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/.test(owner);
}

export function assertOwnerLogin(owner: string): void {
  if (!isOwnerLogin(owner))
    throw new Error(`bad owner: ${JSON.stringify(owner)} is not a GitHub login`);
}

export function shardQuery(s: Shard, owner?: string): string {
  const size = isWholeRange(s)
    ? ''
    : s.size[0] === s.size[1]
      ? ` size:${s.size[0]}`
      : ` size:${s.size[0]}..${s.size[1]}`;
  const filename = s.filename ? ` filename:${s.filename}` : '';
  const user = owner ? ` user:${owner}` : '';
  return `"${s.action}" path:.github/workflows${size}${filename}${user}`;
}

export async function discover(opts: DiscoverOptions): Promise<DiscoverResult> {
  const { client, owner } = opts;
  if (owner !== undefined) assertOwnerLogin(owner);
  const queryOf = (s: Shard): string => shardQuery(s, owner);
  const actions = opts.actions ?? AGENT_PROFILES.map((p) => p.action);
  const maxDepth = opts.maxDepth ?? 24;
  const variants = opts.filenameVariants ?? DEFAULT_FILENAME_VARIANTS;
  const seeds = opts.sizeSeeds ?? DEFAULT_SIZE_SEEDS;
  const budget = opts.budget ?? Number.POSITIVE_INFINITY;
  const nowIso = (opts.now?.() ?? new Date()).toISOString();

  // Work on a copy: the caller's state is never mutated.
  const prior = opts.state && owner === undefined ? structuredClone(opts.state) : undefined;
  const state: DiscoveryState =
    prior && prior.sweep.completedAt === undefined
      ? prior
      : {
          schemaVersion: 1,
          sweep: newSweep(nowIso, actions),
          repos: prior?.repos ?? {},
        };
  const sweepId = state.sweep.startedAt;
  const queue = state.sweep.pending;
  const truncated = new Set(state.sweep.truncated);
  const partial = new Set(state.sweep.partial);
  /** Repos a search item says are private, forks, or archived. */
  const excluded = new Set<string>();
  let searches = 0;

  function see(name: string): void {
    if (isPlainRepoName(name) && !excluded.has(name)) {
      state.repos[name] = { lastSeenSweep: sweepId };
    }
  }

  /** A failed page (after the client's retries) marks the shard partial and yields nothing. */
  async function fetchPage(shard: Shard, page: number): Promise<Page & { failed?: true }> {
    const query = queryOf(shard);
    for (let attempt = 0; ; attempt++) {
      if (searches >= budget) throw new BudgetExhausted();
      searches++;
      let res;
      try {
        res = await client.get('/search/code', { q: query, per_page: PER_PAGE, page });
      } catch (e) {
        if (e instanceof GitHubRateLimitError) throw e;
        partial.add(query);
        return { total: 0, incomplete: true, names: [], failed: true };
      }
      if (res.status !== 200) {
        partial.add(query);
        return { total: 0, incomplete: true, names: [], failed: true };
      }
      const body = res.json as {
        total_count?: number;
        incomplete_results?: boolean;
        items?: {
          repository?: {
            full_name?: unknown;
            private?: unknown;
            fork?: unknown;
            archived?: unknown;
          };
        }[];
      };
      const names: string[] = [];
      for (const i of body.items ?? []) {
        const r = i.repository;
        if (typeof r?.full_name !== 'string') continue;
        if (r.private === true || r.fork === true || r.archived === true) excluded.add(r.full_name);
        names.push(r.full_name);
      }
      const incomplete = body.incomplete_results === true;
      if (incomplete && attempt === 0) continue;
      if (incomplete) partial.add(query);
      return { total: body.total_count ?? 0, incomplete, names };
    }
  }

  async function collect(shard: Shard, first: Page): Promise<void> {
    for (const n of first.names) see(n);
    const pages = Math.min(MAX_PAGES, Math.ceil(first.total / PER_PAGE));
    for (let p = 2; p <= pages; p++) {
      const next = await fetchPage(shard, p);
      for (const n of next.names) see(n);
      if (next.failed) return;
    }
  }

  /** Search one shard; returns the child shards that replace it in the queue. */
  async function process(shard: Shard): Promise<Shard[]> {
    const first = await fetchPage(shard, 1);
    if (first.total === 0) return [];
    if (first.total < SEARCH_CAP) {
      await collect(shard, first);
      return [];
    }
    // Saturated: split if we can, otherwise take the reachable hits and say so.
    const split = splitShard(shard);
    if (split?.[0]?.filename) {
      // A filename split only reaches the listed variants, so coverage of this bucket is not
      // guaranteed: report it, and keep the parent's reachable hits too.
      truncated.add(queryOf(shard));
      await collect(shard, first);
    }
    if (split) return split;
    truncated.add(queryOf(shard));
    await collect(shard, first);
    return [];
  }

  function splitShard(shard: Shard): Shard[] | undefined {
    if (shard.filename) return undefined;
    const depth = shard.depth + 1;
    const [lo, hi] = shard.size;
    if (isWholeRange(shard) && seeds.length > 0) {
      return seeds.map(([a, b]) => ({ action: shard.action, size: [a, b], depth }));
    }
    if (lo === hi) {
      return variants.map((filename) => ({ ...shard, filename, depth }));
    }
    if (shard.depth >= maxDepth) return undefined;
    const mid = Math.floor((lo + hi) / 2);
    return [
      { ...shard, size: [lo, mid], depth },
      { ...shard, size: [mid + 1, hi], depth },
    ];
  }

  let rateLimited = false;
  let budgetExhausted = false;
  while (queue.length > 0) {
    const shard = queue[0] as Shard;
    try {
      const children = await process(shard);
      queue.splice(0, 1, ...children);
    } catch (e) {
      // The shard stays at the head of the queue: it is retried first next run.
      if (e instanceof GitHubRateLimitError) rateLimited = true;
      else if (e instanceof BudgetExhausted) budgetExhausted = true;
      else throw e;
      break;
    }
  }

  // The search items already carry private/fork/archived (GitHub's minimal-repository schema);
  // metadata is NOT fetched here. The authoritative `checkEligible` runs later, only for the
  // repos the delta selects.
  for (const name of excluded) delete state.repos[name];

  const complete = queue.length === 0;
  if (complete) {
    state.sweep.completedAt = nowIso;
    // Repos the finished sweep did not see no longer use an agent action. Unless a shard failed:
    // then coverage is unknown and absence proves nothing.
    if (partial.size === 0) {
      for (const [name, e] of Object.entries(state.repos)) {
        if (e.lastSeenSweep !== sweepId) delete state.repos[name];
      }
    }
  }
  state.sweep.truncated = [...truncated];
  state.sweep.partial = [...partial];

  const repos = Object.keys(state.repos).filter(isPlainRepoName).sort();
  return {
    repos,
    truncated: state.sweep.truncated,
    partial: state.sweep.partial,
    state,
    complete,
    rateLimited,
    budgetExhausted,
    searches,
  };
}

export type Eligibility = 'eligible' | 'ineligible' | 'error';

/**
 * Public, non-fork, non-archived; a repo gone since indexing is ineligible. A metadata failure
 * that outlasts the client's retries is `error` (skip this repo this run), never a throw.
 */
export async function checkEligible(client: GitHubClient, name: string): Promise<Eligibility> {
  if (!isPlainRepoName(name)) return 'ineligible';
  let res;
  try {
    res = await client.get(`/repos/${name}`);
  } catch {
    return 'error';
  }
  if (res.status === 404 || res.status === 410 || res.status === 451) return 'ineligible';
  if (res.status !== 200) return 'error';
  const meta = res.json as { private?: boolean; fork?: boolean; archived?: boolean } | null;
  return meta?.private === false && meta.fork === false && meta.archived === false
    ? 'eligible'
    : 'ineligible';
}
