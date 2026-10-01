/**
 * Discovery (R1, KTD2): find public, non-fork, non-archived repos whose workflows
 * reference a recognized agent action. GitHub code search returns at most 1,000 hits
 * per query, so a saturated shard is split by `size:` (bisection), then — for a
 * single-size bucket — by `filename:` variants, to a depth cap. Whatever cannot be
 * covered is reported (`truncated`: hits beyond the cap; `partial`: GitHub said the
 * results were incomplete), never silently lost.
 */

import { AGENT_PROFILES } from '../analyzers/ci/agents';
import { GitHubRateLimitError, isPlainRepoName, type GitHubClient } from './github';

export { isPlainRepoName };

/** Code search returns at most this many hits per query. */
const SEARCH_CAP = 1000;
const PER_PAGE = 100;
const MAX_PAGES = SEARCH_CAP / PER_PAGE;
/** Upper bound for the `size:` bisection; GitHub does not index files this large. */
const MAX_FILE_SIZE = 1_000_000;

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
}

export interface DiscoverResult {
  /** Sorted, deduplicated `owner/repo`; items flagged private/fork/archived are dropped (see checkEligible). */
  repos: string[];
  /** Shard queries with more than the search cap that could not be split further. */
  truncated: string[];
  /** Shard queries GitHub kept reporting as incomplete after one retry. */
  partial: string[];
}

interface Shard {
  action: string;
  size?: [number, number];
  filename?: string;
  depth: number;
}

interface Page {
  total: number;
  incomplete: boolean;
  names: string[];
}

export function shardQuery(s: Shard): string {
  const size = s.size
    ? s.size[0] === s.size[1]
      ? ` size:${s.size[0]}`
      : ` size:${s.size[0]}..${s.size[1]}`
    : '';
  const filename = s.filename ? ` filename:${s.filename}` : '';
  return `"${s.action}" path:.github/workflows${size}${filename}`;
}

export async function discover(opts: DiscoverOptions): Promise<DiscoverResult> {
  const { client } = opts;
  const actions = opts.actions ?? AGENT_PROFILES.map((p) => p.action);
  const maxDepth = opts.maxDepth ?? 24;
  const variants = opts.filenameVariants ?? DEFAULT_FILENAME_VARIANTS;
  const found = new Set<string>();
  const truncated: string[] = [];
  const partial = new Set<string>();
  /** Repos a search item already says are private, forks, or archived. */
  const excluded = new Set<string>();

  /** A failed page (after the client's retries) marks the shard partial and yields nothing. */
  async function fetchPage(shard: Shard, page: number): Promise<Page & { failed?: true }> {
    const query = shardQuery(shard);
    for (let attempt = 0; ; attempt++) {
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
        names.push(r.full_name);
        if (r.private === true || r.fork === true || r.archived === true) excluded.add(r.full_name);
      }
      const incomplete = body.incomplete_results === true;
      if (incomplete && attempt === 0) continue;
      if (incomplete) partial.add(query);
      return { total: body.total_count ?? 0, incomplete, names };
    }
  }

  async function collect(shard: Shard, first: Page): Promise<void> {
    for (const n of first.names) found.add(n);
    const pages = Math.min(MAX_PAGES, Math.ceil(first.total / PER_PAGE));
    for (let p = 2; p <= pages; p++) {
      const next = await fetchPage(shard, p);
      for (const n of next.names) found.add(n);
      if (next.failed) return;
    }
  }

  async function run(shard: Shard): Promise<void> {
    const first = await fetchPage(shard, 1);
    if (first.total === 0) return;
    if (first.total < SEARCH_CAP) {
      await collect(shard, first);
      return;
    }
    // Saturated: split if we can, otherwise take the reachable hits and say so.
    const split = splitShard(shard);
    if (split) {
      if (split[0]?.filename) {
        // A filename split only reaches the listed variants, so coverage of this bucket is not
        // guaranteed: report it, and keep the parent's reachable hits too.
        truncated.push(shardQuery(shard));
        await collect(shard, first);
      }
      for (const child of split) await run(child);
      return;
    }
    truncated.push(shardQuery(shard));
    await collect(shard, first);
  }

  function splitShard(shard: Shard): Shard[] | undefined {
    if (shard.filename) return undefined;
    const depth = shard.depth + 1;
    if (!shard.size) {
      return bisect([0, MAX_FILE_SIZE], shard, depth);
    }
    const [lo, hi] = shard.size;
    if (lo === hi) {
      return variants.map((filename) => ({ ...shard, filename, depth }));
    }
    if (shard.depth >= maxDepth) return undefined;
    return bisect([lo, hi], shard, depth);
  }

  function bisect([lo, hi]: [number, number], shard: Shard, depth: number): Shard[] {
    const mid = Math.floor((lo + hi) / 2);
    return [
      { ...shard, size: [lo, mid], depth },
      { ...shard, size: [mid + 1, hi], depth },
    ];
  }

  for (const action of actions) {
    await run({ action, depth: 0 });
  }

  // Metadata is NOT fetched here: that would cost one request per discovered repo. The search
  // items already carry private/fork/archived (GitHub's minimal-repository schema); the
  // authoritative `checkEligible` runs later, only for the repos the delta selects.
  const repos = [...found].filter((n) => isPlainRepoName(n) && !excluded.has(n)).sort();
  return { repos, truncated, partial: [...partial] };
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
