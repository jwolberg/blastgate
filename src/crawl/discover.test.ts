import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AGENT_PROFILES } from '../analyzers/ci/agents';
import { discover } from './discover';
import {
  createGitHubClient,
  GitHubRateLimitError,
  type HttpRequest,
  type HttpResponse,
  type Transport,
} from './github';

function fixture<T = unknown>(name: string): T {
  const url = new URL(`./fixtures/search/${name}`, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as T;
}

const T0 = 1_800_000_000_000;
const CLAUDE = 'anthropics/claude-code-action';

/** A fake clock: sleep advances time instantly, so tests never wait. */
function fakeClock() {
  let t = T0;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    sleeps,
  };
}

interface Record_ {
  repo: string;
  size: number;
  filename: string;
}
interface ParsedQuery {
  action: string;
  size?: [number, number];
  filename?: string;
  raw: string;
}

function parseQuery(raw: string): ParsedQuery {
  const action = /^"([^"]+)"/.exec(raw)?.[1] ?? '';
  const range = /size:(\d+)\.\.(\d+)/.exec(raw);
  const single = /size:(\d+)(?!\.)/.exec(raw);
  const size: [number, number] | undefined = range
    ? [Number(range[1]), Number(range[2])]
    : single
      ? [Number(single[1]), Number(single[1])]
      : undefined;
  const filename = /filename:(\S+)/.exec(raw)?.[1];
  return { action, size, filename, raw };
}

interface Env {
  clock: ReturnType<typeof fakeClock>;
  calls: { req: HttpRequest; at: number }[];
  searches: { q: ParsedQuery; page: number; total: number }[];
  transport: Transport;
}

/**
 * A fake GitHub: code search over `data` (filtered by the query's action/size/filename)
 * plus repo metadata. `intercept` can answer a request first (to inject 403s, etc.).
 */
function makeEnv(opts: {
  data: (action: string) => Record_[];
  meta?: Record<string, unknown>;
  intercept?: (req: HttpRequest, n: number) => HttpResponse | undefined;
}): Env {
  const clock = fakeClock();
  const calls: Env['calls'] = [];
  const searches: Env['searches'] = [];
  let n = 0;
  const transport: Transport = async (req) => {
    calls.push({ req, at: clock.now() });
    const hijacked = opts.intercept?.(req, n++);
    if (hijacked) return hijacked;
    const url = new URL(req.url);
    if (url.pathname === '/search/code') {
      const q = parseQuery(url.searchParams.get('q') ?? '');
      const page = Number(url.searchParams.get('page') ?? '1');
      const perPage = Number(url.searchParams.get('per_page') ?? '30');
      const hits = opts
        .data(q.action)
        .filter((r) => !q.size || (r.size >= q.size[0] && r.size <= q.size[1]))
        .filter((r) => !q.filename || r.filename === q.filename);
      searches.push({ q, page, total: hits.length });
      const items = hits
        .slice((page - 1) * perPage, page * perPage)
        .map((r) => ({ name: r.filename, repository: { full_name: r.repo } }));
      return json({ total_count: hits.length, incomplete_results: false, items });
    }
    const m = /^\/repos\/([^/]+\/[^/]+)$/.exec(url.pathname);
    if (m) {
      const name = m[1] ?? '';
      const meta = opts.meta?.[name] ?? {
        full_name: name,
        private: false,
        fork: false,
        archived: false,
      };
      return json(meta);
    }
    return { status: 404, headers: {}, json: { message: 'Not Found' } };
  };
  return { clock, calls, searches, transport };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): HttpResponse {
  return { status, headers, json: body };
}

function clientFor(env: Env) {
  return createGitHubClient({
    transport: env.transport,
    now: env.clock.now,
    sleep: env.clock.sleep,
  });
}

/** n synthetic records spread over sizes [0, n*step) under one filename. */
function uniform(n: number, step = 100, filename = 'claude.yml'): Record_[] {
  return Array.from({ length: n }, (_, i) => ({
    repo: `org${i}/repo${i}`,
    size: i * step,
    filename,
  }));
}

describe('GitHubClient', () => {
  it('encodes the query string on get and sends JSON on post', async () => {
    const env = makeEnv({ data: () => [] });
    const client = clientFor(env);
    await client.get('/repos/a/b', { per_page: 5, q: 'x y' });
    await client.post('/repos/a/b/issues', { title: 't' });
    expect(env.calls[0]?.req.url).toBe('https://api.github.com/repos/a/b?per_page=5&q=x+y');
    expect(env.calls[0]?.req.method).toBe('GET');
    expect(env.calls[1]?.req.method).toBe('POST');
    expect(env.calls[1]?.req.body).toBe(JSON.stringify({ title: 't' }));
  });

  it('sends the token as a bearer credential and never throws on a plain 404', async () => {
    const env = makeEnv({ data: () => [] });
    const client = createGitHubClient({
      transport: env.transport,
      token: 'tok',
      now: env.clock.now,
      sleep: env.clock.sleep,
    });
    const res = await client.get('/nope');
    expect(res.status).toBe(404);
    expect(env.calls[0]?.req.headers['authorization']).toBe('Bearer tok');
  });

  it('throttles search so no 10 requests land inside any 60 second window', async () => {
    const env = makeEnv({ data: () => [] });
    const client = clientFor(env);
    for (let i = 0; i < 35; i++) await client.get('/search/code', { q: 'x' });
    const t = env.calls.map((c) => c.at);
    for (let i = 0; i + 9 < t.length; i++) {
      expect((t[i + 9] ?? 0) - (t[i] ?? 0)).toBeGreaterThanOrEqual(60_000);
    }
    expect(env.clock.sleeps.length).toBeGreaterThan(0);
  });

  it('does not throttle non-search requests', async () => {
    const env = makeEnv({ data: () => [] });
    const client = clientFor(env);
    for (let i = 0; i < 25; i++) await client.get('/repos/a/b');
    expect(env.clock.sleeps).toEqual([]);
  });

  it('honors retry-after on a 403 and retries the same request', async () => {
    const env = makeEnv({
      data: () => [],
      intercept: (_req, n) =>
        n === 0 ? json({ message: 'secondary' }, 403, { 'retry-after': '30' }) : undefined,
    });
    const res = await clientFor(env).get('/repos/a/b');
    expect(res.status).toBe(200);
    expect(env.clock.sleeps).toContain(30_000);
    expect(env.calls).toHaveLength(2);
  });

  it('waits until x-ratelimit-reset when the primary limit is exhausted', async () => {
    const env = makeEnv({
      data: () => [],
      intercept: (_req, n) =>
        n === 0
          ? json({ message: 'rate limit' }, 403, {
              'x-ratelimit-remaining': '0',
              'x-ratelimit-reset': String(T0 / 1000 + 90),
            })
          : undefined,
    });
    const res = await clientFor(env).get('/repos/a/b');
    expect(res.status).toBe(200);
    expect(env.clock.sleeps[0]).toBeGreaterThanOrEqual(90_000);
  });

  it('retries a 429 and gives up with GitHubRateLimitError after the retry cap', async () => {
    const env = makeEnv({
      data: () => [],
      intercept: () => json({ message: 'slow down' }, 429, { 'retry-after': '1' }),
    });
    await expect(clientFor(env).get('/repos/a/b')).rejects.toBeInstanceOf(GitHubRateLimitError);
    expect(env.calls.length).toBeLessThanOrEqual(10);
  });

  it('does not retry a 403 that carries no rate-limit signal', async () => {
    const env = makeEnv({ data: () => [], intercept: () => json({ message: 'Forbidden' }, 403) });
    const res = await clientFor(env).get('/repos/a/b');
    expect(res.status).toBe(403);
    expect(env.calls).toHaveLength(1);
  });
});

describe('discover', () => {
  it('queries every recognized agent action, scoped to workflow files', async () => {
    const env = makeEnv({ data: () => [] });
    await discover({ client: clientFor(env) });
    const actions = new Set(env.searches.map((s) => s.q.action));
    expect(actions).toEqual(new Set(AGENT_PROFILES.map((p) => p.action)));
    for (const s of env.searches) expect(s.q.raw).toContain('path:.github/workflows');
  });

  it('returns each repo once when shards overlap (split by size, repo has several files)', async () => {
    const data: Record_[] = [
      ...uniform(1200, 300),
      { repo: 'org0/repo0', size: 350_000, filename: 'second.yml' },
    ];
    const env = makeEnv({ data: (a) => (a === CLAUDE ? data : []) });
    const out = await discover({ client: clientFor(env) });
    expect(out.repos).toHaveLength(1200);
    expect(new Set(out.repos).size).toBe(1200);
    expect(out.truncated).toEqual([]);
    expect(out.partial).toEqual([]);
  });

  it('splits a 2400-hit shard until every paged sub-shard is under 1000', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(2400) : []) });
    const out = await discover({ client: clientFor(env) });
    expect(out.repos).toHaveLength(2400);
    expect(out.truncated).toEqual([]);
    // Any query that was paged past page 1 must have been under the cap.
    for (const s of env.searches.filter((x) => x.page > 1)) expect(s.total).toBeLessThan(1000);
    // Sanity on the budget: well under one request per repo.
    expect(env.searches.length).toBeLessThan(120);
  });

  it('splits an over-cap single-size bucket by filename and reports an unsplittable one as truncated', async () => {
    const bucket: Record_[] = [
      ...Array.from({ length: 300 }, (_, i) => ({
        repo: `a${i}/x`,
        size: 5000,
        filename: 'claude.yml',
      })),
      ...Array.from({ length: 1200 }, (_, i) => ({
        repo: `b${i}/x`,
        size: 5000,
        filename: 'ci.yml',
      })),
    ];
    const env = makeEnv({ data: (a) => (a === CLAUDE ? bucket : []) });
    const out = await discover({
      client: clientFor(env),
      filenameVariants: ['claude.yml', 'ci.yml'],
    });
    // The bucket itself (variant split, coverage not guaranteed) and the unsplittable ci.yml shard.
    expect(out.truncated).toHaveLength(2);
    expect(out.truncated.some((q) => q.includes('size:5000') && !q.includes('filename:'))).toBe(
      true,
    );
    expect(out.truncated.some((q) => q.includes('filename:ci.yml'))).toBe(true);
    // All 300 claude.yml repos plus the first 1000 reachable ci.yml hits.
    expect(out.repos.filter((r) => r.startsWith('a'))).toHaveLength(300);
    expect(out.repos.filter((r) => r.startsWith('b'))).toHaveLength(1000);
  });

  it('reports a filename-split bucket as truncated: the variant list cannot guarantee coverage', async () => {
    const bucket: Record_[] = [
      ...Array.from({ length: 1000 }, (_, i) => ({
        repo: `a${i}/x`,
        size: 5000,
        filename: 'claude.yml',
      })),
      ...Array.from({ length: 100 }, (_, i) => ({
        repo: `odd${i}/x`,
        size: 5000,
        filename: 'my-bot.yml',
      })),
    ];
    const env = makeEnv({ data: (a) => (a === CLAUDE ? bucket : []) });
    const out = await discover({
      client: clientFor(env),
      filenameVariants: ['claude.yml', 'ci.yml'],
    });
    // my-bot.yml matches no variant, so those files are unreachable: the gap must be reported.
    expect(out.truncated.some((q) => q.includes('size:5000') && !q.includes('filename:'))).toBe(
      true,
    );
  });

  it('terminates and reports truncation when the depth cap is reached', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(3000, 50) : []) });
    const out = await discover({ client: clientFor(env), maxDepth: 1 });
    expect(out.truncated.length).toBeGreaterThan(0);
    expect(env.searches.length).toBeLessThan(200);
  });

  it('retries a page flagged incomplete_results once and keeps the shard if it recovers', async () => {
    const incomplete = fixture<{ items: unknown[] }>('incomplete.json');
    const env = makeEnv({
      data: (a) =>
        a === CLAUDE ? [{ repo: 'acme/widgets', size: 10, filename: 'claude.yml' }] : [],
      intercept: (req, n) =>
        req.url.includes('/search/code') && n === 0 ? json(incomplete) : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual(['acme/widgets']);
    expect(out.partial).toEqual([]);
    expect(env.calls.filter((c) => c.req.url.includes('/search/code'))).toHaveLength(2);
  });

  it('reports the shard as partial when it stays incomplete after one retry', async () => {
    const incomplete = fixture('incomplete.json');
    const env = makeEnv({
      data: () => [],
      intercept: (req) => (req.url.includes('/search/code') ? json(incomplete) : undefined),
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.partial).toHaveLength(1);
    expect(out.partial[0]).toContain(CLAUDE);
    expect(env.calls.filter((c) => c.req.url.includes('/search/code'))).toHaveLength(2);
    // What was returned is still used.
    expect(out.repos).toEqual(['acme/widgets']);
  });

  it('drops forks, archived, private repos, and malformed names (without fetching metadata for bad names)', async () => {
    const page = fixture('page-basic.json');
    const meta = fixture<Record<string, unknown>>('repos.json');
    const env = makeEnv({
      data: () => [],
      meta,
      intercept: (req, n) => (req.url.includes('/search/code') && n === 0 ? json(page) : undefined),
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual(['acme/widgets']);
    const fetched = env.calls
      .map((c) => new URL(c.req.url).pathname)
      .filter((p) => p.startsWith('/repos/'));
    expect(fetched.sort()).toEqual([
      '/repos/acme/forked',
      '/repos/acme/widgets',
      '/repos/oldco/archived-thing',
      '/repos/someone/private-repo',
    ]);
  });

  it('drops a repo whose metadata is 404 (deleted since indexing)', async () => {
    const env = makeEnv({
      data: (a) => (a === CLAUDE ? [{ repo: 'gone/repo', size: 10, filename: 'c.yml' }] : []),
      intercept: (req) =>
        req.url.includes('/repos/gone/repo') ? json({ message: 'Not Found' }, 404) : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual([]);
  });

  it('pages through a shard of more than 100 hits', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(250) : []) });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toHaveLength(250);
    expect(env.searches.map((s) => s.page)).toEqual([1, 2, 3]);
  });

  it('never puts more than 9 search requests in a 60 second window across a large discovery', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(2400) : []) });
    await discover({ client: clientFor(env) });
    const t = env.calls.filter((c) => c.req.url.includes('/search/')).map((c) => c.at);
    expect(t.length).toBeGreaterThan(10);
    for (let i = 0; i + 9 < t.length; i++) {
      expect((t[i + 9] ?? 0) - (t[i] ?? 0)).toBeGreaterThanOrEqual(60_000);
    }
  });

  it('honors a 403 secondary-limit retry-after without dropping the shard', async () => {
    const env = makeEnv({
      data: (a) => (a === CLAUDE ? [{ repo: 'acme/widgets', size: 10, filename: 'c.yml' }] : []),
      intercept: (req, n) =>
        req.url.includes('/search/code') && n === 0
          ? json({ message: 'You have exceeded a secondary rate limit' }, 403, {
              'retry-after': '45',
            })
          : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual(['acme/widgets']);
    expect(out.partial).toEqual([]);
    expect(env.clock.sleeps).toContain(45_000);
  });

  it('returns a deterministic, sorted list', async () => {
    const data: Record_[] = [
      { repo: 'zed/z', size: 1, filename: 'c.yml' },
      { repo: 'abe/a', size: 2, filename: 'c.yml' },
    ];
    const env = makeEnv({ data: () => data });
    const out = await discover({ client: clientFor(env) });
    expect(out.repos).toEqual(['abe/a', 'zed/z']);
  });
});
