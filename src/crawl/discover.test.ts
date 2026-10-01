import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AGENT_PROFILES } from '../analyzers/ci/agents';
import { checkEligible, discover } from './discover';
import { DEFAULT_SIZE_SEEDS } from './discovery-state';
import {
  createFetchTransport,
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
    const dense = Array.from({ length: 4000 }, (_, i) => ({
      repo: `org${i}/repo${i}`,
      size: i >> 3,
      filename: 'claude.yml',
    }));
    const env = makeEnv({ data: (a) => (a === CLAUDE ? dense : []) });
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

  it('drops forks, archived, private repos (by the search item) and malformed names, with no metadata calls', async () => {
    const page = fixture('page-basic.json') as { items: { repository: Record<string, unknown> }[] };
    const flags: Record<string, Record<string, boolean>> = {
      'acme/widgets': { private: false, fork: false, archived: false },
      'acme/forked': { private: false, fork: true, archived: false },
      'oldco/archived-thing': { private: false, fork: false, archived: true },
      'someone/private-repo': { private: true, fork: false, archived: false },
    };
    for (const i of page.items) Object.assign(i.repository, flags[String(i.repository.full_name)]);
    const env = makeEnv({
      data: () => [],
      intercept: (req, n) => (req.url.includes('/search/code') && n === 0 ? json(page) : undefined),
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual(['acme/widgets']);
    expect(env.calls.filter((c) => c.req.url.includes('/repos/'))).toHaveLength(0);
  });

  it('does not call repo metadata at all, however many repos it discovers', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(250) : []) });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toHaveLength(250);
    expect(env.calls.filter((c) => new URL(c.req.url).pathname.startsWith('/repos/'))).toHaveLength(
      0,
    );
  });

  it('rejects dot-dot repo segments from search results', async () => {
    const page = {
      total_count: 3,
      incomplete_results: false,
      items: ['own/..', 'own/.', 'own/ok'].map((n) => ({ repository: { full_name: n } })),
    };
    const env = makeEnv({
      data: () => [],
      intercept: (req, n) => (req.url.includes('/search/code') && n === 0 ? json(page) : undefined),
    });
    expect((await discover({ client: clientFor(env), actions: [CLAUDE] })).repos).toEqual([
      'own/ok',
    ]);
  });

  it('marks a shard partial (not a throw) when search keeps answering 5xx', async () => {
    const OTHER = 'google-github-actions/run-gemini-cli';
    const env = makeEnv({
      data: (a) => (a === OTHER ? [{ repo: 'acme/widgets', size: 10, filename: 'c.yml' }] : []),
      intercept: (req) =>
        req.url.includes('/search/code') && decodeURIComponent(req.url).includes(CLAUDE)
          ? json({ message: 'boom' }, 502)
          : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE, OTHER] });
    expect(out.repos).toEqual(['acme/widgets']);
    expect(out.partial).toHaveLength(1);
    expect(out.partial[0]).toContain(CLAUDE);
  });

  it('marks a shard partial when the transport throws on every try', async () => {
    const env = makeEnv({
      data: () => [],
      intercept: (req) => {
        if (req.url.includes('/search/code')) throw new Error('ECONNRESET');
        return undefined;
      },
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toEqual([]);
    expect(out.partial).toHaveLength(1);
  });

  it('keeps page 1 hits and reports partial when a later page fails', async () => {
    const env = makeEnv({
      data: (a) => (a === CLAUDE ? uniform(250) : []),
      intercept: (req) =>
        req.url.includes('/search/code') && new URL(req.url).searchParams.get('page') === '2'
          ? json({ message: 'boom' }, 500)
          : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.repos).toHaveLength(100);
    expect(out.partial).toHaveLength(1);
  });

  it('ends discovery (no throw) on a persistent rate limit and reports it', async () => {
    const env = makeEnv({
      data: () => [],
      intercept: (req) =>
        req.url.includes('/search/code') ? json(null, 429, { 'retry-after': '1' }) : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE] });
    expect(out.rateLimited).toBe(true);
    expect(out.complete).toBe(false);
    expect(out.state.sweep.pending.length).toBeGreaterThan(0);
  });
});

describe('checkEligible (review #3, #4)', () => {
  const metaEnv = (res: HttpResponse | (() => never)) =>
    makeEnv({
      data: () => [],
      intercept: (req) => {
        if (!req.url.includes('/repos/')) return undefined;
        return typeof res === 'function' ? res() : res;
      },
    });
  const check = (e: Env) => checkEligible(clientFor(e), 'acme/widgets');

  it('is eligible for a public, non-fork, non-archived repo', async () => {
    const e = metaEnv(json({ private: false, fork: false, archived: false }));
    expect(await check(e)).toBe('eligible');
  });

  it.each([
    [{ private: true, fork: false, archived: false }],
    [{ private: false, fork: true, archived: false }],
    [{ private: false, fork: false, archived: true }],
  ])('is ineligible for %j', async (meta) => {
    expect(await check(metaEnv(json(meta)))).toBe('ineligible');
  });

  it.each([404, 410, 451])('is ineligible on HTTP %i', async (status) => {
    expect(await check(metaEnv(json({}, status)))).toBe('ineligible');
  });

  it('reports an error (no throw) on persistent 5xx and on transport failure', async () => {
    expect(await check(metaEnv(json({}, 503)))).toBe('error');
    expect(
      await check(
        metaEnv(() => {
          throw new Error('ECONNRESET');
        }),
      ),
    ).toBe('error');
  });
});

describe('GitHubClient resilience (review #3, #5)', () => {
  const ok = (): HttpResponse => json({ ok: true });
  function seq(steps: Array<HttpResponse | Error>) {
    const calls: HttpRequest[] = [];
    const sleeps: number[] = [];
    const client = createGitHubClient({
      transport: async (req) => {
        calls.push(req);
        const step = steps[Math.min(calls.length - 1, steps.length - 1)] as HttpResponse | Error;
        if (step instanceof Error) throw step;
        return step;
      },
      now: () => 0,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    return { client, calls, sleeps };
  }

  it('retries a GET 5xx with exponential backoff and then succeeds', async () => {
    const t = seq([json({}, 502), json({}, 503), ok()]);
    expect((await t.client.get('/x')).status).toBe(200);
    expect(t.calls).toHaveLength(3);
    expect(t.sleeps).toEqual([1000, 2000]);
  });

  it('returns the last 5xx after three tries', async () => {
    const t = seq([json({}, 500)]);
    expect((await t.client.get('/x')).status).toBe(500);
    expect(t.calls).toHaveLength(3);
  });

  it('retries a thrown transport error, then rethrows after three tries', async () => {
    const t = seq([new Error('ECONNRESET'), ok()]);
    expect((await t.client.get('/x')).status).toBe(200);
    const u = seq([new Error('ECONNRESET')]);
    await expect(u.client.get('/x')).rejects.toThrow('ECONNRESET');
    expect(u.calls).toHaveLength(3);
  });

  it('never retries a POST (a repeated report could be filed twice)', async () => {
    const t = seq([json({}, 502)]);
    expect((await t.client.post('/x', {})).status).toBe(502);
    expect(t.calls).toHaveLength(1);
    const u = seq([new Error('ECONNRESET')]);
    await expect(u.client.post('/x', {})).rejects.toThrow('ECONNRESET');
    expect(u.calls).toHaveLength(1);
  });
});

describe('createFetchTransport timeout (review #5)', () => {
  const req: HttpRequest = { method: 'GET', url: 'https://api.github.com/x', headers: {} };

  it('aborts a request that never answers and surfaces an error', async () => {
    let seen: AbortSignal | undefined;
    const hang = ((_url: string, init: RequestInit) => {
      seen = init.signal ?? undefined;
      return new Promise((_res, rej) => {
        init.signal?.addEventListener('abort', () => rej(init.signal?.reason));
      });
    }) as unknown as typeof fetch;
    const t = createFetchTransport({ timeoutMs: 20, fetchImpl: hang });
    await expect(t(req)).rejects.toBeDefined();
    expect(seen?.aborted).toBe(true);
  });

  it('passes a response through when it arrives in time', async () => {
    const fast = (async () =>
      new Response('{"a":1}', {
        status: 200,
        headers: { 'X-Foo': 'bar' },
      })) as unknown as typeof fetch;
    const r = await createFetchTransport({ timeoutMs: 1000, fetchImpl: fast })(req);
    expect(r).toEqual({
      status: 200,
      headers: { 'x-foo': 'bar', 'content-type': 'text/plain;charset=UTF-8' },
      json: { a: 1 },
    });
  });
});

describe('discover (cont.)', () => {
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

describe('resilient, incremental discovery (0083)', () => {
  const t = (n: number) => new Date(T0 + n * 86_400_000);

  it('a rate limit mid-discovery ends this run but keeps what was found and what is pending', async () => {
    let searchCalls = 0;
    const env = makeEnv({
      data: (a) => (a === CLAUDE ? uniform(2400) : []),
      intercept: (req) =>
        req.url.includes('/search/code') && ++searchCalls > 4
          ? json(null, 429, { 'retry-after': '1' })
          : undefined,
    });
    const out = await discover({ client: clientFor(env), actions: [CLAUDE], now: () => t(0) });
    expect(out.rateLimited).toBe(true);
    expect(out.complete).toBe(false);
    expect(out.repos.length).toBeGreaterThan(0);
    expect(out.state.sweep.pending.length).toBeGreaterThan(0);
    expect(out.state.sweep.completedAt).toBeUndefined();
    // a non-rate-limit failure is still just a partial shard, not an end of discovery
    expect(out.partial).toEqual([]);
  });

  it('resumes across two runs under a budget without re-searching finished shards', async () => {
    const data = (a: string) => (a === CLAUDE ? uniform(2400) : []);
    const full = makeEnv({ data });
    const fullOut = await discover({ client: clientFor(full), actions: [CLAUDE], now: () => t(0) });
    expect(fullOut.complete).toBe(true);

    const env1 = makeEnv({ data });
    const r1 = await discover({
      client: clientFor(env1),
      actions: [CLAUDE],
      budget: 12,
      now: () => t(0),
    });
    expect(r1.complete).toBe(false);
    expect(r1.budgetExhausted).toBe(true);
    const env2 = makeEnv({ data });
    const r2 = await discover({
      client: clientFor(env2),
      actions: [CLAUDE],
      state: JSON.parse(JSON.stringify(r1.state)),
      now: () => t(0),
    });
    expect(r2.complete).toBe(true);
    expect(r2.repos).toEqual(fullOut.repos);
    // run 2 is the same sweep, not a fresh one
    expect(r2.state.sweep.startedAt).toBe(r1.state.sweep.startedAt);
    // Finished shards are not searched again: at most the one interrupted shard repeats.
    const first = (e: Env) => new Set(e.searches.filter((s) => s.page === 1).map((s) => s.q.raw));
    const repeated = [...first(env1)].filter((q) => first(env2).has(q));
    expect(repeated.length).toBeLessThanOrEqual(1);
    expect(env1.searches.length + env2.searches.length).toBeLessThanOrEqual(
      full.searches.length + 1,
    );
  });

  it('never spends more search requests than the budget, and says so', async () => {
    const env = makeEnv({ data: (a) => (a === CLAUDE ? uniform(2400) : []) });
    const out = await discover({ client: clientFor(env), budget: 5, now: () => t(0) });
    expect(env.searches.length).toBeLessThanOrEqual(5);
    expect(out.searches).toBeLessThanOrEqual(5);
    expect(out.budgetExhausted).toBe(true);
    expect(out.rateLimited).toBe(false);
    expect(out.complete).toBe(false);
    expect(out.state.sweep.pending.length).toBeGreaterThan(0);
  });

  it('a completed sweep drops repos it did not see, but only once the sweep completes', async () => {
    const withGone: Record_[] = [
      ...uniform(1500),
      { repo: 'gone/repo', size: 77, filename: 'claude.yml' },
    ];
    const env1 = makeEnv({ data: (a) => (a === CLAUDE ? withGone : []) });
    const s1 = await discover({ client: clientFor(env1), actions: [CLAUDE], now: () => t(0) });
    expect(s1.complete).toBe(true);
    expect(s1.repos).toContain('gone/repo');
    expect(s1.state.sweep.completedAt).toBeDefined();

    // Next run starts a new sweep. Mid-sweep the known set is kept.
    const still = uniform(1500);
    const env2 = makeEnv({ data: (a) => (a === CLAUDE ? still : []) });
    const s2 = await discover({
      client: clientFor(env2),
      actions: [CLAUDE],
      state: s1.state,
      budget: 3,
      now: () => t(1),
    });
    expect(s2.complete).toBe(false);
    expect(s2.state.sweep.startedAt).not.toBe(s1.state.sweep.startedAt);
    expect(s2.repos).toContain('gone/repo');

    const env3 = makeEnv({ data: (a) => (a === CLAUDE ? still : []) });
    const s3 = await discover({
      client: clientFor(env3),
      actions: [CLAUDE],
      state: s2.state,
      now: () => t(1),
    });
    expect(s3.complete).toBe(true);
    expect(s3.repos).not.toContain('gone/repo');
    expect(s3.repos).toHaveLength(1500);
    expect(Object.keys(s3.state.repos).sort()).toEqual(s3.repos);
  });

  it('does not drop unseen repos when the sweep had partial (failed) shards', async () => {
    const env1 = makeEnv({ data: (a) => (a === CLAUDE ? uniform(10) : []) });
    const s1 = await discover({ client: clientFor(env1), actions: [CLAUDE], now: () => t(0) });
    const env2 = makeEnv({
      data: () => [],
      intercept: (req) => (req.url.includes('/search/code') ? json(null, 500) : undefined),
    });
    const s2 = await discover({
      client: clientFor(env2),
      actions: [CLAUDE],
      state: s1.state,
      now: () => t(1),
    });
    expect(s2.complete).toBe(true);
    expect(s2.partial.length).toBeGreaterThan(0);
    expect(s2.repos).toEqual(s1.repos);
  });

  it('drops a known repo that a search item now flags as a fork', async () => {
    const env1 = makeEnv({ data: (a) => (a === CLAUDE ? uniform(3) : []) });
    const s1 = await discover({ client: clientFor(env1), actions: [CLAUDE], now: () => t(0) });
    const env2 = makeEnv({
      data: () => [],
      intercept: (req) =>
        req.url.includes('/search/code')
          ? json({
              total_count: 1,
              incomplete_results: false,
              items: [{ repository: { full_name: 'org0/repo0', fork: true } }],
            })
          : undefined,
    });
    const s2 = await discover({
      client: clientFor(env2),
      actions: [CLAUDE],
      state: s1.state,
      now: () => t(1),
    });
    expect(s2.repos).not.toContain('org0/repo0');
  });

  describe('size-range seeding', () => {
    /** Workflow-file sizes cluster at 1-5 KB with a long tail (deterministic LCG, log-normal-ish). */
    function realistic(n: number): Record_[] {
      let x = 12345;
      const rnd = () => {
        x = (x * 1103515245 + 12345) % 2 ** 31;
        return x / 2 ** 31;
      };
      return Array.from({ length: n }, (_, i) => {
        const g = rnd() + rnd() + rnd() + rnd() - 2; // ~N(0, .58)
        return {
          repo: `o${i}/r${i}`,
          size: Math.max(1, Math.round(2200 * Math.exp(g * 1.3))),
          filename: 'claude.yml',
        };
      });
    }

    it('seeds are contiguous, non-overlapping, start at 0 and end with one tail range', () => {
      expect(DEFAULT_SIZE_SEEDS[0]?.[0]).toBe(0);
      for (let i = 1; i < DEFAULT_SIZE_SEEDS.length; i++) {
        expect(DEFAULT_SIZE_SEEDS[i]?.[0]).toBe((DEFAULT_SIZE_SEEDS[i - 1]?.[1] ?? 0) + 1);
      }
      expect(DEFAULT_SIZE_SEEDS.at(-1)).toEqual([20_001, 1_000_000]);
    });

    it('finds the same repos in fewer requests than bisecting from the whole range', async () => {
      const data = realistic(9000);
      const seeded = makeEnv({ data: (a) => (a === CLAUDE ? data : []) });
      const a = await discover({ client: clientFor(seeded), actions: [CLAUDE], now: () => t(0) });
      const old = makeEnv({ data: (x) => (x === CLAUDE ? data : []) });
      const b = await discover({
        client: clientFor(old),
        actions: [CLAUDE],
        sizeSeeds: [],
        now: () => t(0),
      });
      expect(a.repos).toEqual(b.repos);
      expect(a.repos).toHaveLength(9000);
      expect(a.truncated).toEqual([]);
      // Paging (hits / 100) is the floor for both; the saving is in the probing requests.
      const probes = (e: Env) => e.searches.filter((s) => s.page === 1).length;
      expect(probes(seeded)).toBeLessThan(probes(old));
      expect(seeded.searches.length).toBeLessThan(old.searches.length);
      expect(seeded.searches.length).toBeLessThanOrEqual(9000 / 100 + 40);
    });

    it('an action with under 1,000 hits costs one probe plus its pages, not a seed sweep', async () => {
      const env = makeEnv({ data: (a) => (a === CLAUDE ? realistic(830) : []) });
      const out = await discover({ client: clientFor(env), actions: [CLAUDE], now: () => t(0) });
      expect(out.repos).toHaveLength(830);
      expect(env.searches.length).toBe(9);
      expect(env.searches.filter((s) => s.page === 1)).toHaveLength(1);
    });

    it('a saturated seed range still bisects, then filename-splits, and reports truncation', async () => {
      const env = makeEnv({
        data: (a) =>
          a === CLAUDE
            ? Array.from({ length: 1200 }, (_, i) => ({
                repo: `b${i}/x`,
                size: 5000,
                filename: 'ci.yml',
              }))
            : [],
      });
      const out = await discover({
        client: clientFor(env),
        actions: [CLAUDE],
        filenameVariants: ['ci.yml'],
        now: () => t(0),
      });
      expect(out.truncated.length).toBeGreaterThan(0);
      expect(out.repos).toHaveLength(1000);
    });
  });
});
