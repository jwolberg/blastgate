/**
 * Small GitHub REST client for the public crawler. The transport, clock, and sleep
 * are injectable so tests are instant and offline. Search requests are evenly spaced
 * under GitHub's code-search budget (10/min authenticated), and rate-limit
 * responses are waited out and retried: an exhausted primary limit until its reset, a
 * secondary limit for at least a minute, doubling on consecutive hits (GitHub's REST best
 * practices; 0087).
 * Surface is deliberately generic (`get`/`post`) so the PVR submitter and advisory
 * tracker can reuse it.
 */

/** Plain `owner/repo` only: no traversal ('.'/'..' segments), extra segments, or whitespace. */
const REPO_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

/** The one strict repo-name check, shared by every entry point that takes a name from outside. */
export function isPlainRepoName(name: string): boolean {
  return REPO_NAME_RE.test(name);
}

export interface HttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  /** Header names lowercased. */
  headers: Record<string, string>;
  json: unknown;
}

export type Transport = (req: HttpRequest) => Promise<HttpResponse>;

export interface GitHubClient {
  get(path: string, query?: Record<string, string | number>): Promise<HttpResponse>;
  post(path: string, body: unknown): Promise<HttpResponse>;
}

export interface GitHubClientOptions {
  token?: string;
  /** Defaults to `fetch`. */
  transport?: Transport;
  /** Epoch milliseconds. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  baseUrl?: string;
  /** Rate-limit retries per request before giving up. */
  maxRetries?: number;
  /** Extra tries for a GET that got a 5xx or a thrown transport error (POSTs are never retried). */
  transientRetries?: number;
  /** First backoff for a transient retry; doubles each time. */
  backoffMs?: number;
  /** Search requests allowed per window (kept under GitHub's 10/min), spaced evenly across it. */
  searchPerWindow?: number;
  searchWindowMs?: number;
  /** First wait on a secondary limit; doubles on each consecutive hit (0087). */
  secondaryBackoffMs?: number;
  /**
   * Called for every rate-limited response (before any wait or give-up) with GitHub's limit
   * headers. It gets a route class, never the URL: a `/repos/owner/name` path is a repo name, and
   * run logs must not pair repos with anything (0085).
   */
  onRateLimit?: (info: RateLimitInfo) => void;
}

/** What a rate-limited response said about the limit it hit (header values, verbatim). */
export interface RateLimitInfo {
  status: number;
  route: 'search' | 'core';
  limit?: string;
  remaining?: string;
  used?: string;
  reset?: string;
  resource?: string;
  retryAfter?: string;
}

function rateLimitInfo(res: HttpResponse, isSearch: boolean): RateLimitInfo {
  const h = res.headers;
  const pick: [keyof RateLimitInfo, string][] = [
    ['limit', 'x-ratelimit-limit'],
    ['remaining', 'x-ratelimit-remaining'],
    ['used', 'x-ratelimit-used'],
    ['reset', 'x-ratelimit-reset'],
    ['resource', 'x-ratelimit-resource'],
    ['retryAfter', 'retry-after'],
  ];
  const info: RateLimitInfo = { status: res.status, route: isSearch ? 'search' : 'core' };
  for (const [k, header] of pick) {
    const v = h[header];
    if (v !== undefined) (info as unknown as Record<string, string>)[k] = v;
  }
  return info;
}

/** A rate-limit response persisted past the retry cap. */
export class GitHubRateLimitError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'GitHubRateLimitError';
  }
}

const DEFAULT_BASE = 'https://api.github.com';

export interface FetchTransportOptions {
  /** Whole-request bound, response body included. Defaults to 30s. */
  timeoutMs?: number;
  /** Defaults to global `fetch` (tests inject a fake). */
  fetchImpl?: typeof fetch;
}

export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** A fetch-backed transport whose every request is aborted after `timeoutMs`. */
export function createFetchTransport(opts: FetchTransportOptions = {}): Transport {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const doFetch = opts.fetchImpl ?? fetch;
  return async (req) => {
    const signal = AbortSignal.timeout(timeoutMs);
    const res = await doFetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      signal,
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { status: res.status, headers, json };
  };
}

export const fetchTransport: Transport = createFetchTransport();

const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

type RateLimit = { kind: 'primary'; waitMs: number } | { kind: 'secondary'; retryAfterMs: number };

/**
 * Classify a rate-limited response, or undefined if it is not one. Primary: the quota is spent
 * (`x-ratelimit-remaining: 0`), so wait for `retry-after` or the reset. Secondary: a response
 * carrying `retry-after` while quota remains, or, for an idempotent GET only, a bare 429 or a 403
 * naming a secondary rate limit. A POST without a header signal is returned as is: submit stops
 * the run on it rather than risk a second report.
 */
function classifyRateLimit(res: HttpResponse, now: number, isGet: boolean): RateLimit | undefined {
  if (res.status !== 403 && res.status !== 429) return undefined;
  const raw = res.headers['retry-after'];
  const retryAfter = Number(raw);
  const retryAfterMs =
    raw !== undefined && Number.isFinite(retryAfter) ? Math.max(0, retryAfter) * 1000 : undefined;
  if (res.headers['x-ratelimit-remaining'] === '0') {
    if (retryAfterMs !== undefined) return { kind: 'primary', waitMs: retryAfterMs };
    const reset = Number(res.headers['x-ratelimit-reset']);
    if (Number.isFinite(reset))
      return { kind: 'primary', waitMs: Math.max(0, reset * 1000 - now) + 1000 };
  }
  const message = (res.json as { message?: unknown } | null)?.message;
  const namesSecondary = typeof message === 'string' && /secondary rate limit/i.test(message);
  if (retryAfterMs !== undefined || (isGet && (res.status === 429 || namesSecondary))) {
    return { kind: 'secondary', retryAfterMs: retryAfterMs ?? 0 };
  }
  return undefined;
}

export function createGitHubClient(opts: GitHubClientOptions = {}): GitHubClient {
  const transport = opts.transport ?? fetchTransport;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? realSleep;
  const base = opts.baseUrl ?? DEFAULT_BASE;
  const maxRetries = opts.maxRetries ?? 5;
  const transientRetries = opts.transientRetries ?? 2;
  const backoffMs = opts.backoffMs ?? 1000;
  const searchPerWindow = opts.searchPerWindow ?? 9;
  const searchWindowMs = opts.searchWindowMs ?? 60_000;
  const secondaryBackoffMs = opts.secondaryBackoffMs ?? 60_000;
  /** Even spacing keeps any window under the cap without bursts (GitHub: requests serially). */
  const searchIntervalMs = Math.ceil(searchWindowMs / searchPerWindow);
  let lastSearchAt: number | undefined;
  /** Consecutive secondary-limit hits, client-wide; any non-rate-limited response resets it. */
  let secondaryStreak = 0;

  /** Block until the previous search is at least one interval old, then record this one. */
  async function throttleSearch(): Promise<void> {
    if (lastSearchAt !== undefined) {
      const wait = lastSearchAt + searchIntervalMs - now();
      if (wait > 0) await sleep(wait);
    }
    lastSearchAt = now();
  }

  /**
   * GETs are idempotent, so a 5xx or a thrown transport error is retried with exponential
   * backoff; after the last try the 5xx response is returned and a thrown error rethrown. A POST
   * is sent exactly once: repeating one could file a second report.
   */
  async function transportWithRetry(req: HttpRequest): Promise<HttpResponse> {
    const tries = req.method === 'GET' ? transientRetries : 0;
    for (let n = 0; ; n++) {
      try {
        const res = await transport(req);
        if (res.status < 500 || n >= tries) return res;
      } catch (e) {
        if (n >= tries) throw e;
      }
      await sleep(backoffMs * 2 ** n);
    }
  }

  async function send(req: HttpRequest, isSearch: boolean): Promise<HttpResponse> {
    for (let attempt = 0; ; attempt++) {
      if (isSearch) await throttleSearch();
      const res = await transportWithRetry(req);
      const limit = classifyRateLimit(res, now(), req.method === 'GET');
      if (limit === undefined) {
        secondaryStreak = 0;
        return res;
      }
      opts.onRateLimit?.(rateLimitInfo(res, isSearch));
      const wait =
        limit.kind === 'primary'
          ? limit.waitMs
          : Math.max(limit.retryAfterMs, secondaryBackoffMs * 2 ** secondaryStreak++);
      if (attempt >= maxRetries) {
        throw new GitHubRateLimitError(
          `GitHub rate limit persisted after ${maxRetries} retries (${res.status})`,
          res.status,
        );
      }
      await sleep(wait);
    }
  }

  const headers = (): Record<string, string> => ({
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'blastgate-crawler',
    ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
  });

  return {
    get(path, query) {
      const qs = query
        ? `?${new URLSearchParams(Object.entries(query).map(([k, v]): [string, string] => [k, String(v)])).toString()}`
        : '';
      return send(
        { method: 'GET', url: `${base}${path}${qs}`, headers: headers() },
        path.startsWith('/search/'),
      );
    },
    post(path, body) {
      return send(
        {
          method: 'POST',
          url: `${base}${path}`,
          headers: { ...headers(), 'content-type': 'application/json' },
          body: JSON.stringify(body),
        },
        path.startsWith('/search/'),
      );
    },
  };
}
