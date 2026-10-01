/**
 * Small GitHub REST client for the public crawler. The transport, clock, and sleep
 * are injectable so tests are instant and offline. Search requests are throttled
 * under GitHub's code-search budget (10/min authenticated), and rate-limit
 * responses (`retry-after`, exhausted `x-ratelimit-*`) are waited out and retried.
 * Surface is deliberately generic (`get`/`post`) so the PVR submitter and advisory
 * tracker can reuse it.
 */

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
  /** Search requests allowed per window (kept under GitHub's 10/min). */
  searchPerWindow?: number;
  searchWindowMs?: number;
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

export const fetchTransport: Transport = async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body });
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

const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Ms to wait before retrying a rate-limited response, or undefined if it is not one. */
function rateLimitWait(res: HttpResponse, now: number): number | undefined {
  if (res.status !== 403 && res.status !== 429) return undefined;
  const retryAfter = Number(res.headers['retry-after']);
  if (res.headers['retry-after'] !== undefined && Number.isFinite(retryAfter)) {
    return Math.max(0, retryAfter) * 1000;
  }
  if (res.headers['x-ratelimit-remaining'] === '0') {
    const reset = Number(res.headers['x-ratelimit-reset']);
    if (Number.isFinite(reset)) return Math.max(0, reset * 1000 - now) + 1000;
  }
  return undefined;
}

export function createGitHubClient(opts: GitHubClientOptions = {}): GitHubClient {
  const transport = opts.transport ?? fetchTransport;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? realSleep;
  const base = opts.baseUrl ?? DEFAULT_BASE;
  const maxRetries = opts.maxRetries ?? 5;
  const searchPerWindow = opts.searchPerWindow ?? 9;
  const searchWindowMs = opts.searchWindowMs ?? 60_000;
  const searchTimes: number[] = [];

  /** Block until one more search request fits the sliding window, then record it. */
  async function throttleSearch(): Promise<void> {
    for (;;) {
      const t = now();
      while (searchTimes.length > 0 && t - (searchTimes[0] ?? 0) >= searchWindowMs) {
        searchTimes.shift();
      }
      if (searchTimes.length < searchPerWindow) {
        searchTimes.push(t);
        return;
      }
      await sleep(searchWindowMs - (t - (searchTimes[0] ?? t)));
    }
  }

  async function send(req: HttpRequest, isSearch: boolean): Promise<HttpResponse> {
    for (let attempt = 0; ; attempt++) {
      if (isSearch) await throttleSearch();
      const res = await transport(req);
      const wait = rateLimitWait(res, now());
      if (wait === undefined) return res;
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
