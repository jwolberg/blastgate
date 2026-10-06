import { describe, expect, it } from 'vitest';
import { DEFAULT_CRAWL_CONFIG, type CrawlConfig } from './config';
import { createGitHubClient, type HttpRequest, type HttpResponse } from './github';
import {
  UNCERTAIN_REASON,
  createDisclosure,
  emptyLedger,
  recoverSubmitting,
  transition,
  type Ledger,
} from './ledger';
import { tierReport } from './disclose';
import { submitAll, type SubmitCandidate } from './submit';

const NOW = new Date('2026-10-01T12:00:00.000Z');
const ARCH = 'pr-title-injection';

const SHA = 'd'.repeat(40);
/** Every repo these tests file for, approved at SHA for its default finding id (0092). */
const REPOS = [
  'a/one',
  'b/two',
  'c/three',
  'o/a',
  'o/b',
  'o/c',
  ...[0, 1, 2, 3, 4, 5].map((i) => `o/r${i}`),
];
const approvedAll = REPOS.map((repo) => ({
  repo,
  sha: SHA,
  findingId: `${repo}#1`,
  skeptic: 'could-not-refute' as const,
}));

const live: CrawlConfig = {
  ...DEFAULT_CRAWL_CONFIG,
  allowlist: [ARCH],
  approved: approvedAll,
  submitMode: true,
};

const cand = (repo: string, over: Partial<SubmitCandidate> = {}): SubmitCandidate => ({
  repo,
  sha: SHA,
  archetype: ARCH,
  findingIds: [`${repo}#1`],
  report: { summary: `sum ${repo}`, description: `desc ${repo}` },
  reverify: 'still-fails',
  ...over,
});

type Handler = (req: HttpRequest) => HttpResponse | undefined;
const res = (status: number, json: unknown = null, headers = {}): HttpResponse => ({
  status,
  headers,
  json,
});
const onPost =
  (r: HttpResponse | (() => HttpResponse)): Handler =>
  (req) =>
    req.method === 'POST' ? (typeof r === 'function' ? r() : r) : undefined;

function env(handler?: Handler, pvr = true) {
  const calls: HttpRequest[] = [];
  const events: string[] = [];
  const transport = async (req: HttpRequest): Promise<HttpResponse> => {
    calls.push(req);
    events.push(`${req.method} ${req.url.replace('https://api.github.com', '')}`);
    const custom = handler?.(req);
    if (custom) return custom;
    if (req.method === 'GET') return res(200, { enabled: pvr });
    const repo = /repos\/(.+)\/security-advisories/.exec(req.url)?.[1] ?? '?';
    return res(201, { html_url: `https://github.com/${repo}/security/advisories/GHSA-1` });
  };
  const client = createGitHubClient({ transport, now: () => NOW.getTime(), sleep: async () => {} });
  const posts = () => calls.filter((c) => c.method === 'POST');
  return { client, calls, events, posts };
}

async function run(
  e: ReturnType<typeof env>,
  candidates: SubmitCandidate[],
  opts: { ledger?: Ledger; config?: CrawlConfig; killSwitch?: boolean; now?: Date } = {},
) {
  const persisted: Ledger[] = [];
  const result = await submitAll({
    ledger: opts.ledger ?? emptyLedger(),
    candidates,
    config: opts.config ?? live,
    client: e.client,
    killSwitch: opts.killSwitch ?? false,
    persist: async (l) => {
      e.events.push(`persist:${l.disclosures.map((d) => d.state).join(',')}`);
      persisted.push(l);
    },
    now: () => opts.now ?? NOW,
  });
  return { ...result, persisted };
}

describe('submitAll (U5)', () => {
  it('AE3: success records the report URL, and a second run with the same ids POSTs nothing', async () => {
    const e = env();
    const r1 = await run(e, [cand('a/one')]);
    expect(e.posts()).toHaveLength(1);
    const post = e.posts()[0] as HttpRequest;
    expect(post.url).toBe('https://api.github.com/repos/a/one/security-advisories/reports');
    expect(JSON.parse(post.body ?? '')).toEqual({
      summary: 'Security vulnerability in a/one: attacker-controlled input reaches a secret',
      description: tierReport(cand('a/one').report, 'vulnerability', 'a/one').description,
      severity: 'high',
      vulnerabilities: [],
    });
    const d = r1.ledger.disclosures[0];
    expect(d?.state).toBe('submitted');
    expect(d?.reportUrl).toBe('https://github.com/a/one/security/advisories/GHSA-1');

    const e2 = env();
    const r2 = await run(e2, [cand('a/one')], { ledger: r1.ledger });
    expect(e2.calls).toHaveLength(0);
    expect(r2.outcomes[0]?.outcome).toBe('duplicate');
    expect(r2.ledger.disclosures.map((x) => x.state)).toEqual(['submitted']);
  });

  it('AE7: persist(submitting) happens before the transport sees the POST, then submitted', async () => {
    const e = env();
    await run(e, [cand('a/one')]);
    const i = e.events.findIndex((x) => x.startsWith('POST'));
    expect(e.events[i - 1]).toBe('persist:submitting');
    expect(e.events[i + 1]).toBe('persist:submitted');
  });

  it('AE7: if persisting submitting fails, nothing is POSTed', async () => {
    const e = env();
    await expect(
      submitAll({
        ledger: emptyLedger(),
        candidates: [cand('a/one')],
        config: live,
        client: e.client,
        killSwitch: false,
        persist: async () => {
          throw new Error('disk full');
        },
        now: () => NOW,
      }),
    ).rejects.toThrow('disk full');
    expect(e.posts()).toHaveLength(0);
  });

  it('AE4: PVR disabled never files the report; in a dry run it asks nobody either', async () => {
    const e = env(undefined, false);
    const r = await run(e, [cand('a/one')], { config: { ...live, submitMode: false } });
    expect(e.posts()).toHaveLength(0);
    expect(r.ledger.disclosures[0]?.state).toBe('held');
    expect(r.ledger.disclosures[0]?.reason).toBe('no PVR');
    expect(e.calls[0]?.url).toContain('/repos/a/one/private-vulnerability-reporting');
  });

  describe('0102: asking an owner with PVR off to enable it', () => {
    const issuePosts = (e: ReturnType<typeof env>) =>
      e.posts().filter((p) => p.url.endsWith('/issues'));
    const reportPosts = (e: ReturnType<typeof env>) =>
      e.posts().filter((p) => p.url.includes('/security-advisories/'));
    const issueOk: Handler = (req) =>
      req.method === 'POST' && req.url.endsWith('/issues')
        ? res(201, { html_url: 'https://github.com/a/one/issues/7' })
        : undefined;

    it('opens one detail-free public issue asking for PVR, and never files the report', async () => {
      const e = env(issueOk, false);
      const r = await run(e, [cand('a/one')]);
      expect(reportPosts(e)).toHaveLength(0);
      expect(issuePosts(e)).toHaveLength(1);
      expect(issuePosts(e)[0]?.url).toBe('https://api.github.com/repos/a/one/issues');
      const sent = JSON.parse(issuePosts(e)[0]?.body ?? '{}') as { title: string; body: string };
      expect(sent.title).toMatch(/private vulnerability reporting/i);
      expect(sent.body).toMatch(/configure-for-a-repository/);
      // Nothing about the finding goes public: no report text, ids, workflow, secret or tier.
      for (const leak of ['sum a/one', 'desc a/one', 'a/one#1', 'workflow', 'secret', 'Possible']) {
        expect(`${sent.title}\n${sent.body}`).not.toContain(leak);
      }
      const d = r.ledger.disclosures[0];
      expect(d?.state).toBe('held');
      expect(d?.reason).toBe('no PVR (enable requested)');
      expect(d?.pvrRequest).toMatchObject({ url: 'https://github.com/a/one/issues/7' });
      expect(r.outcomes[0]?.outcome).toBe('requested');
    });

    it('asks at most once per repo, ever', async () => {
      const e = env(issueOk, false);
      const r1 = await run(e, [cand('a/one')]);
      await run(e, [cand('a/one')], {
        ledger: r1.ledger,
        now: new Date(NOW.getTime() + 2 * 86_400_000),
      });
      expect(issuePosts(e)).toHaveLength(1);
    });

    it('files the private report once the owner turns PVR on', async () => {
      const r1 = await run(env(issueOk, false), [cand('a/one')]);
      const e2 = env(undefined, true);
      const r2 = await run(e2, [cand('a/one')], { ledger: r1.ledger });
      expect(reportPosts(e2)).toHaveLength(1);
      expect(issuePosts(e2)).toHaveLength(0);
      expect(r2.ledger.disclosures[0]?.state).toBe('submitted');
    });

    it.each([401, 403, 404])(
      'never asks when the PVR check itself failed (HTTP %i)',
      async (status) => {
        const e = env((req) =>
          req.method === 'GET' ? res(status, { message: 'x' }) : issueOk(req),
        );
        await run(e, [cand('a/one')]);
        expect(e.posts()).toHaveLength(0);
      },
    );

    it('records the request before posting, so a crash can never post it twice', async () => {
      const e = env(issueOk, false);
      await run(e, [cand('a/one')]);
      const persistAt = e.events.findIndex((x) => x.startsWith('persist:'));
      const postAt = e.events.findIndex((x) => x.startsWith('POST /repos/a/one/issues'));
      expect(persistAt).toBeGreaterThanOrEqual(0);
      expect(persistAt).toBeLessThan(postAt);
    });

    it('a failed request (issues disabled) is recorded and never retried', async () => {
      const gone: Handler = (req) =>
        req.method === 'POST' && req.url.endsWith('/issues')
          ? res(410, { message: 'Issues are disabled' })
          : undefined;
      const e = env(gone, false);
      const r1 = await run(e, [cand('a/one')]);
      expect(r1.ledger.disclosures[0]?.reason).toBe('no PVR (enable request failed: HTTP 410)');
      expect(r1.ledger.disclosures[0]?.pvrRequest).toMatchObject({ failedStatus: 410 });
      await run(e, [cand('a/one')], { ledger: r1.ledger });
      expect(issuePosts(e)).toHaveLength(1);
    });

    it('counts requests against the throttle like reports', async () => {
      const e = env(issueOk, false);
      await run(e, [cand('o/a'), cand('o/b')], {
        config: { ...live, throttle: { perHour: 1, perDay: 20 } },
      });
      expect(issuePosts(e)).toHaveLength(1);
    });

    it('stops the run on a 429 from the issue POST', async () => {
      const limited: Handler = (req) =>
        req.method === 'POST' && req.url.endsWith('/issues') ? res(429, {}) : undefined;
      const e = env(limited, false);
      const r = await run(e, [cand('o/a'), cand('o/b')]);
      expect(issuePosts(e)).toHaveLength(1);
      expect(r.summary.stoppedReason).toMatch(/rate limit/);
    });
  });

  describe('0104: watching the PVR request issue', () => {
    const ISSUE = 'https://github.com/a/one/issues/7';
    const reportPosts = (e: ReturnType<typeof env>) =>
      e.posts().filter((p) => p.url.includes('/security-advisories/'));
    /** A ledger where a/one was asked (issue #7) and is held waiting for PVR. */
    async function asked(): Promise<Ledger> {
      const issueOk: Handler = (req) =>
        req.method === 'POST' && req.url.endsWith('/issues')
          ? res(201, { html_url: ISSUE })
          : undefined;
      return (await run(env(issueOk, false), [cand('a/one')])).ledger;
    }
    const issue =
      (state: string | number, comments: unknown[] = []): Handler =>
      (req) => {
        if (req.method !== 'GET') return undefined;
        if (/\/issues\/7\/comments/.test(req.url)) return res(200, comments);
        if (/\/issues\/7$/.test(req.url)) {
          return typeof state === 'number'
            ? res(state, { message: 'x' })
            : res(200, { state, user: { login: 'reporter' } });
        }
        return undefined;
      };
    const comment = (login: string, at: string) => ({ user: { login }, created_at: at });

    it('PVR still off and the issue closed: the owner declined, final, nothing sent ever', async () => {
      const l = await asked();
      const e = env(issue('closed'), false);
      const r = await run(e, [cand('a/one')], { ledger: l });
      expect(e.posts()).toHaveLength(0);
      expect(r.ledger.disclosures[0]).toMatchObject({
        state: 'held',
        reason: 'declined (request issue closed)',
      });
      const e2 = env(issue('closed'), true);
      await run(e2, [cand('a/one')], { ledger: r.ledger });
      expect(e2.posts()).toHaveLength(0);
    });

    it('PVR on and the issue closed: the owner did what was asked, so the report is filed', async () => {
      const l = await asked();
      const e = env(issue('closed'), true);
      const r = await run(e, [cand('a/one')], { ledger: l });
      expect(reportPosts(e)).toHaveLength(1);
      expect(r.ledger.disclosures[0]?.state).toBe('submitted');
    });

    it('PVR off and the issue open: still waiting', async () => {
      const l = await asked();
      const e = env(issue('open'), false);
      const r = await run(e, [cand('a/one')], { ledger: l });
      expect(e.posts()).toHaveLength(0);
      expect(r.ledger.disclosures[0]?.reason).toBe('no PVR (enable requested)');
    });

    it.each([404, 410])('PVR off and the issue gone (HTTP %i): final', async (status) => {
      const l = await asked();
      const r = await run(env(issue(status), false), [cand('a/one')], { ledger: l });
      expect(r.ledger.disclosures[0]?.reason).toBe(`declined (request issue gone: HTTP ${status})`);
    });

    it('an issue lookup that errors leaves the hold as it was', async () => {
      const l = await asked();
      const r = await run(env(issue(500), false), [cand('a/one')], { ledger: l });
      expect(r.ledger.disclosures[0]?.reason).toBe('no PVR (enable requested)');
    });

    it('an issue lookup whose transport throws is skipped, not fatal', async () => {
      const l = await asked();
      const e = env((req) => {
        if (req.method === 'GET' && /\/issues\/7$/.test(req.url)) throw new Error('reset');
        return undefined;
      }, false);
      const r = await run(e, [cand('a/one')], { ledger: l });
      expect(r.ledger.disclosures[0]?.reason).toBe('no PVR (enable requested)');
    });

    it('a rate limit on the issue lookup stops the run', async () => {
      const l = await asked();
      const e = env(
        (req) =>
          req.method === 'GET' && /\/issues\/7$/.test(req.url)
            ? res(429, null, { 'retry-after': '1' })
            : undefined,
        false,
      );
      const r = await run(e, [cand('a/one'), cand('b/two')], { ledger: l });
      expect(r.summary.stoppedReason).toMatch(/rate limit/);
      expect(r.outcomes.find((o) => o.repo === 'b/two')?.outcome).toBe('stopped');
    });

    it('counts new owner replies once, ignoring our own comments', async () => {
      const l = await asked();
      const thread = [
        comment('reporter', '2026-10-01T13:00:00Z'),
        comment('owner', '2026-10-01T14:00:00Z'),
        comment('Owner2', '2026-10-01T15:00:00Z'),
      ];
      const r1 = await run(env(issue('open', thread), false), [cand('a/one')], { ledger: l });
      expect(r1.summary.ownerReplies).toBe(2);
      expect(r1.ledger.disclosures[0]?.pvrRequest?.repliesSeenAt).toBe('2026-10-01T15:00:00Z');
      const r2 = await run(env(issue('open', thread), false), [cand('a/one')], {
        ledger: r1.ledger,
      });
      expect(r2.summary.ownerReplies).toBe(0);
      const more = [...thread, comment('owner', '2026-10-02T09:00:00Z')];
      const r3 = await run(env(issue('open', more), false), [cand('a/one')], {
        ledger: r2.ledger,
      });
      expect(r3.summary.ownerReplies).toBe(1);
    });
  });

  it('a non-200 PVR check holds as "no PVR"', async () => {
    const e = env((req) => (req.method === 'GET' ? res(404, { message: 'nope' }) : undefined));
    const r = await run(e, [cand('a/one')]);
    expect(e.posts()).toHaveLength(0);
    expect(r.ledger.disclosures[0]?.reason).toBe('no PVR');
  });

  it('a non-allowlisted archetype is held by the gate without a POST', async () => {
    const e = env();
    const r = await run(e, [cand('a/one', { archetype: 'other' })]);
    expect(e.posts()).toHaveLength(0);
    expect(r.ledger.disclosures[0]).toMatchObject({
      state: 'held',
      reason: 'archetype not allowlisted',
    });
  });

  it('0092: an allowlisted but unapproved fail is held without a POST, then sent once approved', async () => {
    const e = env();
    const unapproved = { ...live, approved: [] };
    const r1 = await run(e, [cand('a/one')], { config: unapproved });
    expect(e.calls).toHaveLength(0);
    expect(r1.ledger.disclosures[0]).toMatchObject({
      state: 'held',
      reason: 'not approved at this commit',
    });
    const r2 = await run(e, [cand('a/one')], { ledger: r1.ledger });
    expect(e.posts()).toHaveLength(1);
    expect(r2.ledger.disclosures[0]?.state).toBe('submitted');
  });

  it('0092: an approval for an older commit does not release the fail at the new one', async () => {
    const e = env();
    const r = await run(e, [cand('a/one', { sha: 'e'.repeat(40) })]);
    expect(e.posts()).toHaveLength(0);
    expect(r.ledger.disclosures[0]?.reason).toBe('not approved at this commit');
  });

  it('kill switch: zero requests, nothing created, reason in the summary', async () => {
    const e = env();
    const r = await run(e, [cand('a/one'), cand('b/two')], { killSwitch: true });
    expect(e.calls).toHaveLength(0);
    expect(r.ledger.disclosures).toHaveLength(0);
    expect(r.summary.stoppedReason).toBe('kill switch');
    expect(r.outcomes.every((o) => o.outcome === 'stopped')).toBe(true);
  });

  it('throttle: the 6th in an hour is deferred, not dropped, and goes next run', async () => {
    const e = env();
    const cands = Array.from({ length: 6 }, (_, i) => cand(`o/r${i}`));
    const r = await run(e, cands);
    expect(e.posts()).toHaveLength(5);
    expect(r.summary.counts['deferred']).toBe(1);
    expect(r.ledger.disclosures.find((d) => d.repo === 'o/r5')).toBeUndefined();

    const later = env();
    const r2 = await run(later, cands, {
      ledger: r.ledger,
      now: new Date(NOW.getTime() + 2 * 3600_000),
    });
    expect(later.posts()).toHaveLength(1);
    expect(r2.ledger.disclosures.find((d) => d.repo === 'o/r5')?.state).toBe('submitted');
  });

  it('throttle: the daily budget also applies', async () => {
    const e = env();
    const config = { ...live, throttle: { perHour: 100, perDay: 2 } };
    const r = await run(e, [cand('o/a'), cand('o/b'), cand('o/c')], { config });
    expect(e.posts()).toHaveLength(2);
    expect(r.outcomes.map((o) => o.outcome)).toEqual(['submitted', 'submitted', 'deferred']);
  });

  it('a 429 on the first POST stops further POSTs and leaves the rest untouched', async () => {
    const e = env(onPost(res(429, { message: 'slow' })));
    const r = await run(e, [cand('a/one'), cand('b/two'), cand('c/three')]);
    expect(e.posts()).toHaveLength(1);
    expect(r.summary.stoppedReason).toMatch(/rate limit/);
    expect(r.ledger.disclosures.map((d) => d.repo)).toEqual(['a/one']);
    expect(r.ledger.disclosures.some((d) => d.state === 'submitting')).toBe(false);
    expect(r.outcomes.filter((o) => o.outcome === 'stopped').map((o) => o.repo)).toEqual([
      'b/two',
      'c/three',
    ]);
  });

  it('a plain 403 on the POST holds that repo non-retryably and the run continues', async () => {
    const e = env(onPost(res(403, { message: 'forbidden' })));
    const r = await run(e, [cand('a/one'), cand('b/two')]);
    expect(e.posts()).toHaveLength(2);
    expect(r.summary.stoppedReason).toBeUndefined();
    expect(r.ledger.disclosures.map((d) => [d.state, d.reason])).toEqual([
      ['held', 'submission failed (HTTP 403)'],
      ['held', 'submission failed (HTTP 403)'],
    ]);
    // never retried automatically
    const later = env();
    const r2 = await run(later, [cand('a/one')], { ledger: r.ledger });
    expect(later.calls).toHaveLength(0);
    expect(r2.outcomes[0]?.outcome).toBe('duplicate');
  });

  it('a 403 carrying retry-after is a rate limit and stops the run', async () => {
    const e = env(onPost(res(403, null, { 'retry-after': '1' })));
    const r = await run(e, [cand('a/one'), cand('b/two')]);
    expect(r.summary.stoppedReason).toMatch(/rate limit/);
    expect(r.outcomes.find((o) => o.repo === 'b/two')?.outcome).toBe('stopped');
  });

  it('a plain 403 on the PVR pre-check holds that repo as retryable and the run continues', async () => {
    const e = env((req) =>
      req.method === 'GET' && req.url.includes('/a/one/') ? res(403, { message: 'no' }) : undefined,
    );
    const r = await run(e, [cand('a/one'), cand('b/two')]);
    expect(r.summary.stoppedReason).toBeUndefined();
    expect(e.posts()).toHaveLength(1);
    expect(r.outcomes.map((o) => o.outcome)).toEqual(['held', 'submitted']);
    const held = r.ledger.disclosures.find((d) => d.repo === 'a/one');
    expect(held).toMatchObject({ state: 'held', reason: 'no PVR (HTTP 403)' });

    // retryable: a later run with PVR enabled files it
    const later = env();
    const r2 = await run(later, [cand('a/one')], { ledger: r.ledger });
    expect(later.posts()).toHaveLength(1);
    expect(r2.ledger.disclosures.find((d) => d.repo === 'a/one')?.state).toBe('submitted');
  });

  it('a retried hold whose reason changes is re-held, not an illegal move', async () => {
    const e1 = env((req) => (req.method === 'GET' ? res(403, { message: 'no' }) : undefined));
    const r1 = await run(e1, [cand('a/one')]);
    expect(r1.ledger.disclosures[0]?.reason).toBe('no PVR (HTTP 403)');
    const e2 = env((req) => (req.method === 'GET' ? res(404, { message: 'nope' }) : undefined));
    const r2 = await run(e2, [cand('a/one')], { ledger: r1.ledger });
    expect(r2.ledger.disclosures[0]).toMatchObject({ state: 'held', reason: 'no PVR' });
  });

  it('rejects a repo name with a dot-dot segment', async () => {
    const e = env();
    const r = await run(e, [cand('owner/..'), cand('owner/.')]);
    expect(e.calls).toHaveLength(0);
    expect(r.outcomes.map((o) => o.outcome)).toEqual(['held', 'held']);
    expect(r.ledger.disclosures).toHaveLength(0);
  });

  it('a rate limit that outlasts the client retries (GitHubRateLimitError) stops the run', async () => {
    const e = env(onPost(res(429, null, { 'retry-after': '1' })));
    const r = await run(e, [cand('a/one'), cand('b/two')]);
    expect(r.summary.stoppedReason).toMatch(/rate limit/);
    expect(r.outcomes.find((o) => o.repo === 'b/two')?.outcome).toBe('stopped');
  });

  it('a rate limit on the PVR pre-check stops the run and leaves the entry queued', async () => {
    const e = env((req) =>
      req.method === 'GET' ? res(429, null, { 'retry-after': '1' }) : undefined,
    );
    const r = await run(e, [cand('a/one'), cand('b/two')]);
    expect(e.posts()).toHaveLength(0);
    expect(r.summary.stoppedReason).toMatch(/rate limit/);
    expect(r.ledger.disclosures[0]?.state).toBe('queued');
  });

  it('dry run records the full would-send body and never POSTs', async () => {
    const e = env();
    const r = await run(e, [cand('a/one')], { config: { ...live, submitMode: false } });
    expect(e.posts()).toHaveLength(0);
    const d = r.ledger.disclosures[0];
    expect(d?.state).toBe('queued');
    expect(d?.wouldSend).toMatchObject({
      summary: 'Security vulnerability in a/one: attacker-controlled input reaches a secret',
      severity: 'high',
      vulnerabilities: [],
    });
    expect(String(d?.wouldSend?.description)).toMatch(/^## Security vulnerability in `a\/one`/);
    expect(r.outcomes[0]?.outcome).toBe('dry-run');
  });

  it('0101: a doubtful approval goes out as a possible vulnerability, severity medium, only with sendPossible', async () => {
    const doubtful = {
      ...live,
      approved: approvedAll.map((a) => ({ ...a, skeptic: 'doubtful' as const })),
    };
    const e = env();
    const held = await run(e, [cand('a/one')], { config: doubtful });
    expect(e.posts()).toHaveLength(0);
    expect(held.ledger.disclosures[0]?.reason).toBe('possible vulnerability: sending paused');
    const r = await run(e, [cand('a/one')], {
      ledger: held.ledger,
      config: { ...doubtful, sendPossible: true },
    });
    expect(e.posts()).toHaveLength(1);
    expect(r.ledger.disclosures[0]?.state).toBe('submitted');
    const sent = JSON.parse(String(e.posts()[0]?.body)) as Record<string, unknown>;
    expect(sent.summary).toMatch(/^Possible security vulnerability in a\/one: /);
    expect(sent.severity).toBe('medium');
    expect(String(sent.description)).toMatch(/please investigate/i);
  });

  it('reverify resolved moves the disclosure to resolved-before-report with no requests', async () => {
    const e = env();
    const r = await run(e, [cand('a/one', { reverify: 'resolved' })]);
    expect(e.calls).toHaveLength(0);
    expect(r.ledger.disclosures[0]?.state).toBe('resolved-before-report');
  });

  it.each(['head-mismatch', 'unknown'] as const)(
    'reverify %s leaves the entry queued for the next run',
    async (rv) => {
      const e = env();
      const r = await run(e, [cand('a/one', { reverify: rv })]);
      expect(e.calls).toHaveLength(0);
      expect(r.outcomes[0]?.outcome).toBe('retry');
      expect(r.ledger.disclosures[0]?.state).toBe('queued');
    },
  );

  it('POST 500 holds the entry and a later run does not retry it', async () => {
    const e = env(onPost(res(500, { message: 'boom' })));
    const r = await run(e, [cand('a/one')]);
    expect(r.ledger.disclosures[0]?.state).toBe('held');
    expect(r.ledger.disclosures[0]?.reason).toMatch(/HTTP 500/);
    const e2 = env();
    const r2 = await run(e2, [cand('a/one')], { ledger: r.ledger });
    expect(e2.calls).toHaveLength(0);
    expect(r2.ledger.disclosures[0]?.state).toBe('held');
  });

  it('a transport that throws mid-POST is uncertain and never retried', async () => {
    const e = env(
      onPost(() => {
        throw new Error('socket hang up');
      }),
    );
    const r = await run(e, [cand('a/one')]);
    expect(r.ledger.disclosures[0]).toMatchObject({ state: 'held', reason: UNCERTAIN_REASON });
    const e2 = env();
    await run(e2, [cand('a/one')], { ledger: r.ledger });
    expect(e2.calls).toHaveLength(0);
  });

  it('a recovered-uncertain held entry is never re-submitted', async () => {
    const key = { repo: 'a/one', findingIds: ['a/one#1'] };
    let l = createDisclosure(emptyLedger(), {
      ...key,
      archetype: ARCH,
      state: 'queued',
      now: NOW.toISOString(),
    });
    l = transition(l, key, 'submitting', { now: NOW.toISOString() });
    l = recoverSubmitting(l, NOW.toISOString());
    const e = env();
    await run(e, [cand('a/one')], { ledger: l });
    expect(e.calls).toHaveLength(0);
  });

  it('a held "no PVR" entry is re-checked later and submitted once PVR is on', async () => {
    const r = await run(env(undefined, false), [cand('a/one')]);
    const e2 = env(undefined, true);
    const r2 = await run(e2, [cand('a/one')], { ledger: r.ledger });
    expect(e2.posts()).toHaveLength(1);
    expect(r2.ledger.disclosures).toHaveLength(1);
    expect(r2.ledger.disclosures[0]?.state).toBe('submitted');
  });

  it('refuses a repo name that is not owner/repo, with no request', async () => {
    const e = env();
    const r = await run(e, [cand('../evil')]);
    expect(e.calls).toHaveLength(0);
    expect(r.outcomes[0]?.outcome).toBe('held');
  });
});
