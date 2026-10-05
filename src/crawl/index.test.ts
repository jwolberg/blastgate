import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { composeReport } from './disclose';
import { discover } from './discover';
import { type DiscoveryState, serializeDiscoveryState } from './discovery-state';
import type { HttpRequest, HttpResponse } from './github';
import { createGitHubClient } from './github';
import {
  type ScanDeps,
  type ScanResultFile,
  type SubmitDeps,
  defaultScanDeps,
  execOut,
  formatRateLimit,
  gitPersist,
  main,
  parseScanResult,
  runScan,
  runSubmit,
} from './index';
import {
  type Ledger,
  applyScan,
  createDisclosure,
  emptyLedger,
  lsRemoteHeads,
  serializeLedger,
  transition,
} from './ledger';
import { reverify, scanRepos } from './scan';
import { fileURLToPath } from 'node:url';
import { submitAll } from './submit';

const STUB = join(__dirname, 'fixtures', 'orchestrator', 'stub-cli.mjs');
const NOW = new Date('2026-10-01T12:00:00.000Z');
const SHA = 'a'.repeat(40);
const ARCH = 'untrusted-text-injection->credential';

let base: string;
const sh = (cwd: string, ...args: string[]): string =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', ...args], {
    cwd,
    encoding: 'utf8',
  }).trim();

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'crawl-orch-'));
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const p = (...parts: string[]): string => join(base, ...parts);

function makeRemote(repo: string, mode: string): string {
  const dir = p('remote', `${repo}.git`);
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(dir, '.github', 'workflows', 'ci.yml'), 'on: push\njobs: {}\n');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: mode }));
  sh(dir, 'init', '-q', '-b', 'main');
  sh(dir, 'config', 'uploadpack.allowFilter', 'true');
  sh(dir, 'add', '-A');
  sh(dir, 'commit', '-qm', 'init');
  return sh(dir, 'rev-parse', 'HEAD');
}

// ---------------------------------------------------------------- scan

const stubEnv = (): NodeJS.ProcessEnv => ({
  ...process.env,
  EVAL_REMOTE_BASE: `file://${p('remote')}`,
  BLASTGATE_CLI: STUB,
  JOBS: '1',
});

/** A client whose repo-metadata answers are scripted; counts every /repos request. */
function metaClient(meta: (repo: string) => HttpResponse = () => publicRepo()) {
  const asked: string[] = [];
  const client = createGitHubClient({
    sleep: async () => {},
    transport: async (r) => {
      const m = /\/repos\/([^/]+\/[^/?]+)$/.exec(r.url);
      if (!m) return { status: 404, headers: {}, json: null };
      asked.push(m[1] ?? '');
      return meta(m[1] ?? '');
    },
  });
  return { client, asked };
}
const publicRepo = (): HttpResponse => ({
  status: 200,
  headers: {},
  json: { private: false, fork: false, archived: false },
});

function localScanDeps(over: Partial<ScanDeps> = {}): ScanDeps {
  return {
    ...defaultScanDeps({}),
    client: metaClient().client,
    discover: async () => ({ repos: ['acme/fail', 'acme/pass'], truncated: ['q1'], partial: [] }),
    lsRemoteHeads: (repos) =>
      lsRemoteHeads(repos, {
        exec: async (args) =>
          sh(
            p('remote', 'acme'),
            ...args.map((a) =>
              a.replace(/^https:\/\/github.com\/(.*)\.git$/, p('remote', '$1.git')),
            ),
          ),
      }),
    scanEnv: stubEnv(),
    cliVersion: async () => '9.9.9',
    blastgateSha: async () => 'f'.repeat(40),
    now: () => NOW,
    log: () => {},
    ...over,
  };
}

const scanArgs = (): Parameters<typeof runScan>[0] => ({
  ledger: p('ledger.json'),
  config: p('config.json'),
  out: p('out'),
  cap: 50,
});

describe('runScan', () => {
  it('stages run in order and the result file carries only the agreed fields', async () => {
    const calls: string[] = [];
    const deps = localScanDeps({
      discover: async () => {
        calls.push('discover');
        return { repos: ['acme/a'], truncated: [], partial: ['q2'] };
      },
      lsRemoteHeads: async (repos) => {
        calls.push('lsRemoteHeads');
        return new Map(repos.map((r) => [r, SHA]));
      },
      scanRepos: async (repos, o) => {
        calls.push(`scanRepos:${o.engineVersion}`);
        return {
          'acme/a': {
            fullSha: SHA,
            engineVersion: o.engineVersion ?? '',
            verdict: 'pass',
            scannedAt: NOW.toISOString(),
            failFindings: [],
          },
        };
      },
      reverify: async () => {
        calls.push('reverify');
        throw new Error('no fails, no reverify');
      },
    });
    const res = await runScan(scanArgs(), deps);
    expect(calls).toEqual(['discover', 'lsRemoteHeads', `scanRepos:9.9.9+${'f'.repeat(40)}`]);
    const onDisk = JSON.parse(readFileSync(p('out', 'scan-result.json'), 'utf8')) as ScanResultFile;
    expect(onDisk).toEqual(res);
    expect(Object.keys(onDisk).sort()).toEqual([
      'candidates',
      'currentFails',
      'discovered',
      'engineVersion',
      'partial',
      'scans',
      'truncated',
    ]);
    expect(onDisk.engineVersion).toBe(`9.9.9+${'f'.repeat(40)}`);
    expect(onDisk.discovered).toEqual(['acme/a']);
    expect(onDisk.partial).toEqual(['q2']);
    expect(onDisk.candidates).toEqual([]);
  });

  it('skips unchanged repos: the delta, not discovery, picks what is scanned', async () => {
    const scanned: string[][] = [];
    let ledger: Ledger = emptyLedger();
    ledger = applyScan(ledger, 'acme/a', {
      fullSha: SHA,
      engineVersion: `9.9.9+${'f'.repeat(40)}`,
      verdict: 'pass',
      scannedAt: NOW.toISOString(),
      failFindings: [],
    });
    writeFileSync(p('ledger.json'), serializeLedger(ledger));
    const res = await runScan(
      scanArgs(),
      localScanDeps({
        discover: async () => ({ repos: ['acme/a'], truncated: [], partial: [] }),
        lsRemoteHeads: async (repos) => new Map(repos.map((r) => [r, SHA])),
        scanRepos: async (repos) => {
          scanned.push([...repos]);
          return {};
        },
      }),
    );
    expect(scanned.flat()).toEqual([]);
    expect(res.discovered).toEqual(['acme/a']);
  });

  it('real scan + reverify on local remotes: a fail becomes one candidate, payload never leaves', async () => {
    const failHead = makeRemote('acme/fail', 'fail');
    makeRemote('acme/pass', 'pass');
    const res = await runScan(scanArgs(), localScanDeps({ scanRepos, reverify }));

    expect(res.scans['acme/fail']?.verdict).toBe('fail');
    expect(res.scans['acme/fail']?.fullSha).toBe(failHead);
    expect(res.scans['acme/pass']?.verdict).toBe('pass');
    expect(res.truncated).toEqual(['q1']);
    expect(Object.keys(res.currentFails).sort()).toEqual(['acme/fail', 'acme/pass']);
    expect(res.currentFails['acme/pass']).toEqual([]);
    expect(res.candidates).toHaveLength(1);
    const c = res.candidates[0];
    expect(c?.repo).toBe('acme/fail');
    expect(c?.sha).toBe(failHead);
    expect(c?.archetype).toBe(ARCH);
    expect(c?.reverify).toBe('still-fails');
    expect(c?.findingIds).toEqual(res.currentFails['acme/fail']);
    expect(c?.report.description).toContain('Blastgate');
    expect(c?.report.summary.length).toBeLessThanOrEqual(1024);

    const raw = readFileSync(p('out', 'scan-result.json'), 'utf8');
    expect(raw).not.toContain('PAYLOAD-SECRET-TEXT');
    expect(raw).not.toContain('attacker.example');
  });

  describe('resilient, incremental discovery (0083)', () => {
    const CLAUDE_ACTION = 'anthropics/claude-code-action';
    const dstate = (over: Partial<DiscoveryState['sweep']> = {}): DiscoveryState => ({
      schemaVersion: 1,
      sweep: {
        startedAt: '2026-09-30T00:00:00.000Z',
        pending: [{ action: CLAUDE_ACTION, size: [0, 1000], depth: 0 }],
        truncated: [],
        partial: [],
        ...over,
      },
      repos: { 'acme/pass': { lastSeenSweep: '2026-09-30T00:00:00.000Z' } },
    });

    it('a persistent search rate limit does not kill the job: it scans what is known', async () => {
      writeFileSync(p('discovery.json'), serializeDiscoveryState(dstate()));
      let searches = 0;
      const client = createGitHubClient({
        sleep: async () => {},
        transport: async (r) => {
          if (r.url.includes('/search/code')) {
            searches++;
            return { status: 429, headers: { 'retry-after': '1' }, json: null };
          }
          return publicRepo();
        },
      });
      const scanned: string[][] = [];
      const res = await runScan(
        { ...scanArgs(), discovery: p('discovery.json') },
        localScanDeps({
          client,
          discover: (c, ctx) => discover({ client: c, ...ctx, now: () => NOW }),
          lsRemoteHeads: async (repos) => new Map(repos.map((r) => [r, SHA])),
          scanRepos: async (repos, o) => {
            scanned.push([...repos]);
            return {
              'acme/pass': {
                fullSha: SHA,
                engineVersion: o.engineVersion ?? '',
                verdict: 'pass',
                scannedAt: NOW.toISOString(),
                failFindings: [],
              },
            };
          },
        }),
      );
      expect(searches).toBeGreaterThan(0);
      expect(scanned.flat()).toEqual(['acme/pass']);
      expect(res.discovered).toEqual(['acme/pass']);
      expect(res.discoveryState?.sweep.pending).toHaveLength(1);
      const onDisk = JSON.parse(
        readFileSync(p('out', 'scan-result.json'), 'utf8'),
      ) as ScanResultFile;
      expect(onDisk.discoveryState).toEqual(res.discoveryState);
    });

    it('survives a rate-limit error escaping a custom discover dep, keeping the old state', async () => {
      writeFileSync(p('discovery.json'), serializeDiscoveryState(dstate()));
      const { GitHubRateLimitError } = await import('./github');
      const res = await runScan(
        { ...scanArgs(), discovery: p('discovery.json') },
        localScanDeps({
          discover: async () => {
            throw new GitHubRateLimitError('limited', 429);
          },
          lsRemoteHeads: async (repos) => new Map(repos.map((r) => [r, SHA])),
          scanRepos: async () => ({}),
        }),
      );
      expect(res.discovered).toEqual(['acme/pass']);
      expect(res.discoveryState).toEqual(dstate());
    });

    it('loads --discovery state (missing file = fresh) and passes the config budget', async () => {
      const seen: Array<{ state: DiscoveryState | undefined; budget: number }> = [];
      const deps = localScanDeps({
        discover: async (_c, ctx) => {
          seen.push(ctx);
          return { repos: [], truncated: [], partial: [] };
        },
        lsRemoteHeads: async () => new Map(),
        scanRepos: async () => ({}),
      });
      await runScan({ ...scanArgs(), discovery: p('nope.json') }, deps);
      expect(seen[0]).toMatchObject({ state: undefined, budget: 300 });

      writeFileSync(p('discovery.json'), serializeDiscoveryState(dstate()));
      writeFileSync(p('config.json'), JSON.stringify({ discoveryBudget: 42 }));
      await runScan({ ...scanArgs(), discovery: p('discovery.json') }, deps);
      expect(seen[1]).toMatchObject({ state: dstate(), budget: 42 });
    });

    it('refuses a corrupt discovery file instead of silently restarting the sweep', async () => {
      writeFileSync(p('discovery.json'), '{"schemaVersion":1,"sweep":"x"}');
      await expect(
        runScan({ ...scanArgs(), discovery: p('discovery.json') }, localScanDeps()),
      ).rejects.toThrow(/discovery/);
    });

    it('0088: passes a discovery deadline of now + discoveryMinutes and logs a time stop', async () => {
      const seen: Array<{ deadline?: number; clock?: () => number }> = [];
      const lines: string[] = [];
      writeFileSync(p('config.json'), JSON.stringify({ discoveryMinutes: 20 }));
      await runScan(
        scanArgs(),
        localScanDeps({
          discover: async (_c, ctx) => {
            seen.push(ctx);
            return {
              repos: [],
              truncated: [],
              partial: [],
              state: dstate(),
              complete: false,
              timedOut: true,
              searches: 7,
            };
          },
          lsRemoteHeads: async () => new Map(),
          scanRepos: async () => ({}),
          log: (l) => lines.push(l),
        }),
      );
      expect(seen[0]?.deadline).toBe(NOW.getTime() + 20 * 60_000);
      expect(seen[0]?.clock?.()).toBe(NOW.getTime()); // judged by the scan's clock, not Date.now
      expect(lines.join('\n')).toMatch(/stopped by time limit/);
    });

    it('0086: an owner-scoped scan passes the owner, ignores and never emits discovery state', async () => {
      const seen: Array<{ state: DiscoveryState | undefined; budget: number; owner?: string }> = [];
      const deps = localScanDeps({
        discover: async (_c, ctx) => {
          seen.push(ctx);
          return { repos: [], truncated: [], partial: [], state: dstate() };
        },
        lsRemoteHeads: async () => new Map(),
        scanRepos: async () => ({}),
      });
      writeFileSync(p('discovery.json'), serializeDiscoveryState(dstate()));
      const before = readFileSync(p('discovery.json'), 'utf8');
      const res = await runScan(
        { ...scanArgs(), discovery: p('discovery.json'), owner: 'jwolberg' },
        deps,
      );
      expect(seen[0]).toMatchObject({ state: undefined, budget: 300, owner: 'jwolberg' });
      expect(res.discoveryState).toBeUndefined();
      const file = JSON.parse(readFileSync(p('out', 'scan-result.json'), 'utf8')) as ScanResultFile;
      expect(file.discoveryState).toBeUndefined();
      expect(readFileSync(p('discovery.json'), 'utf8')).toBe(before);

      // and an unscoped scan still carries the state through
      const res2 = await runScan({ ...scanArgs(), discovery: p('discovery.json') }, deps);
      expect(seen[1]?.owner).toBeUndefined();
      expect(res2.discoveryState).toBeDefined();
    });

    it('0086: refuses a bad owner before reading anything or searching', async () => {
      let searched = false;
      const deps = localScanDeps({
        discover: async () => {
          searched = true;
          return { repos: [], truncated: [], partial: [] };
        },
      });
      await expect(
        runScan({ ...scanArgs(), ledger: p('missing.json'), owner: 'x repo:evil/y' }, deps),
      ).rejects.toThrow(/owner/);
      expect(searched).toBe(false);
      await expect(
        main(
          [
            'scan',
            '--ledger',
            p('missing.json'),
            '--config',
            p('c.json'),
            '--out',
            p('o'),
            '--owner',
            'a b',
          ],
          {},
        ),
      ).rejects.toThrow(/owner/);
    });
  });

  it('checks eligibility only for the capped selection, not for every discovered repo (review #4)', async () => {
    const repos = Array.from({ length: 50 }, (_, i) => `acme/r${String(i).padStart(2, '0')}`);
    const m = metaClient();
    const scanned: string[][] = [];
    await runScan(
      { ...scanArgs(), cap: 3 },
      localScanDeps({
        client: m.client,
        discover: async () => ({ repos, truncated: [], partial: [] }),
        lsRemoteHeads: async (rs) => new Map(rs.map((r) => [r, SHA])),
        scanRepos: async (rs) => {
          scanned.push([...rs]);
          return {};
        },
      }),
    );
    expect(m.asked).toHaveLength(3);
    expect(scanned.flat()).toEqual(m.asked);
  });

  it('skips ineligible repos and backfills the cap, with a bounded number of checks (review #4)', async () => {
    const repos = Array.from({ length: 50 }, (_, i) => `acme/r${String(i).padStart(2, '0')}`);
    const m = metaClient((r) =>
      r <= 'acme/r03' ? { status: 200, headers: {}, json: { private: true } } : publicRepo(),
    );
    const scanned: string[][] = [];
    await runScan(
      { ...scanArgs(), cap: 3 },
      localScanDeps({
        client: m.client,
        discover: async () => ({ repos, truncated: [], partial: [] }),
        lsRemoteHeads: async (rs) => new Map(rs.map((r) => [r, SHA])),
        scanRepos: async (rs) => {
          scanned.push([...rs]);
          return {};
        },
      }),
    );
    expect(scanned.flat()).toEqual(['acme/r04', 'acme/r05', 'acme/r06']);
    expect(m.asked).toHaveLength(7);
    // never more than 3x the cap, however many are ineligible
    const all = metaClient(() => ({ status: 200, headers: {}, json: { private: true } }));
    await runScan(
      { ...scanArgs(), cap: 3 },
      localScanDeps({
        client: all.client,
        discover: async () => ({ repos, truncated: [], partial: [] }),
        lsRemoteHeads: async (rs) => new Map(rs.map((r) => [r, SHA])),
        scanRepos: async () => ({}),
      }),
    );
    expect(all.asked).toHaveLength(9);
  });

  it('skips and reports a repo whose metadata call fails instead of throwing (review #3)', async () => {
    const m = metaClient((r) =>
      r === 'acme/a' ? { status: 503, headers: {}, json: null } : publicRepo(),
    );
    const scanned: string[][] = [];
    const lines: string[] = [];
    await runScan(
      scanArgs(),
      localScanDeps({
        client: m.client,
        discover: async () => ({ repos: ['acme/a', 'acme/b'], truncated: [], partial: [] }),
        lsRemoteHeads: async (rs) => new Map(rs.map((r) => [r, SHA])),
        scanRepos: async (rs) => {
          scanned.push([...rs]);
          return {};
        },
        log: (l) => lines.push(l),
      }),
    );
    expect(scanned.flat()).toEqual(['acme/b']);
    expect(lines.join('\n')).toMatch(/eligibility errors 1/);
  });

  it('logs counts only: no repo name, no repo/verdict pair', async () => {
    makeRemote('acme/fail', 'fail');
    makeRemote('acme/pass', 'pass');
    const lines: string[] = [];
    await runScan(scanArgs(), localScanDeps({ scanRepos, reverify, log: (l) => lines.push(l) }));
    const out = lines.join('\n');
    expect(out).toMatch(/discovered\D+2/i);
    expect(out).not.toContain('acme');
    expect(out).not.toMatch(/\S+\/\S+\s*[:=]\s*(pass|fail|warn|unknown)/);
  });
});

// ---------------------------------------------------------------- submit

interface Net {
  reqs: HttpRequest[];
  transport: (r: HttpRequest) => Promise<HttpResponse>;
}
function fakeNet(opts: { pvrEnabled?: boolean } = {}): Net {
  const reqs: HttpRequest[] = [];
  return {
    reqs,
    transport: async (r) => {
      reqs.push(r);
      if (r.method === 'GET' && r.url.endsWith('/private-vulnerability-reporting')) {
        return { status: 200, headers: {}, json: { enabled: opts.pvrEnabled ?? true } };
      }
      if (r.method === 'POST') {
        return {
          status: 201,
          headers: {},
          json: {
            html_url: 'https://github.com/acme/fail/security/advisories/GHSA-aaaa-bbbb-cccc',
            ghsa_id: 'GHSA-aaaa-bbbb-cccc',
          },
        };
      }
      return { status: 404, headers: {}, json: null };
    },
  };
}

const REAL = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('./fixtures/disclose/real-fails.json', import.meta.url)),
    'utf8',
  ),
) as Record<string, Finding[]>;
const REAL_FINDING = Object.values(REAL)[0]?.[0] as Finding;
const ENGINE = '9.9.9+abc';
const REPORT = composeReport({
  repo: 'acme/fail',
  sha: SHA,
  findings: [REAL_FINDING],
  blastgateVersion: ENGINE,
});

/** Jay's approval of the fixture fail at SHA (0092). */
const APPROVED = [{ repo: 'acme/fail', sha: SHA, findingId: 'f1', skeptic: 'could-not-refute' }];

function scanResult(over: Partial<ScanResultFile> = {}): ScanResultFile {
  return {
    engineVersion: '9.9.9+abc',
    discovered: ['acme/fail', 'acme/pass'],
    truncated: [],
    partial: [],
    scans: {
      'acme/fail': {
        fullSha: SHA,
        engineVersion: '9.9.9+abc',
        verdict: 'fail',
        scannedAt: NOW.toISOString(),
        failFindings: [{ id: 'f1', archetype: ARCH }],
      },
      'acme/pass': {
        fullSha: 'b'.repeat(40),
        engineVersion: '9.9.9+abc',
        verdict: 'pass',
        scannedAt: NOW.toISOString(),
        failFindings: [],
      },
    },
    candidates: [
      {
        repo: 'acme/fail',
        sha: SHA,
        archetype: ARCH,
        findingIds: ['f1'],
        report: REPORT,
        reverify: 'still-fails',
      },
    ],
    currentFails: { 'acme/fail': ['f1'] },
    ...over,
  };
}

function setup(config: object | null, result: ScanResultFile, ledger?: Ledger): void {
  mkdirSync(p('in'), { recursive: true });
  writeFileSync(p('in', 'scan-result.json'), JSON.stringify(result));
  if (config !== null) writeFileSync(p('config.json'), JSON.stringify(config));
  if (ledger) writeFileSync(p('ledger.json'), serializeLedger(ledger));
}

const submitArgs = (): Parameters<typeof runSubmit>[0] => ({
  ledger: p('ledger.json'),
  config: p('config.json'),
  in: p('in', 'scan-result.json'),
  site: p('site'),
});

interface Harness {
  deps: SubmitDeps;
  net: Net;
  persisted: Ledger[];
  published: string[];
  logs: string[];
}
function harness(over: Partial<SubmitDeps> = {}, net: Net = fakeNet()): Harness {
  const persisted: Ledger[] = [];
  const published: string[] = [];
  const logs: string[] = [];
  const deps: SubmitDeps = {
    client: createGitHubClient({ token: 't', transport: net.transport, sleep: async () => {} }),
    persist: async (l) => {
      persisted.push(l);
    },
    publish: async (dir) => {
      published.push(dir);
    },
    now: () => NOW,
    log: (l) => logs.push(l),
    ...over,
  };
  return { deps, net, persisted, published, logs };
}

describe('runSubmit', () => {
  it('stages run in order; the ledger is persisted before the site is built, even if it fails', async () => {
    const order: string[] = [];
    setup({ publishSite: true, reporterLogin: 'bot' }, scanResult());
    const h = harness({
      persist: async () => {
        order.push('persist');
      },
      submitAll: async (o) => {
        order.push('submit');
        return submitAll(o);
      },
      trackAll: async (o) => {
        order.push('track');
        return { ledger: o.ledger, flagged: [] };
      },
      renderSite: () => {
        order.push('render');
        throw new Error('render exploded');
      },
      publish: async () => {
        order.push('publish');
      },
    });
    const code = await runSubmit({ ...submitArgs(), remote: 'git@example:r.git' }, h.deps);
    expect(order.indexOf('submit')).toBeGreaterThan(-1);
    expect(order.indexOf('track')).toBeGreaterThan(order.indexOf('submit'));
    expect(order.indexOf('render')).toBeGreaterThan(order.lastIndexOf('track'));
    expect(order.lastIndexOf('persist')).toBeLessThan(order.indexOf('render'));
    expect(order).not.toContain('publish');
    expect(code).not.toBe(0);
  });

  it('recovers a submitting entry to held and persists that before anything else', async () => {
    let l = createDisclosure(emptyLedger(), {
      repo: 'acme/old',
      findingIds: ['x'],
      archetype: ARCH,
      state: 'queued',
      now: NOW.toISOString(),
    });
    l = transition(l, { repo: 'acme/old', findingIds: ['x'] }, 'submitting', {
      now: NOW.toISOString(),
    });
    setup({}, scanResult({ candidates: [] }), l);
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    const first = h.persisted[0];
    expect(first?.disclosures.find((d) => d.repo === 'acme/old')?.state).toBe('held');
  });

  it('default config: no POST, no publish, ledger and site still written', async () => {
    setup({}, scanResult());
    const h = harness();
    const code = await runSubmit({ ...submitArgs(), remote: 'git@example:r.git' }, h.deps);
    expect(code).toBe(0);
    expect(h.net.reqs.filter((r) => r.method === 'POST')).toEqual([]);
    expect(h.published).toEqual([]);
    expect(h.logs.join('\n')).toMatch(/publish skipped/);
    const last = h.persisted[h.persisted.length - 1];
    expect(last?.disclosures[0]?.state).toBe('held');
    expect(last?.repos['acme/pass']?.verdict).toBe('pass');
    const html = readFileSync(p('site', 'index.html'), 'utf8');
    expect(html).toContain('acme/pass');
    expect(html).not.toContain('acme/fail');
  });

  it('allowlisted but submitMode off: dry run records the body, still zero POSTs', async () => {
    setup({ allowlist: [ARCH], approved: APPROVED }, scanResult());
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    expect(h.net.reqs.filter((r) => r.method === 'POST')).toEqual([]);
    expect(h.net.reqs.some((r) => r.method === 'GET')).toBe(true);
    const d = h.persisted[h.persisted.length - 1]?.disclosures[0];
    expect(d?.state).toBe('queued');
    expect(d?.wouldSend).toMatchObject(REPORT);
  });

  it('0092: allowlisted and live but unapproved: held, zero POSTs', async () => {
    setup({ allowlist: [ARCH], submitMode: true }, scanResult());
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    expect(h.net.reqs.filter((r) => r.method === 'POST')).toEqual([]);
    const d = h.persisted[h.persisted.length - 1]?.disclosures[0];
    expect(d).toMatchObject({ state: 'held', reason: 'not approved at this commit' });
  });

  it('submitMode on: persists `submitting` before the POST, then the URL', async () => {
    setup({ allowlist: [ARCH], approved: APPROVED, submitMode: true }, scanResult());
    const net = fakeNet();
    const states: string[] = [];
    const h = harness(
      {
        persist: async (l) => {
          states.push(
            `${l.disclosures[0]?.state}@posts=${net.reqs.filter((r) => r.method === 'POST').length}`,
          );
        },
      },
      net,
    );
    await runSubmit(submitArgs(), h.deps);
    expect(states[0]).toBe('submitting@posts=0');
    expect(states[states.length - 1]).toContain('submitted');
    expect(net.reqs.filter((r) => r.method === 'POST')).toHaveLength(1);
    expect(net.reqs.find((r) => r.method === 'POST')?.url).toContain(
      '/repos/acme/fail/security-advisories/reports',
    );
  });

  it('publishes only when publishSite is on and a remote is given', async () => {
    setup({ publishSite: true }, scanResult());
    const h = harness();
    await runSubmit({ ...submitArgs(), remote: 'git@example:r.git' }, h.deps);
    expect(h.published).toEqual([p('site')]);

    const h2 = harness();
    await runSubmit(submitArgs(), h2.deps);
    expect(h2.published).toEqual([]);
  });

  it('kill switch file stops every outbound write whatever the config says', async () => {
    setup({ allowlist: [ARCH], approved: APPROVED, submitMode: true }, scanResult());
    writeFileSync(p('KILL'), '');
    const h = harness();
    await runSubmit({ ...submitArgs(), killSwitch: p('KILL') }, h.deps);
    expect(h.net.reqs).toEqual([]);
  });

  it('tracks with the configured reporter login; empty login skips tracking', async () => {
    const seen: string[] = [];
    const track: SubmitDeps['trackAll'] = async (o) => {
      seen.push(o.reporterLogin);
      return { ledger: o.ledger, flagged: [] };
    };
    setup({ reporterLogin: 'bot' }, scanResult({ candidates: [] }));
    await runSubmit(submitArgs(), harness({ trackAll: track }).deps);
    setup({}, scanResult({ candidates: [] }));
    await runSubmit(submitArgs(), harness({ trackAll: track }).deps);
    expect(seen).toEqual(['bot']);
  });

  it('summary is counts only: no repo names, no repo/verdict pairs', async () => {
    setup({ allowlist: [ARCH], approved: APPROVED }, scanResult());
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    const out = h.logs.join('\n');
    expect(out).toMatch(/\d/);
    expect(out).not.toContain('acme');
    expect(out).not.toMatch(/\S+\/\S+\s*[:=]\s*(pass|fail|warn|unknown|held|submitted)/);
  });

  it('a malformed scan result is refused before any write', async () => {
    mkdirSync(p('in'), { recursive: true });
    writeFileSync(p('in', 'scan-result.json'), '{"candidates":"nope"}');
    const h = harness();
    await expect(runSubmit(submitArgs(), h.deps)).rejects.toThrow(/scan result/);
    expect(h.net.reqs).toEqual([]);
    expect(existsSync(p('site'))).toBe(false);
  });
});

describe('forged scan-job artifacts (review #6)', () => {
  const valid = (): ScanResultFile => scanResult();
  const cand = (r: ScanResultFile) => r.candidates[0] as ScanResultFile['candidates'][number];
  const scan = (r: ScanResultFile) => r.scans['acme/fail'] as ScanResultFile['scans'][string];

  it('keeps a well-formed artifact intact', () => {
    const r = parseScanResult(JSON.stringify(valid()));
    expect(r.candidates).toHaveLength(1);
    expect(r.dropped).toEqual({ scans: 0, candidates: 0 });
  });

  const forgeries: Array<[string, (r: ScanResultFile) => void]> = [
    ['dot-dot repo segment', (r) => (cand(r).repo = 'acme/..')],
    ['traversal repo', (r) => (cand(r).repo = '../etc/passwd')],
    ['repo not discovered', (r) => (r.discovered = ['acme/pass'])],
    ['repo without a scan', (r) => delete r.scans['acme/fail']],
    ['empty finding ids', (r) => (cand(r).findingIds = [])],
    ['finding id the scan never failed', (r) => (cand(r).findingIds = ['f1', 'invented'])],
    ['archetype that differs from the scan', (r) => (cand(r).archetype = 'other->thing')],
    ['sha that differs from the scan (0092)', (r) => (cand(r).sha = 'c'.repeat(40))],
    ['missing sha (0092)', (r) => delete (cand(r) as { sha?: string }).sha],
    ['scan verdict that is not fail', (r) => (scan(r).verdict = 'warn')],
    [
      'summary over 1024',
      (r) => (cand(r).report.summary = `${REPORT.summary.slice(0, 80)}${'x'.repeat(1100)}`),
    ],
    ['summary without the disclosure prefix', (r) => (cand(r).report.summary = 'Click here')],
    [
      'description without the header',
      (r) => (cand(r).report.description = `hi\n${REPORT.description}`),
    ],
    [
      'description without the footer',
      (r) => (cand(r).report.description = `${REPORT.description}\nextra`),
    ],
    [
      'description over 65535',
      (r) => {
        const d = REPORT.description;
        const cut = d.lastIndexOf('\n\n---\n\n');
        cand(r).report.description = `${d.slice(0, cut)}${'x'.repeat(66000)}${d.slice(cut)}`;
      },
    ],
    ['non-hex sha', (r) => (scan(r).fullSha = 'z'.repeat(40))],
    ['non-ISO scannedAt', (r) => (scan(r).scannedAt = 'yesterday')],
    ['oversized engineVersion', (r) => (scan(r).engineVersion = 'v'.repeat(300))],
  ];

  it.each(forgeries)('drops a candidate with %s', (_name, mutate) => {
    const r = valid();
    mutate(r);
    const parsed = parseScanResult(JSON.stringify(r));
    expect(parsed.candidates).toHaveLength(0);
    expect(parsed.dropped.candidates + parsed.dropped.scans).toBeGreaterThan(0);
  });

  it('drops scans keyed by an invalid or undiscovered repo name', () => {
    const r = valid();
    r.scans['x/..'] = scan(r);
    r.scans['evil/undiscovered'] = scan(r);
    r.currentFails['x/..'] = ['f1'];
    const parsed = parseScanResult(JSON.stringify(r));
    expect(Object.keys(parsed.scans).sort()).toEqual(['acme/fail', 'acme/pass']);
    expect(parsed.currentFails['x/..']).toBeUndefined();
    expect(parsed.dropped.scans).toBe(2);
  });

  it('a forged artifact reaches no network and writes no forged ledger entry', async () => {
    const r = valid();
    cand(r).repo = 'acme/..';
    cand(r).report.description = 'FORGED: click http://evil.example';
    setup({ allowlist: [ARCH], approved: APPROVED, submitMode: true }, r);
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    expect(h.net.reqs.filter((q) => q.method === 'POST')).toEqual([]);
    expect(h.net.reqs).toEqual([]);
    expect(h.persisted.at(-1)?.disclosures).toEqual([]);
    expect(h.logs.join('\n')).toMatch(/dropped 0 scan\(s\) and 1 candidate/);
  });
});

describe('discoveryState in the scan result (0083)', () => {
  const good = (): DiscoveryState => ({
    schemaVersion: 1,
    sweep: {
      startedAt: '2026-10-01T00:00:00.000Z',
      pending: [{ action: 'openai/codex-action', size: [0, 1000], depth: 0 }],
      truncated: [],
      partial: [],
    },
    repos: { 'acme/fail': { lastSeenSweep: '2026-10-01T00:00:00.000Z' } },
  });
  const withState = (st: unknown): string =>
    JSON.stringify({ ...scanResult(), discoveryState: st });

  it('accepts a well-formed state and returns it', () => {
    expect(parseScanResult(withState(good())).discoveryState).toEqual(good());
  });

  it('is optional: an older scan result without it still parses', () => {
    expect(parseScanResult(JSON.stringify(scanResult())).discoveryState).toBeUndefined();
  });

  const forgeries: Array<[string, (s: DiscoveryState) => unknown]> = [
    ['wrong schemaVersion', (s) => ({ ...s, schemaVersion: 2 })],
    ['dot-dot repo', (s) => ({ ...s, repos: { 'acme/..': s.repos['acme/fail'] } })],
    ['traversal repo', (s) => ({ ...s, repos: { '../x/y': s.repos['acme/fail'] } })],
    ['non-ISO startedAt', (s) => ({ ...s, sweep: { ...s.sweep, startedAt: 'now' } })],
    [
      'unknown action',
      (s) => ({
        ...s,
        sweep: { ...s.sweep, pending: [{ action: 'evil" x', size: [0, 5], depth: 0 }] },
      }),
    ],
    [
      'inverted size range',
      (s) => ({
        ...s,
        sweep: { ...s.sweep, pending: [{ action: 'openai/codex-action', size: [9, 1], depth: 0 }] },
      }),
    ],
    [
      'size beyond 1,000,000',
      (s) => ({
        ...s,
        sweep: {
          ...s.sweep,
          pending: [{ action: 'openai/codex-action', size: [0, 2_000_000], depth: 0 }],
        },
      }),
    ],
    [
      'filename with a space or injection',
      (s) => ({
        ...s,
        sweep: {
          ...s.sweep,
          pending: [
            { action: 'openai/codex-action', size: [5, 5], filename: 'a.yml size:1', depth: 1 },
          ],
        },
      }),
    ],
    [
      'negative depth',
      (s) => ({
        ...s,
        sweep: {
          ...s.sweep,
          pending: [{ action: 'openai/codex-action', size: [0, 5], depth: -1 }],
        },
      }),
    ],
    [
      'extra key on a shard',
      (s) => ({
        ...s,
        sweep: {
          ...s.sweep,
          pending: [{ action: 'openai/codex-action', size: [0, 5], depth: 0, x: 1 }],
        },
      }),
    ],
    [
      'repo entry with a bad lastSeenSweep',
      (s) => ({ ...s, repos: { 'acme/fail': { lastSeenSweep: 5 } } }),
    ],
    ['repos as an array', (s) => ({ ...s, repos: ['acme/fail'] })],
    ['pending as a string', (s) => ({ ...s, sweep: { ...s.sweep, pending: 'all' } })],
    ['an unexpected top-level key', (s) => ({ ...s, extra: 1 })],
    [
      'oversized pending queue',
      (s) => ({
        ...s,
        sweep: {
          ...s.sweep,
          pending: Array.from({ length: 200_001 }, () => ({
            action: 'openai/codex-action',
            size: [0, 5],
            depth: 0,
          })),
        },
      }),
    ],
    ['truncated holding a non-string', (s) => ({ ...s, sweep: { ...s.sweep, truncated: [1] } })],
    ['not an object', () => 'state'],
  ];

  it.each(forgeries)('rejects the whole result with %s', (_n, mutate) => {
    expect(() => parseScanResult(withState(mutate(good())))).toThrow(/discoveryState/);
  });

  it('runSubmit hands the validated state to persist, with every ledger write', async () => {
    setup({}, { ...scanResult(), discoveryState: good() } as ScanResultFile);
    const seen: Array<DiscoveryState | undefined> = [];
    const h = harness({
      persist: async (_l, d) => {
        seen.push(d);
      },
    });
    await runSubmit(submitArgs(), h.deps);
    expect(seen.length).toBeGreaterThan(0);
    for (const d of seen) expect(d).toEqual(good());
  });

  it('a forged state is refused before any network call or write', async () => {
    setup({}, {
      ...scanResult(),
      discoveryState: { ...good(), schemaVersion: 9 },
    } as unknown as ScanResultFile);
    const h = harness();
    await expect(runSubmit(submitArgs(), h.deps)).rejects.toThrow(/discoveryState/);
    expect(h.net.reqs).toEqual([]);
    expect(h.persisted).toEqual([]);
  });
});

describe('execOut timeout (review #5)', () => {
  it('rejects a git-style subprocess that outlives its bound', async () => {
    const t0 = Date.now();
    await expect(execOut('sleep', ['5'], base, 50)).rejects.toBeDefined();
    expect(Date.now() - t0).toBeLessThan(3000);
  });
  it('returns trimmed stdout otherwise', async () => {
    expect(await execOut('echo', ['hi'], base, 5000)).toBe('hi');
  });
});

// ---------------------------------------------------------------- persist

describe('gitPersist', () => {
  it('writes the ledger, commits and pushes it; an unchanged ledger makes no commit', async () => {
    const origin = p('ops.git');
    execFileSync('git', ['init', '-q', '--bare', '-b', 'main', origin]);
    const work = p('ops');
    execFileSync('git', ['clone', '-q', origin, work]);
    sh(work, 'checkout', '-q', '-b', 'main');
    writeFileSync(join(work, 'README'), 'ops');
    sh(work, 'add', '-A');
    sh(work, 'commit', '-qm', 'init');
    sh(work, 'push', '-q', 'origin', 'main');

    const persist = gitPersist({ ledgerPath: join(work, 'ledger.json') });
    const l = applyScan(emptyLedger(), 'acme/a', {
      fullSha: SHA,
      engineVersion: 'v',
      verdict: 'pass',
      scannedAt: NOW.toISOString(),
      failFindings: [],
    });
    await persist(l);
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('2');
    expect(sh(origin, 'show', 'main:ledger.json')).toBe(serializeLedger(l).trim());
    await persist(l);
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('2');
    await persist(emptyLedger());
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('3');
  });

  it('commits discovery.json in the same commit as the ledger', async () => {
    const origin = p('ops2.git');
    execFileSync('git', ['init', '-q', '--bare', '-b', 'main', origin]);
    const work = p('ops2');
    execFileSync('git', ['clone', '-q', origin, work]);
    sh(work, 'checkout', '-q', '-b', 'main');
    writeFileSync(join(work, 'README'), 'ops');
    sh(work, 'add', '-A');
    sh(work, 'commit', '-qm', 'init');
    sh(work, 'push', '-q', 'origin', 'main');

    const persist = gitPersist({
      ledgerPath: join(work, 'ledger.json'),
      discoveryPath: join(work, 'discovery.json'),
    });
    const st: DiscoveryState = {
      schemaVersion: 1,
      sweep: { startedAt: NOW.toISOString(), pending: [], truncated: [], partial: [] },
      repos: {},
    };
    await persist(emptyLedger(), st);
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('2');
    expect(sh(origin, 'show', '--name-only', '--format=', 'main').split('\n').sort()).toEqual([
      'discovery.json',
      'ledger.json',
    ]);
    expect(sh(origin, 'show', 'main:discovery.json')).toBe(serializeDiscoveryState(st).trim());
    // discovery progress alone is enough for a commit
    await persist(emptyLedger(), {
      ...st,
      repos: { 'a/b': { lastSeenSweep: st.sweep.startedAt } },
    });
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('3');
    await persist(emptyLedger());
    expect(sh(origin, 'rev-list', '--count', 'main')).toBe('3');
  });
});

describe('formatRateLimit (0085)', () => {
  it('prints status, route, resource and the limit headers in one line', () => {
    expect(
      formatRateLimit({
        status: 429,
        route: 'search',
        limit: '10',
        remaining: '0',
        used: '10',
        reset: '1790909850',
        resource: 'code_search',
        retryAfter: '30',
      }),
    ).toBe(
      'crawl: rate limited (429, search, code_search): limit=10 remaining=0 used=10 reset=1790909850 retry-after=30',
    );
  });

  it('degrades to the status line when GitHub sent no limit headers', () => {
    expect(formatRateLimit({ status: 403, route: 'core', retryAfter: '60' })).toBe(
      'crawl: rate limited (403, core, resource?): retry-after=60',
    );
  });
});
