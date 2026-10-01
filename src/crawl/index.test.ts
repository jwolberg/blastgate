import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { HttpRequest, HttpResponse } from './github';
import { createGitHubClient } from './github';
import {
  type ScanDeps,
  type ScanResultFile,
  type SubmitDeps,
  defaultScanDeps,
  gitPersist,
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

function localScanDeps(over: Partial<ScanDeps> = {}): ScanDeps {
  return {
    ...defaultScanDeps({}),
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
    expect(c?.archetype).toBe(ARCH);
    expect(c?.reverify).toBe('still-fails');
    expect(c?.findingIds).toEqual(res.currentFails['acme/fail']);
    expect(c?.report.description).toContain('Blastgate');
    expect(c?.report.summary.length).toBeLessThanOrEqual(1024);

    const raw = readFileSync(p('out', 'scan-result.json'), 'utf8');
    expect(raw).not.toContain('PAYLOAD-SECRET-TEXT');
    expect(raw).not.toContain('attacker.example');
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
        archetype: ARCH,
        findingIds: ['f1'],
        report: { summary: 'S', description: 'D' },
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
    setup({ allowlist: [ARCH] }, scanResult());
    const h = harness();
    await runSubmit(submitArgs(), h.deps);
    expect(h.net.reqs.filter((r) => r.method === 'POST')).toEqual([]);
    expect(h.net.reqs.some((r) => r.method === 'GET')).toBe(true);
    const d = h.persisted[h.persisted.length - 1]?.disclosures[0];
    expect(d?.state).toBe('queued');
    expect(d?.wouldSend).toMatchObject({ summary: 'S', description: 'D' });
  });

  it('submitMode on: persists `submitting` before the POST, then the URL', async () => {
    setup({ allowlist: [ARCH], submitMode: true }, scanResult());
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
    setup({ allowlist: [ARCH], submitMode: true }, scanResult());
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
    setup({ allowlist: [ARCH] }, scanResult());
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
});
