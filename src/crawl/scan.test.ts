import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { applyScan, emptyLedger, serializeLedger } from './ledger';
import { reverify, scanRepos } from './scan';

/**
 * U3: the real scripts/eval-scan.sh against a file:// "GitHub" and a stub CLI whose
 * behavior is picked by each remote repo's package.json name.
 */
const STUB = join(__dirname, 'fixtures', 'scan', 'stub-cli.mjs');
const NOW = new Date('2026-10-01T12:00:00.000Z');
let base: string;

const git = (cwd: string, ...args: string[]): string =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', ...args], {
    cwd,
    encoding: 'utf8',
  }).trim();

const remote = (repo: string): string => join(base, 'remote', `${repo}.git`);

function makeRepo(repo: string, mode: string): void {
  const dir = remote(repo);
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(dir, '.github', 'workflows', 'ci.yml'), 'on: push\njobs: {}\n');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: mode }));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'uploadpack.allowFilter', 'true');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'init');
}

const env = (): NodeJS.ProcessEnv => ({
  ...process.env,
  EVAL_REMOTE_BASE: `file://${join(base, 'remote')}`,
  BLASTGATE_CLI: STUB,
  JOBS: '1',
});

const MODES = ['pass', 'warn', 'fail', 'exit1', 'exit1-clean', 'exit2', 'garbage'];

beforeAll(() => {
  base = mkdtempSync(join(tmpdir(), 'crawl-scan-'));
  for (const m of MODES) makeRepo(`acme/${m}`, m);
});
afterAll(() => rmSync(base, { recursive: true, force: true }));

describe('scanRepos — KTD3 verdict table', () => {
  let results: Awaited<ReturnType<typeof scanRepos>>;
  beforeAll(async () => {
    results = await scanRepos([...MODES.map((m) => `acme/${m}`), 'acme/missing'], {
      workdir: join(base, 'work'),
      outdir: join(base, 'out'),
      env: env(),
      now: () => NOW,
    });
  });

  it.each([
    ['pass', 'pass'],
    ['warn', 'warn'],
    ['fail', 'fail'],
    ['exit1', 'unknown'], // exit 1, no fail-tier finding
    ['exit1-clean', 'unknown'],
    ['exit2', 'unknown'], // exit > 1, empty output
    ['garbage', 'unknown'], // unparseable JSON
  ])('%s -> %s', (mode, verdict) => {
    expect(results[`acme/${mode}`]?.verdict).toBe(verdict);
  });

  it('records a clone failure as clone-failed, never pass', () => {
    expect(results['acme/missing']?.verdict).toBe('clone-failed');
    expect(results['acme/missing']?.failFindings).toEqual([]);
  });

  it('records the full 40-char HEAD sha, engine version and scan time', () => {
    const r = results['acme/pass'];
    expect(r?.fullSha).toBe(git(remote('acme/pass'), 'rev-parse', 'HEAD'));
    expect(r?.fullSha).toMatch(/^[0-9a-f]{40}$/);
    expect(r?.engineVersion).toBe('9.9.9');
    expect(r?.scannedAt).toBe(NOW.toISOString());
  });

  it('keeps only fail-tier findings, as id + archetype', () => {
    expect(results['acme/fail']?.failFindings).toEqual([
      { id: 'e2=>s2', archetype: 'pull_request_target->agent' },
    ]);
    expect(results['acme/warn']?.failFindings).toEqual([]);
  });

  it('index.tsv carries a 40-char sha', () => {
    const rows = readFileSync(join(base, 'out', 'index.tsv'), 'utf8')
      .trim()
      .split('\n');
    const pass = rows.find((r) => r.startsWith('acme/pass\t'));
    expect(pass?.split('\t')[1]).toMatch(/^[0-9a-f]{40}$/);
  });

  it('payload text appears nowhere in the results or the serialized ledger', () => {
    let ledger = emptyLedger();
    for (const [repo, scan] of Object.entries(results)) ledger = applyScan(ledger, repo, scan);
    expect(JSON.stringify(results)).not.toContain('PAYLOAD-SECRET-TEXT');
    expect(serializeLedger(ledger)).not.toContain('PAYLOAD-SECRET-TEXT');
    // sanity: the raw per-repo output (local only) does contain it, so the check is real
    expect(readFileSync(join(base, 'out', 'acme__fail.json'), 'utf8')).toContain(
      'PAYLOAD-SECRET-TEXT',
    );
  });
});

describe('reverify (AE5)', () => {
  const repo = 'acme/fixme';
  const fresh = (n: string): string => join(base, 'fresh', n);

  it('sees an upstream fix that a cached scan missed, and refuses a stale head', async () => {
    makeRepo(repo, 'fail');
    const oldHead = git(remote(repo), 'rev-parse', 'HEAD');
    const opts = { workdir: join(base, 'cached'), outdir: join(base, 'cached-out'), env: env() };

    const first = (await scanRepos([repo], opts))[repo];
    expect(first?.verdict).toBe('fail');
    const expectedFindingIds = first?.failFindings.map((f) => f.id) ?? [];

    // Still failing at the same head: re-verify confirms.
    const same = await reverify(repo, {
      ...opts,
      freshWorkdir: fresh('a'),
      outdir: join(base, 'rv-a'),
      expectedFindingIds,
      remoteHead: oldHead,
    });
    expect(same.status).toBe('still-fails');

    // Upstream fixes the repo.
    writeFileSync(join(remote(repo), 'package.json'), JSON.stringify({ name: 'pass' }));
    git(remote(repo), 'commit', '-qam', 'fix');
    const newHead = git(remote(repo), 'rev-parse', 'HEAD');

    // The cached workdir still vouches for the stale tree...
    expect((await scanRepos([repo], opts))[repo]?.fullSha).toBe(oldHead);

    // ...a fresh run-scoped workdir does not.
    const fixed = await reverify(repo, {
      ...opts,
      freshWorkdir: fresh('b'),
      outdir: join(base, 'rv-b'),
      expectedFindingIds,
      remoteHead: newHead,
    });
    expect(fixed.status).toBe('resolved');
    expect(fixed.scan.fullSha).toBe(newHead);
    expect(fixed.scan.verdict).toBe('pass');

    // Remote moved after we read its head: head-mismatch, never a verdict.
    const stale = await reverify(repo, {
      ...opts,
      freshWorkdir: fresh('c'),
      outdir: join(base, 'rv-c'),
      expectedFindingIds,
      remoteHead: oldHead,
    });
    expect(stale.status).toBe('head-mismatch');
  });

  it('is unknown when the fresh scan cannot be evaluated', async () => {
    const r = await reverify('acme/exit2', {
      env: env(),
      freshWorkdir: fresh('d'),
      outdir: join(base, 'rv-d'),
      expectedFindingIds: ['e2=>s2'],
      remoteHead: git(remote('acme/exit2'), 'rev-parse', 'HEAD'),
    });
    expect(r.status).toBe('unknown');
  });

  it('refuses a non-fresh workdir', async () => {
    mkdirSync(fresh('e'), { recursive: true });
    writeFileSync(join(fresh('e'), 'x'), '');
    await expect(
      reverify(repo, {
        env: env(),
        freshWorkdir: fresh('e'),
        outdir: join(base, 'rv-e'),
        expectedFindingIds: [],
        remoteHead: 'a'.repeat(40),
      }),
    ).rejects.toThrow(/fresh/);
  });
});
