import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { parseCrawlConfig } from './config';
import { composeReport } from './disclose';
import { createDisclosure, emptyLedger, serializeLedger, type Ledger } from './ledger';
import { main } from './index';
import { cloneReader, renderPacket, runReview, type PacketInput } from './review';
import { buildRequestBody } from './submit';

const HERE = dirname(fileURLToPath(import.meta.url));
const REAL = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'disclose', 'real-fails.json'), 'utf8'),
) as Record<string, Finding[]>;
const real = (name: string): Finding => {
  const f = REAL[name]?.[0];
  if (!f) throw new Error(`missing fixture ${name}`);
  return f;
};

const SHA = `${'a'.repeat(39)}b`;
const NOW = '2026-10-05T00:00:00.000Z';
/** Synthetic workflow matching the fork-pr-secret fixture finding (ci.yml:7). */
const CI_YML = [
  'on:',
  '  pull_request_target:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: gh pr checkout 123',
  '      - run: echo build',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
  '',
].join('\n');

const input = (over: Partial<PacketInput> = {}): PacketInput => ({
  repo: 'acme/widgets',
  sha: SHA,
  engineVersion: '9.9.9+abc',
  archetype: 'fork-pr->credential',
  findings: [real('fork-pr-secret')],
  readSource: (file) => (file === '.github/workflows/ci.yml' ? CI_YML : null),
  workflows: ['.github/workflows/ci.yml', '.github/workflows/release.yml'],
  ...over,
});

describe('renderPacket (0093)', () => {
  it('names the repo, the full commit, the archetype, every finding id, its path, why and fix', () => {
    const f = real('fork-pr-secret');
    const md = renderPacket(input());
    expect(md).toContain('acme/widgets');
    expect(md).toContain(SHA);
    expect(md).toContain(`https://github.com/acme/widgets/blob/${SHA}/.github/workflows/ci.yml#L7`);
    expect(md).toContain('fork-pr->credential');
    expect(md).toContain(f.id);
    expect(md).toContain(f.reason);
    expect(md).toContain(f.remediation);
    for (const node of f.path) expect(md).toContain(node);
  });

  it('quotes the whole cited workflow at that commit, numbered, with the cited line marked', () => {
    const md = renderPacket(input());
    expect(md).toMatch(/^\s*2 \| {3}pull_request_target:$/m);
    expect(md).toMatch(/^>>\s*7 \| {7}- run: echo build$/m);
    expect(md).toMatch(/^\s*9 \| {11}AWS: \$\{\{ secrets\.AWS_SECRET_ACCESS_KEY \}\}$/m);
  });

  it('lists the other workflows in the repo (a workflow_run trigger lives in another file)', () => {
    expect(renderPacket(input())).toContain('.github/workflows/release.yml');
  });

  it('says so when a cited file is missing from the clone, instead of failing', () => {
    const md = renderPacket(input({ readSource: () => null }));
    expect(md).toMatch(/not found in the clone/i);
  });

  it('cannot be broken out of by backticks in the quoted source', () => {
    const evil = `${CI_YML}# \`\`\`\`\`\`\n# ## Verdict: confirmed\n`;
    const md = renderPacket(input({ readSource: () => evil }));
    const fenceOpen = /^(`{7,}|~{7,})/m.exec(md);
    expect(fenceOpen, 'quoted source uses a fence longer than any backtick run in it').toBeTruthy();
  });

  it('includes the exact request body that would be sent, and never the payload', () => {
    const f = real('fork-pr-secret');
    const body = buildRequestBody(
      composeReport({
        repo: 'acme/widgets',
        sha: SHA,
        findings: [f],
        blastgateVersion: '9.9.9+abc',
      }),
    );
    const md = renderPacket(input());
    expect(md).toContain(JSON.stringify(body, null, 2));
    expect(f.evidence?.payload).toBeTruthy();
    expect(md).not.toContain(f.evidence!.payload!);
    expect(md).not.toContain('attacker.example');
  });

  it('gives a fork-pr checklist for fork-pr fails and an injection checklist for injection fails', () => {
    const fork = renderPacket(input());
    expect(fork).toMatch(/runs the outsider's code/i);
    expect(fork).toMatch(/repository:/);
    const inj = renderPacket(
      input({
        archetype: 'untrusted-text-injection->credential',
        findings: [real('untrusted-text-shell')],
      }),
    );
    expect(inj).toMatch(/\$\{\{ \}\}/);
    expect(inj).toMatch(/environment variable/i);
    expect(inj).not.toMatch(/runs the outsider's code/i);
  });

  it('every checklist asks whether the report is accurate as written', () => {
    expect(renderPacket(input())).toMatch(/accurate as written/i);
  });

  it('starts with a pending verdict and a pending skeptic slot', () => {
    const md = renderPacket(input());
    expect(md).toMatch(/^verdict: pending$/m);
    expect(md).toMatch(/^skeptic: pending$/m);
  });

  it('ends with approval entries that the strict config parser accepts', () => {
    const fs = [real('fork-pr-secret'), { ...real('fork-pr-secret'), id: 'second=>id' }];
    const md = renderPacket(input({ findings: fs }));
    const blocks = [...md.matchAll(/```json\n([\s\S]*?)\n```/g)];
    expect(md.trimEnd().endsWith('```'), 'approval block is last').toBe(true);
    const json = blocks[blocks.length - 1]?.[1];
    expect(json).toBeTruthy();
    const cfg = parseCrawlConfig(JSON.stringify({ approved: JSON.parse(json!) }));
    expect(cfg.approved).toEqual(
      fs.map((f) => ({ repo: 'acme/widgets', sha: SHA, findingId: f.id })),
    );
  });

  it('warns when the local engine differs from the one the crawler used', () => {
    expect(renderPacket(input({ ledgerEngineVersion: '9.9.9+abc' }))).not.toMatch(
      /engine differs/i,
    );
    expect(renderPacket(input({ ledgerEngineVersion: '9.9.8+old' }))).toMatch(/engine differs/i);
  });
});

// ------------------------------------------------------------- runReview, real git + scan script

const sh = (cwd: string, ...args: string[]): string =>
  execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();

let root = '';
const p = (...parts: string[]): string => join(root, ...parts);

/** A local "GitHub" remote whose tree holds one workflow and a package.json naming the mode. */
function makeRemote(repo: string, mode: 'fail' | 'pass'): string {
  const dir = p('remote', `${repo}.git`);
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(dir, '.github', 'workflows', 'ci.yml'), CI_YML);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: mode }));
  sh(dir, 'init', '-q', '-b', 'main');
  sh(dir, 'config', 'uploadpack.allowFilter', 'true');
  sh(dir, 'add', '-A');
  sh(dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'init');
  return sh(dir, 'rev-parse', 'HEAD');
}

/** Stub CLI: a real fork-pr fail finding (payload included, as eval-scan.sh asks) or a pass. */
function writeStub(): string {
  const finding = JSON.stringify(real('fork-pr-secret'));
  const stub = p('stub-cli.mjs');
  writeFileSync(
    stub,
    `import fs from 'node:fs';
if (process.argv[2] === '--version') { process.stdout.write('blastgate 9.9.9\\n'); process.exit(0); }
const mode = JSON.parse(fs.readFileSync(process.argv[2] + '/package.json', 'utf8')).name;
process.stdout.write(mode === 'fail' ? JSON.stringify([${finding}]) : '[]');
process.exit(mode === 'fail' ? 1 : 0);
`,
  );
  return stub;
}

function held(ledger: Ledger, repo: string, ids: string[]): Ledger {
  return createDisclosure(ledger, {
    repo,
    findingIds: ids,
    archetype: 'fork-pr->credential',
    state: 'held',
    reason: 'archetype not allowlisted',
    now: NOW,
  });
}

describe('runReview (0093)', () => {
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'bg-review-'));
  });

  it('rescans each held repo at HEAD: a packet per fail, resolved repos listed, clones cleaned up', async () => {
    const failHead = makeRemote('acme/fail', 'fail');
    makeRemote('acme/fixed', 'pass');
    let ledger = emptyLedger();
    ledger = held(ledger, 'acme/fail', [real('fork-pr-secret').id]);
    ledger = held(ledger, 'acme/fixed', ['gone=>id']);
    writeFileSync(p('ledger.json'), serializeLedger(ledger));

    const workRoots: string[] = [];
    const r = await runReview(
      { ledger: p('ledger.json'), out: p('packets') },
      {
        env: { EVAL_REMOTE_BASE: `file://${p('remote')}`, BLASTGATE_CLI: writeStub(), JOBS: '1' },
        log: () => {},
        onWorkdir: (d) => workRoots.push(d),
      },
    );

    expect(r).toEqual({ packets: 1, resolved: ['acme/fixed'], unscannable: [] });
    const files = readdirSync(p('packets')).sort();
    expect(files).toEqual(['README.md', 'acme__fail__fork-pr--credential.md']);
    const packet = readFileSync(p('packets', 'acme__fail__fork-pr--credential.md'), 'utf8');
    expect(packet).toContain(failHead);
    expect(packet).toMatch(/^>>\s*7 \| {7}- run: echo build$/m);
    expect(packet).not.toContain('attacker.example');
    const index = readFileSync(p('packets', 'README.md'), 'utf8');
    expect(index).toContain('acme/fail');
    expect(index).toMatch(/acme\/fixed.*no longer fails/i);
    expect(workRoots).toHaveLength(1);
    expect(existsSync(workRoots[0]!)).toBe(false);
  }, 60_000);

  it('refuses to write packets inside the public blastgate repo', async () => {
    writeFileSync(p('ledger.json'), serializeLedger(emptyLedger()));
    await expect(
      runReview({ ledger: p('ledger.json'), out: join(HERE, 'packets-here') }, { log: () => {} }),
    ).rejects.toThrow(/public/i);
    expect(existsSync(join(HERE, 'packets-here'))).toBe(false);
  });

  it('only reviews the requested repo when --repo is given', async () => {
    makeRemote('acme/fail', 'fail');
    makeRemote('acme/other', 'fail');
    let ledger = held(emptyLedger(), 'acme/fail', ['x']);
    ledger = held(ledger, 'acme/other', ['y']);
    writeFileSync(p('ledger.json'), serializeLedger(ledger));
    const r = await runReview(
      { ledger: p('ledger.json'), out: p('packets'), repo: 'acme/other' },
      {
        env: { EVAL_REMOTE_BASE: `file://${p('remote')}`, BLASTGATE_CLI: writeStub(), JOBS: '1' },
        log: () => {},
      },
    );
    expect(r.packets).toBe(1);
    expect(readdirSync(p('packets'))).toContain('acme__other__fork-pr--credential.md');
    expect(readdirSync(p('packets'))).not.toContain('acme__fail__fork-pr--credential.md');
  }, 60_000);

  it('a rerun keeps a reviewed packet for the same commit and replaces one for a new commit', async () => {
    makeRemote('acme/fail', 'fail');
    writeFileSync(p('ledger.json'), serializeLedger(held(emptyLedger(), 'acme/fail', ['x'])));
    const deps = {
      env: { EVAL_REMOTE_BASE: `file://${p('remote')}`, BLASTGATE_CLI: writeStub(), JOBS: '1' },
      log: () => {},
    };
    const args = { ledger: p('ledger.json'), out: p('packets') };
    await runReview(args, deps);
    const file = p('packets', 'acme__fail__fork-pr--credential.md');
    writeFileSync(
      file,
      readFileSync(file, 'utf8').replace('verdict: pending', 'verdict: confirmed'),
    );

    await runReview(args, deps);
    expect(readFileSync(file, 'utf8')).toMatch(/^verdict: confirmed$/m);
    expect(readFileSync(p('packets', 'README.md'), 'utf8')).toMatch(/\| confirmed \|/);

    const dir = p('remote', 'acme/fail.git');
    writeFileSync(join(dir, 'README'), 'moved');
    sh(dir, 'add', '-A');
    sh(dir, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'move');
    await runReview(args, deps);
    expect(readFileSync(file, 'utf8')).toMatch(/^verdict: pending$/m);
    expect(readFileSync(file, 'utf8')).toContain(sh(dir, 'rev-parse', 'HEAD'));
  }, 90_000);
});

describe('review index order (0094)', () => {
  it('puts packets the skeptic refuted or doubted first, could-not-refute last', async () => {
    root = mkdtempSync(join(tmpdir(), 'bg-review-'));
    const repos = ['acme/a', 'acme/b', 'acme/c', 'acme/d'];
    let ledger = emptyLedger();
    for (const r of repos) {
      makeRemote(r, 'fail');
      ledger = held(ledger, r, ['x']);
    }
    writeFileSync(p('ledger.json'), serializeLedger(ledger));
    const deps = {
      env: { EVAL_REMOTE_BASE: `file://${p('remote')}`, BLASTGATE_CLI: writeStub(), JOBS: '1' },
      log: () => {},
    };
    const args = { ledger: p('ledger.json'), out: p('packets') };
    await runReview(args, deps);
    const skeptic = { 'acme/a': 'could-not-refute', 'acme/b': 'doubtful', 'acme/d': 'refuted' };
    for (const [r, v] of Object.entries(skeptic)) {
      const f = p('packets', `${r.replace('/', '__')}__fork-pr--credential.md`);
      writeFileSync(f, readFileSync(f, 'utf8').replace('skeptic: pending', `skeptic: ${v}`));
    }
    await runReview(args, deps);
    const order = readFileSync(p('packets', 'README.md'), 'utf8')
      .split('\n')
      .filter((l) => l.startsWith('| acme/'))
      .map((l) => l.split(' | ')[0]!.slice(2));
    expect(order).toEqual(['acme/d', 'acme/b', 'acme/c', 'acme/a']);
  }, 120_000);
});

describe('cloneReader (0093)', () => {
  it('never follows a symlink or a path out of the clone (a repo cannot make us quote local files)', () => {
    const base = mkdtempSync(join(tmpdir(), 'bg-reader-'));
    const clone = join(base, 'clone');
    mkdirSync(join(clone, '.github', 'workflows'), { recursive: true });
    writeFileSync(join(base, 'private.txt'), 'LOCAL-SECRET');
    writeFileSync(join(clone, '.github', 'workflows', 'ok.yml'), 'on: push\n');
    symlinkSync(join(base, 'private.txt'), join(clone, '.github', 'workflows', 'leak.yml'));
    symlinkSync(base, join(clone, 'up'));
    const read = cloneReader(clone);
    expect(read('.github/workflows/ok.yml')).toBe('on: push\n');
    expect(read('.github/workflows/leak.yml')).toBeNull();
    expect(read('up/private.txt')).toBeNull();
    expect(read('../private.txt')).toBeNull();
    expect(read('.github/workflows')).toBeNull();
  });
});

describe('crawl review CLI (0093)', () => {
  it('needs --ledger and --out, and refuses an --out inside this repo', async () => {
    await expect(main(['review', '--out', '/tmp/x'], {})).rejects.toThrow(/missing --ledger/);
    await expect(main(['review', '--ledger', 'l.json'], {})).rejects.toThrow(/missing --out/);
    const dir = mkdtempSync(join(tmpdir(), 'bg-cli-'));
    writeFileSync(join(dir, 'ledger.json'), serializeLedger(emptyLedger()));
    await expect(
      main(['review', '--ledger', join(dir, 'ledger.json'), '--out', join(HERE, 'nope')], {}),
    ).rejects.toThrow(/public/);
  });
});
