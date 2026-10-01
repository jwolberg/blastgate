import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const ROOT = join(__dirname, '..', '..');
const raw = readFileSync(join(ROOT, 'ops', 'crawl.yml'), 'utf8');
const wf = parse(raw) as {
  on: Record<string, unknown>;
  concurrency: { group?: string; 'cancel-in-progress'?: boolean };
  permissions: Record<string, string>;
  jobs: Record<
    string,
    {
      needs?: string | string[];
      environment?: string;
      permissions?: Record<string, string>;
      steps: Array<{ uses?: string; run?: string; env?: Record<string, string> }>;
    }
  >;
};

const jobText = (name: string): string => JSON.stringify(wf.jobs[name]);

describe('ops/crawl.yml template', () => {
  it('has a schedule and a manual trigger', () => {
    expect(wf.on).toHaveProperty('schedule');
    expect(wf.on).toHaveProperty('workflow_dispatch');
  });

  it('pins every action by a full 40-hex SHA with a version comment', () => {
    const uses = raw.split('\n').filter((l) => /^\s*-?\s*uses:/.test(l));
    expect(uses.length).toBeGreaterThanOrEqual(5);
    for (const line of uses) {
      expect(line, line).toMatch(/uses:\s+[\w.-]+\/[\w.-]+@[0-9a-f]{40}\s+#\s*v\d+/);
    }
    for (const job of Object.values(wf.jobs)) {
      for (const s of job.steps) {
        if (s.uses) expect(s.uses).toMatch(/@[0-9a-f]{40}$/);
      }
    }
  });

  it('references no secrets in the scan job', () => {
    expect(jobText('scan')).not.toMatch(/secrets\./);
    expect(raw).not.toMatch(/secrets\.GITHUB_TOKEN/);
  });

  it('uses secrets only in the submit job, and each one only where it is needed', () => {
    const lines = raw.split('\n');
    const start = lines.findIndex((l) => /^ {2}submit:/.test(l));
    expect(start).toBeGreaterThan(-1);
    const before = lines.slice(0, start).join('\n');
    expect(before).not.toMatch(/secrets\./);
    const used = [...raw.matchAll(/secrets\.([A-Z_]+)/g)].map((m) => m[1]).sort();
    expect(used).toEqual(['PVR_TOKEN', 'REGISTRY_DEPLOY_KEY']);

    const steps = wf.jobs.submit?.steps ?? [];
    const holders = (name: string): string[] =>
      steps.filter((s) => JSON.stringify(s.env ?? {}).includes(name)).map((s) => s.run ?? '');
    expect(holders('PVR_TOKEN')).toHaveLength(1);
    expect(holders('PVR_TOKEN')[0]).toContain('crawl/index.js submit');
    expect(holders('REGISTRY_DEPLOY_KEY')).toHaveLength(1);
    expect(holders('REGISTRY_DEPLOY_KEY')[0]).toContain('crawl/index.js publish');
    expect(holders('REGISTRY_DEPLOY_KEY')[0]).not.toContain('crawl/index.js submit');
  });

  it('serializes runs without cancelling an in-flight one', () => {
    expect(wf.concurrency.group).toBe('crawl');
    expect(wf.concurrency['cancel-in-progress']).toBe(false);
  });

  it('declares empty top-level permissions and per-job least privilege', () => {
    expect(wf.permissions).toEqual({});
    expect(wf.jobs.scan?.permissions).toEqual({ contents: 'read' });
    expect(wf.jobs.submit?.permissions).toEqual({ contents: 'write' });
  });

  it('runs submit after scan, in the protected crawler environment', () => {
    expect(wf.jobs.submit?.needs).toBe('scan');
    expect(wf.jobs.submit?.environment).toBe('crawler');
    expect(wf.jobs.scan?.environment).toBeUndefined();
  });

  it('installs without lifecycle scripts and uploads only the scan result for one day', () => {
    for (const j of ['scan', 'submit']) expect(jobText(j)).toContain('npm ci --ignore-scripts');
    const up = wf.jobs.scan?.steps.find((s) => s.uses?.includes('upload-artifact')) as
      { with?: Record<string, unknown> } | undefined;
    expect(up?.with?.['retention-days']).toBe(1);
    expect(String(up?.with?.path)).toMatch(/scan-result\.json$/);
  });
});

describe('npm package contents (KTD9)', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'crawl-pack-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  // Packs a stand-in tree that uses the REAL package.json `files`, so the test never races
  // other suites over `dist/` (tsup cleans it) yet exercises the exact exclusion pattern.
  it('keeps dist/crawl out of the tarball and dist/cli in', () => {
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    for (const f of ['cli/index.js', 'crawl/index.js', 'crawl/index.js.map']) {
      mkdirSync(join(tmp, 'dist', f, '..'), { recursive: true });
      writeFileSync(join(tmp, 'dist', f), '// stub\n');
    }
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      cwd: tmp,
      encoding: 'utf8',
    });
    const files = (JSON.parse(out) as Array<{ files: Array<{ path: string }> }>)[0]?.files.map(
      (f) => f.path,
    );
    expect(files).toContain('dist/cli/index.js');
    expect(files?.filter((f) => f.startsWith('dist/crawl'))).toEqual([]);
  });

  it('package.json negates dist/crawl in files', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      files: string[];
    };
    expect(pkg.files).toContain('dist');
    expect(pkg.files.some((f) => f.startsWith('!dist/crawl'))).toBe(true);
  });
});
