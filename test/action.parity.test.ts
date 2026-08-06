import { describe, expect, it } from 'vitest';
import type { RepoFs } from '../src/cli/collect';
import { runCli } from '../src/cli/index';
import { runAction, runActionCore, type ActionEnv } from '../src/action/index';

const HEAD_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true },
  },
});
const BASE_LOCK = JSON.stringify({ packages: { '': { name: 'app' } } });
const WORKFLOW = [
  'on:',
  '  pull_request_target:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');

function memFs(files: Record<string, string>, base?: Record<string, string>): RepoFs {
  return {
    read: (p) => (p in files ? files[p]! : null),
    listWorkflows: () =>
      Object.keys(files).filter((p) => /^\.github\/workflows\/.*\.ya?ml$/.test(p)),
    gitShow: base ? (_ref, p) => (p in base ? base[p]! : null) : undefined,
  };
}
function failingFs(): RepoFs {
  return memFs(
    { 'package-lock.json': HEAD_LOCK, '.github/workflows/ci.yml': WORKFLOW },
    { 'package-lock.json': BASE_LOCK },
  );
}
function cleanFs(): RepoFs {
  return memFs({ 'package.json': '{"name":"app"}' });
}

interface Sink {
  annotations: Array<{ level: string; message: string }>;
  summaries: string[];
}
function captureEnv(fs: RepoFs, base?: string): { env: ActionEnv; sink: Sink } {
  const sink: Sink = { annotations: [], summaries: [] };
  const env: ActionEnv = {
    fs,
    base,
    annotate: (level, message) => sink.annotations.push({ level, message }),
    summary: (markdown) => sink.summaries.push(markdown),
  };
  return { env, sink };
}

async function cliFindings(fs: RepoFs): Promise<unknown> {
  let out = '';
  await runCli(['.', '--base', 'HEAD', '--json'], {
    fs,
    stdin: () => Promise.resolve(''),
    stdout: (s) => {
      out += s;
    },
    stderr: () => {},
  });
  return JSON.parse(out);
}

describe('action / CLI parity (KTD10)', () => {
  it('the Action and the CLI produce identical findings JSON on the AE1 fixture', async () => {
    const actionResult = runActionCore(failingFs(), { base: 'HEAD' });
    const cli = await cliFindings(failingFs());
    expect(JSON.parse(JSON.stringify(actionResult.findings))).toEqual(cli);
  });
});

describe('runAction exit codes', () => {
  it('exits non-zero on the AE1 fixture', () => {
    const { env } = captureEnv(failingFs(), 'HEAD');
    expect(runAction(env)).not.toBe(0);
  });

  it('exits zero on a clean fixture', () => {
    const { env } = captureEnv(cleanFs());
    expect(runAction(env)).toBe(0);
  });
});

describe('runAction PR surfacing', () => {
  it('emits an error annotation and the shared markdown report as the job summary', () => {
    const { env, sink } = captureEnv(failingFs(), 'HEAD');
    runAction(env);

    const errors = sink.annotations.filter((a) => a.level === 'error');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((a) => a.message.includes('AWS_SECRET_ACCESS_KEY'))).toBe(true);

    // The summary is the same report `blastgate --format md` prints (KTD10 parity):
    // verdict header, the workflow-guidance banner, the sink, and the OWASP label.
    expect(sink.summaries.length).toBe(1);
    const summary = sink.summaries[0]!;
    expect(summary).toMatch(/^#/m);
    expect(summary).toMatch(/where this runs/i);
    expect(summary).toContain('AWS_SECRET_ACCESS_KEY');
    expect(summary).toContain('ASI04:2026');
  });

  it('renders a clean summary and no error annotations for a passing run', () => {
    const { env, sink } = captureEnv(cleanFs());
    runAction(env);
    expect(sink.annotations.filter((a) => a.level === 'error')).toHaveLength(0);
    expect(sink.summaries).toHaveLength(1);
  });

  it('does not throw on a failing run even though findings carry no file/line position', () => {
    const { env } = captureEnv(failingFs(), 'HEAD');
    expect(() => runAction(env)).not.toThrow();
  });
});
