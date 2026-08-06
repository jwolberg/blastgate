import { describe, expect, it } from 'vitest';
import type { RepoFs } from './collect';
import { runCli } from './index';

/** Full-path wiring: a Bash command → hook JSON → classify → allow/deny/gate (0025). */

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
/** A repo whose committed state fails the gate (reachable secret path). */
const failingFs = (): RepoFs =>
  memFs(
    { 'package-lock.json': HEAD_LOCK, '.github/workflows/ci.yml': WORKFLOW },
    { 'package-lock.json': BASE_LOCK },
  );
const cleanFs = (): RepoFs => memFs({ 'package.json': '{"name":"app"}' });

async function hook(command: string, phase: string, fs: RepoFs) {
  const stdin = JSON.stringify({ tool_input: { command } });
  let out = '';
  let err = '';
  const code = await runCli(['check', '--gate', phase], {
    fs,
    stdin: () => Promise.resolve(stdin),
    stdout: (s) => (out += s),
    stderr: (s) => (err += s),
  });
  return { code, out, err };
}

describe('shell-guard wiring (0025)', () => {
  it('allows a non-mutating command fast — no engine run even in a failing repo', async () => {
    const r = await hook('ls -la', 'shell-pre', failingFs());
    expect(r.code).toBe(0);
    expect(r.out).toBe('');
  });

  it('DENIES a --no-verify bypass (never runs, never allows)', async () => {
    const r = await hook('git commit --no-verify -m x', 'shell-pre', cleanFs());
    expect(r.out).toContain('permissionDecision');
    expect(r.out).toContain('deny');
    expect(r.out).toMatch(/bypass/i);
  });

  it('DENIES a core.hooksPath bypass wrapped in bash -c', async () => {
    const r = await hook(
      "bash -c 'git -c core.hooksPath=/dev/null commit'",
      'shell-pre',
      cleanFs(),
    );
    expect(r.out).toContain('deny');
  });

  it('gates a wrapped commit and denies when the repo is failing', async () => {
    const r = await hook("bash -c 'git commit -m x'", 'shell-pre', failingFs());
    expect(r.out).toContain('deny'); // the literal matcher would have missed this wrapping
  });

  it('gates a commit but allows when the repo is clean', async () => {
    const r = await hook('git commit -m x', 'shell-pre', cleanFs());
    expect(r.code).toBe(0);
    expect(r.out).toBe('');
  });

  it('shell-post blocks a failing npm install (react-only)', async () => {
    const r = await hook('npm install evil-pkg', 'shell-post', failingFs());
    expect(r.out).toContain('block');
  });
});
