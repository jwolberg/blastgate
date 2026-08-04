import { describe, expect, it } from 'vitest';
import { diffLockfiles } from './diff';
import { analyzeDependencies } from './index';
import { parseLockfile } from './lockfile';
import { parseNpmrc } from './npmrc';

const lockWithScript = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'root' },
    'node_modules/left-pad': { version: '1.3.0' },
    'node_modules/evil-pkg': { version: '2.0.0', hasInstallScript: true },
  },
});

describe('parseLockfile', () => {
  it('flags a dependency that declares an install script (offline)', () => {
    const deps = parseLockfile(lockWithScript);
    expect(deps.find((d) => d.pkg === 'evil-pkg')?.hasInstallScript).toBe(true);
    const leftPad = deps.find((d) => d.pkg === 'left-pad');
    expect(leftPad?.hasInstallScript).toBe(false);
    expect(leftPad?.isDirect).toBe(true);
  });
});

describe('diffLockfiles', () => {
  it('detects a newly added dependency in head vs base', () => {
    const base = JSON.stringify({
      packages: { '': {}, 'node_modules/left-pad': { version: '1.3.0' } },
    });
    const change = diffLockfiles(base, lockWithScript).find((c) => c.pkg === 'evil-pkg');
    expect(change?.change).toBe('added');
  });

  it('detects a version / integrity change', () => {
    const base = JSON.stringify({
      packages: { 'node_modules/x': { version: '1.0.0', integrity: 'sha512-a' } },
    });
    const head = JSON.stringify({
      packages: { 'node_modules/x': { version: '1.0.1', integrity: 'sha512-b' } },
    });
    expect(diffLockfiles(base, head)[0]?.change).toBe('changed');
  });
});

describe('parseNpmrc', () => {
  it('flags a registry redirect and ignores comments and strict-ssl=true', () => {
    const findings = parseNpmrc('# comment\nregistry=https://evil.example.com/\nstrict-ssl=true\n');
    expect(findings.map((f) => f.key)).toEqual(['registry']);
  });

  it('flags strict-ssl=false and a custom CA file', () => {
    const findings = parseNpmrc('strict-ssl=false\ncafile=/tmp/evil.pem\n');
    expect(findings.map((f) => f.key).sort()).toEqual(['cafile', 'strict-ssl']);
  });
});

describe('analyzeDependencies', () => {
  it('emits dependency nodes and a new-dependency entry with a controls edge', () => {
    const base = JSON.stringify({ packages: { '': {} } });
    const result = analyzeDependencies({ headLockfile: lockWithScript, baseLockfile: base });
    expect(result.nodes.some((n) => n.kind === 'dependency' && n.pkg === 'evil-pkg')).toBe(true);
    expect(result.nodes.some((n) => n.kind === 'entry')).toBe(true);
    expect(result.edges.some((e) => e.edge.kind === 'controls')).toBe(true);
  });

  it('emits an entry for a security-relevant .npmrc change', () => {
    const result = analyzeDependencies({
      headLockfile: JSON.stringify({ packages: { '': {} } }),
      npmrc: 'registry=https://evil.example.com/\n',
      baseNpmrc: null,
    });
    expect(result.nodes.some((n) => n.kind === 'entry' && n.label.includes('.npmrc'))).toBe(true);
  });

  it('returns a parse-error diagnostic on a malformed lockfile instead of throwing', () => {
    const result = analyzeDependencies({ headLockfile: '{ not valid json' });
    expect(result.diagnostics.some((d) => d.level === 'error')).toBe(true);
    expect(result.nodes).toEqual([]);
  });
});
