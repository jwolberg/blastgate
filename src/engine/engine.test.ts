import { describe, expect, it } from 'vitest';
import type { EngineInputs } from './build';
import { gateFails, runEngine } from './gate';

/** package-lock.json head that adds `evil-pkg@1.0.0` with a lifecycle script. */
function headLock(): string {
  return JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app' },
      'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true },
    },
  });
}
/** Base lockfile without the dependency, so the diff yields a new-dependency entry. */
function baseLock(): string {
  return JSON.stringify({ packages: { '': { name: 'app' } } });
}

/**
 * AE1 — cross-layer true positive: a newly added install-script dependency, a
 * fork-triggerable (`pull_request_target`) job that runs `npm ci` and references
 * `AWS_SECRET_ACCESS_KEY`.
 */
function ae1Inputs(): EngineInputs {
  const workflow = [
    'on:',
    '  pull_request_target:',
    'jobs:',
    '  test:',
    '    steps:',
    '      - run: gh pr checkout 123',
    '      - uses: actions/checkout@v4',
    '      - run: npm ci',
    '        env:',
    '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
  ].join('\n');
  return {
    deps: { headLockfile: headLock(), baseLockfile: baseLock() },
    ci: { workflows: [{ path: '.github/workflows/ci.yml', content: workflow }] },
  };
}

/** AE2 — anti-false-positive: an install-script dep, but the job is secretless and non-fork. */
function ae2Inputs(): EngineInputs {
  const workflow = [
    'on:',
    '  push:',
    'jobs:',
    '  build:',
    '    steps:',
    '      - run: gh pr checkout 123',
    '      - run: npm ci',
  ].join('\n');
  return {
    deps: { headLockfile: headLock(), baseLockfile: baseLock() },
    ci: { workflows: [{ path: '.github/workflows/ci.yml', content: workflow }] },
  };
}

/** AE4 — agent over-privilege: an MCP filesystem server rooted at `/` (out of repo). */
function ae4Inputs(): EngineInputs {
  const mcpJson = JSON.stringify({
    mcpServers: {
      fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    },
  });
  return { agent: { mcpJson } };
}

/**
 * Integration negative: an install-script dep whose install runs in a
 * secret-holding but NON-fork-triggerable (`push`) job — the entry is not
 * attacker-controllable, so no fail.
 */
function nonForkSecretInputs(): EngineInputs {
  const workflow = [
    'on:',
    '  push:',
    'jobs:',
    '  deploy:',
    '    steps:',
    '      - run: gh pr checkout 123',
    '      - run: npm ci',
    '        env:',
    '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
  ].join('\n');
  return {
    deps: { headLockfile: headLock(), baseLockfile: baseLock() },
    ci: { workflows: [{ path: '.github/workflows/ci.yml', content: workflow }] },
  };
}

describe('runEngine — cross-layer gate', () => {
  it('AE1: fails on the cross-layer install-script → fork-triggerable job → secret path', () => {
    const result = runEngine(ae1Inputs());

    expect(result.verdict).toBe('fail');
    expect(gateFails(result.verdict)).toBe(true);

    const crossLayer = result.findings.find((f) => f.entry.kind === 'new-dependency');
    expect(crossLayer, 'a new-dependency (postinstall) finding is reported').toBeDefined();
    // path: postinstall entry → dependency → fork-triggerable job → secret
    expect(crossLayer!.pathNodeIds[0]).toBe('entry:new-dep:evil-pkg');
    expect(crossLayer!.pathNodeIds).toContain('dep:evil-pkg@1.0.0');
    expect(crossLayer!.pathNodeIds).toContain('job:.github/workflows/ci.yml#test');
    expect(crossLayer!.pathNodeIds.at(-1)).toBe('sink:secret:AWS_SECRET_ACCESS_KEY');
    expect(crossLayer!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
    expect(crossLayer!.tier).toBe('fail');
    // carries a fix and an OWASP label (KTD9 supply-chain archetype)
    expect(crossLayer!.remediation.length).toBeGreaterThan(0);
    expect(crossLayer!.labels).toContain('ASI04:2026');
    expect(crossLayer!.labels).toContain('MCP04:2025');
    expect(crossLayer!.reason.toLowerCase()).toContain('install script');
  });

  it('AE2: passes — a present install script with no reachable sink never fails (R14)', () => {
    const result = runEngine(ae2Inputs());
    expect(result.verdict).toBe('pass');
    expect(result.findings).toHaveLength(0);
    expect(gateFails(result.verdict)).toBe(false);
  });

  it('AE4: warns (does not fail) on a reachable over-privileged agent capability path', () => {
    const result = runEngine(ae4Inputs());
    expect(result.verdict).toBe('warn');
    expect(gateFails(result.verdict)).toBe(false);
    const warn = result.findings.find((f) => f.sink.kind === 'privileged-capability');
    expect(warn, 'a capability finding is reported').toBeDefined();
    expect(warn!.tier).toBe('warn');
    expect(warn!.remediation.length).toBeGreaterThan(0);
    expect(warn!.labels).toContain('MCP02:2025');
  });

  it('integration: a secret-holding but non-fork-triggerable install job does not fail', () => {
    const result = runEngine(nonForkSecretInputs());
    expect(result.verdict).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });

  it('determinism: two runs over one repo produce byte-identical findings', () => {
    const a = JSON.stringify(runEngine(ae1Inputs()).findings);
    const b = JSON.stringify(runEngine(ae1Inputs()).findings);
    expect(a).toBe(b);
  });

  it('completeness: every finding carries path, sink, reason, remediation, and a label field', () => {
    for (const f of runEngine(ae1Inputs()).findings) {
      expect(f.path.length).toBeGreaterThan(0);
      expect(f.pathNodeIds.length).toBe(f.path.length);
      expect(f.sink.identity.length).toBeGreaterThan(0);
      expect(f.reason.length).toBeGreaterThan(0);
      expect(f.remediation.length).toBeGreaterThan(0);
      expect(Array.isArray(f.labels)).toBe(true);
    }
  });

  it('ranks a fail-tier secret/credential path first', () => {
    const result = runEngine(ae1Inputs());
    expect(result.findings[0]!.tier).toBe('fail');
    expect(['secret', 'credential']).toContain(result.findings[0]!.sink.kind);
  });
});
