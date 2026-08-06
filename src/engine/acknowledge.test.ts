import { describe, expect, it } from 'vitest';
import { applyAcknowledgements, parseAcknowledgements } from './acknowledge';
import { runEngine } from './gate';
import type { EngineInputs } from './build';
import type { Finding } from '../findings/finding';

function fail(id: string): Finding {
  return {
    id,
    tier: 'fail',
    score: 300,
    path: ['e', 's'],
    pathNodeIds: ['e', 's'],
    hops: 1,
    entry: { kind: 'fork-pr', label: 'e' },
    sink: { kind: 'secret', identity: 'S' },
    reason: 'r',
    remediation: 'fix',
    owasp: {},
    labels: [],
  };
}

describe('parseAcknowledgements', () => {
  it('parses id + reason and tolerates malformed input', () => {
    expect(parseAcknowledgements('{"acknowledged":[{"id":"a","reason":"why"}]}')).toEqual([
      { id: 'a', reason: 'why' },
    ]);
    expect(parseAcknowledgements('not json')).toEqual([]);
    expect(parseAcknowledgements(null)).toEqual([]);
    expect(parseAcknowledgements('{"acknowledged":[{"noid":1}]}')).toEqual([]);
  });
});

describe('applyAcknowledgements', () => {
  it('downgrades an acknowledged fail to warn and records the reason — never drops it', () => {
    const out = applyAcknowledgements([fail('x')], [{ id: 'x', reason: 'reviewed 2026-08-05' }]);
    expect(out).toHaveLength(1); // still present, not silently removed
    expect(out[0]!.tier).toBe('warn');
    expect(out[0]!.acknowledged).toBe('reviewed 2026-08-05');
  });

  it('leaves an unacknowledged fail untouched', () => {
    const out = applyAcknowledgements([fail('x')], [{ id: 'other', reason: 'n/a' }]);
    expect(out[0]!.tier).toBe('fail');
    expect(out[0]!.acknowledged).toBeUndefined();
  });
});

// AE1-shaped inputs whose fork-pr finding id is deterministic.
function ae1(acknowledged?: EngineInputs['acknowledged']): EngineInputs {
  const headLock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app' },
      'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true },
    },
  });
  const workflow = [
    'on:',
    '  pull_request_target:',
    'jobs:',
    '  test:',
    '    steps:',
    '      - run: gh pr checkout 123',
    '      - run: npm ci',
    '        env:',
    '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
  ].join('\n');
  return {
    deps: { headLockfile: headLock, baseLockfile: JSON.stringify({ packages: { '': {} } }) },
    ci: { workflows: [{ path: '.github/workflows/ci.yml', content: workflow }] },
    acknowledged,
  };
}

describe('runEngine with acknowledgements', () => {
  it('a fully acknowledged repo drops from fail to warn (gate no longer fails)', () => {
    const ids = runEngine(ae1()).findings.map((f) => f.id);
    expect(ids.length).toBeGreaterThan(0);
    const acknowledged = ids.map((id) => ({ id, reason: 'accepted risk' }));

    const result = runEngine(ae1(acknowledged));
    expect(result.verdict).toBe('warn'); // not fail, and not pass — still surfaced
    expect(result.findings.every((f) => f.tier === 'warn')).toBe(true);
    expect(result.findings.every((f) => f.acknowledged === 'accepted risk')).toBe(true);
  });

  it('acknowledging only some fail findings still fails on the rest', () => {
    const ids = runEngine(ae1()).findings.map((f) => f.id);
    const result = runEngine(ae1([{ id: ids[0]!, reason: 'partial' }]));
    expect(result.verdict).toBe('fail'); // an un-acked fail remains
  });
});
