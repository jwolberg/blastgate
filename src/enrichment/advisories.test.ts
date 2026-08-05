import { describe, expect, it } from 'vitest';
import type { Advisory } from '../findings/finding';
import type { Finding } from '../findings/finding';
import { depFromNodeId, enrichWithAdvisories, type AdvisorySource } from './advisories';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'e=>s',
    tier: 'fail',
    score: 300,
    path: [
      'added dependency evil-pkg@1.0.0',
      'evil-pkg@1.0.0',
      'ci.yml#test',
      'AWS_SECRET_ACCESS_KEY',
    ],
    pathNodeIds: ['entry:new-dep:evil-pkg', 'dep:evil-pkg@1.0.0', 'job:ci.yml#test', 'sink:secret'],
    hops: 3,
    entry: { kind: 'new-dependency', label: 'x' },
    sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
    reason: 'r',
    remediation: 'fix',
    owasp: { agentic: 'ASI04' },
    labels: ['ASI04:2026'],
    ...over,
  };
}

const advisory: Advisory = { id: 'GHSA-xxxx', package: 'evil-pkg', summary: 'rce' };

/** A source that returns a fixed advisory only for evil-pkg. */
const fakeSource: AdvisorySource = {
  query: (name) => Promise.resolve(name === 'evil-pkg' ? [advisory] : []),
};

describe('depFromNodeId', () => {
  it('parses npm, RubyGems, and PyPI dependency node ids to OSV ecosystems', () => {
    expect(depFromNodeId('dep:evil-pkg@1.0.0')).toEqual({
      ecosystem: 'npm',
      name: 'evil-pkg',
      version: '1.0.0',
    });
    expect(depFromNodeId('dep:ruby:nokogiri@1.14.0')).toEqual({
      ecosystem: 'RubyGems',
      name: 'nokogiri',
      version: '1.14.0',
    });
    expect(depFromNodeId('dep:python:pkg:flask')).toEqual({ ecosystem: 'PyPI', name: 'flask' });
    expect(depFromNodeId('sink:secret:X')).toBeNull();
    expect(depFromNodeId('dep:python:setup.py')).toBeNull(); // not a named package
  });
});

describe('enrichWithAdvisories (enrichment only — never gates)', () => {
  it('attaches advisories to a finding whose path includes a known-vulnerable dependency', async () => {
    const [f] = await enrichWithAdvisories([finding()], fakeSource);
    expect(f!.advisories).toEqual([advisory]);
  });

  it('bumps the score but never changes the tier (never gates)', async () => {
    const before = finding();
    const [f] = await enrichWithAdvisories([before], fakeSource);
    expect(f!.score).toBeGreaterThan(before.score);
    expect(f!.tier).toBe(before.tier); // tier/verdict is untouched by enrichment
  });

  it('leaves a finding with no dependency on its path untouched', async () => {
    const forkOnly = finding({
      pathNodeIds: ['entry:fork-pr', 'job:ci.yml#test', 'sink:secret'],
    });
    const [f] = await enrichWithAdvisories([forkOnly], fakeSource);
    expect(f!.advisories).toBeUndefined();
  });

  it('attaches nothing when the dependency has no advisory (a clean dep is not decorated)', async () => {
    const clean = finding({
      pathNodeIds: ['entry:new-dep:safe', 'dep:safe-pkg@2.0.0', 'job', 'sink'],
    });
    const [f] = await enrichWithAdvisories([clean], fakeSource);
    expect(f!.advisories).toBeUndefined();
  });

  it('is resilient to a source error — the finding is returned unchanged', async () => {
    const throwing: AdvisorySource = { query: () => Promise.reject(new Error('network down')) };
    const [f] = await enrichWithAdvisories([finding()], throwing);
    expect(f!.advisories).toBeUndefined();
    expect(f!.tier).toBe('fail');
  });

  it('re-ranks so an advisory-bearing finding sorts above an equal-score clean one', async () => {
    const clean = finding({ id: 'clean', pathNodeIds: ['dep:safe-pkg@2.0.0'], score: 300 });
    const vuln = finding({ id: 'vuln', pathNodeIds: ['dep:evil-pkg@1.0.0'], score: 300 });
    const out = await enrichWithAdvisories([clean, vuln], fakeSource);
    expect(out[0]!.id).toBe('vuln');
  });
});
