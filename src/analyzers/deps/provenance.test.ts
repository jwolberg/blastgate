import { describe, expect, it } from 'vitest';
import { analyzeProvenance } from './provenance';
import { runEngine } from '../../engine/gate';
import { cachedFetcher, type PackumentSource, readProvenance } from '../../registry/packument';

/** A packument with provenance (dist.attestations present) at some versions. */
function packument(provenanceByVersion: Record<string, boolean>) {
  const versions: Record<string, { dist: { attestations?: unknown } }> = {};
  for (const [v, hasProv] of Object.entries(provenanceByVersion)) {
    versions[v] = { dist: hasProv ? { attestations: { url: 'x', provenance: {} } } : {} };
  }
  return { versions };
}

/** A recorded (offline) registry: no network, plus a call counter to prove caching. */
function recordedSource(recorded: Record<string, ReturnType<typeof packument> | null>): {
  source: PackumentSource;
  calls: () => number;
} {
  let calls = 0;
  return {
    source: {
      fetch: (pkg) => {
        calls++;
        return Promise.resolve(recorded[pkg] ?? null);
      },
    },
    calls: () => calls,
  };
}

function lock(pkgs: Record<string, string>): string {
  const packages: Record<string, unknown> = { '': { name: 'app' } };
  for (const [name, version] of Object.entries(pkgs)) {
    packages[`node_modules/${name}`] = { version };
  }
  return JSON.stringify({ lockfileVersion: 3, packages });
}

describe('readProvenance', () => {
  it('reads dist.attestations presence for a version, null when unknown', () => {
    const p = packument({ '1.0.0': true, '1.0.1': false });
    expect(readProvenance(p, '1.0.0')).toBe(true);
    expect(readProvenance(p, '1.0.1')).toBe(false);
    expect(readProvenance(p, '9.9.9')).toBeNull(); // version not in packument
    expect(readProvenance(null, '1.0.0')).toBeNull(); // fetch failed
  });
});

describe('analyzeProvenance (AE3)', () => {
  it('flags a regression: base had attestations, head does not', async () => {
    const { source } = recordedSource({ evil: packument({ '1.0.0': true, '1.0.1': false }) });
    const result = await analyzeProvenance(
      lock({ evil: '1.0.0' }),
      lock({ evil: '1.0.1' }),
      cachedFetcher(source),
    );
    expect(result.nodes.some((n) => n.kind === 'entry' && n.id === 'entry:provenance:evil')).toBe(
      true,
    );
    expect(result.edges.some((e) => e.to === 'dep:evil@1.0.1' && e.edge.kind === 'controls')).toBe(
      true,
    );
    expect(result.diagnostics.some((d) => /provenance regression/i.test(d.message))).toBe(true);
  });

  it('does not flag when both versions have attestations', async () => {
    const { source } = recordedSource({ ok: packument({ '1.0.0': true, '1.0.1': true }) });
    const result = await analyzeProvenance(
      lock({ ok: '1.0.0' }),
      lock({ ok: '1.0.1' }),
      cachedFetcher(source),
    );
    expect(result.nodes).toHaveLength(0);
    expect(result.diagnostics).toHaveLength(0);
  });

  it('does not flag when neither version ever had provenance (absence is not regression)', async () => {
    const { source } = recordedSource({ x: packument({ '1.0.0': false, '1.0.1': false }) });
    const result = await analyzeProvenance(
      lock({ x: '1.0.0' }),
      lock({ x: '1.0.1' }),
      cachedFetcher(source),
    );
    expect(result.nodes).toHaveLength(0);
  });

  it('does not flag a newly added package (no prior version to regress from)', async () => {
    const { source } = recordedSource({ fresh: packument({ '2.0.0': false }) });
    const result = await analyzeProvenance(
      lock({}),
      lock({ fresh: '2.0.0' }),
      cachedFetcher(source),
    );
    expect(result.nodes).toHaveLength(0);
  });

  it('treats a registry failure as a soft error — no finding, no throw', async () => {
    const { source } = recordedSource({ evil: null }); // fetch returns null (network failure)
    const result = await analyzeProvenance(
      lock({ evil: '1.0.0' }),
      lock({ evil: '1.0.1' }),
      cachedFetcher(source),
    );
    expect(result.nodes).toHaveLength(0);
  });

  it('caches the packument per package — two version checks, one fetch', async () => {
    const { source, calls } = recordedSource({
      evil: packument({ '1.0.0': true, '1.0.1': false }),
    });
    await analyzeProvenance(
      lock({ evil: '1.0.0' }),
      lock({ evil: '1.0.1' }),
      cachedFetcher(source),
    );
    expect(calls()).toBe(1); // base@1.0.0 and head@1.0.1 share one packument fetch
  });

  it('makes no fetch when there is no base lockfile (no baseline)', async () => {
    const { source, calls } = recordedSource({ evil: packument({ '1.0.1': false }) });
    const result = await analyzeProvenance(null, lock({ evil: '1.0.1' }), cachedFetcher(source));
    expect(result.nodes).toHaveLength(0);
    expect(calls()).toBe(0);
  });
});

describe('provenance feeds the engine (U7 merge)', () => {
  it('a regressed install-script dep reaching a fork-job secret becomes a fail finding', async () => {
    // head adds an install script to evil@1.0.1; the provenance result marks evil an entry.
    const headLock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/evil': { version: '1.0.1', hasInstallScript: true },
      },
    });
    const baseLock = lock({ evil: '1.0.0' });
    const workflow = [
      'on:',
      '  pull_request:',
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: npm ci',
      '        env:',
      '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
    ].join('\n');
    const { source } = recordedSource({ evil: packument({ '1.0.0': true, '1.0.1': false }) });
    const provenance = await analyzeProvenance(baseLock, headLock, cachedFetcher(source));

    const result = runEngine({
      deps: { headLockfile: headLock, baseLockfile: baseLock },
      ci: { workflows: [{ path: '.github/workflows/ci.yml', content: workflow }] },
      provenance,
    });

    const provFinding = result.findings.find((f) => f.pathNodeIds[0] === 'entry:provenance:evil');
    expect(provFinding, 'the provenance entry produces a reachable finding').toBeDefined();
    expect(provFinding!.tier).toBe('fail');
    expect(provFinding!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
  });
});
