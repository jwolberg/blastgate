import { describe, expect, it } from 'vitest';
import { runEngine } from '../../engine/gate';
import { analyzeExec } from './index';

describe('analyzeExec — CI-divergent install/build scripts (0021)', () => {
  it('emits a ci-divergent entry → privileged-capability sink for a gated postinstall', () => {
    const r = analyzeExec({
      scripts: [{ name: 'postinstall → scripts/setup.js', source: 'if (!process.env.CI) drop();' }],
    });
    const entry = r.nodes.find((n) => n.kind === 'entry');
    const sink = r.nodes.find((n) => n.kind === 'sink');
    expect(entry).toMatchObject({ kind: 'entry', entryKind: 'ci-divergent' });
    expect(sink).toMatchObject({ kind: 'sink', sinkKind: 'privileged-capability' });
    expect(r.edges).toHaveLength(1);
    expect(r.edges[0]).toMatchObject({ from: entry!.id, to: sink!.id, edge: { kind: 'reaches' } });
  });

  it('emits nothing for a clean lifecycle script', () => {
    const r = analyzeExec({ scripts: [{ name: 'postinstall', source: "echo 'built'" }] });
    expect(r.nodes).toHaveLength(0);
    expect(r.edges).toHaveLength(0);
  });
});

describe('engine over an exec layer (0021 integration)', () => {
  it('a CI-divergent lifecycle script produces a warn finding, not a fail', () => {
    const result = runEngine({
      exec: { scripts: [{ name: 'postinstall', source: 'if (!process.env.CI) { exfil(); }' }] },
    });
    expect(result.verdict).toBe('warn');
    const f = result.findings.find((x) => x.entry.kind === 'ci-divergent');
    expect(f, 'a ci-divergent finding').toBeDefined();
    expect(f!.tier).toBe('warn');
    expect(f!.sink.kind).toBe('privileged-capability');
    expect(f!.reason).toContain('concealment');
    expect(f!.labels).toContain('ASI04:2026');
  });

  it('a clean lifecycle script yields a pass with no findings', () => {
    const result = runEngine({
      exec: { scripts: [{ name: 'build', source: 'tsc -p tsconfig.json' }] },
    });
    expect(result.verdict).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });
});
